# Authunnel

![Lock](Lock.svg)

Authunnel is an authenticated tunnel for reaching private TCP services, including SSH, through an OAuth2-protected TLS WebSocket conduit.

## Primary use-case: OIDC SSH bastion

 An Authunnel server acts as an "SSH Bastion": it exposes a TLS-secured, OIDC-authenticated port, through which clients can reach internal SSH hosts that are otherwise firewalled from the internet.
 
 The typical workflow is:

1. `ssh` launches the Authunnel client as `ProxyCommand`.
2. The client reuses a cached token, refreshes it, or completes Authorization Code + PKCE in a browser.
3. The Authunnel server, acting as an OAuth2 resource server, locates the issuer's JWKS endpoint (by OIDC discovery unless configured otherwise) and validates the JWT access token locally.
4. The server opens the requested `%h:%p` destination.
5. SSH stdio is bridged over that authenticated path.

### Scope: tunnel authentication, not SSH login

Authunnel authenticates the **network path** to a private service: it decides, using OIDC, who may open a tunnel to a destination. It does **not** provide OIDC-authenticated SSH login. Once the tunnel is open, SSH performs its own host and user authentication (keys, certificates, passwords) exactly as it would over any other transport. Authunnel never sees or brokers your SSH credentials, and a valid OIDC token does not by itself grant a login to any host.

In other words, Authunnel provides **bastion-like** functionality — a single authenticated, audited entry point to an internal network — rather than federating SSH login to your identity provider.

If you want OIDC identity to issue the SSH credential itself, use a purpose-built tool built on open source and open standards, optionally alongside Authunnel:

- **opkssh / OpenPubkey** — embeds an OIDC ID token in the SSH public key so OpenSSH can authenticate the user against their IdP ([github.com/openpubkey/opkssh](https://github.com/openpubkey/opkssh)).
- **Smallstep `step-ca`** with its OIDC provisioner — an open source SSH certificate authority that issues short-lived SSH user certificates after an OIDC browser login ([smallstep.com/docs/step-ca](https://smallstep.com/docs/step-ca/)).

These compose naturally with Authunnel: OIDC governs the tunnel (network admission and audit) while an OIDC-backed SSH CA governs the login on the host at the far end.

## Documentation

- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — running the server: TLS modes, reverse-proxy configuration, the full server flag reference, egress policy, OIDC client registration, and the deployment hardening checklist. Also two things that span both binaries: the [transport rules on the auth path](docs/DEPLOYMENT.md#transport-rules-on-the-auth-path), and [protected-resource metadata](docs/DEPLOYMENT.md#protected-resource-metadata-and-zero-configuration-clients), which is how a client can be configured with nothing but `--tunnel-url`.
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — building and testing from source: codebase layout, auth-flow invariants, the test suite, and the local Keycloak environment.
- [examples/](examples/) — runnable CloudFormation templates that stand up a complete Authunnel topology on AWS, so you can see it working end to end before deploying on your own infrastructure.

## Components

- `server/server.go`
  - HTTPS server on a configurable listen address (default `:8443` for TLS-files, `:443` for ACME, `:8080` for plaintext-behind-reverse-proxy)
  - Conservative HTTP server timeouts to reduce slow-client resource exhaustion risk
  - Structured JSON logs with three correlation IDs:
    - `request_id` — generated per HTTP request; scoped to a single request/response cycle
    - `trace_id` — extracted from an incoming `Traceparent` header (W3C Trace Context) when present, otherwise generated; allows correlation with upstream infrastructure such as a load balancer or reverse proxy
    - `tunnel_id` — generated when a WebSocket upgrade succeeds; scoped to the lifetime of the SOCKS tunnel and inherited by all subsequent tunnel events (open, SOCKS CONNECT, close)
  - Tunnel logs include the authenticated user identity, with per-destination SOCKS CONNECT logs at debug level; all three correlation IDs are carried through so HTTP admission, tunnel lifecycle, and per-destination events can be joined
  - OAuth2 resource-server JWT validation: the issuer's JWKS endpoint is located once at startup; claim checks run locally against a cached key set, refreshed only when a token presents an unknown key ID
  - Optional admission controls: global and per-user concurrent-tunnel caps, per-user tunnel-open rate limit, and a bounded dial timeout for outbound SOCKS CONNECT
  - WebSocket tunnel endpoint (`/protected/tunnel`) connected to an in-process SOCKS5 server
- `client/client.go`
  - **ProxyCommand mode**: stdio bridge for direct SSH integration
  - **Unix socket mode**: local SOCKS5 endpoint for generic client tooling
  - **Managed OIDC mode**: public-client PKCE login with token cache + refresh, configured from the server's RFC 9728 protected-resource metadata unless overridden by flags
  - Control-message listener for server-initiated longevity warnings; automatic token refresh when the server signals imminent token expiry

## How It Works

### Server flow

1. Reads OIDC issuer, audience, listen address, TLS mode, and connection longevity configuration from flags or environment.
2. Locates the issuer's JWKS endpoint once at startup — by OIDC discovery unless configured otherwise. The mode in effect is reported as `discovery_mode` on the `token_validator_ready` startup log line; see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#issuer-metadata-and-key-discovery) for the three modes and their trade-offs.
3. Publishes RFC 9728 protected-resource metadata at `GET /.well-known/oauth-protected-resource`, unauthenticated, naming the issuer it validates against so clients need no OIDC configuration of their own. Disabled by `--no-resource-metadata`.
4. Accepts `GET /protected/tunnel`, verifies the bearer token's signature, issuer, expiration, audience, subject presence, `iat` sanity, and `nbf` (the token must be usable now at admission), then checks the WebSocket upgrade headers. Unauthenticated `GET` requests under `/protected/` receive `401`; other HTTP methods receive `405` from the router.
5. Applies admission controls (concurrent-tunnel caps and per-user rate limits) when configured, rejecting over-limit requests with `429`/`503` and a `Retry-After` header.
6. Upgrades the connection to WebSocket.
7. Hands each upgraded connection to the SOCKS5 server implementation.
8. If connection longevity is configured, manages tunnel lifetime: warns clients before expiry and disconnects when limits are reached. When token-expiry enforcement is active, the server accepts refreshed tokens from the client to extend the tunnel.
9. Emits structured JSON logs for request lifecycle, auth failures, tunnel open/close events, token refresh outcomes, and debug-level SOCKS CONNECT destinations.

### Client flow

1. Either:
   - uses a bearer token supplied via the `ACCESS_TOKEN` environment variable, or
   - runs managed OIDC mode, which is the default whenever `ACCESS_TOKEN` is unset.
2. In managed mode, any OIDC value not passed as a flag is read from the tunnel server's RFC 9728 protected-resource metadata, so `--tunnel-url` on its own is a complete configuration. The fetch happens only when something essential is missing, and never on a cache hit — a configuration that supplies everything makes no extra request. A value you pass always wins over the published one. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#protected-resource-metadata-and-zero-configuration-clients).
3. In managed mode the client:
   - reuses a cached token when it remains valid for more than 60 seconds,
   - otherwise refreshes it when a refresh token is available,
   - otherwise launches a browser to the IdP and listens on `127.0.0.1` for the callback.
4. The client opens an authenticated WebSocket connection to the Authunnel server.
5. A background control-message listener handles server-initiated longevity messages. When the server warns that the access token is about to expire, the client automatically obtains a fresh token (via its existing refresh logic) and sends it to the server to extend the tunnel.
6. In ProxyCommand mode it performs a SOCKS5 CONNECT for `%h:%p` and bridges `stdin/stdout`.
7. In unix-socket mode it exposes a local SOCKS5 endpoint and opens a dedicated tunnel per local connection.

## Security Posture

Authunnel is deliberately simple in both functionality and implementation — a small, focused codebase that is intended to be easy to read and audit in full. Complexity is kept low by design; if a feature would make the security model harder to reason about, that is a reason not to add it.

### Required guarantees

The following properties are enforced by default with no silent bypass. Where a development override exists it is noted explicitly:

- **Bearer token validation** at the WebSocket layer before any SOCKS5 connection can be attempted: signature, issuer, audience (`aud`), expiry (`exp`), non-empty subject (`sub`), not-before (`nbf` must be usable at admission time, with a 30-second clock-skew allowance), and sane issued-at (`iat` must not be meaningfully in the future). The bearer token is length-capped at 8 KiB and the `Authorization` header at 8 KiB + 64 bytes before the verifier runs, so anonymous callers cannot push oversized payloads onto the JWT parser. The `http.Server` request-header memory cap is also lowered from Go's 1 MiB default to 16 KiB as a defence-in-depth boundary against oversized non-bearer headers.
- **Bounded issuer metadata and JWKS fetches**: both the server-side validator and the managed client share an HTTP transport with conservative dial, TLS-handshake, response-header, and overall timeouts. A stalled or unreachable issuer fails closed instead of holding startup or in-flight token validation open. Server startup wraps metadata discovery in a 30-second context, so a misconfigured issuer surfaces as a fast `create token validator` error. Under `--oidc-jwks-uri` there is no startup fetch to bound, so that check moves to the first authenticated request instead.
- **No internal-address pivot from discovered configuration**: addresses named by a *remote* metadata document — the issuer, the authorization-server metadata URL, and the endpoints it advertises — are refused when they resolve into the built-in protected set (loopback, IPv4/IPv6 link-local including cloud IMDS, unspecified, multicast). Enforced at each layer that can see something the others cannot: a resolution check on the value itself (the only protection for the authorization URL handed to the OS), a per-request destination check, and — on a directly-dialled connection — a dial-time check that connects to the address it verified, so a name cannot resolve differently a moment later. Through an HTTP proxy the address checks describe a lookup the connection will not use, so what protects you there is TLS: the client issues `CONNECT` and then validates the origin's certificate against the name it asked for, which a rebound internal service cannot present. **Proxied `https` is therefore allowed and bound by the certificate; proxied plaintext is refused**, because it has nothing to be checked against. Plaintext discovery already requires `--insecure-oidc-issuer`, so in a normal deployment this costs nothing — zero-configuration discovery works behind a proxy. One limit: a TLS-terminating proxy whose CA you installed *is* the origin as far as validation goes, and no check here substitutes for that proxy's own egress policy. Private networks (RFC1918, CGNAT, IPv6 ULA) are deliberately *not* refused — an authorization server on an internal network is an ordinary deployment. The guard applies only to discovered values, and is relaxed only when the tunnel URL names this machine *by spelling* — a **loopback** literal, or `localhost` per RFC 6761 — which is the local-development case. That set is narrower than the refused set on purpose: link-local (including cloud IMDS), multicast and unspecified addresses are refused as destinations but are *not* this machine, and treating them as local would mean a tunnel URL pointing at the metadata service switched off the guard protecting it. That decision resolves nothing on purpose: the tunnel host's DNS belongs to the party the guard constrains, so a hostname answering with both a public and a loopback address would otherwise switch the guard off. A development host reached through a private alias should pass `--oidc-issuer` instead.
- **No origin change on the auth path**: a metadata fetch or a token request refuses to follow a redirect off the origin it started on. Validating where a fetch begins is worth nothing if it may end somewhere else — an open redirect on the expected host would otherwise let a third party supply the document, and on the token endpoint a 307 preserves the body, so a cross-origin hop would forward a refresh token or an authorization code.
- **No transport downgrade on the auth path**: neither side will fetch credentials or signing keys over a weaker transport than the metadata that named them. An `https` metadata document may not advertise plaintext endpoints, and redirects may not move a metadata, JWKS, or token fetch off `https`. Advertised endpoints must be `http(s)` URLs with a host in every mode, including under `--insecure-oidc-issuer` — this is what keeps a scheme like `file://` out of the authorization URL that the client hands to the OS. On the client, a refusal is terminal rather than falling back to an interactive login that would fail the same way. The PKCE loopback callback stays plaintext by design (RFC 8252). Details in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#transport-rules-on-the-auth-path).
- **Subject pinning during token refresh**: the server rejects any refreshed token whose `sub` differs from the original tunnel's subject.
- **Refresh deadline enforcement**: a refreshed token whose `nbf` falls after the current enforced connection deadline (`exp + --expiry-grace`) is rejected. A refresh handover cannot silently extend the policy beyond what the operator has opted into. The comparison is strict — no additional clock-skew allowance applies beyond `--expiry-grace`.
- **Secure transport by default**: the OIDC issuer URL must be `https://`; the client's tunnel endpoint URL must be `https://` or `wss://`. Plaintext variants require explicit override flags (see the development-only overrides in the [server flag reference](docs/DEPLOYMENT.md#server-flags-and-environment-variables)).
- **Explicit egress posture at startup**: the server refuses to start without either `--allow` rules or `--allow-open-egress`. This prevents a misconfigured deployment from silently becoming an open TCP pivot.

### A trade to understand: where the client's OIDC configuration comes from

By default a client takes the authorization server's identity from the tunnel server
it is connecting to. That is what makes `--tunnel-url` a complete configuration, and
it is a real change in what the tunnel URL controls:

- **What it removes.** Every value an operator would otherwise transcribe into an
  `ssh_config` line per user, per host block — and with it the class of failure where
  a wrong issuer or client ID survives a browser login and comes back as an
  uninformative `401` from the tunnel server.
- **What it costs.** A hostile `--tunnel-url` can name an authorization server of its
  choosing and so send the user to a credential-phishing page. Note the starting
  point: whoever controls that URL already receives every access token this client
  obtains, so the escalation is from harvesting the tunnel's token to phishing the
  IdP password — serious, but from a position that is already lost.
- **What bounds it.** The document is fetched from the tunnel URL's own origin, over
  the transport that URL specifies, and it must declare **exactly** the identifier the
  client is using — scheme, host, path and query — so a host serving several protected
  resources cannot hand one client another resource's configuration. Under `https` that
  means only the holder of a certificate for the tunnel host can supply it. The addresses
  such a document names are also held to the resolved-IP deny-list: a tunnel server
  reached over a public address may not aim the client's own auth traffic at loopback,
  a link-local address, or a cloud instance-metadata service.
  Discovery can also only ever cause an *interactive* login to a newly-named
  authorization server, which the user sees — never a silent hand-off of an
  already-issued refresh token, because a cached credential whose recorded issuer,
  client, or metadata URL no longer matches is discarded rather than reused.
- **How to decline it, and exactly what that pins.** Pass `--oidc-issuer`: the client
  then refuses a document naming a different issuer, and — the part worth stating,
  because it was missing at first — it also refuses to take the *location* of that
  issuer's metadata from the tunnel server unless the published location is on the
  issuer's own origin. Without that second rule, a hostile server could echo your
  issuer, relocate its metadata document, and choose the authorization and token
  endpoints anyway. So a pinned issuer pins where the login goes.
  Discovery-input filtering follows the same line: the transport, address and downgrade
  rules apply to what the *tunnel server* chose, so a configured issuer stays unfiltered
  whether or not some other flag was also supplied — omitting only `--oidc-client-id`
  does not turn your own loopback issuer into remote input.
  What it does **not** pin is what the token is *for*: the audience and RFC 8707
  resource are still taken from the document when you do not supply them, so an
  operator who does not trust the tunnel URL should pass `--oidc-audience` or
  `--oidc-resource` too. To refuse the lookup
  as a standing rule rather than as a side effect of having configured everything,
  add `--no-resource-metadata` on the client: the configuration must then be complete,
  checked at startup. Server-side, the flag of the same name switches publication off
  entirely.

### Operator-controlled

The following are disabled or unlimited by default and must be explicitly configured for a hardened deployment. [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) covers each in detail and ends with a [hardening checklist](docs/DEPLOYMENT.md#deployment-hardening-checklist) to verify before going to production:

- **Egress allowlist** (`--allow`): limits the destinations authenticated clients may reach. Recommended for production; restricts the blast radius if a credential is compromised.
- **Egress open mode** (`--allow-open-egress`): explicit opt-in to allow any destination reachable by the server process. Logged at warn level on startup. Mutually exclusive with `--allow`.
- **Resolved-IP deny-list** (`--ip-block`, `--no-ip-block`): on by default with a built-in protected set — loopback, IPv4/IPv6 link-local (incl. cloud IMDS `169.254.169.254`), unspecified, and multicast. Applied independently of the egress posture: the deny-list runs after the allow check in both restrictive and open modes, so a hostname rule that resolves to a protected address is rejected regardless. RFC1918, CGNAT, and IPv6 ULA are not in the default set. `--ip-block` replaces the default with an operator-supplied list (CIDR, bare IP, or bracketed IPv6); `--no-ip-block` disables the guard entirely.
- **Connection longevity** (`--max-connection-duration`, `--expiry-grace`, `--no-connection-token-expiry`): by default tunnel lifetime is tied to the access token's `exp`. These flags let operators tune for specific IdP behaviors or impose hard ceilings. Some IdPs (e.g. Auth0) cache access tokens; `--expiry-grace` extends the enforcement deadline beyond `exp` to give the client time to obtain a genuinely new token.
- **Admission limits** (`--max-concurrent-tunnels`, `--max-tunnels-per-user`, `--tunnel-open-rate`, `--dial-timeout`): zero or default by default. Configure for production to bound resource use and prevent a single credential from monopolising tunnel capacity or tying up goroutines on blackholed destinations.
- **Published client configuration** (`--client-id`, `--client-scopes`, `--client-audience`, `--client-resource`, `--no-resource-metadata`): the protected-resource document is published by default and names the issuer; the hints that let a client run with no OIDC flags at all are opt-in per value. Setting them is what turns `--tunnel-url` into a complete client configuration. See the trade described above before deciding.
- **Pre-auth IP rate limit** (`--preauth-rate`, `--preauth-burst`): off by default, matching the explicit-posture style of the egress flags. When enabled, runs before bearer-token parsing on every authenticated route (`/protected`, `/protected/`, any `/protected/*`, and `/protected/tunnel`) so a flood of anonymous or junk-JWT requests is rejected with `429` before any validator or JWKS work happens. Recommended for direct internet exposure; deployments behind a load balancer that already rate-limits anonymous traffic can leave it off. Buckets key on the TCP peer by default; `--preauth-trust-forwarded-for` opts into trusting `X-Forwarded-For` behind a known proxy (see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)).

### Known non-goals

- **Live token revocation**: revoking a token at the IdP does not terminate an already-established tunnel. Authunnel enforces token expiry but does not perform per-request introspection checks.
- **Tunnel chain observability**: Authunnel can only log and control connections it directly brokers. A client could SOCKS CONNECT to a second tunnel or proxy, creating a chain Authunnel cannot observe.
- **OIDC-authenticated SSH login**: Authunnel authenticates the tunnel, not the SSH session. It does not federate host login to your IdP — see [Scope: tunnel authentication, not SSH login](#scope-tunnel-authentication-not-ssh-login) for the distinction and for open-source tools that do.
- **Session architecture redesign**: the current WebSocket-to-SOCKS model is intentionally simple and is not expected to change.

## Usage

### Prerequisites

- Released `authunnel-server` and `authunnel-client` binaries for your
  platform. Go is only needed if you build from source or run the `go run`
  examples below.
- An OIDC provider that issues JWT access tokens carrying both a server audience (emitted as `aud`) and a non-empty `sub` — Authunnel pins each tunnel's refresh identity to `sub`, so tokens without one are rejected at admission. Most IdPs emit `sub` by default; on Keycloak 26+ the client's default scopes must cover it (the built-in `basic` scope, or an equivalent custom scope with an `oidc-sub-mapper` — see [`testenv/keycloak/authunnel-realm.json`](testenv/keycloak/authunnel-realm.json) for a working example)
- A TLS certificate trusted by the client runtime (for TLS-files mode; not required for ACME or plaintext-behind-reverse-proxy modes)

The **server** runs on Linux and macOS. The **client** runs on Linux, macOS, and Windows (10 1803 or later).

The examples below use `go run` from a source checkout. When using released
binaries, invoke `authunnel-server` or `authunnel-client` with the same flags
and environment variables.

### Start server

Server setup is covered in full in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — TLS modes (certificate files, ACME / Let's Encrypt, plaintext behind a reverse proxy), the complete flag reference, and egress policy. A minimal example using TLS certificate files:

```bash
export OIDC_ISSUER='https://<issuer>'
export TOKEN_AUDIENCE='authunnel-server'
export TLS_CERT_FILE='/etc/authunnel/tls/server.crt'
export TLS_KEY_FILE='/etc/authunnel/tls/server.key'

cd server && CGO_ENABLED=0 go run . --allow '*.internal:22'
```

**Egress posture is required at startup.** Either pass one or more `--allow` rules (recommended) or pass `--allow-open-egress` to explicitly opt into open mode. Running without either is rejected — see the "Security Posture" section above.

### Managed OIDC client mode

This is the intended `ssh` workflow.

Example SSH config entry:

```sshconfig
Host internal-host
  HostName internal-host
  User myuser
  ProxyCommand /path/to/authunnel-client \
    --tunnel-url https://localhost:8443/protected/tunnel \
    --proxycommand %h %p
```

The issuer, client ID, scopes and audience come from the server. Pass them explicitly
(`--oidc-issuer`, `--oidc-client-id`, …) if the server is run with
`--no-resource-metadata`, or to override what it publishes.

On Windows with OpenSSH, use the full path with backslashes and quote it if it contains spaces:

```sshconfig
Host internal-host
  HostName internal-host
  User myuser
  ProxyCommand "C:\path\to\authunnel-client.exe" --tunnel-url https://... --proxycommand %h %p
```

Useful client flags. Every OIDC flag is optional — each overrides the corresponding
value the tunnel server publishes, and is needed only when the server publishes
nothing:

- `--oidc-issuer`
- `--oidc-client-id`
- `--oidc-metadata-url` to fetch the authorization server metadata document from a URL other than the well-known path derived from `--oidc-issuer`; needed for an authorization server publishing RFC 8414 metadata, which inserts the well-known segment before the path component. Usable with or without `--oidc-issuer`. **With** an issuer, the document's `issuer` field is compared against it — but a document asserts that field itself, so the check catches an honestly-wrong URL rather than a hostile one. **Without** one, the document's issuer is adopted and that check is gone, so a URL pointing at the wrong tenant is discovered as correct and fails after a browser login instead. **Changing this value discards the token cache and requires a fresh login.** That is deliberate: the document names the token endpoint your credentials are posted to, and the issuer check only compares a string the document supplies about itself — it cannot prove the metadata host speaks for that issuer. Discarding the cache stops an already-issued refresh token being handed over silently. It is not a defence against an untrustworthy metadata URL: complete the fallback login and the authorization code still goes wherever that document says. Point this flag only at a URL you trust as much as the issuer itself
- `--oidc-audience` to send the Auth0-style `audience` parameter during managed login
- `--oidc-resource` to send the RFC 8707 `resource` parameter during managed login; required by providers that bind the token `aud` to a requested resource, such as AWS Cognito
- `--oidc-redirect-port` to use a fixed loopback callback port instead of a random one
- `--oidc-scopes`, defaulting to the scopes the tunnel server publishes, or `openid offline_access` when it publishes none
- `--oidc-cache` with default `${XDG_CONFIG_HOME:-~/.config}/authunnel/tokens.json` (macOS/Linux) or `%AppData%\authunnel\tokens.json` (Windows)
- `--oidc-no-browser` to print the URL without attempting automatic browser launch
- `--no-resource-metadata` to refuse the tunnel-server lookup outright. `--oidc-client-id` and one of `--oidc-issuer` / `--oidc-metadata-url` are then required, and a missing one is a startup error rather than a failure at first use. Distinct from simply supplying everything, which also results in no lookup: this is a prohibition that survives someone shortening the `ProxyCommand` line, and it is visible in that line. Same flag name as the server's, same document, opposite direction — there it means do not publish, here it means do not read
- `--tunnel-url` — tunnel endpoint URL. Secure schemes `https://` and `wss://` are accepted by default; plaintext `http://` and `ws://` require `--insecure-tunnel-url`. **Required.** May also be supplied via the `AUTHUNNEL_TUNNEL_URL` environment variable (the flag takes precedence)
- `--unix-socket`
- `--proxycommand`
- `--insecure-oidc-issuer` — allow non-HTTPS OIDC issuer and metadata URLs, discovered as well as configured **(development only; do not use in production)**. Relaxes transport security only; other schemes such as `file://` stay rejected
- `--insecure-tunnel-url` — allow a non-HTTPS tunnel endpoint URL **(development only; do not use in production)**

On first use the client prints the authorization URL to `stderr` and tries to open the system browser. Subsequent runs reuse the cache or refresh token when possible.

The IdP-side client registration required for managed mode (public client, PKCE, loopback redirects, refresh tokens) is described in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#oidc-client-registration).

### Manual token (not recommended; for testing only)

A pre-obtained bearer token can be supplied via the `ACCESS_TOKEN`
environment variable. This is mutually exclusive with all managed OIDC
flags. There is no command-line equivalent: bearer tokens passed as
arguments would be visible via process listings and shell history.

The examples below source the token from a secrets manager so the literal
value never appears in shell history or argv. Substitute whichever helper
you use (`pass`, `vault kv get`, `op read`, `security find-generic-password
-w`, `gpg --decrypt`, etc.); the goal is that the token comes from outside
the typed command line.

```bash
# The ACCESS_TOKEN= prefix scopes the value to this single client
# invocation; it is not exported to the shell. Avoid
# `export ACCESS_TOKEN=<literal>`, which writes the token to shell history.
cd client
ACCESS_TOKEN="$(pass show authunnel/access-token)" \
  CGO_ENABLED=0 SSL_CERT_FILE=../cert.pem go run . \
    --tunnel-url https://localhost:8443/protected/tunnel \
    --unix-socket /tmp/authunnel/proxy.sock
```

ProxyCommand example, same pattern:

```bash
ACCESS_TOKEN="$(pass show authunnel/access-token)" /path/to/authunnel-client \
  --tunnel-url https://localhost:8443/protected/tunnel \
  --proxycommand internal-host 22
```

If you already export `ACCESS_TOKEN` from a wrapper script or a
shell-startup integration with your secrets manager, you can omit the
inline substitution and just invoke the client directly.

### Unix socket SOCKS5 endpoint

```bash
cd client
CGO_ENABLED=0 SSL_CERT_FILE=../cert.pem go run . \
  --tunnel-url https://<host>:8443/protected/tunnel \
  --unix-socket /tmp/authunnel/proxy.sock
```

Use with `socat` in an SSH `ProxyCommand`:

```sshconfig
Host internal-host-via-socat
  HostName internal-host
  User myuser
  ProxyCommand socat - SOCKS5:/tmp/authunnel/proxy.sock:%h:%p
```

If the unix-socket parent directory does not already exist, the client creates
it with `0700` permissions. It also tightens the socket itself to `0600` so
other local users cannot connect by default on shared hosts.

On shared POSIX hosts the client fails closed if the socket's parent directory
is group- or world-writable, or if it is owned by another local user. It also
walks every ancestor up to the filesystem root: any ancestor directory a peer
can `rename(2)` past would let them swap the private subtree between
validation and bind, so ancestors that are writable by others without the
sticky bit, or owned by an unprivileged user other than the operator, are
rejected too. Sticky directories (the classic case is `/tmp`, mode `1777`)
are accepted as ancestors because sticky-bit semantics restrict renames to
the entry's owner — but the leaf must still be a private subdirectory (for
example `/tmp/authunnel/`, mode `0700`), so point `--unix-socket` at a file
inside it rather than directly at `/tmp/proxy.sock`. A bare filename like
`--unix-socket proxy.sock` is validated against the current working
directory under the same rules, so starting the client from a shared cwd
(such as `/tmp` itself) is refused. The same checks apply to the OIDC token
cache directory (`--oidc-cache`) and its advisory-lock companion file, so a
directory that is safe for the socket is also safe for cached tokens.

#### Token cache at rest

Managed OIDC mode writes the cached access token and refresh token to
`--oidc-cache` as plaintext JSON. Confidentiality on disk is enforced by
POSIX filesystem permissions alone: the cache file is created `0600` via
atomic rename, inside a `0700` directory whose ancestors have been
validated against peer `rename(2)` as described above.

The client also re-validates an existing cache file before reading it, so
a `tokens.json` left over from another tool with `0o644` (or any
group/world bit), with a foreign owner, or replaced by a symlink is
rejected with a `validate OIDC token cache:` startup error rather than
silently honoured. The fix is one of `chmod 600
~/.config/authunnel/tokens.json` (POSIX) or deleting the file and
re-authenticating; the validator deliberately does not auto-chmod, so
the audit signal is preserved.

This design matches the pattern used by most OIDC CLIs, but operators
should be explicit about what it does and does not defend against:

- **Defended:** read access by other unprivileged users on the same host,
  including concurrent attackers who can observe the config directory but
  not write into it.
- **Not defended:** the machine's root user, offline forensic access to an
  unencrypted disk or disk image, backups of the user's config directory,
  or any process running as the same uid (which by construction already
  has the same tokens available through the authunnel client itself).

If your threat model requires stronger at-rest protection, either run
authunnel on a system with full-disk encryption (so offline disk access is
excluded), or supply the access token directly via `ACCESS_TOKEN` from a
secrets manager so no refresh token is ever persisted by authunnel.

During listener creation the client restricts its process umask to `0o077`,
so the socket inode is created owner-only in the first place; the follow-up
`chmod` to `0600` is kept as a safety net for filesystems that ignore umask
on AF_UNIX bind. Stale-socket cleanup after a previous crash refuses to
remove anything other than a unix-domain socket owned by the current user,
so a regular file accidentally placed at the socket path will surface as an
error rather than being silently unlinked.

Unix socket mode works on Windows 10 1803 and later. Windows uses NTFS ACLs
rather than POSIX mode bits, so the parent-directory safety check there only
verifies that the target path exists as a directory; detailed ACL inspection
is out of scope and operators should rely on the default `%AppData%`
location, which is already user-scoped.

## Versioning

Authunnel follows [Semantic Versioning](https://semver.org/). A new major version may introduce breaking changes to configuration flags, environment variables, or the wire protocol. Check the release notes before upgrading across a major version boundary.

## Release artifact verification

Release assets are accompanied by SHA-256 checksums and GitHub artifact
attestations. After downloading an asset, verify its provenance with:

```sh
gh attestation verify authunnel-client-linux-amd64 -R dkj/authunnel
```

## License

See [`LICENSE`](./LICENSE).

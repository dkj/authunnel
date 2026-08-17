# Deploying Authunnel

This guide covers running the Authunnel server: TLS modes, reverse-proxy configuration, the full server flag reference, egress policy, and the pre-production hardening checklist. One section — [Transport rules on the auth path](#transport-rules-on-the-auth-path) — applies to the client as well, since both binaries enforce the same rules on the endpoints an issuer advertises. For the security model these controls implement, see the [Security Posture](../README.md#security-posture) section of the README.

The **server** runs on Linux and macOS. The examples below use `go run` from a source checkout. When using released binaries, invoke `authunnel-server` with the same flags and environment variables.

## Start server

Choose one TLS mode. All modes also accept `--oidc-issuer`, `--token-audience`, `--listen-addr`, `--log-level`, and `--allow`.

**Egress posture is required at startup.** Either pass one or more `--allow` rules (recommended) or pass `--allow-open-egress` to explicitly opt into open mode. Running without either is rejected — see the [Security Posture](../README.md#security-posture) section of the README.

**TLS certificate files** (default `:8443`):

```bash
export OIDC_ISSUER='https://<issuer>'
export TOKEN_AUDIENCE='authunnel-server'
export TLS_CERT_FILE='/etc/authunnel/tls/server.crt'
export TLS_KEY_FILE='/etc/authunnel/tls/server.key'

cd server && CGO_ENABLED=0 go run . --allow '*.internal:22'
```

The server validates the TLS key file at startup on POSIX. The resolved
target must:

- be a regular file with no group or world permission bits (`mode &
  0o077 == 0`, e.g. `0600` or `0400`),
- be owned by the current user or by root — any other unprivileged owner
  could read the key, so accepting that ownership would defeat the
  "unreadable by others" contract,
- live under a parent chain that is itself safe against `rename(2)`.

Symlinks are followed so canonical certbot paths such as
`/etc/letsencrypt/live/<domain>/privkey.pem` work out of the box; both
the un-resolved and resolved parent chains are checked for ancestor
safety. As a final step the server opens the key once to confirm it can
actually read it, so an ACL or group-membership mismatch surfaces at
startup rather than mid-handshake. Any failure logs `tls_key_file_unsafe`
and exits. The cert file is public material and is not validated.

**ACME / Let's Encrypt** (default `:443`; server must be reachable on port 443):

```bash
export OIDC_ISSUER='https://<issuer>'
export TOKEN_AUDIENCE='authunnel-server'
export ACME_DOMAINS='authunnel.example.com'
export ACME_CACHE_DIR='/var/cache/authunnel/acme'

cd server && CGO_ENABLED=0 go run . --allow '*.internal:22'
```

Certificates are obtained and renewed automatically using the TLS-ALPN-01 challenge. The cache directory must be writable by the server process and should persist across restarts to avoid hitting Let's Encrypt rate limits. autocert writes Let's Encrypt private keys into this directory, so on POSIX the server applies the same ancestor + leaf checks used for the OIDC cache: the directory is created `0o700` if missing, and an existing one is rejected if it is group/world writable, owned by another unprivileged user, or sits beneath a permissive ancestor.

**Plaintext HTTP** (default `:8080`; for use behind a TLS-terminating reverse proxy):

```bash
export OIDC_ISSUER='https://<issuer>'
export TOKEN_AUDIENCE='authunnel-server'

cd server && CGO_ENABLED=0 go run . --plaintext-behind-reverse-proxy --allow '*.internal:22'
```

The server trusts `X-Forwarded-Proto` and `X-Forwarded-Host` for WebSocket origin checks. Most proxies forward these headers automatically; nginx requires explicit configuration:

```nginx
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host  $host;
```

**`X-Forwarded-For` trust is separate and off by default.** The pre-auth limiter (`--preauth-rate`) keys on the TCP peer address (`RemoteAddr`) unless you explicitly opt in with `--preauth-trust-forwarded-for`. This is deliberately decoupled from `--plaintext-behind-reverse-proxy`: even in plaintext mode, a client-supplied `X-Forwarded-For` cannot mint per-IP buckets by default, so it cannot defeat the limiter. The option is also valid in TLS modes, so a reverse proxy may reach this server over a secured connection and still have its XFF honoured. Modes:

| Mode | Keys on | Use when |
|------|---------|----------|
| `off` (default) | TCP peer (`RemoteAddr`) | The server sees the real client IP directly, or you don't want XFF trusted. |
| `rightmost` | Rightmost XFF entry | **Recommended for a single reverse proxy.** The rightmost entry is the address your immediate proxy appended, so a client-injected leftmost value is ignored. |
| `leftmost` | Leftmost XFF entry | Only on a fully trusted network where the leftmost value is sanitised/overwritten upstream; it is the client's own claim and is otherwise spoofable. |
| `single-hop` | The sole XFF entry | A single trusted proxy that appends exactly one hop; any other count is rejected. |

In any trusting mode, a request whose `X-Forwarded-For` violates the expectation (absent, empty, or the wrong hop count) is rejected with `400`. The trusted client IP is also logged as `forwarded_client_ip`, while `remote_ip` always remains the TCP peer for forensics.

**Why `rightmost` is the easy choice:** every common reverse proxy *appends* the client to `X-Forwarded-For` by default — AWS ALB, HAProxy (`option forwardfor`), Caddy 2's `reverse_proxy`, Traefik, and nginx's `$proxy_add_x_forwarded_for`. With `rightmost`, that append behaviour is exactly what you want: a single trusted proxy appends the real client to the right of any client-supplied prefix, so the value Authunnel reads is spoof-resistant with no special proxy configuration. Use `leftmost` only if your proxy *overwrites* XFF (e.g. nginx `proxy_set_header X-Forwarded-For $remote_addr`, HAProxy `http-request set-header X-Forwarded-For %[src]`, Caddy `header_up X-Forwarded-For {remote_host}`). For multi-proxy chains, neither leftmost nor rightmost reliably identifies the client — terminate at a single proxy you control before forwarding.

For `X-Forwarded-Proto` and `X-Forwarded-Host` (used only by the WebSocket origin check), Caddy, AWS ALB, Traefik, and HAProxy generally set sane values, but you should still explicitly configure them so the value is proxy-issued rather than client-passthrough.

## Server flags and environment variables

- `--oidc-issuer` or `OIDC_ISSUER` — **required in every mode.** This is the identity anchor: it is enforced as the `iss` claim on every token, and on the discovery paths the metadata document's own `issuer` must match it. The two overrides below change only *where the key set is found*; neither replaces this
- `--oidc-metadata-url` or `OIDC_METADATA_URL` — authorization server metadata document URL, overriding the well-known path derived from the issuer. Use this for an authorization server that publishes RFC 8414 metadata at a path the OIDC derivation cannot construct (RFC 8414 inserts the well-known segment *before* the path component, so an issuer of `https://as.example/tenant1` publishes at `https://as.example/.well-known/oauth-authorization-server/tenant1`), or whose metadata sits off the issuer path entirely. The document's `issuer` is compared against `--oidc-issuer`, but a document asserts that field about itself, so the comparison catches an honestly-wrong URL rather than a hostile one. Unlike the derived path — which fetches from the issuer's own host over TLS, an authenticated origin — this mode rests on your choice of URL. Trust it as much as you trust `--oidc-issuer`. Mutually exclusive with `--oidc-jwks-uri`
- `--oidc-jwks-uri` or `OIDC_JWKS_URI` — pinned JWKS endpoint. Skips metadata discovery entirely, so the server makes **no network call at startup** and comes up even when the issuer is unreachable. Two consequences to weigh: a wrong URL surfaces on the first protected request rather than at startup, and because there is no metadata document to cross-check, the issuer-to-keys binding is asserted by you rather than verified by the server. Key rotation still works — the key set refetches on an unrecognised `kid`, so only the endpoint is fixed, not the key material. Mutually exclusive with `--oidc-metadata-url`
- `--token-audience` or `TOKEN_AUDIENCE`
- `--listen-addr` or `LISTEN_ADDR` (default varies by TLS mode; see above)
- `--log-level` or `LOG_LEVEL` with default `info`
- `--tls-cert` or `TLS_CERT_FILE` — path to TLS certificate PEM
- `--tls-key` or `TLS_KEY_FILE` — path to TLS private key PEM
- `--acme-domain` or `ACME_DOMAINS` (comma-separated) — domain(s) for automatic ACME certificate; repeatable
- `--acme-cache-dir` or `ACME_CACHE_DIR` with default `/var/cache/authunnel/acme`
- `--plaintext-behind-reverse-proxy` or `PLAINTEXT_BEHIND_REVERSE_PROXY=true` — serve plain HTTP, trusting a TLS-terminating reverse proxy for transport security; `X-Forwarded-Proto` and `X-Forwarded-Host` are used for WebSocket origin checks
- `--allow` or `ALLOW_RULES` (comma-separated in env) — restrict outbound connections to matching rules; repeatable. At least one rule is required unless `--allow-open-egress` is set
- `--allow-open-egress` or `ALLOW_OPEN_EGRESS=true` — explicit opt-in for running with no allowlist; mutually exclusive with `--allow`. Use only when arbitrary authenticated egress from the server host is acceptable for the deployment
- `--ip-block` or `IP_BLOCK` (comma-separated in env) — resolved-IP deny-list applied after `--allow`; repeatable. Accepts CIDR (`127.0.0.0/8`), bare IP (`127.0.0.1`), or bracketed IPv6 (`[::1]`, `[fe80::/10]`). When unset and `--no-ip-block` is not set, defaults to the built-in protected set (loopback, IPv4/IPv6 link-local incl. IMDS `169.254.169.254`, unspecified, multicast). Applies in both restrictive and open-egress modes; deny wins over `--allow`
- `--no-ip-block` or `NO_IP_BLOCK=true` — disable the resolved-IP deny-list entirely; mutually exclusive with `--ip-block`. Use only when the deployment legitimately needs to reach default-protected addresses (e.g. tunnelling to a localhost service) and a tighter `--ip-block` list is not sufficient
- `--insecure-oidc-issuer` or `INSECURE_OIDC_ISSUER=true` — allow non-HTTPS OIDC issuer, metadata and JWKS URLs **(development only; do not use in production)**. This relaxes transport security only; it does not widen the set of permitted URL schemes, so `file://` is still refused. Loading a JWKS from disk is not supported — routing `file://` through the shared auth HTTP client would make local files reachable from any redirect that client follows
- `--max-connection-duration` or `MAX_CONNECTION_DURATION` — hard maximum tunnel lifetime (e.g. `4h`, `30m`); default `0` (unlimited)
- `--no-connection-token-expiry` or `NO_CONNECTION_TOKEN_EXPIRY=true` — do not tie tunnel lifetime to access token expiry; by default expiry IS enforced and clients can refresh tokens to extend. Setting this **and** leaving `--max-connection-duration` at `0` removes every enforced lifetime cap; the server logs a `connection_lifetime_unbounded` warning at startup so the posture is visible in logs
- `--expiry-warning` or `EXPIRY_WARNING` — warning period before either longevity limit; default `3m`
- `--expiry-grace` or `EXPIRY_GRACE` — extend the connection deadline beyond the access token's `exp` claim to accommodate providers (e.g. Auth0) that cache access tokens; default `0` (no grace)
- `--max-concurrent-tunnels` or `MAX_CONCURRENT_TUNNELS` — server-wide cap on simultaneous tunnels; default `0` (unlimited). Over-cap requests receive `503 Service Unavailable` with `Retry-After`.
- `--max-tunnels-per-user` or `MAX_TUNNELS_PER_USER` — per-subject cap on simultaneous tunnels, keyed on the OIDC `sub` claim; default `0` (unlimited). Over-cap requests receive `429 Too Many Requests` with `Retry-After`.
- `--tunnel-open-rate` or `TUNNEL_OPEN_RATE` — per-user tunnel-open rate (tunnels/sec); default `0` (disabled). Exceeding the rate yields `429` with `Retry-After` derived from the token-bucket delay.
- `--tunnel-open-burst` or `TUNNEL_OPEN_BURST` — burst size for the per-user rate limiter; defaults to `ceil(rate)` when rate is set. Setting burst without rate is a startup error.
- `--dial-timeout` or `DIAL_TIMEOUT` — per-outbound-dial timeout applied to SOCKS CONNECT destinations; default `10s`. Bounds failure time against blackholed targets.
- `--preauth-rate` or `PREAUTH_RATE` — per-source-IP rate limit applied before token parsing on every authenticated route (`/protected`, `/protected/`, any `/protected/*`, and `/protected/tunnel`); requests/sec; default `0` (disabled), max `10000`. Behind a load balancer that already rate-limits anonymous traffic this can stay off; enable it for direct internet exposure so junk JWTs and oversized headers are rejected with `429` before reaching the validator. By default the limiter keys on the TCP peer address; see `--preauth-trust-forwarded-for` to key on `X-Forwarded-For` behind a trusted proxy.
- `--preauth-burst` or `PREAUTH_BURST` — burst size for `--preauth-rate`; defaults to `ceil(rate)` when the rate is set. Setting burst without rate is a startup error.
- `--preauth-trust-forwarded-for` or `PREAUTH_TRUST_FORWARDED_FOR` — how the pre-auth limiter derives the client IP from `X-Forwarded-For`: `off` (default; bucket by the TCP peer), `leftmost`, `rightmost` (recommended for a single reverse proxy), or `single-hop` (require exactly one entry). Decoupled from the listening mode and off by default even under `--plaintext-behind-reverse-proxy`, so a client-supplied header cannot mint new buckets; valid in TLS modes too. In any trusting mode a request whose header violates the expectation is rejected with `400`, and the trusted client IP is logged as `forwarded_client_ip`.

Admission rejections are emitted as structured `warn` log records with `event=tunnel_admission_denied` and a `reason` field (`global`, `per_user`, or `rate`), so operators can distinguish abuse from undersized limits without adding a metrics stack. Pre-auth rejections are logged separately with `event=preauth_rate_limited` so the two layers can be told apart in queries. Per-user policy is keyed on the OIDC `sub` claim; tokens without a stable subject are rejected earlier by the JWT validator before admission runs.

## Issuer metadata and key discovery

The server needs one thing from the issuer: the JWKS endpoint that its signing keys are
published at. Every claim check after that — signature, `iss`, `exp`, `aud`, `sub`, `iat`, `nbf`
— is evaluated locally against the cached key set, with no per-request round trip to the issuer.

That is not the same as "no runtime traffic to the issuer", and the difference matters when
planning egress. The key set is fetched **lazily, not at startup**, and is refetched when a token
presents a `kid` that is not in the cache:

- the first authenticated request after startup triggers a JWKS fetch, in every discovery mode;
- a token whose `kid` does not match a cached key triggers a fetch. This is what makes issuer key
  rotation self-healing, and it is also why a stream of tokens bearing unrecognised `kid` values
  drives repeated outbound fetches — concurrent ones are coalesced into a single in-flight
  request, but there is no negative cache or backoff between them. `--preauth-rate` is the
  control for that; see the flag list above;
- otherwise verification is served entirely from cache.

So the server needs outbound access to the JWKS endpoint for the life of the process, not only
during startup. Firewall rules that permit issuer traffic only during a startup window will fail
later, at the first rotation, in a way that looks like a token problem rather than a network one.

There are three ways the JWKS endpoint is located. The mode in effect is reported as
`discovery_mode` on the `token_validator_ready` log line at startup, so it can be confirmed on a
running server rather than inferred from deployment config.

| `discovery_mode` | Set by | Startup network call | Issuer-to-keys binding |
| --- | --- | --- | --- |
| `derived` (default) | nothing; derived from `--oidc-issuer` | yes | verified |
| `metadata_url` | `--oidc-metadata-url` | yes | rests on the operator-supplied URL |
| `pinned_jwks` | `--oidc-jwks-uri` | **no** | **asserted by the operator** |

- **`derived`** — OIDC discovery at `<issuer>/.well-known/openid-configuration`. Correct for
  essentially every OIDC provider.
- **`metadata_url`** — discovery against a URL you supply. Needed when the authorization server
  publishes RFC 8414 metadata, which inserts the well-known segment *before* the path component
  (`https://as.example/tenant1` publishes at
  `https://as.example/.well-known/oauth-authorization-server/tenant1`), or when metadata sits off
  the issuer path entirely. A document advertising a *different* issuer is refused at startup —
  which catches an honestly-wrong URL, since a legitimate server declares its own issuer. It does
  not catch a hostile one: that field is self-asserted, so a document anywhere can echo your
  issuer and advertise keys you would then accept for it. This mode moves the binding from
  "fetched from the issuer's own host over TLS" to "fetched from a URL the operator chose", so
  the URL needs the same trust as `--oidc-issuer` itself.
- **`pinned_jwks`** — metadata discovery is skipped. The server makes no network call at startup
  and comes up with the issuer unreachable, which is the reason to use it. The costs: a wrong
  endpoint surfaces on the first authenticated request rather than at startup, and with no
  metadata document to cross-check, nothing verifies that those keys belong to that issuer except
  your configuration. Logged at **warn** level for that reason. Key rotation still works — the key
  set refetches on an unrecognised `kid`, so only the endpoint is pinned, not the key material.

`--oidc-issuer` is required in all three. It is the value enforced as the `iss` claim on every
token; under `pinned_jwks` it is the *only* thing binding accepted tokens to an issuer.

## Transport rules on the auth path

These apply to **both** binaries, which is why they sit outside the server section above.
Signing keys decide whether a token is genuine, and on the client the token endpoint receives
the refresh token, so neither side will use an endpoint reached over a weaker transport than
the metadata that named it. Two independent rules:

**Endpoints must be `http(s)` URLs with a host.** Applied to `jwks_uri` on the server and to
`authorization_endpoint` and `token_endpoint` on the client, in **every** mode — including under
`--insecure-oidc-issuer`, which relaxes transport security but does not widen permitted schemes.
This is what keeps a scheme like `file://` or a custom app scheme out of the authorization URL,
which the client hands to the OS URL dispatcher (`open`, `xdg-open`, `ShellExecute`) — those
launch whatever application claims the scheme, not only a browser.

**No downgrade relative to the metadata source.** Metadata retrieved over `https` may not
advertise plaintext endpoints, and a redirect may not move a metadata, JWKS, or token fetch off
`https`. Go follows cross-scheme redirects silently, so this is enforced explicitly rather than
inherited from the HTTP client. An issuer already served over `http` — development only, behind
`--insecure-oidc-issuer` — has no downgrade left to prevent and is unaffected; the first rule
still applies there.

The two are not interchangeable: over an `http` metadata source nothing is a downgrade, so the
second rule passes everything and the first is the only thing filtering schemes.

**When they fire** differs by rule, and not all of it is at startup. On the server, the endpoint
checks run during discovery, so a bad or downgraded `jwks_uri` fails startup — but the redirect
rule cannot, because the key set is fetched lazily on the first token verified (see above). A
JWKS endpoint that redirects off `https` therefore surfaces on the first authenticated request,
as a rejected token rather than a failed boot. Under `--oidc-jwks-uri` the pinned URL is checked
at startup while everything about the fetch is deferred the same way.

On the client a refusal is **terminal** — it does not fall back to interactive login, because the
browser flow ends at the same token endpoint and would fail identically after walking the user
through authenticating. The PKCE loopback callback (`http://127.0.0.1:…`) is deliberately outside
all of this: it is RFC 8252's native-app pattern and never leaves the host.

## Egress rules and the resolved-IP deny-list

Rule formats: `host-glob:port`, `host-glob:lo-hi`, `CIDR:port`, `CIDR:lo-hi`, `[IPv6]:port`, `[IPv6]:lo-hi`

IPv6 addresses must use bracketed notation (`[addr]:port`). Unbracketed IPv6 is rejected at startup because the last-colon port split is otherwise ambiguous.

A resolved-IP deny-list runs after the allow check, independently of the egress posture. By default it covers loopback (`127.0.0.0/8`, `::1`), IPv4 link-local (`169.254.0.0/16`, including IMDS `169.254.169.254`), IPv6 link-local (`fe80::/10`), unspecified (`0.0.0.0/8`, `::`), and multicast (`224.0.0.0/4`, `ff00::/8`). A request that the allow-list permits but whose resolved address falls in the deny-list is rejected with `event=socks_connect_denied_ip_blocked` and a `reason` field (`loopback`, `link_local_ipv4`, `link_local_ipv6`, `unspecified`, or `multicast`). RFC1918, CGNAT, and IPv6 ULA ranges are not in the default set.

To replace the default deny-list, pass one or more `--ip-block` rules (or set `IP_BLOCK`):

```bash
# Block only IMDS; loopback becomes reachable subject to --allow
authunnel-server --allow '127.0.0.1:5432' --ip-block '169.254.0.0/16'
```

To disable the guard entirely, pass `--no-ip-block`. This is the only way to reach default-protected addresses when a tighter `--ip-block` list is not sufficient (for example, when running with `--allow-open-egress` and a deliberate need to reach loopback):

```bash
authunnel-server --allow '127.0.0.1:5432' --no-ip-block
authunnel-server --allow-open-egress --no-ip-block   # fully open posture
```

```bash
# Only allow SSH to *.internal and HTTPS to the 10.x network
authunnel-server --allow '*.internal:22' --allow '10.0.0.0/8:443'
# Or via environment variable (comma-separated)
ALLOW_RULES='*.internal:22,10.0.0.0/8:443' authunnel-server
# IPv6 example
authunnel-server --allow '[::1]:22' --allow '[2001:db8::1]:443'
# Explicit open mode (no allowlist) — only if arbitrary egress from the
# server host is genuinely acceptable for the deployment
authunnel-server --allow-open-egress
```

## OIDC Client Registration

For managed client mode, register a **public** OIDC client with:

- standard authorization code flow enabled
- PKCE required with `S256`
- loopback redirect URIs allowed for `http://127.0.0.1/*` or for a specific fixed callback such as `http://127.0.0.1:38081/callback`
- refresh tokens enabled
- scopes that include `openid` and `offline_access`
- an access-token audience that includes the Authunnel resource, for example `authunnel-server`

Some providers require an explicit audience/resource parameter on the authorization request before they will populate the access-token `aud` claim. The parameter name differs by provider: Auth0 custom APIs use `audience` (pass `--oidc-audience`), while providers implementing RFC 8707 resource indicators — notably AWS Cognito — use `resource` (pass `--oidc-resource <url>`, whose value becomes the `aud`). For Cognito also request the resource server's custom scope, e.g. `--oidc-scopes 'openid https://your-resource/tunnel'`.

Some providers require an exact loopback callback URL instead of allowing a random local port. Use `--oidc-redirect-port` when you need to register a fixed callback URL in the IdP.

Some providers require extra configuration before `offline_access` can be requested successfully. When that is not configured, override the client with `--oidc-scopes openid` and rely on cached access tokens only.

## Deployment Hardening Checklist

Before going to production, verify:

- [ ] OIDC issuer is `https://` — `--insecure-oidc-issuer` is **not** set.
- [ ] Issuer metadata is discovered rather than bypassed. The startup log line `token_validator_ready` reports `discovery_mode`; `derived` is the default. If it reports `pinned_jwks`, confirm the `--oidc-jwks-uri` value really belongs to the configured issuer — the server cannot verify that binding for itself in this mode, and it is logged at warn level for that reason. If it reports `metadata_url`, the binding rests on that URL too: the document's `issuer` field is compared to yours, but it is self-asserted, so any host you point at can echo your issuer and advertise keys you would then accept. Confirm the URL is one you control, and treat it with the same care as `--oidc-issuer`. Only `derived` verifies the binding, by fetching from the issuer's own host over TLS.
- [ ] Tunnel endpoint is `https://` or `wss://` — `--insecure-tunnel-url` is **not** set on the client.
- [ ] The client's `--oidc-issuer` (and `--oidc-metadata-url`, if used) are `https://`, and `--insecure-oidc-issuer` is **not** set on the client either. The server's setting does not cover the client: it is a separate process with its own flags, and it is the side that transmits the refresh token.
- [ ] Token-expiry enforcement is active — `--no-connection-token-expiry` is **not** set. By default, tunnels close when the access token expires and clients must refresh. Disabling this removes token expiry as a tunnel lifetime control; tunnels will still close at `--max-connection-duration` if set, but without that limit they persist until the client disconnects.
- [ ] At least one `--allow` rule is configured. `--allow-open-egress` should only appear in deployments where arbitrary authenticated egress from the server host is explicitly acceptable.
- [ ] The default `--ip-block` set is in effect (loopback, link-local incl. IMDS, unspecified, multicast), or any deviation via `--ip-block` / `--no-ip-block` is intentional and documented for the deployment.
- [ ] A hard connection ceiling is set (`--max-connection-duration`) appropriate for your session-length policy.
- [ ] Admission limits are sized for expected load: `--max-concurrent-tunnels`, `--max-tunnels-per-user`, and `--tunnel-open-rate` are set.
- [ ] `--dial-timeout` is set (default `10s`). Setting it to `0` allows authenticated users to hold goroutines open on blackholed destinations indefinitely.
- [ ] The unix-socket path (if used) lives inside a private directory such as `/tmp/authunnel/` (`0700`), not directly under a world-writable parent like `/tmp`.
- [ ] The authunnel server (if using `--plaintext-behind-reverse-proxy`) is not directly reachable over untrusted networks — only the TLS-terminating reverse proxy should be. The proxy must overwrite (not append to) client-supplied `X-Forwarded-Proto` and `X-Forwarded-Host` before forwarding, since these drive the WebSocket origin check. `X-Forwarded-For` is *not* trusted for per-IP buckets unless you set `--preauth-trust-forwarded-for`; with the recommended `rightmost` mode the proxy's default append behaviour is safe, so no overwrite is needed for bucketing.

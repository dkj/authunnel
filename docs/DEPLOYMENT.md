# Deploying Authunnel

This guide covers running the Authunnel server: TLS modes, reverse-proxy configuration, the full server flag reference, egress policy, and the pre-production hardening checklist. Two sections apply to the client as well: [Transport rules on the auth path](#transport-rules-on-the-auth-path), since both binaries enforce the same rules on the endpoints an issuer advertises, and [Protected-resource metadata and zero-configuration clients](#protected-resource-metadata-and-zero-configuration-clients), which is what the server publishes and the client reads. For the security model these controls implement, see the [Security Posture](../README.md#security-posture) section of the README.

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
- `--oidc-metadata-url` or `OIDC_METADATA_URL` — authorization server metadata document URL, overriding the well-known path derived from the issuer. Use this for an authorization server that publishes RFC 8414 metadata at a path the OIDC derivation cannot construct (RFC 8414 inserts the well-known segment *before* the path component, so an issuer of `https://as.example/tenant1` publishes at `https://as.example/.well-known/oauth-authorization-server/tenant1`), or whose metadata sits off the issuer path entirely. The document's `issuer` is compared against `--oidc-issuer`, but that self-asserted value catches an honestly-wrong URL rather than a hostile one. Trust the configured URL as much as the issuer. Mutually exclusive with `--oidc-jwks-uri`
- `--oidc-jwks-uri` or `OIDC_JWKS_URI` — pinned JWKS endpoint. Skips metadata discovery so the resource server's auth egress can be restricted to the key endpoint instead of the issuer's discovery, authorization, and token services. Requires runtime JWKS egress as described below. Because no metadata document supplies the endpoint, the issuer-to-keys binding is asserted by your configuration. Mutually exclusive with `--oidc-metadata-url`
- `--token-audience` or `TOKEN_AUDIENCE`
- `--client-oidc-metadata-url` or `CLIENT_OIDC_METADATA_URL` — authorization server metadata document URL published to clients. Defaults to `--oidc-metadata-url`. Unlike it, may be combined with `--oidc-jwks-uri`: this server never fetches the published value, so pinned-JWKS isolation and a non-derivable client metadata location can coexist
- `--client-id` or `CLIENT_ID` — public OIDC client ID published to clients, so they need no `--oidc-client-id` of their own. This is the client you registered at the IdP for authunnel; it is not a secret. See [Protected-resource metadata and zero-configuration clients](#protected-resource-metadata-and-zero-configuration-clients)
- `--client-default-scopes` or `CLIENT_DEFAULT_SCOPES` — space-delimited scopes clients should request when they configure none; a client's own `--oidc-scopes` wins. Include `offline_access` unless you want every `ssh` past the access token's lifetime to open a browser. Published as the extension field `authunnel_default_scopes`, not as `scopes_supported`. Under RFC 9728 §7.2 that registered field is the *protected resource* disclosing the scopes it supports, which is a different question from which of them a client should ask for — and authunnel discloses none there, because it enforces no scope requirement: a token is accepted on its signature, audience and standard claims, and its `scope` claim is never read. This flag is advice about the authorization request, which is what a client actually needs to know
- `--client-audience` or `CLIENT_AUDIENCE` — value clients should send as the provider-specific `audience` authorization parameter (the Auth0 style)
- `--client-resource` or `CLIENT_RESOURCE` — value clients should send as the RFC 8707 `resource` authorization parameter, for providers that bind the token `aud` to it (e.g. AWS Cognito). Set whichever of these two your IdP implements: this server knows what audience it requires, but not how yours wants it asked for, and a provider ignores the parameter it does not implement silently — producing a login that succeeds and a token this server then rejects
- `--no-resource-metadata` or `NO_RESOURCE_METADATA=true` — do not publish the protected-resource document, and omit the `resource_metadata` parameter from the `WWW-Authenticate` challenge — the challenge
  itself stays, since every `401` must carry one. Clients then need their own `--oidc-client-id` and either `--oidc-issuer` or `--oidc-metadata-url`. Setting any `--client-*` hint alongside this is a startup error, since nothing would publish it
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

| `discovery_mode` | Startup auth egress | Runtime auth egress | Issuer-to-keys binding |
| --- | --- | --- | --- |
| `derived` (default) | issuer-derived metadata URL | discovered JWKS endpoint | rooted at the issuer's authenticated HTTPS origin |
| `metadata_url` | configured metadata URL | discovered JWKS endpoint | rests on the operator-supplied metadata URL |
| `pinned_jwks` | none | configured JWKS endpoint | asserted by the operator |

If any permitted endpoint redirects to another HTTPS URL, the redirect target
also needs egress access. A restrictive deployment should resolve the provider's
actual metadata and JWKS destinations before setting firewall or proxy policy.

- **`derived`** — OIDC discovery at `<issuer>/.well-known/openid-configuration`. Correct for
  essentially every OIDC provider. The request is rooted at the issuer's authenticated HTTPS
  origin; an HTTPS redirect may delegate the final document to another HTTPS host.
- **`metadata_url`** — discovery against a URL you supply. Needed when the authorization server
  publishes RFC 8414 metadata, which inserts the well-known segment *before* the path component
  (`https://as.example/tenant1` publishes at
  `https://as.example/.well-known/oauth-authorization-server/tenant1`), or when metadata sits off
  the issuer path entirely. A document advertising a *different* issuer is refused at startup —
  which catches an honestly-wrong URL, since a legitimate server declares its own issuer. It does
  not catch a hostile one: that field is self-asserted, so a document anywhere can echo your
  issuer and advertise keys you would then accept for it. The URL therefore needs the same trust
  as `--oidc-issuer` itself.
- **`pinned_jwks`** — metadata discovery is skipped so an isolated resource server can be granted
  access only to the signing-key endpoint. For example, a provider may publish discovery and JWKS
  on different hosts; pinning lets an egress policy deny the discovery host. The server starts at
  the configured URL and skips discovery — it does not follow the issuer to a key endpoint of the
  issuer's choosing — but an HTTPS redirect from that URL is still followed, so its target needs
  egress too, and a hostname-level firewall may permit other paths on that host. For strong isolation, prefer an egress proxy capable of hostname and, where available,
  path policy over static provider IP allowlists. With no metadata document to cross-check, your
  configuration is the issuer-to-keys binding, so this mode is logged at **warn** level.

  Pinned mode changes how the endpoint is selected, not the lazy cache behavior described above.

`--oidc-issuer` is required in all three and is enforced as the `iss` claim on every token. Under
`pinned_jwks`, the configured pairing of that issuer and the JWKS URL defines which keys are
trusted to sign for it.

The managed client has a different egress requirement. It always needs the tunnel endpoint and,
when it cannot reuse a valid cached access token, the configured or derived metadata endpoint,
authorization endpoint, and token endpoint. Server-side JWKS pinning does not reduce client
egress and has no client-side equivalent.

Because the requirements differ, so do the flags. `--oidc-metadata-url` is where *this server*
fetches the document for JWT validation, and `--client-oidc-metadata-url` is the location published
to clients; the second defaults to the first, which is right whenever both read the same document.
Set them apart when the authorization server publishes RFC 8414 metadata at a path the OIDC
derivation cannot construct **and** you are pinning JWKS: this server then reads no metadata document
at all, so an egress policy can deny it the discovery host, while clients are still told where their
document lives. `--oidc-jwks-uri` remains mutually exclusive with `--oidc-metadata-url` — one process
cannot both skip discovery and be given a document to fetch — but not with the client-facing flag,
which this server never requests.

## Protected-resource metadata and zero-configuration clients

This section spans both binaries: the server publishes the document, the client reads it.

**What is published, and where.** By default the server serves RFC 9728 protected-resource
metadata, unauthenticated, at `GET /.well-known/oauth-protected-resource` and at the same path
with the resource's own path appended — RFC 9728 §3.1 forms the URL by inserting that segment
*before* the resource path, so a client using `https://tunnel.example/protected/tunnel` looks in
`https://tunnel.example/.well-known/oauth-protected-resource/protected/tunnel`. Both shapes serve
the same document, because a deployment behind a path-rewriting reverse proxy may present either.

```console
$ curl -s https://tunnel.example/.well-known/oauth-protected-resource | jq
{
  "resource": "https://tunnel.example/protected/tunnel",
  "authorization_servers": ["https://idp.example/realms/main"],
  "bearer_methods_supported": ["header"],
  "authunnel_client_id": "authunnel-cli",
  "authunnel_default_scopes": ["openid", "offline_access"]
}
```

The registered fields come from configuration the server already has. The `authunnel_`-prefixed
ones are extensions — RFC 9728 §3 permits additional parameters — carrying the values the registry
has no room for but a client cannot start without:

| Field | Set by | Fills the client's |
| --- | --- | --- |
| `resource` | derived from the request's scheme and host | — (checked by the client against the URL it used) |
| `authorization_servers` | `--oidc-issuer` | `--oidc-issuer` |
| `authunnel_default_scopes` | `--client-default-scopes` | `--oidc-scopes` |
| `authunnel_client_id` | `--client-id` | `--oidc-client-id` |
| `authunnel_authorization_server_metadata_url` | `--client-oidc-metadata-url`, else `--oidc-metadata-url` | `--oidc-metadata-url` |
| `authunnel_audience` | `--client-audience` | `--oidc-audience` |
| `authunnel_resource` | `--client-resource` | `--oidc-resource` |

`resource` is derived per request rather than from a configured public URL. Under
`--plaintext-behind-reverse-proxy` that means `X-Forwarded-Proto` and `X-Forwarded-Host` are
honoured, exactly as for the WebSocket origin check; otherwise the `Host` header and the actual
scheme are used. The `Host` header is caller-controlled, so a caller can make the document
describe an origin of its choosing — but only in the response to its own request, and a client
compares `resource` against the URL it actually used and refuses a mismatch. That
self-consistency check is what makes the derived value safe without a flag.

**The client's comparison is exact.** RFC 9728 §3.3 requires the document's `resource` to be
*identical* to the identifier the well-known suffix was inserted into, and the client compares them
by code point — nothing about the document is normalised first. The reason is concrete: one hostname
can serve several protected resources, and a looser comparison would let a document about
`/a/tunnel` supply the authorization server and client ID for a client asking about `/b/tunnel`.

Normalisation happens on each side's *own* input, before the comparison, so that identity holds
without either side being lenient about what the other sent. The client normalises the identifier it
derives from `--tunnel-url` (it is also a token-cache key, and an operator may spell one authority
several ways — upper-case host, a redundant `:443`); this server publishes `--resource-url`
normalised for the same reason. Both are RFC 3986 syntax-based normalisation only: case folding and
redundant default ports, never the path or query. Two consequences for deployments:

- **A path-rewriting reverse proxy needs `--resource-url`.** If the proxy strips a prefix, the
  identifier a client uses is not the one this server derives, and the comparison correctly
  fails. Set `--resource-url https://tunnel.example/authunnel/protected/tunnel` (the externally
  visible identifier) and it is published with its path intact, after authority normalisation only —
  host case and a redundant default port are folded so the value matches what a client derives from
  its own tunnel URL. It must be an `http`/`https` URL with a host and
  no fragment — a client derives the metadata location from it and fetches that over HTTP — and a
  value that fails those rules is refused at startup rather than published. Proxies that forward the
  path unchanged — the common case — need nothing.
- **Escaped path segments are preserved, not decoded.** `/tenant%2Fone/tunnel` and
  `/tenant/one/tunnel` are two identifiers, so a proxy that routes on an encoded segment gets two
  resources with separate discovery results and separate cached credentials. Percent-encodings that
  RFC 3986 would call equivalent (`%7E` and `~`) are *not* folded together, so publish `resource`
  spelled exactly as your clients will spell their `--tunnel-url`; a mismatch is refused, with both
  values quoted.
- **The document does not live under `/protected/`.** RFC 9728 §3.1 *inserts* the well-known segment
  between the authority and the resource's path, so the document for
  `https://tunnel.example/protected/tunnel` is at
  `https://tunnel.example/.well-known/oauth-protected-resource/protected/tunnel` — outside the prefix
  this server uses to mean "a token is required". Appending the segment instead would put an
  unauthenticated document under that prefix; requests to those shapes
  (`/protected/.well-known/…`, `/protected/tunnel/.well-known/…`) stay behind the token check and
  answer 401, then 404 once authenticated.
- **A query in the tunnel URL is part of the identifier.** It is echoed back into `resource`, and
  into the `resource_metadata` URL in the `WWW-Authenticate` challenge, so a standards-following
  client that follows the challenge lands on the document describing the identifier it is using;
  this server routes on path alone and attaches no meaning to a query, so a client whose tunnel URL
  carries one is still talking about this same resource. Client-side those are distinct identifiers
  and part of the token cache's identity, which is what stops a token obtained for
  `?tenant=a` being presented for `?tenant=b`: the stored token is not reused, and a fresh login
  replaces it. A bare `?` counts: `…/tunnel?` and `…/tunnel` are different request
  targets — Go puts the delimiter on the wire — so they are different identifiers here too. A
  fragment is the opposite case and is refused, since it is never sent at all.

**The challenge header, and the status codes.** Both follow RFC 6750 §3.1:

| Outcome | Status | `WWW-Authenticate` |
|---|---|---|
| No credential, or one this server cannot parse as Bearer | `401` | `Bearer resource_metadata="https://…"` |
| A token that failed validation — signature, issuer, audience, expiry, `nbf` | `401` | `Bearer error="invalid_token", resource_metadata="https://…"` |
| Either of the above, under `--no-resource-metadata` | `401` | as above without `resource_metadata`; where that would leave no parameter at all, `Bearer realm="authunnel"` |
| WebSocket origin check refused | `403` | none |
| Authenticated | `2xx` | none |

`403` is reserved for a *valid* token that is not permitted, which this server never decides — it
enforces no scopes — so it appears only for the origin check. Earlier versions answered a failed
token with `403` and no challenge; that was neither §3.1's meaning nor usable by a client, since a
`403` alone cannot be told apart from a WAF, a reverse proxy, or the origin check.

`--no-resource-metadata` removes the `resource_metadata` parameter, **not the challenge**: RFC 9110
§11.6.1 requires a `WWW-Authenticate` on every `401` and §3 requires it to name Bearer, and a client
still needs the `invalid_token` code to tell a stale configuration from any other refusal. Turning
publishing off does not turn a client's recovery off with it.

The `realm` in that last case is there only to satisfy §3's grammar, which is
`challenge = "Bearer" RWS 1#param` — at least one parameter, so a bare `Bearer` is not a conformant
challenge even though the wider HTTP grammar allows it. It is a label, not a scope.

The `error="invalid_token"` code is what the authunnel client keys its recovery on. It does not
*navigate* by `resource_metadata` — it derives the well-known URL from its own `--tunnel-url` rather
than spending a request to be told — but the presence of that error code is how it knows the
rejection concerned the token and that re-reading configuration might help. See
[Recovery when this configuration changes](#protected-resource-metadata-and-zero-configuration-clients).

**What the client does with it.** A value passed as a flag always wins over the published one, and
whatever is missing is filled from the document — **but the lookup only happens when an *essential*
value is absent**: the client ID, or both the issuer and the metadata URL. Supply those and no
request is made, so a published audience, resource indicator or default scope set is **not** adopted.
That is deliberate — a fully-configured invocation should cost no extra round trip — but it has a
sharp edge worth knowing: if your IdP needs an `audience` or `resource` parameter to populate the
token's `aud`, a client passing only `--oidc-issuer` and `--oidc-client-id` will not pick yours up
and its tokens will be refused here. Pass `--oidc-audience`/`--oidc-resource` on such clients, or
leave one essential value out so the lookup runs. No fetch ever happens on a cache hit. Discovered URLs
are held to the same rules as configured ones: `https` unless `--insecure-oidc-issuer`, `file://`
refused either way, and no downgrade relative to the tunnel URL, so an `https` tunnel cannot send
a client to a plaintext authorization server. Redirects may not downgrade onto plaintext either, and
the **token requests may not change origin at all**: a 307 preserves the body, so that hop would
forward a refresh token or an authorization code. A metadata fetch is pinned the same way in the one
case where an origin was promised — see [What `--oidc-issuer` pins, precisely](#what---oidc-issuer-pins-precisely).

They are additionally held to the resolved-IP deny-list (RFC 9728 §7.7): a client that reached its
tunnel server over a public address refuses to follow that server to loopback, a link-local address,
or a cloud instance-metadata service.

**Behind a forward proxy the connection-level half of this deny-list does not apply, and what
replaces it is certificate verification.** Through a proxy the destination is resolved by the proxy,
so a local lookup describes a connection that will not happen; those checks are therefore skipped
rather than applied, because a proxied network often resolves external names only at the proxy and
demanding a local answer would break exactly the clients that can reach the destination. The static
check on the discovered value keeps running either way — see
[Discovered addresses and the internal-address guard](#discovered-addresses-and-the-internal-address-guard)
for which layer survives what. For an `https` destination the client issues
`CONNECT` and then performs its own TLS handshake with the origin, validating the certificate against
the name it asked for. That is a real guarantee, and a narrower one than an address check: it binds
the *hostname*, not the address, so it does not establish that the destination is external. **The
residual case is an internal endpoint holding a certificate valid for the hostname a document named.**

The model holds under three conditions, which are worth checking against your environment rather than
assuming:

1. the proxy issues `CONNECT` and does **not** intercept TLS;
2. authorization and token endpoints are `https`, which is enforced unless `--insecure-oidc-issuer`
   is set;
3. internal services do not present client-trusted certificates under hostnames a remote party could
   name.

Where (3) is doubtful, `--oidc-issuer` takes the choice of *authorization-server origin* away from
the tunnel server — the part a client-side control can reach. It does not silence the server
entirely: it may still publish non-address hints (client ID, audience, scopes), and a metadata path
on that same pinned origin. It is **not** a defence against (1): a proxy holding
a CA the client trusts can forge any document, including one carrying the configured issuer, so an
intercepting proxy is trusted with the whole OAuth exchange. That trust is either acceptable or the
proxy must be bypassed for these destinations; no flag here changes it. Nor does configuring an
internal issuer make it *safe* — it makes it a destination the operator has chosen to trust, which is
the position on configured values everywhere else in this document.

Proxied *plaintext* is refused outright: nothing binds the origin, and a proxy fetching an internal
`http` endpoint on the client's behalf is the §7.7 pivot exactly. Since a plaintext discovered
endpoint already requires `--insecure-oidc-issuer`, that refusal does not arise in a normal
deployment; if it does, the message names both ways forward (`NO_PROXY` for a directly-reachable host,
or an explicit `--oidc-client-id` plus either `--oidc-issuer` or `--oidc-metadata-url`).

These rules apply only to discovered values; `--oidc-issuer` is the operator's own decision and is
not filtered. See
[Discovered addresses and the internal-address guard](#discovered-addresses-and-the-internal-address-guard)
for the three layers, the proxy reasoning, and the narrow — loopback-only — relaxation.

**Recovery when this configuration changes.** A client holding a cached access token that is still
valid by its own expiry presents it without reading any metadata, so changing the issuer, client ID
or audience would otherwise lock every such client out until their caches expired. On a rejected
token the client re-reads this document once; if the configuration has genuinely changed it obtains
a token under the new one and retries the connection, and if it has not it reports the server's
rejection unchanged rather than starting a login that cannot help.

**Two consequences worth understanding before enabling the hints.** The
[trade described in the README](../README.md#a-trade-to-understand-where-the-clients-oidc-configuration-comes-from)
covers the first — the tunnel URL becomes the thing that names your IdP. The second is
operational: changing `--client-id`, or the issuer, invalidates every client's cached refresh
token, because a client refuses to post a credential to an authorization server or client identity
other than the one it was issued under. Users re-authenticate once. That is the intended price of
the check, not a bug to work around.

**Turning it off, from either end.** The client has a `--no-resource-metadata` of its own, which
refuses to *read* the document — the same subject as the server flag, the opposite direction. A
client that sets it must be given `--oidc-client-id` and one of `--oidc-issuer` /
`--oidc-metadata-url`, and a missing one fails at startup instead of at first use. Use it where the
refusal should be a standing rule visible in the `ProxyCommand` line rather than an accident of the
configuration happening to be complete.

Server-side, `--no-resource-metadata` stops publication and removes the challenge header;
both well-known paths then return `404`. The document is public by default because a feature both
ends must opt into removes no configuration from anyone. What the switch buys is narrow: any client
holding a token already knows the issuer, since it obtained the token there, and a public client ID
is not a credential. It is a switch for a deployment whose policy treats the IdP's identity as
non-public, not a security control.

### What `--oidc-issuer` pins, precisely

A document naming a different issuer is a local error. The *location* of that issuer's
metadata may not be relocated by the tunnel server either: a published
`authunnel_authorization_server_metadata_url` is used only when it shares an origin with
the configured issuer, which is where TLS makes the issuer's own host answer for the
document. A cross-origin location is announced and ignored, and an operator who wants it
passes `--oidc-metadata-url` themselves. Without that rule the pin would be hollow — a
hostile server could echo the expected issuer, point the client at its own document, and
name the authorization and token endpoints from there.

The same-origin rule is enforced at use time as well as at adoption: that fetch may not redirect off
the pinned origin, since an open redirect on the issuer's own host would restore exactly the
substitution the rule prevents. It applies only to a location the tunnel server *published* and this
client adopted under a configured `--oidc-issuer`. A client that pinned nothing has no origin to hold
a redirect to; a `--oidc-metadata-url` you passed yourself is a location you chose; and the issuer's
own derived document may be delegated between HTTPS origins as
[Transport rules on the auth path](#transport-rules-on-the-auth-path) describes. Token requests are
pinned separately and in every mode, because their bodies carry a credential.

Discovery-input filtering follows the same line: the transport, address and downgrade
rules apply to what the *tunnel server* chose. A client that supplies `--oidc-issuer`
(or `--oidc-metadata-url`) and omits only `--oidc-client-id` still runs discovery for
that one hint, and its own issuer is not filtered as remote input on that account —
otherwise the same configuration would work or fail depending on which unrelated flag
was present.

It does not pin what the token is *for*. `authunnel_audience` and `authunnel_resource`
are still adopted when the client supplies neither, so a tunnel server can influence
which audience is requested. Clients that pin the issuer because they do not fully trust
the tunnel URL should pin `--oidc-audience` or `--oidc-resource` alongside it.

### Discovered addresses and the internal-address guard

An address named by a remote metadata document is held to the resolved-IP deny-list
(RFC 9728 §7.7): a client that reached its tunnel server over a public address refuses
to follow that server to loopback, a link-local address, or a cloud instance-metadata
service. Private networks (RFC1918, CGNAT, IPv6 ULA) are **not** refused — an
authorization server on an internal network is an ordinary deployment.

Three layers, because each sees something the others cannot:

1. a resolution check on the discovered value itself — the only protection for the
   `authorization_endpoint`, which is handed to the OS URL dispatcher rather than fetched;
2. a per-request destination check, which also covers each redirect hop;
3. a dial-time check that connects to the address it verified, so a name cannot resolve
   differently a moment later.

**A forward proxy changes what layers 2 and 3 are worth; layer 1 is unaffected.** Layers 2 and
3 concern a connection this client makes itself, and past a proxy it does not make one: the
proxy resolves the destination, so both would describe a connection that never happens. For an
`https` destination they are therefore skipped rather than applied — a proxied network often
resolves external names only at the proxy, and demanding a local answer would break exactly
the clients that can reach the destination.

Layer 1 has no proxy awareness at all and keeps running. It resolves the name locally and
refuses an answer inside the protected set, whatever the transport does afterwards, so it still
catches a document naming a host that resolves to loopback or IMDS *on this machine*. What it
cannot do is decide anything when there is no local answer: a resolution failure is not treated
as a refusal, because in a split-DNS or proxy-resolved network the absence of an answer is
normal rather than evidence. So behind a proxy the guarantee is "refused if local DNS can see
it is internal", not "refused if it is internal".

For the rest, what holds is the certificate: the transport issues `CONNECT` and then validates
the origin's certificate against the name it asked for. That binds the **hostname** — it is not
evidence the address is external, so an internal service holding a certificate valid for the
name a document supplied still passes layers 2 and 3, and passes layer 1 too whenever local DNS
does not resolve it. See
[Discovery inputs and the transport rules](#protected-resource-metadata-and-zero-configuration-clients)
for the three conditions this rests on and what `--oidc-issuer` does and does not answer.

The `authorization_endpoint` sits outside all of this: it is opened in a browser, which uses the
system's own proxy settings rather than this client's transport, so layer 1 is both the first and
the last check applied to it.

Proxied *plaintext* is refused: nothing binds the origin, and a proxy fetching an internal
`http` endpoint on the client's behalf is the pivot this guard exists for. Since a plaintext
discovered endpoint already requires `--insecure-oidc-issuer`, that refusal does not arise
in a normal deployment.

**The relaxation is narrow.** The guard is lifted only when the tunnel URL names the
client's own machine *by spelling* — a **loopback** literal, or a name RFC 6761 reserves for
loopback — and it resolves nothing, because the tunnel host's DNS belongs to the party the
guard constrains: a host answering with both a public and a loopback address would otherwise
switch the guard off. That set is deliberately smaller than the refused set: link-local
(including IMDS), multicast and unspecified addresses are refused as destinations without
being "this machine", so pointing a tunnel URL at one of them buys a client no extra trust.
A development host reached through a private alias in `/etc/hosts` should pass
`--oidc-issuer` rather than rely on classification.

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

**When they fire** differs by rule, and not all of it is at startup. On the server, endpoint
checks performed during discovery can fail startup. Redirect policy is evaluated only when the
lazy JWKS fetch runs, so a downgrade there surfaces as a rejected token rather than a failed
boot. Under `--oidc-jwks-uri`, URL validation occurs at startup and the fetch remains deferred.

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

Once registered, publish the client ID and scopes from the server with `--client-id` and
`--client-default-scopes` so users do not each transcribe them into an `ssh_config` line. See
[Protected-resource metadata and zero-configuration clients](#protected-resource-metadata-and-zero-configuration-clients).

Some providers require an explicit audience/resource parameter on the authorization request before they will populate the access-token `aud` claim. The parameter name differs by provider: Auth0 custom APIs use `audience` (pass `--oidc-audience` on the client, or publish it with `--client-audience` on the server), while providers implementing RFC 8707 resource indicators — notably AWS Cognito — use `resource` (pass `--oidc-resource <url>` or publish `--client-resource <url>`, whose value becomes the `aud`). For Cognito also request the resource server's custom scope, e.g. `--oidc-scopes 'openid https://your-resource/tunnel'`, or publish it with `--client-default-scopes`.

Some providers require an exact loopback callback URL instead of allowing a random local port. Use `--oidc-redirect-port` when you need to register a fixed callback URL in the IdP.

Some providers require extra configuration before `offline_access` can be requested successfully. When that is not configured, override the client with `--oidc-scopes openid` and rely on cached access tokens only.

## Deployment Hardening Checklist

Before going to production, verify:

- [ ] OIDC issuer is `https://` — `--insecure-oidc-issuer` is **not** set.
- [ ] The startup log line `token_validator_ready` reports the intended `discovery_mode`. `derived` is the default and roots discovery at the issuer's authenticated HTTPS origin. For `metadata_url`, trust the configured metadata URL as much as the issuer. For `pinned_jwks`, confirm the configured issuer/JWKS pairing and its required runtime egress.
- [ ] Tunnel endpoint is `https://` or `wss://` — `--insecure-tunnel-url` is **not** set on the client.
- [ ] The client's `--oidc-issuer` (and `--oidc-metadata-url`, if used) are `https://`, and `--insecure-oidc-issuer` is **not** set on the client either. The server's setting does not cover the client: it is a separate process with its own flags, and it is the side that transmits the refresh token. Discovered issuers are held to the same rule, so this covers clients that configure nothing too.
- [ ] If clients rely on published configuration, the tunnel URL they are given is `https://` or `wss://` and is a host you control. With discovery, that URL is what names the authorization server clients log in to — see [the trade](../README.md#a-trade-to-understand-where-the-clients-oidc-configuration-comes-from). Deployments that would rather pin the IdP out-of-band have three options, in increasing order of strictness: have clients pass `--oidc-issuer`; have clients pass `--no-resource-metadata` as well, so the lookup is refused rather than merely unnecessary; or run the server with `--no-resource-metadata` so nothing is published at all.

**What `--oidc-issuer` pins, precisely.** A document naming a different issuer is a local error, and the *location* of that issuer's metadata may not be relocated by the tunnel server: a published `authunnel_authorization_server_metadata_url` is used only when it shares an origin with the configured issuer, which is where TLS makes the issuer's own host answer for the document. A cross-origin location is announced and ignored, and an operator who wants it passes `--oidc-metadata-url` themselves. Without that rule the pin was hollow — a hostile server could echo the expected issuer, point the client at its own document, and name the authorization and token endpoints from there.

The filtering follows what was *chosen remotely*, not whether discovery ran at all. A client
that supplies `--oidc-issuer` (or `--oidc-metadata-url`) and omits only `--oidc-client-id` still runs
discovery for that hint, and its own issuer is not subjected to the discovery transport and address
rules on that account — otherwise the same configuration would work or fail depending on which
unrelated flag was present. A published metadata URL that will not be used is announced and ignored
without being judged at all, so a tunnel server cannot break a client that pinned its issuer by
advertising a location that happens to be plaintext or internal.

It does not pin what the token is *for*. `authunnel_audience` and `authunnel_resource` are still adopted when the client supplies neither, so a tunnel server can influence which audience is requested. Clients that pin the issuer because they do not fully trust the tunnel URL should pin `--oidc-audience` or `--oidc-resource` alongside it.
- [ ] If a client is run with `--oidc-metadata-url` and no `--oidc-issuer`, that is a deliberate choice: the document's declared issuer is then adopted rather than checked, so a URL pointing at the wrong tenant is not caught locally.
- [ ] Token-expiry enforcement is active — `--no-connection-token-expiry` is **not** set. By default, tunnels close when the access token expires and clients must refresh. Disabling this removes token expiry as a tunnel lifetime control; tunnels will still close at `--max-connection-duration` if set, but without that limit they persist until the client disconnects.
- [ ] At least one `--allow` rule is configured. `--allow-open-egress` should only appear in deployments where arbitrary authenticated egress from the server host is explicitly acceptable.
- [ ] The default `--ip-block` set is in effect (loopback, link-local incl. IMDS, unspecified, multicast), or any deviation via `--ip-block` / `--no-ip-block` is intentional and documented for the deployment.
- [ ] A hard connection ceiling is set (`--max-connection-duration`) appropriate for your session-length policy.
- [ ] Admission limits are sized for expected load: `--max-concurrent-tunnels`, `--max-tunnels-per-user`, and `--tunnel-open-rate` are set.
- [ ] `--dial-timeout` is set (default `10s`). Setting it to `0` allows authenticated users to hold goroutines open on blackholed destinations indefinitely.
- [ ] The unix-socket path (if used) lives inside a private directory such as `/tmp/authunnel/` (`0700`), not directly under a world-writable parent like `/tmp`.
- [ ] The authunnel server (if using `--plaintext-behind-reverse-proxy`) is not directly reachable over untrusted networks — only the TLS-terminating reverse proxy should be. The proxy must overwrite (not append to) client-supplied `X-Forwarded-Proto` and `X-Forwarded-Host` before forwarding, since these drive the WebSocket origin check. `X-Forwarded-For` is *not* trusted for per-IP buckets unless you set `--preauth-trust-forwarded-for`; with the recommended `rightmost` mode the proxy's default append behaviour is safe, so no overwrite is needed for bucketing.

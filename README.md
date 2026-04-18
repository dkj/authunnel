# Authunnel

![Lock](Lock.svg)

Authunnel is an authenticated tunnel for reaching private TCP services, including SSH, through an OAuth2-protected TLS WebSocket conduit.

The target workflow is:

1. `ssh` launches the Authunnel client as `ProxyCommand`.
2. The client reuses a cached token, refreshes it, or completes Authorization Code + PKCE in a browser.
3. The Authunnel server, acting as an OAuth2 resource server, uses OIDC discovery to locate the issuer's JWKS endpoint and validates the JWT access token locally.
4. The server hosts a SOCKS5 backend and opens the requested `%h:%p` destination.
5. SSH stdio is bridged over that authenticated path.

The project also supports a unix-domain SOCKS5 endpoint mode (`proxy.sock`) for tools such as `socat`.

## Components

- `server/server.go`
  - HTTPS server on a configurable listen address (default `:8443` for TLS-files, `:443` for ACME, `:8080` for plaintext-behind-reverse-proxy)
  - Conservative HTTP server timeouts to reduce slow-client resource exhaustion risk
  - Structured JSON logs with three correlation IDs:
    - `request_id` — generated per HTTP request; scoped to a single request/response cycle
    - `trace_id` — extracted from an incoming `Traceparent` header (W3C Trace Context) when present, otherwise generated; allows correlation with upstream infrastructure such as a load balancer or reverse proxy
    - `tunnel_id` — generated when a WebSocket upgrade succeeds; scoped to the lifetime of the SOCKS tunnel and inherited by all subsequent tunnel events (open, SOCKS CONNECT, close)
  - Tunnel logs include the authenticated user identity, with per-destination SOCKS CONNECT logs at debug level; all three correlation IDs are carried through so HTTP admission, tunnel lifecycle, and per-destination events can be joined
  - OAuth2 resource-server JWT validation: OIDC discovery used only to bootstrap the JWKS endpoint, all token verification done locally
  - WebSocket tunnel endpoint (`/protected/tunnel`) connected to an in-process SOCKS5 server
- `client/client.go`
  - **ProxyCommand mode**: stdio bridge for direct SSH integration
  - **Unix socket mode**: local SOCKS5 endpoint for generic client tooling
  - **Managed OIDC mode**: public-client PKCE login with token cache + refresh
  - Control-message listener for server-initiated longevity warnings; automatic token refresh when the server signals imminent token expiry

## How It Works

### Server flow

1. Reads OIDC issuer, audience, listen address, TLS mode, and connection longevity configuration from flags or environment.
2. Performs OIDC discovery once at startup, solely to locate the issuer's JWKS endpoint.
3. Verifies bearer-token signature, issuer, expiration, and audience.
4. Accepts WebSocket connections at `/protected/tunnel`.
5. Hands each upgraded connection to the SOCKS5 server implementation.
6. If connection longevity is configured, manages tunnel lifetime: warns clients before expiry and disconnects when limits are reached. When token-expiry enforcement is active, the server accepts refreshed tokens from the client to extend the tunnel.
7. Emits structured JSON logs for request lifecycle, auth failures, tunnel open/close events, token refresh outcomes, and debug-level SOCKS CONNECT destinations.

### Client flow

1. Either:
   - uses a bearer token supplied via `--access-token` or the `ACCESS_TOKEN` environment variable, or
   - runs managed OIDC mode when `--oidc-issuer` and `--oidc-client-id` are configured.
2. In managed mode the client:
   - reuses a cached token when it remains valid for more than 60 seconds,
   - otherwise refreshes it when a refresh token is available,
   - otherwise launches a browser to the IdP and listens on `127.0.0.1` for the callback.
3. The client opens an authenticated WebSocket connection to the Authunnel server.
4. A background control-message listener handles server-initiated longevity messages. When the server warns that the access token is about to expire, the client automatically obtains a fresh token (via its existing refresh logic) and sends it to the server to extend the tunnel.
5. In ProxyCommand mode it performs a SOCKS5 CONNECT for `%h:%p` and bridges `stdin/stdout`.
6. In unix-socket mode it exposes a local SOCKS5 endpoint and opens a dedicated tunnel per local connection.

## Security Posture

Authunnel is deliberately simple in both functionality and implementation — a small, focused codebase that is intended to be easy to read and audit in full. Complexity is kept low by design; if a feature would make the security model harder to reason about, that is a reason not to add it.

Authunnel enforces authentication (JWT validation) at the WebSocket layer before any SOCKS5 connection can be attempted. By default, tunnel lifetime is tied to the access token's `exp` claim, so an expired token causes the tunnel to close rather than persisting indefinitely. Clients with a valid refresh token can extend tunnels by refreshing before expiry; the server validates the new token, pins it to the original subject, and rejects refreshes that would reduce the expiry. This can be disabled with `--no-connection-token-expiry` if needed. An optional hard maximum duration (`--max-connection-duration`) provides an additional ceiling. Both limits are orthogonal and can be active simultaneously. Some identity providers (e.g. Auth0) cache access tokens and return the same one on refresh until it expires; `--expiry-grace` adds a grace period beyond the token's `exp`, giving the client time to obtain a genuinely new token after the old one expires at the provider. Note: revoking a token at the identity provider does not terminate an already-established tunnel — the server enforces token expiry but does not perform live revocation checks. The `--allow` option provides a further layer of control over *where* an authenticated user can connect.

**Open mode (no `--allow` rules — the default):** Any destination reachable by the server process is accessible to authenticated clients. This is convenient and gives operators full visibility: every SOCKS CONNECT destination is logged at debug level.

**Allowlist mode (one or more `--allow` rules):** Only destinations matching a rule are permitted. Denied attempts are logged at warn level. This limits exposure if a credential is compromised, at the cost of requiring explicit enumeration of allowed targets.

**Note:** Like any tunnel, Authunnel can only log and control the connections it directly brokers; what an authenticated client does once a connection is open is outside its scope — for example, a client could SOCKS CONNECT to a second tunnel or proxy, creating a chain that Authunnel cannot observe.

## Usage

### Prerequisites

- Go 1.25.0+
- An OIDC provider that issues JWT access tokens
- A server audience configured in the IdP and emitted into access-token `aud`
- A TLS certificate trusted by the client runtime (for TLS-files mode; not required for ACME or plaintext-behind-reverse-proxy modes)

The **server** runs on Linux and macOS. The **client** runs on Linux, macOS, and Windows (10 1803 or later).

### Start server

Choose one TLS mode. All modes also accept `--oidc-issuer`, `--token-audience`, `--listen-addr`, `--log-level`, and `--allow`.

**TLS certificate files** (default `:8443`):

```bash
export OIDC_ISSUER='https://<issuer>'
export TOKEN_AUDIENCE='authunnel-server'
export TLS_CERT_FILE='/etc/authunnel/tls/server.crt'
export TLS_KEY_FILE='/etc/authunnel/tls/server.key'

cd server && CGO_ENABLED=0 go run .
```

**ACME / Let's Encrypt** (default `:443`; server must be reachable on port 443):

```bash
export OIDC_ISSUER='https://<issuer>'
export TOKEN_AUDIENCE='authunnel-server'
export ACME_DOMAINS='authunnel.example.com'
export ACME_CACHE_DIR='/var/cache/authunnel/acme'

cd server && CGO_ENABLED=0 go run .
```

Certificates are obtained and renewed automatically using the TLS-ALPN-01 challenge. The cache directory must be writable by the server process and should persist across restarts to avoid hitting Let's Encrypt rate limits.

**Plaintext HTTP** (default `:8080`; for use behind a TLS-terminating reverse proxy):

```bash
export OIDC_ISSUER='https://<issuer>'
export TOKEN_AUDIENCE='authunnel-server'

cd server && CGO_ENABLED=0 go run . --plaintext-behind-reverse-proxy
```

The server trusts `X-Forwarded-Proto` and `X-Forwarded-Host` for WebSocket origin checks. Most proxies forward these automatically; nginx requires explicit configuration:

```nginx
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Proto $scheme;
```

**Security note:** The reverse proxy must strip or overwrite any `X-Forwarded-Proto` and `X-Forwarded-Host` headers supplied by clients before forwarding requests to the backend. If client-supplied headers are forwarded unchanged, a malicious client can set them to arbitrary values and influence the WebSocket origin check. Add the following to your nginx configuration to ensure this:

```nginx
proxy_set_header X-Forwarded-Host $host;
```

Caddy, AWS ALB, Traefik, and HAProxy overwrite these headers with trusted values by default.

Useful server flags and environment variables:

- `--oidc-issuer` or `OIDC_ISSUER`
- `--token-audience` or `TOKEN_AUDIENCE`
- `--listen-addr` or `LISTEN_ADDR` (default varies by TLS mode; see above)
- `--log-level` or `LOG_LEVEL` with default `info`
- `--tls-cert` or `TLS_CERT_FILE` — path to TLS certificate PEM
- `--tls-key` or `TLS_KEY_FILE` — path to TLS private key PEM
- `--acme-domain` or `ACME_DOMAINS` (comma-separated) — domain(s) for automatic ACME certificate; repeatable
- `--acme-cache-dir` or `ACME_CACHE_DIR` with default `/var/cache/authunnel/acme`
- `--plaintext-behind-reverse-proxy` or `PLAINTEXT_BEHIND_REVERSE_PROXY=true` — serve plain HTTP, trusting a TLS-terminating reverse proxy for transport security; `X-Forwarded-Proto` and `X-Forwarded-Host` are used for WebSocket origin checks
- `--allow` or `ALLOW_RULES` (comma-separated in env) — restrict outbound connections to matching rules; repeatable; if unset all connections are allowed
- `--max-connection-duration` or `MAX_CONNECTION_DURATION` — hard maximum tunnel lifetime (e.g. `4h`, `30m`); default `0` (unlimited)
- `--no-connection-token-expiry` or `NO_CONNECTION_TOKEN_EXPIRY=true` — do not tie tunnel lifetime to access token expiry; by default expiry IS enforced and clients can refresh tokens to extend
- `--expiry-warning` or `EXPIRY_WARNING` — warning period before either longevity limit; default `3m`
- `--expiry-grace` or `EXPIRY_GRACE` — extend the connection deadline beyond the access token's `exp` claim to accommodate providers (e.g. Auth0) that cache access tokens; default `0` (no grace)

Rule formats: `host-glob:port`, `host-glob:lo-hi`, `CIDR:port`, `CIDR:lo-hi`, `[IPv6]:port`, `[IPv6]:lo-hi`

IPv6 addresses must use bracketed notation (`[addr]:port`). Unbracketed IPv6 is rejected at startup because the last-colon port split is otherwise ambiguous.

```bash
# Only allow SSH to *.internal and HTTPS to the 10.x network
authunnel-server --allow '*.internal:22' --allow '10.0.0.0/8:443'
# Or via environment variable (comma-separated)
ALLOW_RULES='*.internal:22,10.0.0.0/8:443' authunnel-server
# IPv6 example
authunnel-server --allow '[::1]:22' --allow '[2001:db8::1]:443'
```

### Managed OIDC client mode

This is the intended `ssh` workflow.

Example SSH config entry:

```sshconfig
Host internal-host
  HostName internal-host
  User myuser
  ProxyCommand /path/to/authunnel-client \
    --tunnel-url https://localhost:8443/protected/tunnel \
    --oidc-issuer https://<issuer> \
    --oidc-client-id authunnel-cli \
    --proxycommand %h %p
```

On Windows with OpenSSH, use the full path with backslashes and quote it if it contains spaces:

```sshconfig
Host internal-host
  HostName internal-host
  User myuser
  ProxyCommand "C:\path\to\authunnel-client.exe" --tunnel-url https://... --oidc-issuer https://<issuer> --oidc-client-id authunnel-cli --proxycommand %h %p
```

Useful client flags:

- `--oidc-issuer`
- `--oidc-client-id`
- `--oidc-audience` to request a specific API/resource audience during managed login
- `--oidc-redirect-port` to use a fixed loopback callback port instead of a random one
- `--oidc-scopes` with default `openid offline_access`
- `--oidc-cache` with default `${XDG_CONFIG_HOME:-~/.config}/authunnel/tokens.json` (macOS/Linux) or `%AppData%\authunnel\tokens.json` (Windows)
- `--oidc-no-browser` to print the URL without attempting automatic browser launch
- `--access-token` to supply a bearer token directly (not recommended; mutually exclusive with all OIDC flags)
- `--tunnel-url` — HTTPS endpoint used for the authenticated HTTP request that is then upgraded to WebSocket
- `--unix-socket`
- `--proxycommand`

On first use the client prints the authorization URL to `stderr` and tries to open the system browser. Subsequent runs reuse the cache or refresh token when possible.

### Manual token (not recommended; for testing only)

A pre-obtained bearer token can be supplied via the `ACCESS_TOKEN` environment variable or the `--access-token` flag. This is mutually exclusive with all managed OIDC flags.

```bash
export ACCESS_TOKEN='<access-token>'
cd client
CGO_ENABLED=0 SSL_CERT_FILE=../cert.pem go run . --unix-socket /tmp/authunnel/proxy.sock
```

ProxyCommand example with a pre-supplied token:

```bash
/path/to/authunnel-client \
  --access-token "$ACCESS_TOKEN" \
  --tunnel-url https://localhost:8443/protected/tunnel \
  --proxycommand internal-host 22
```

### Unix socket SOCKS5 endpoint

```bash
cd client
CGO_ENABLED=0 SSL_CERT_FILE=../cert.pem go run . \
  --oidc-issuer https://<issuer> \
  --oidc-client-id authunnel-cli \
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

Unix socket mode works on Windows 10 1803 and later.

## OIDC Client Registration

For managed client mode, register a **public** OIDC client with:

- standard authorization code flow enabled
- PKCE required with `S256`
- loopback redirect URIs allowed for `http://127.0.0.1/*` or for a specific fixed callback such as `http://127.0.0.1:38081/callback`
- refresh tokens enabled
- scopes that include `openid` and `offline_access`
- an access-token audience that includes the Authunnel resource, for example `authunnel-server`

Some providers, including Auth0 custom APIs, require an explicit audience/resource parameter on the authorization request. Use `--oidc-audience` in those environments.

Some providers require an exact loopback callback URL instead of allowing a random local port. Use `--oidc-redirect-port` when you need to register a fixed callback URL in the IdP.

Some providers require extra configuration before `offline_access` can be requested successfully. When that is not configured, override the client with `--oidc-scopes openid` and rely on cached access tokens only.

## Testing

Run the fast suite:

```bash
go test ./...
```

Current fast coverage includes:

- client config validation for manual vs managed auth modes
- token cache reuse, mismatch rejection, and refresh-before-browser behavior
- PKCE callback state validation and stderr-only auth messaging
- SOCKS5 CONNECT request construction and handshake behavior
- bidirectional proxy forwarding behavior
- server authorization-header rejection and JWT audience validation
- WebSocket multiplexing: binary data round-trip, control message routing, interleaved text/binary frame handling, bidirectional control messages

## Developer Notes

The codebase is intentionally split so the moving parts of the auth and tunnel
flows are easy to locate:

- [`client/client.go`](client/client.go)
  - CLI parsing
  - ProxyCommand and unix-socket tunnel setup
  - SOCKS5 client-side handshake and byte forwarding
- [`client/auth.go`](client/auth.go)
  - auth-mode abstraction
  - OIDC discovery, refresh, and Authorization Code + PKCE flow
  - token cache and lock-file coordination for concurrent `ssh` invocations
- [`internal/tunnelserver/tunnelserver.go`](internal/tunnelserver/tunnelserver.go)
  - issuer discovery and JWKS-backed JWT validation
  - HTTP route setup for protected endpoints
  - websocket-to-SOCKS bridge wiring
  - connection longevity management: token-expiry and max-duration enforcement, token refresh validation with subject pinning
- [`internal/wsconn/wsconn.go`](internal/wsconn/wsconn.go)
  - `MultiplexConn` adapter: wraps a `*websocket.Conn` as `net.Conn` for binary SOCKS5 data, routing text frames to a control channel for longevity messages (expiry warnings, disconnect, token refresh)

When changing the auth flow, keep these invariants intact:

- ProxyCommand mode must only write transport bytes to `stdout`; any user-facing auth output belongs on `stderr`.
- Managed OIDC mode must prefer cache, then refresh, then browser login, so repeated `ssh` runs stay fast and predictable.
- Server-side authorization must continue to fail closed on missing bearer token, invalid JWT signature, wrong issuer, expired token, or wrong `aud`.
- Token refresh over the control channel must verify that the new token's subject matches the original tunnel's subject (subject pinning). Never send refresh tokens to the server; only access tokens travel over the control channel.

## Local Keycloak Test Environment

The repository includes a Keycloak-based development environment under `testenv/keycloak/`.

### 1) Start Keycloak

```bash
docker compose -f testenv/keycloak/docker-compose.yml up -d
```

This imports a realm with:

- realm: `authunnel`
- issuer: `http://127.0.0.1:18080/realms/authunnel`
- public client: `authunnel-cli`
- bearer-only resource client: `authunnel-server`
- test user: `dev-user` / `dev-password`

### 2) Start Authunnel server against Keycloak

```bash
export OIDC_ISSUER='http://127.0.0.1:18080/realms/authunnel'
export TOKEN_AUDIENCE='authunnel-server'
export TLS_CERT_FILE='../cert.pem'
export TLS_KEY_FILE='../key.pem'

cd server
CGO_ENABLED=0 go run .
```

### 3) Start Authunnel client in managed mode

```bash
cd client
CGO_ENABLED=0 SSL_CERT_FILE=../cert.pem go run . \
  --oidc-issuer http://127.0.0.1:18080/realms/authunnel \
  --oidc-client-id authunnel-cli \
  --oidc-scopes openid \
  --unix-socket /tmp/authunnel/proxy.sock
```

### 4) Exercise the SSH-style flow

Direct ProxyCommand-compatible invocation:

```bash
SSL_CERT_FILE=../cert.pem ./client/client \
  --tunnel-url https://localhost:8443/protected/tunnel \
  --oidc-issuer http://127.0.0.1:18080/realms/authunnel \
  --oidc-client-id authunnel-cli \
  --oidc-scopes openid \
  --proxycommand localhost 22
```

Or via `socat` + unix-socket mode:

```bash
socat - SOCKS5:/tmp/authunnel/proxy.sock:localhost:22
```

## End-To-End Test

An opt-in Keycloak-backed end-to-end test is available:

```bash
AUTHUNNEL_E2E=1 go test ./client -run TestKeycloakProxyCommandManagedOIDCE2E -count=1
```

The GitHub Actions workflow in [`.github/workflows/keycloak-e2e.yml`](.github/workflows/keycloak-e2e.yml) starts Keycloak from `testenv/keycloak/docker-compose.yml` and runs that test in CI.

## License

See [`LICENSE`](./LICENSE).

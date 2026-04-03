# Authunnel

Authunnel is an authenticated tunnel for reaching private TCP services, including SSH, through an OAuth2-protected TLS WebSocket conduit.

The target workflow is:

1. `ssh` launches the Authunnel client as `ProxyCommand`.
2. The client reuses a cached token, refreshes it, or completes Authorization Code + PKCE in a browser.
3. The Authunnel server validates the JWT access token against issuer discovery and JWKS.
4. The server hosts a SOCKS5 backend and opens the requested `%h:%p` destination.
5. SSH stdio is bridged over that authenticated path.

The project also supports a unix-domain SOCKS5 endpoint mode (`proxy.sock`) for tools such as `socat`.

## Components

- `server/server.go`
  - HTTPS server on a configurable listen address, default `:8443`
  - Conservative HTTP server timeouts to reduce slow-client resource exhaustion risk
  - Structured JSON request logs with request/trace correlation IDs
  - Tunnel logs include the authenticated user, with per-destination SOCKS CONNECT logs at debug level
  - JWT access-token validation via OIDC discovery + JWKS
  - WebSocket endpoint (`/protected/socks`) connected to an in-process SOCKS5 server
- `client/client.go`
  - **ProxyCommand mode**: stdio bridge for direct SSH integration
  - **Unix socket mode**: local SOCKS5 endpoint for generic client tooling
  - **Managed OIDC mode**: public-client PKCE login with token cache + refresh

## How It Works

### Server flow

1. Reads OIDC issuer, audience, listen address, and TLS file paths from flags or environment.
2. Discovers issuer metadata and JWKS.
3. Verifies bearer-token signature, issuer, expiration, and audience.
4. Accepts WebSocket connections at `/protected/socks`.
5. Hands each upgraded connection to the SOCKS5 server implementation.
6. Emits structured JSON logs for request lifecycle, auth failures, tunnel open/close events, and debug-level SOCKS CONNECT destinations.

### Client flow

1. Either:
   - uses a bearer token supplied via `--access-token` or the `ACCESS_TOKEN` environment variable, or
   - runs managed OIDC mode when `--oidc-issuer` and `--oidc-client-id` are configured.
2. In managed mode the client:
   - reuses a cached token when it remains valid for more than 60 seconds,
   - otherwise refreshes it when a refresh token is available,
   - otherwise launches a browser to the IdP and listens on `127.0.0.1` for the callback.
3. The client opens an authenticated WebSocket connection to the Authunnel server.
4. In ProxyCommand mode it performs a SOCKS5 CONNECT for `%h:%p` and bridges `stdin/stdout`.
5. In unix-socket mode it exposes a local SOCKS5 endpoint and opens a dedicated tunnel per local connection.

## Security Posture

Authunnel enforces authentication (JWT validation) at the WebSocket layer before any SOCKS5 connection can be attempted. The `--allow` option provides a second layer of control over *where* an authenticated user can connect.

**Open mode (no `--allow` rules — the default):** Any destination reachable by the server process is accessible to authenticated clients. This is convenient and gives operators full visibility: every SOCKS CONNECT destination is logged at debug level.

**Allowlist mode (one or more `--allow` rules):** Only destinations matching a rule are permitted. Denied attempts are logged at warn level. This limits exposure if a credential is compromised, at the cost of requiring explicit enumeration of allowed targets.

**The "tunnels within tunnels" trade-off:** Authunnel is itself a tunneling tool. In open mode a client could make a SOCKS CONNECT to another proxy or tunnel that then reaches a second destination the Authunnel server cannot observe or log. Allowlisting reduces this surface — but it cannot eliminate it for destinations that are themselves allowed. Operators should treat `--allow` rules as defence-in-depth rather than a complete control boundary. Conversely, locking down the allowlist too aggressively can impede the visibility that makes Authunnel useful as a monitored ingress point, since permitted connections can still forward traffic opaquely once the tunnel is open.

## Usage

### Prerequisites

- Go 1.24.10+
- An OIDC provider that issues JWT access tokens
- A server audience configured in the IdP and emitted into access-token `aud`
- A local TLS certificate trusted by the client runtime

### Start server

```bash
export OIDC_ISSUER='https://<issuer>'
export TOKEN_AUDIENCE='authunnel-server'
export TLS_CERT_FILE='/etc/authunnel/tls/server.crt'
export TLS_KEY_FILE='/etc/authunnel/tls/server.key'

cd server
go run .
```

Useful server flags and environment variables:

- `--oidc-issuer` or `OIDC_ISSUER`
- `--token-audience` or `TOKEN_AUDIENCE`
- `--listen-addr` or `LISTEN_ADDR` with default `:8443`
- `--log-level` or `LOG_LEVEL` with default `info`
- `--tls-cert` or `TLS_CERT_FILE`
- `--tls-key` or `TLS_KEY_FILE`
- `--allow` or `ALLOW_RULES` (comma-separated in env) — restrict outbound connections to matching rules; repeatable; if unset all connections are allowed

Rule formats: `host-glob:port`, `host-glob:lo-hi`, `CIDR:port`, `CIDR:lo-hi`

```bash
# Only allow SSH to *.internal and HTTPS to the 10.x network
authunnel-server --allow '*.internal:22' --allow '10.0.0.0/8:443'
# Or via environment variable (comma-separated)
ALLOW_RULES='*.internal:22,10.0.0.0/8:443' authunnel-server
```

### Managed OIDC client mode

This is the intended `ssh` workflow.

Example SSH config entry:

```sshconfig
Host internal-host
  HostName internal-host
  User myuser
  ProxyCommand /path/to/authunnel-client \
    --ws-url https://localhost:8443/protected/socks \
    --oidc-issuer https://<issuer> \
    --oidc-client-id authunnel-cli \
    --proxycommand %h %p
```

Useful client flags:

- `--oidc-issuer`
- `--oidc-client-id`
- `--oidc-audience` to request a specific API/resource audience during managed login
- `--oidc-redirect-port` to use a fixed loopback callback port instead of a random one
- `--oidc-scopes` with default `openid offline_access`
- `--oidc-cache` with default `${XDG_CONFIG_HOME:-~/.config}/authunnel/tokens.json`
- `--oidc-no-browser` to print the URL without attempting automatic browser launch
- `--access-token` to supply a bearer token directly (not recommended; mutually exclusive with all OIDC flags)
- `--ws-url`
- `--unix-socket`
- `--proxycommand`

On first use the client prints the authorization URL to `stderr` and tries to open the system browser. Subsequent runs reuse the cache or refresh token when possible.

### Manual token (not recommended; for testing only)

A pre-obtained bearer token can be supplied via the `ACCESS_TOKEN` environment variable or the `--access-token` flag. This is mutually exclusive with all managed OIDC flags.

```bash
export ACCESS_TOKEN='<access-token>'
cd client
SSL_CERT_FILE=../cert.pem go run . --unix-socket /tmp/authunnel/proxy.sock
```

ProxyCommand example with a pre-supplied token:

```bash
/path/to/authunnel-client \
  --access-token "$ACCESS_TOKEN" \
  --ws-url https://localhost:8443/protected/socks \
  --proxycommand internal-host 22
```

### Unix socket SOCKS5 endpoint

```bash
cd client
SSL_CERT_FILE=../cert.pem go run . \
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

When changing the auth flow, keep these invariants intact:

- ProxyCommand mode must only write transport bytes to `stdout`; any user-facing auth output belongs on `stderr`.
- Managed OIDC mode must prefer cache, then refresh, then browser login, so repeated `ssh` runs stay fast and predictable.
- Server-side authorization must continue to fail closed on missing bearer token, invalid JWT signature, wrong issuer, expired token, or wrong `aud`.

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
go run .
```

### 3) Start Authunnel client in managed mode

```bash
cd client
SSL_CERT_FILE=../cert.pem go run . \
  --oidc-issuer http://127.0.0.1:18080/realms/authunnel \
  --oidc-client-id authunnel-cli \
  --oidc-scopes openid \
  --unix-socket /tmp/authunnel/proxy.sock
```

### 4) Exercise the SSH-style flow

Direct ProxyCommand-compatible invocation:

```bash
SSL_CERT_FILE=../cert.pem ./client/client \
  --ws-url https://localhost:8443/protected/socks \
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

See `LICENSE`.

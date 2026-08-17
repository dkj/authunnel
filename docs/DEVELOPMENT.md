# Developing Authunnel

This guide covers building and testing Authunnel from source: codebase layout, the invariants to preserve when changing the auth flow, the test suite, and the local Keycloak environment.

Developers need Go 1.26.6+ to build and test Authunnel from source.

## Codebase layout

The codebase is intentionally split so the moving parts of the auth and tunnel
flows are easy to locate:

- [`client/client.go`](../client/client.go)
  - CLI parsing
  - ProxyCommand and unix-socket tunnel setup
  - SOCKS5 client-side handshake and byte forwarding
- [`client/auth.go`](../client/auth.go)
  - auth-mode abstraction
  - OIDC discovery, refresh, and Authorization Code + PKCE flow
  - token cache and lock-file coordination for concurrent `ssh` invocations
- [`internal/tunnelserver/tunnelserver.go`](../internal/tunnelserver/tunnelserver.go)
  - issuer discovery and JWKS-backed JWT validation
  - HTTP route setup for protected endpoints
  - websocket-to-SOCKS bridge wiring
  - connection longevity management: token-expiry and max-duration enforcement, token refresh validation with subject pinning
- [`internal/wsconn/wsconn.go`](../internal/wsconn/wsconn.go)
  - `MultiplexConn` adapter: wraps a `*websocket.Conn` as `net.Conn` for binary SOCKS5 data, routing text frames to a control channel for longevity messages (expiry warnings, disconnect, token refresh)

## Auth-flow invariants

When changing the auth flow, keep these invariants intact:

- ProxyCommand mode must only write transport bytes to `stdout`; any user-facing auth output belongs on `stderr`.
- Managed OIDC mode must prefer cache, then refresh, then browser login, so repeated `ssh` runs stay fast and predictable.
- Server-side authorization must continue to fail closed on missing bearer token, invalid JWT signature, wrong issuer, expired token, wrong `aud`, missing `sub`, future `iat`, or (at admission) unreached `nbf`.
- Token refresh over the control channel must verify that the new token's subject matches the original tunnel's subject (subject pinning) and that its `nbf`, if in the future, is at or before the current enforced connection deadline (`exp + --expiry-grace`), so the handover stays within the deadline the operator has already opted into. Never send refresh tokens to the server; only access tokens travel over the control channel.

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
- transport hardening: insecure OIDC issuer and tunnel URL rejection, secure-scheme enforcement on client and server
- token validation: `nbf` not-before enforcement, `iat` sanity check, non-empty `sub` requirement, refresh subject pinning, refresh deadline enforcement
- admission controls: global concurrent cap, per-user concurrent cap, per-user rate limiting (fake-clock deterministic), dial timeout against blackholed destinations, handler-level rejection with correct HTTP status and `Retry-After`
- egress posture: startup rejection when neither `--allow` rules nor `--allow-open-egress` is present, mutual exclusion between the two modes, env-var equivalents
- filesystem safety: unix socket directory permission checks (group/world-writable rejection, foreign-owner rejection), stale-socket cleanup refusal on non-socket paths, umask-tightened socket creation, token cache and lock directory safety

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
export INSECURE_OIDC_ISSUER=true   # local Keycloak uses HTTP
export TOKEN_AUDIENCE='authunnel-server'
export TLS_CERT_FILE='../cert.pem'
export TLS_KEY_FILE='../key.pem'

cd server
# Local dev environment — opt into open egress since the destinations
# exercised by the example commands are loopback services
CGO_ENABLED=0 go run . --allow-open-egress
```

Keycloak publishes OIDC discovery at the derived well-known path, so no discovery
override is needed here. To test against an authorization server that only
publishes RFC 8414 metadata, or one whose metadata sits off the issuer path, add
`--oidc-metadata-url` pointing at the document — the server still requires its
`issuer` to match `OIDC_ISSUER`. `--oidc-jwks-uri` skips metadata discovery
altogether, which is useful for reproducing a start-up-with-IdP-down scenario.
Both accept `http://` under `INSECURE_OIDC_ISSUER=true`, but neither accepts
`file://`. The startup log line `token_validator_ready` reports which mode
resolved.

### 3) Start Authunnel client in managed mode

```bash
cd client
CGO_ENABLED=0 SSL_CERT_FILE=../cert.pem go run . \
  --tunnel-url https://localhost:8443/protected/tunnel \
  --oidc-issuer http://127.0.0.1:18080/realms/authunnel \
  --insecure-oidc-issuer \
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
  --insecure-oidc-issuer \
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

The GitHub Actions workflow in [`.github/workflows/keycloak-e2e.yml`](../.github/workflows/keycloak-e2e.yml) starts Keycloak from `testenv/keycloak/docker-compose.yml` and runs that test in CI.

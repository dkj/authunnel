# Authunnel

Authunnel is a proof-of-concept (PoC) authenticated SOCKS5 tunnel built in Go. It demonstrates how to:

- validate OAuth2 access tokens at a TLS-protected server,
- upgrade authenticated requests to WebSocket,
- and bridge local Unix socket traffic through that authenticated WebSocket stream.

The project currently consists of two binaries:

- `server/server.go`: TLS + OAuth2-protected WebSocket endpoint and SOCKS5 backend.
- `client/client.go`: local Unix socket proxy that dials the protected WebSocket endpoint.

## Repository assessment

This repository is currently in **PoC stage**, not production-ready. It successfully demonstrates the core auth-and-tunnel flow, but it still has important limitations:

- Configuration is environment-variable only and lightly validated.
- TLS certificates are expected in fixed relative paths (`../cert.pem`, `../key.pem`).
- Error handling/logging is minimal for operations and observability.
- There are no build, lint, or release workflows.
- Test coverage is basic and focuses on unit-level behavior.

## How the utility works

### Server flow (`server/server.go`)

1. Reads `ISSUER`, `CLIENT_ID`, and `CLIENT_SECRET`.
2. Builds an OAuth2 resource server client for token introspection.
3. Starts an HTTPS server on `:8443`.
4. Exposes endpoints:
   - `/` (health-like response)
   - `/protected` (requires bearer token)
   - `/protected/socks` (requires bearer token, then upgrades to WebSocket)
5. For `/protected/socks`, accepted WebSocket connections are connected to an in-process SOCKS5 server.

### Client flow (`client/client.go`)

1. Reads `ACCESS_TOKEN`.
2. Creates a Unix domain socket listener (`proxy.sock`).
3. Dials `https://localhost:8443/protected/socks` over WebSocket with bearer token.
4. Accepts local Unix socket connections.
5. Bridges local connection traffic to/from the remote WebSocket network connection.

## Quick start (development PoC)

### Prerequisites

- Go 1.24.10+
- OAuth2 provider credentials and token flow as documented in `Notes.md`
- TLS cert + key for localhost (for local demo)

### 1) Start server

```bash
export ISSUER='https://<issuer>/oauth2/default'
export CLIENT_ID='<resource-server-client-id>'
export CLIENT_SECRET='<resource-server-client-secret>'

cd server
go run .
```

### 2) Acquire access token

Use your preferred OAuth2 flow (example commands are in `Notes.md`) and set:

```bash
export ACCESS_TOKEN='<access-token>'
```

### 3) Start client

```bash
cd client
SSL_CERT_FILE=../cert.pem go run .
```

### 4) Use the local proxy socket

```bash
all_proxy="socks5h://localhost$(pwd)/proxy.sock" curl https://example.com
```

> Note: exact socket path usage depends on your shell and tooling expectations for Unix-domain SOCKS endpoints.

## Testing

Run all tests from repository root:

```bash
go test ./...
```

Current tests validate:

- token-header rejection behavior in `checkToken`.
- bidirectional connection forwarding behavior in `proxy`.

## Production readiness plan

The following phased plan is suitable for moving this utility from PoC to production.

### Phase 1: Hardening and correctness

1. **Configuration model**
   - Introduce structured config with explicit validation, defaults, and clear startup failures.
   - Add support for flags/config files alongside env vars.
2. **Security baseline**
   - Enforce minimum TLS versions and cipher policies.
   - Support trust store configuration and optional mTLS between client/server.
   - Remove any hard-coded credential assumptions and document secret-management strategy.
3. **Token validation policy**
   - Define and enforce audience/scope requirements.
   - Add timeout/retry policy around introspection calls.
   - Add explicit deny behavior for partial/introspection errors.
4. **Graceful shutdown**
   - Handle signals and ensure listeners/connections drain cleanly.

### Phase 2: Reliability and operability

1. **Observability**
   - Structured logging (request IDs, connection IDs, token validation outcomes without sensitive token data).
   - Metrics: active tunnels, handshake failures, auth failures, transfer bytes, latency.
2. **Resilience**
   - Reconnect strategy with backoff in the client.
   - Circuit-breaking/rate limiting on auth and tunnel endpoints.
3. **Runtime controls**
   - Max concurrent sessions and per-session throughput/idle limits.
   - Connection timeouts and keepalive policies.

### Phase 3: Delivery and maintainability

1. **Packaging & deployment**
   - Build static binaries and container images.
   - Provide deployment manifests (e.g., systemd/Kubernetes examples).
2. **CI/CD pipeline**
   - `go test ./...`, race tests, linting, vulnerability scans, and reproducible build checks.
3. **Versioning & compatibility**
   - Semantic versioning and changelog process.
   - Backward compatibility contract for client-server protocol settings.

## Recommended test strategy for production

1. **Unit tests**
   - Authorization parsing/validation outcomes.
   - Connection lifecycle and proxy edge cases.
2. **Integration tests**
   - Local end-to-end tunnel with ephemeral certs and mock OIDC introspection server.
   - Auth success/failure matrix (missing header, invalid bearer, inactive token, timeout).
3. **System tests**
   - Throughput and long-lived connection tests.
   - Fault injection (issuer downtime, network interruptions, token introspection latency spikes).
4. **Security tests**
   - TLS posture checks, dependency scanning, secret leakage checks.
5. **Release gates**
   - Full integration suite on PRs and before releases.
   - Performance baseline comparison and rollback criteria.

## License

See `LICENSE`.

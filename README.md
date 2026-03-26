# Authunnel

Authunnel is a proof-of-concept (PoC) authenticated tunnel for reaching private TCP services (including SSH) through an OAuth2-protected, TLS WebSocket conduit.

The intended target workflow is:

1. local SSH client launches Authunnel client as `ProxyCommand`,
2. client authenticates to Authunnel server using bearer token,
3. server hosts a SOCKS5 backend and opens the requested `%h:%p` destination,
4. SSH stdio is bridged over that authenticated path.

The project also supports a unix-domain SOCKS5 endpoint mode (`proxy.sock`) for tools such as `socat`.

## Components

- `server/server.go`
  - HTTPS server on `:8443`.
  - OAuth2 access-token introspection for protected endpoints.
  - WebSocket endpoint (`/protected/socks`) connected to an in-process SOCKS5 server.
- `client/client.go`
  - **ProxyCommand mode**: stdio bridge for direct SSH integration.
  - **Unix socket mode**: local SOCKS5 endpoint for generic client tooling.

## Current maturity assessment

This remains a **PoC**, but now better aligned with SSH usage.

Strengths:
- end-to-end authenticated tunnel concept works,
- clear split between server auth gateway and client-side entrypoint,
- automated unit tests and CI test workflow exist.

Gaps before production:
- robust reconnect/backoff behavior,
- structured observability (metrics + correlation IDs),
- hardened lifecycle/shutdown semantics,
- integration/system tests with realistic network and IdP failure modes.

## How it works

### Server flow

1. Reads `ISSUER`, `CLIENT_ID`, `CLIENT_SECRET`.
2. Validates bearer tokens using introspection.
3. Accepts WebSocket connections at `/protected/socks`.
4. Hands each upgraded connection to SOCKS5 server implementation.

### Client flow: unix socket mode (default)

1. Reads `ACCESS_TOKEN`.
2. Opens unix socket listener (`proxy.sock` by default; configurable).
3. For each local connection, dials authenticated websocket endpoint.
4. Proxies bytes bidirectionally.

### Client flow: ProxyCommand mode

1. SSH invokes client with `%h %p`.
2. Client opens authenticated websocket.
3. Client performs SOCKS5 greeting + CONNECT for `%h:%p`.
4. Client bridges `stdin/stdout` with remote stream.

## Usage

### Prerequisites

- Go 1.24.10+
- OAuth2 provider credentials/tokens
- Local TLS certificate trusted by the client runtime

### Start server

```bash
export ISSUER='https://<issuer>/oauth2/default'
export CLIENT_ID='<resource-server-client-id>'
export CLIENT_SECRET='<resource-server-client-secret>'

cd server
go run .
```

### Acquire access token

Set:

```bash
export ACCESS_TOKEN='<access-token>'
```

### Option A: SSH ProxyCommand (target mode)

Example SSH config entry:

```sshconfig
Host internal-host
  HostName internal-host
  User myuser
  ProxyCommand /path/to/authunnel-client --proxycommand %h %p
```

If needed, override endpoint:

```bash
ACCESS_TOKEN="$ACCESS_TOKEN" /path/to/authunnel-client --ws-url https://localhost:8443/protected/socks --proxycommand internal-host 22
```

### Option B: Unix socket SOCKS5 endpoint

Run client listener:

```bash
cd client
SSL_CERT_FILE=../cert.pem go run . --unix-socket /tmp/authunnel/proxy.sock
```

Use with `socat` in an SSH `ProxyCommand`:

```sshconfig
Host internal-host-via-socat
  HostName internal-host
  User myuser
  ProxyCommand socat - SOCKS5:/tmp/authunnel/proxy.sock:%h:%p
```

(Exact `socat` syntax may vary by version/platform.)

## Testing

Run the full suite:

```bash
go test ./...
```

Current test coverage includes:

- `checkToken` authorization-header rejection behavior,
- bidirectional proxy forwarding behavior,
- SOCKS5 CONNECT request construction and handshake behavior for ProxyCommand mode.

CI also runs `go test ./...` on push and pull request via GitHub Actions.

## Production-readiness plan

### Phase 1 — Security and correctness

1. Add strict startup config validation and documented defaults.
2. Enforce TLS minima, certificate pin/trust options, and optional mTLS.
3. Add request-scoped timeouts for introspection and websocket/socks negotiations.
4. Ensure deterministic graceful shutdown and session draining.

### Phase 2 — Reliability and operations

1. Add reconnect/backoff and transient error handling strategy.
2. Introduce structured logs and metrics (auth failures, active tunnels, bytes, latency).
3. Add runtime controls (session limits, idle timeout, per-session caps).

### Phase 3 — Delivery and quality gates

1. Add lint, race detector, vulnerability scans, and reproducible release builds.
2. Add integration tests with mock IdP + ephemeral certs + end-to-end SSH path.
3. Add system tests for long-lived connections, performance baselines, and fault injection.

## License

See `LICENSE`.

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
  - configuration resolution: filling unset OIDC values from the tunnel server's protected-resource metadata, then locating the authorization server's endpoints
  - refresh and Authorization Code + PKCE flow
  - token cache and lock-file coordination for concurrent `ssh` invocations
- [`internal/ipblock/`](../internal/ipblock/)
  - the resolved-IP deny-list, shared because both sides ask the same question: the server about SOCKS destinations, the client about addresses a remote metadata document names
- [`internal/authmeta/`](../internal/authmeta/)
  - the two metadata documents authunnel reads: authorization server metadata (RFC 8414 / OIDC Discovery) and protected-resource metadata (RFC 9728), with the shared `ProtectedResource` type both binaries use so the wire format cannot drift
  - bounded JSON fetching under `internal/authhttp`'s transport policy, and the validators for values that arrive in a document and leave in an authorization URL
- [`internal/tunnelserver/resourcemeta.go`](../internal/tunnelserver/resourcemeta.go)
  - the published protected-resource document and the `WWW-Authenticate` challenge that points at it
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
- Managed OIDC mode must prefer cache, then refresh, then browser login, so repeated `ssh` runs stay fast and predictable — **except** when the failure is a refusal rather than a rejection. A refresh that failed because an endpoint or transport was refused must not fall through to interactive login: the browser flow ends at the same endpoint and would fail identically after making the user authenticate. Those refusals are identified by `errors.Is(err, authhttp.ErrUnsafeTransport)`; keep them distinguishable from an expired or revoked credential, which *should* fall through.
- Both binaries validate every metadata-advertised endpoint with the combined `CheckDiscoveredEndpoint` policy: an absolute `http(s)` URL with a host and no downgrade from an HTTPS metadata source. Auth HTTP clients separately refuse HTTPS-to-plaintext redirects. See [Transport rules on the auth path](DEPLOYMENT.md#transport-rules-on-the-auth-path).
- The PKCE loopback callback stays plain `http://127.0.0.1:…` deliberately (RFC 8252) and is outside those rules. Do not "fix" it.
- The token cache identity must include everything that determines **where a credential gets sent**, not only what determines whether it is still valid. Today that is the resource URL discovery ran against, issuer, metadata URL, client ID, audience, resource, and scopes — the `oidcIdentity` type. The metadata URL is the non-obvious one: it names the token endpoint the refresh token is posted to, and discovery only checks that the document's `issuer` field equals the configured issuer — a string the document asserts about itself, which does not bind the host serving it. Dropping it from the identity lets a changed or mistyped `--oidc-metadata-url` hand an existing refresh token to whatever endpoint the new document names. Build cache entries with `managedOIDCTokenSource.cacheFor` rather than enumerating fields at the call site.
- Because some of that identity can now be **discovered**, the cache is compared twice and both comparisons are load-bearing. `cacheMatchesConfigured` runs before resolution — it is all the cache-hit path can afford — and exempts a field only when a resolver will supply it; exempting every unconfigured field instead would let a token minted for one audience satisfy a request for none. `cacheMatchesResolved` runs after resolution and before any refresh grant, with no exemptions: a resolution that names a different authorization server, client, or metadata URL than the credential was issued under discards the cache rather than posting the refresh token to it. Removing either check reintroduces the credential-disclosure bug recorded in [PLAN_202608_client_discovery.md](plans/PLAN_202608_client_discovery.md).
- **Resolution is lazy, and must stay lazy.** `AccessToken` returns from the cache before `resolve` is reached, so the common ProxyCommand path makes no network call at all. Moving resolution earlier — into `parseClientConfig`, `newAuthTokenSource`, or above the cache check — adds an HTTP request to every `ssh` invocation. `TestCacheHitMakesNoRequestAtAll` fails if it happens.
- A value taken from a metadata document is held to the rules a configured value is held to, not weaker ones: `https` unless `--insecure-oidc-issuer`, `file://` refused either way, no downgrade relative to the document's own source, length/charset bounds on hints that end up in an authorization URL, and — for addresses — the resolved-IP deny-list in `internal/ipblock`.
- **The protected-resource comparison is exact** (RFC 9728 §3.3): scheme, host, path and query, after syntax-based normalisation only. Loosening it to an origin comparison lets one host's protected resources supply each other's configuration; a deployment whose external identifier differs declares it with the server's `--resource-url` instead. `NormalizeResourceIdentifier` is deliberately conservative — no trailing-slash folding, no dot-segment removal — because each addition makes an "exact" comparison quietly less so.
- **Internal addresses named by a remote document are refused at every layer that can see something the others cannot**, and none is redundant: a resolution check on the value (the only protection for the `authorization_endpoint`, since that URL goes to the OS dispatcher rather than through any client of ours), a per-request destination check in the RoundTripper, and a dial-time check that connects to the address it verified. The proxy decision runs *before* the address checks, because it decides whether they describe anything real: `NewBoundedClient` sets `Proxy: http.ProxyFromEnvironment`, and past a proxy the destination is resolved by the proxy, so a local lookup describes a connection that will not happen. **Proxied `https` is allowed** on certificate verification — which binds the *hostname*, not the address, so an internal service holding a valid certificate for a name a document supplied still passes; that limit is accepted, and DEPLOYMENT.md states the three conditions it rests on. **Proxied plaintext is refused**, having nothing to be checked against. The destination and dial checks are *skipped* on the proxied path rather than applied, since a proxied network frequently has no local answer for an external name. Only those two are proxy-aware: `checkDiscoveredAddress` calls `authhttp.CheckPublicAddress` on the discovered value directly, so that layer runs whatever the transport does, refusing a name local DNS resolves into the protected set and tolerating one it cannot resolve at all. A TLS-terminating proxy is outside all of this by construction: it is trusted with the OAuth exchange itself. `RefuseInternalAddresses` must be applied to a base client and never to its own output — it reads the proxy policy off the `*http.Transport` underneath, so a second application keeps the destination check and drops the classification; `fetchClient` in `client/auth.go` is the single accessor that guarantees this.
- **The condition that relaxes all of the above resolves nothing, and is narrower than the refusal set.** It is satisfied only by a loopback literal or a name RFC 6761 reserves for loopback. The two sets answer different questions — "may a remote party send us here" versus "is this host our own machine" — and reusing `ipblock.Default()` for both meant a tunnel URL at `169.254.169.254` was classified as local and disabled the guard protecting that address. `TestRelaxationIsNarrowerThanRefusal` states it as a property over the whole refusal set rather than a list of cases, so a new entry there cannot quietly inherit "local" along with "refused". It used to be answered by resolving the tunnel host and treating any blocked answer as local — which handed the activation condition to the party the guard constrains, since two A records (one public, one loopback) switched every check off. All name resolution in `internal/authhttp` goes through one `lookupIPAddr` seam so a test can assert which paths resolve and which must not.
- **A resource identifier is an `http`/`https` URL with a host and no fragment**, and that rule lives in one place (`authmeta.NormalizeResourceIdentifier`) which the §3.1 derivation is built on. The scheme part is not stylistic: a client derives the metadata location from the identifier and fetches it over HTTP, so any other scheme names a document nothing can retrieve — which is why `--resource-url` is validated by the same rule rather than merely parsed. A configured value always wins over a discovered one, and a discovered issuer that contradicts a configured one is an error rather than a silent override — that is what leaves an operator a way to decline discovery without declining the client.
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
- issuer metadata location: the three server discovery modes, `--oidc-metadata-url` reaching a non-derived RFC 8414 path on both binaries, rejection of a document whose `issuer` disagrees with the configured one, and adoption of the declared issuer when the client configures none
- protected-resource metadata: the published document at both well-known shapes, hints appearing only when configured, `resource` following `X-Forwarded-*` only in the trusting mode, `WWW-Authenticate` present on each `401` path and pointing at a URL that actually serves the document, and absent on `200`/`403`
- client-side discovery: everything resolved from a stub resource server, configured values winning over published ones, a contradicted issuer refused, malformed hints refused, a document describing another origin refused, and the cache discarded when the published client ID changes — asserted by what the token endpoint *did not* receive, not by an error value
- the exactness of the resource comparison, including the pairs an origin-only comparison collapsed (`/a/tunnel` vs `/b/tunnel`, `?tenant=a` vs `?tenant=b`, trailing slash) and the spellings it must still treat as equal (case, default ports)
- the internal-address guard: literals and names that resolve to loopback or link-local refused, private networks accepted, unresolvable distinguished from refused, the dial guard proven against a control request that succeeds unguarded, and the caller's own client left unmodified
- the same guard **through a proxy**, which is where a dial-only check fails: an internal destination refused even though the proxy would have done the fetching (with an unguarded control proving the proxy does fetch it), and a public destination still reaching a *loopback* proxy, which a dial check applied to the proxy hop would wrongly refuse
- the display boundary: the writer's escaping and newline handling, the wiring function that installs it, and an end-to-end pass through the real `oauth2.RetrieveError` for a non-conforming token endpoint response
- a crafted HTTP reason phrase, served by a raw listener because `httptest` cannot produce one, kept out of the error entirely
- attacker-chosen control bytes escaped at every sink that can carry them: the ignored-hint announcement, the bounded HTTP error body, the issuer-mismatch comparison, and each of the three control-message reasons — asserted by reverting all of them to `%s` at once and watching each test fail
- a configured loopback issuer surviving a discovery run that happened only because `--oidc-client-id` was missing, with the guard that would otherwise refuse it not installed — and the zero-config control still refusing the same address
- an unusable published metadata URL being announced and ignored rather than failing the flow, across a hint refused by the shape rule and one refused by the address rule, since only the first detects the ordering
- a same-origin open redirect on the issuer's host failing to relocate the metadata document, which is the bypass of the pin below
- the document and the `WWW-Authenticate` challenge agreeing on which resource they describe, including for a `--resource-url` that `Validate` would have rejected — `NewHandler` does not validate, so the two are derived from one decision rather than trusted to match
- `SameOrigin` and the shared authority normalisation agreeing on equivalent spellings of one origin, IPv6 literals included, after the two implementations of that rule were found to have drifted
- `PinRedirectOrigin` layering on a caller's own redirect policy rather than replacing it — the contract `RefuseTransportDowngrade` already had a test for, and this one did not
- a cross-origin redirect on the token endpoint refused, with a *working* https mirror on the other origin recording nothing, so the refusal is attributable to the policy rather than to a broken target
- a pinned issuer refusing a relocated metadata document, with the assertion on the resolved *endpoints* rather than on an error, since the failure mode is a flow that succeeds against the wrong server — plus the same-origin case still working and the unpinned cross-origin case still allowed, which is what distinguishes gating on the configured issuer from gating on the resolved one
- the relaxation set being a strict subset of the refusal set, asserted as a property so future additions to `ipblock.Default()` cannot inherit "local"
- the classification that relaxes the guard consulting no name service — asserted with a resolver that fails the test if called, *and* with one answering loopback for every name, since those catch different reintroductions
- a proxied *plaintext* request refused for both an internal and a public destination, with an unguarded control proving the proxy would otherwise fetch the internal one, plus a no-proxy-applies case still judged on its address alone
- proxied `https` allowed **and** the TLS binding demonstrated rather than asserted: a blind `CONNECT` relay that sends every tunnel to one origin regardless of the name requested, where the matching name succeeds and a rebound name fails on the certificate before any request is served — the evidence for scoping the refusal to plaintext
- a proxied `https` request succeeding with a resolver that answers nothing, so the skipped-not-applied choice is pinned against the proxy-side-DNS deployment it exists for
- escaped path segments surviving derivation, normalisation and comparison: `%2F` not collapsed onto `/`, and the two spellings not sharing a discovery or cache identity
- the query surviving `parseClientConfig` into the resource identity and the cache key — through the production config path rather than by assigning the field, which is what let an earlier round of this work drop the query with every test still green
- recovery from a rejected token: a replacement obtained when re-resolution shows the configuration changed, nothing done when it has not, no retry on capacity rejections, and exactly one retry — asserted on the sequence of tokens the tunnel actually saw
- a zero-configuration end-to-end tunnel: a client parsed from `--tunnel-url` alone completing a browser login and moving bytes through the real handler, then a second invocation reusing the cache without touching the metadata endpoint or the browser
- auth-path transport rules: non-`http(s)` and host-less endpoints rejected in every mode including under `--insecure-oidc-issuer`, plaintext endpoints rejected when the metadata came over `https`, and redirect downgrades refused on all three fetches — metadata, JWKS, and the client's token exchange
- redirect-downgrade fixtures use working plaintext mirrors and assert the mirror received no request, proving the unsafe fetch was refused rather than failing later for unrelated content
- token validation: `nbf` not-before enforcement, `iat` sanity check, non-empty `sub` requirement, refresh subject pinning, refresh deadline enforcement
- admission controls: global concurrent cap, per-user concurrent cap, per-user rate limiting (fake-clock deterministic), dial timeout against blackholed destinations, handler-level rejection with correct HTTP status and `Retry-After`
- egress posture: startup rejection when neither `--allow` rules nor `--allow-open-egress` is present, mutual exclusion between the two modes, env-var equivalents
- filesystem safety: unix socket directory permission checks (group/world-writable rejection, foreign-owner rejection), stale-socket cleanup refusal on non-socket paths, umask-tightened socket creation, token cache and lock directory safety

## Known coverage gaps

Recorded rather than implied, so a reader can tell a deliberate limit from an oversight:

- `main`'s single call to `installSafeLogging` is not reachable from a test, so that one
  line is uncovered. Everything downstream of it is covered, and the wiring function it
  calls has its own test.
- `ipblock.Parse` is exported with no cross-package caller; it is used only by
  `ParseListFromCSV` and the flag type. Predates the move out of `tunnelserver`.
- Two tests rely on the system resolver mapping `localhost` to loopback, and one on
  `.invalid` not resolving. Both hold on any normal host; a captive or wildcard DNS
  resolver would break the latter.
- The tests that capture log output mutate process-global `log` state, so they are not
  safe to run in parallel with anything that logs.

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

Add `--client-id authunnel-cli --client-default-scopes openid` to publish the client
configuration, so the client below can run without OIDC flags of its own. One
caveat specific to this environment: the tunnel is served over TLS while Keycloak
runs over plain HTTP, and a discovered issuer is held to the same rules as a
configured one — an `https` resource may not name an `http` authorization server.
Discovery therefore *correctly* refuses this combination. To exercise it locally,
run the server with `--plaintext-behind-reverse-proxy` and the client with
`--insecure-tunnel-url --insecure-oidc-issuer` so both legs are plaintext.

Keycloak publishes OIDC discovery at the derived well-known path, so no discovery
override is needed here. To test against an authorization server that only
publishes RFC 8414 metadata, or one whose metadata sits off the issuer path, add
`--oidc-metadata-url` pointing at the document — the server still requires its
`issuer` to match `OIDC_ISSUER`. `--oidc-jwks-uri` skips metadata discovery so
server auth egress can be restricted to the configured key endpoint. Both
accept `http://` under `INSECURE_OIDC_ISSUER=true`, but neither accepts
`file://`. The startup log line `token_validator_ready` reports which mode
resolved.

The client has the matching `--oidc-metadata-url`, with the same semantics and
the same `--insecure-oidc-issuer` relaxation.

There is no client equivalent of `--oidc-jwks-uri`: pinning the endpoint that
receives refresh tokens has materially different failure consequences from
pinning the server's read-only JWKS endpoint. See the security rationale in
[DEPLOYMENT.md](DEPLOYMENT.md#issuer-metadata-and-key-discovery).

Note the client's OIDC settings are flags only — it has no environment-variable
equivalents beyond `ACCESS_TOKEN` and `AUTHUNNEL_TUNNEL_URL`.

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

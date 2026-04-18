# PLAN 2026-04 Hardening

This document turns the current security review into a concrete hardening plan that can be split across contributors without losing the security intent.

## Goals

- Reduce the default blast radius of a compromised credential.
- Fail closed on insecure or ambiguous transport configuration.
- Make token validation match the security properties the server claims to enforce.
- Tighten local client-side exposure on shared hosts.
- Add verification coverage so regressions are caught automatically.

## Non-goals

- Full token revocation or introspection on every request.
- A complete redesign of tunnel/session architecture.
- New protocol features unrelated to hardening.

## Workstream 1: Make Network Exposure Explicit

### Problem

The server currently defaults to open egress when no `--allow` rules are configured. That makes Authunnel a general-purpose authenticated TCP pivot by default, including access to loopback, link-local, metadata, and internal control-plane destinations reachable from the server host.

### Desired outcome

The operator must make an explicit choice to run in broad-access mode. Least privilege should be the default posture.

### Proposed changes

- Change startup behavior so an empty allowlist is rejected by default.
- Introduce an explicit escape hatch for broad-access mode such as `--allow-open-egress` or similar.
- Keep the allowlist semantics simple and auditable.
- Consider a small built-in denylist even in explicit open mode for especially dangerous destinations if that can be done without surprising operators.
  Suggested examples for evaluation:
  `127.0.0.0/8`, `::1/128`, cloud metadata endpoints, link-local metadata ranges.
- Update README examples so deployment guidance leads with restrictive allowlists.

### Code touchpoints

- [internal/tunnelserver/allowlist.go](internal/tunnelserver/allowlist.go)
- [internal/tunnelserver/observability.go](internal/tunnelserver/observability.go)
- [server/server.go](server/server.go)
- [README.md](README.md)

### Acceptance criteria

- Server startup fails if no allowlist is configured and no explicit open-egress override is present.
- README documents the new default and migration path.
- Tests cover:
  startup rejection with no rules,
  explicit override behavior,
  existing allowlist matching behavior.

## Workstream 2: Fail Closed on Insecure Transport Configuration

### Problem

The current client and server configuration paths permit insecure schemes through ordinary flags. A mistaken `http://` issuer or `http://` tunnel endpoint would silently weaken the trust model while still looking like a normal deployment.

### Desired outcome

Insecure transports are rejected unless the operator intentionally opts in with clearly dangerous flags.

### Proposed changes

- Reject non-HTTPS OIDC issuers by default on both client and server.
- Reject non-HTTPS tunnel endpoint URLs by default on the client.
- If plaintext or insecure modes are needed for local development, require explicit flags such as:
  `--insecure-oidc-issuer`,
  `--insecure-tunnel-url`,
  or one tightly-scoped development flag.
- Keep reverse-proxy plaintext mode on the server, but make sure its documentation clearly distinguishes:
  backend plaintext behind trusted TLS termination,
  versus insecure public-facing transport.
- Audit error messages so configuration failures are obvious and specific.

### Code touchpoints

- [client/client.go](client/client.go)
- [client/auth.go](client/auth.go)
- [server/server.go](server/server.go)
- [README.md](README.md)

### Acceptance criteria

- `http://` issuer URLs are rejected by default.
- `http://` tunnel endpoint URLs are rejected by default.
- Any insecure exception path is explicit in both CLI and docs.
- Tests cover accepted secure forms and rejected insecure forms.

## Workstream 3: Strengthen Token Validation Semantics

### Problem

The current access-token validation path enforces signature, issuer, expiration, and audience, but does not appear to enforce the full validity window represented by `nbf` and `iat`. In addition, Authunnel uses `sub` as the tunnel identity anchor during refresh, so that dependency should be made explicit and validated if refresh continuity relies on it.

### Desired outcome

Token validation should match the intended security model:

- admission only for tokens valid now,
- predictable handling of future-dated or malformed time claims,
- explicit subject requirements if subject pinning is part of refresh security.

### Proposed changes

- Enforce `nbf` if present.
- Decide and document the `iat` policy:
  minimum option: reject tokens with `iat` meaningfully in the future,
  stricter option: also reject tokens missing `iat` if that aligns with supported IdPs.
- Decide and document the `sub` policy:
  if refresh subject pinning remains in place, require non-empty `sub` at admission time,
  otherwise rework refresh identity continuity so it does not silently rely on empty subjects.
- Keep audience enforcement explicit in Authunnel rather than delegating it to opaque library defaults.
- Avoid overly permissive clock-skew handling; make any skew allowance explicit and configurable if needed.

### Code touchpoints

- [internal/tunnelserver/tunnelserver.go](internal/tunnelserver/tunnelserver.go)
- Relevant upstream assumptions are currently exercised through:
  `github.com/zitadel/oidc/v3/pkg/op.VerifyAccessToken`

### Acceptance criteria

- A token with `nbf` in the future is rejected.
- A token with invalid future `iat` is rejected according to the chosen policy.
- Refresh identity continuity is documented and tested.
- Tests clearly distinguish:
  expiration failure,
  not-before failure,
  issued-at failure,
  audience failure,
  subject continuity failure on refresh.

## Workstream 4: Tighten Local Client Exposure

### Problem

The unix-socket mode currently tightens permissions after listen creation, and it tolerates pre-existing parent directories without validating that they are private enough. On shared hosts, that creates unnecessary local attack surface.

### Desired outcome

The local proxy endpoint should be safe-by-default on multi-user systems.

### Proposed changes

- Validate the socket parent directory before binding.
  Reject directories that are group/world writable unless ownership and sticky-bit semantics are intentionally supported and reviewed.
- Tighten the directory and socket creation story so there is no avoidable window between creation and permission hardening.
- Review stale-socket removal behavior to ensure it does not operate unsafely in untrusted directories.
- Review token-cache directory creation similarly; cache and lock paths should not live in unexpectedly permissive directories without warning or failure.
- Re-check Windows behavior separately rather than assuming POSIX semantics apply.

### Code touchpoints

- [client/client.go](client/client.go)
- [client/auth.go](client/auth.go)
- [client/flock_unix.go](client/flock_unix.go)
- [client/flock_windows.go](client/flock_windows.go)

### Acceptance criteria

- Unix-socket mode rejects clearly unsafe parent directories.
- Token cache handling is documented and tested for private permissions.
- New tests cover both safe and unsafe local filesystem setups where feasible.

## Workstream 5: Add Admission and Resource Limits

### Problem

The server currently admits authenticated tunnel upgrades without explicit controls on:

- total concurrent tunnels,
- concurrent tunnels per user,
- tunnel-open rate per user or source IP,
- concurrent in-progress outbound connects.

In addition, outbound TCP dials currently use a zero-timeout `net.Dialer`, so authenticated users can hold resources open by targeting blackholed or slow destinations.

### Desired outcome

The service should have predictable, auditable failure modes under load or abuse:

- no single user can monopolize tunnel capacity,
- total tunnel count is bounded,
- tunnel creation bursts are rate-limited,
- each outbound CONNECT attempt has a bounded failure mode.

### Proposed changes

- Add a global concurrent tunnel cap.
- Add a per-user concurrent tunnel cap keyed by the chosen stable principal identity.
- Add a tunnel-open rate limit, at minimum per user and possibly also per source IP.
- Reject over-limit requests before WebSocket upgrade whenever possible.
- Add an explicit dial timeout for outbound connects.
- Consider separate time budgets for:
  DNS resolution,
  TCP connect,
  total handshake.
- Consider a cap on concurrent in-progress outbound dials if simple dial timeouts are not sufficient.
- Add clear logs and metrics for limit-triggered rejection paths so operators can distinguish abuse from undersized limits.
- Keep the implementation straightforward; avoid introducing a large connection-management subsystem unless needed.

### Code touchpoints

- [internal/tunnelserver/tunnelserver.go](internal/tunnelserver/tunnelserver.go)
- [internal/tunnelserver/observability.go](internal/tunnelserver/observability.go)
- Possibly [server/server.go](server/server.go) for configuration plumbing if timeout values are exposed as flags.

### Acceptance criteria

- Tunnel admission fails cleanly when global or per-user limits are exceeded.
- Limit-triggered rejections are logged with enough context for operators to diagnose them.
- Blackholed destinations fail within the configured timeout.
- Existing successful CONNECT behavior still works.
- Tests cover:
  global concurrent limit behavior,
  per-user concurrent limit behavior,
  rate-limit behavior,
  dial-timeout behavior without becoming flaky.

## Workstream 6: Documentation and Operator Guidance

### Problem

Some current behavior is technically documented, but the docs do not yet reflect a hardened posture as the primary path.

### Desired outcome

The documentation should lead operators toward safer deployments by default.

### Proposed changes

- Rewrite the security posture section to distinguish:
  required guarantees,
  optional operator choices,
  known non-goals.
- Update all examples to use restrictive allowlists unless the example is specifically about open mode.
- Document insecure-development exceptions separately from production usage.
- Add a short “deployment hardening checklist” section.

### Code touchpoints

- [README.md](README.md)

### Acceptance criteria

- README examples match the implemented defaults.
- Security-sensitive flags are explained in terms of risk, not just mechanics.
- New contributors can infer the intended trust model from the docs alone.

## Suggested Delivery Order

1. Workstream 2: insecure transport rejection.
2. Workstream 3: token validation semantics.
3. Workstream 5: admission and resource limits.
4. Workstream 1: explicit network exposure choice.
5. Workstream 4: local client hardening.
6. Workstream 6: final documentation pass over the merged behavior.

This order front-loads the issues most likely to silently weaken the trust model, then adds admission controls once token identity semantics are settled so per-user limits have a clear basis.

## Suggested Task Breakdown

### Task A: Transport hardening ✓ done

- Add secure-scheme validation.
- Add tests for rejected insecure issuer and tunnel URLs.
- Update usage/help text.

### Task B: Token validation hardening ✓ done

- Enforce `nbf`.
- Decide and implement `iat` handling.
- Decide and implement `sub` requirements for refresh continuity.
- Add focused unit tests.

Implemented in [internal/tunnelserver/tunnelserver.go](internal/tunnelserver/tunnelserver.go):

- `validateStandardClaims` enforces non-empty `sub`, rejects `iat` meaningfully in the future (with a 30 s clock-skew allowance), and rejects tokens with `nbf > exp`.
- `checkTokenUsableBy` is a strict comparison used in two places: admission passes `time.Now() + tokenClockSkew` so IdP clock drift is tolerated at the wall-clock boundary; refresh passes the current enforced connection deadline (`exp + --expiry-grace`) unmodified, so a future-`nbf` token is only accepted if it activates at or before that operator-chosen policy point — the skew does not apply there.
- `iat` stays optional (the plan's "minimum option"); tokens omitting it are still accepted.

Tests: `TestValidateStandardClaims` and `TestCheckTokenUsableBy` cover the pure-claim checks and each failure mode; `TestTokenRefreshAcceptedFutureNbfWithinDeadline` and `TestTokenRefreshRejectedNbfAfterDeadline` exercise the refresh handover end-to-end. Existing refresh coverage (subject mismatch, expiry reduced, same-expiry) continues to pass unchanged.

### Task C: Admission and resource limiting ✓ done

- Add global concurrent tunnel limits.
- Add per-user concurrent tunnel limits.
- Add tunnel-open rate limiting.
- Add dial timeout and, if needed, in-progress dial caps.
- Add focused tests for rejection and timeout behavior.

Implemented as a single `Admitter` controller in [internal/tunnelserver/admission.go](internal/tunnelserver/admission.go), wired into the handler after token validation and before the WebSocket upgrade at [internal/tunnelserver/tunnelserver.go](internal/tunnelserver/tunnelserver.go):

- `AdmissionConfig` exposes `GlobalMax`, `PerUserMax`, `PerUserRate`, and `PerUserBurst`; zero values disable the corresponding control, so existing deployments keep today's behaviour until an operator opts in. Per-user state is keyed on the validated `sub` claim (Task B guarantees it is non-empty, so admission does not re-check).
- Rate limiting uses `golang.org/x/time/rate` with a cancel-on-deny pattern so failed attempts do not consume tokens.
- Rejections distinguish `global` (503 + `Retry-After`), `per_user` (429 + `Retry-After`), and `rate` (429 with delay derived from the token-bucket reservation). A single structured warn record per rejection (`event=tunnel_admission_denied`, `reason=...`, `subject`, `remote_ip`, `retry_after_ms`) lets operators distinguish abuse from undersized limits without adding a metrics dependency.
- Outbound SOCKS dials now use a bounded `net.Dialer.Timeout` threaded through `NewObservedSOCKSServer` at [internal/tunnelserver/observability.go](internal/tunnelserver/observability.go), removing the previous zero-timeout hole for blackholed destinations. Default is `10s`.
- Five new flags/envs in [server/server.go](server/server.go): `--max-concurrent-tunnels`, `--max-tunnels-per-user`, `--tunnel-open-rate`, `--tunnel-open-burst` (auto-derived from rate when unset), `--dial-timeout`. Burst without rate is a startup error.
- The client now captures `*http.Response` from `websocket.Dial` and returns a typed `tunnelDialError` carrying `StatusCode` and `Retry-After` at [client/client.go](client/client.go), so 401/429/503 surface as distinct operator-visible messages instead of the prior opaque `"websocket dial failed"`. Automatic retry/backoff is intentionally deferred to a separate PR.

Tests: `TestAdmit_*` in [internal/tunnelserver/admission_test.go](internal/tunnelserver/admission_test.go) cover the global cap, per-user cap, deterministic rate-limit behaviour (fake-clock), idle-user GC, bucket preservation on partial drain, idempotent release, and concurrent safety. `TestHandler_RejectsWhenGlobalCapExceeded` exercises the handler rejection path end-to-end; `TestObservedSOCKSDial_RespectsDialTimeout` verifies the dial timeout. Server config coverage in [server/server_test.go](server/server_test.go) verifies flag/env parsing, burst-from-rate derivation, and negative-value rejection. `TestDialTunnel_SurfacesAdmissionRejection` / `TestDialTunnel_SurfacesCapacityRejection` cover the client wrapper, and `TestE2E_GlobalTunnelCapRejects` / `TestE2E_PerUserTunnelCapRejects` in [client/oidc_e2e_test.go](client/oidc_e2e_test.go) exercise the full real-server + real-OIDC + real-client path.

Intentionally deferred: per-source-IP rate limiting, in-progress outbound dial cap (dial timeout + per-user cap already bound resource use), Prometheus metrics (structured warn logs are sufficient for v1), and automatic client-side retry/backoff on 429/503.

### Task D: Allowlist default posture ✓ done

- Change server startup rules around empty allowlists.
- Add explicit dangerous override if approved.
- Update README and startup tests.

Implemented in [server/server.go](server/server.go):

- `serverConfig.AllowOpenEgress` backs a new `--allow-open-egress` flag and `ALLOW_OPEN_EGRESS=true` env; the flag is documented under "egress posture" in the usage text and alongside `--allow` in the README flag reference.
- Startup validation enforces default-deny: an empty allowlist with no explicit opt-in returns `at least one --allow rule is required, or pass --allow-open-egress ...`. The combination of `--allow` rules and `--allow-open-egress` is rejected as `mutually exclusive`, so the active posture is always unambiguous in logs and config.
- At startup the server emits either `event=egress_mode_allowlist` (info, with rule count) or `event=egress_mode_open` (warn, with hint) so operators can see the posture in the same log stream as admission rejections.
- Built-in denylist for loopback/metadata in open mode was considered and deferred — the plan flags it as a "consider" item contingent on "without surprising operators", and a silent implicit denial of `127.0.0.1` would confuse anyone intentionally choosing `--allow-open-egress` for local-service tunnelling. Operators who want those denies can express them through explicit `--allow` policy.

Tests in [server/server_test.go](server/server_test.go): `TestParseServerConfigRejectsEmptyAllowlistByDefault`, `TestParseServerConfigAcceptsAllowOpenEgressFlag`, `TestParseServerConfigAcceptsAllowOpenEgressEnv`, `TestParseServerConfigAcceptsAllowRulesWithoutOpenEgress`, and `TestParseServerConfigRejectsAllowRulesWithOpenEgress` cover each branch of the new posture gate. A companion helper `minimalServerEnvWithRules` keeps the pre-existing `--allow`-based tests from inheriting the shortcut and tripping the new mutual-exclusion rule. README examples under "Start server", "Security Posture", and the Keycloak test-env section now demonstrate the explicit posture choice.

### Task E: Local client filesystem hardening

- Validate parent directory safety.
- Tighten socket and cache path behavior.
- Add local-permission tests.

### Task F: Documentation cleanup

- Reconcile README with final merged behavior.
- Add a hardening checklist and migration notes.

## Test Expectations

Every workstream should leave behind direct tests for the changed behavior. At minimum:

- unit tests for parsing and validation rules,
- handler tests for admission failures,
- tunnel longevity tests where refresh semantics change,
- end-to-end tests for any changed OIDC flow behavior,
- full-suite confirmation with:

```bash
go test ./...
```

## Contributor Requirements

All work on this plan must follow [AGENTS.md](AGENTS.md). Key obligations relevant to hardening changes:

- Update `README.md` when CLI flags, runtime flows, or architecture change.
- Keep code comments up to date when behavior changes.
- Add or update tests for every behavior change.
- Run `go test ./...` before finalising.

## Review Guidance

Because this repository is security-sensitive, each hardening PR should answer:

- What trust boundary changed?
- What unsafe behavior is now rejected?
- What operator-visible migration, if any, is required?
- What tests prove the new behavior?

Avoid broad rewrites. Prefer small, auditable PRs with one hardening intent each.

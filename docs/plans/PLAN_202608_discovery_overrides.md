# PLAN 2026-08: Server-side discovery overrides

Decouple *how the server locates issuer metadata* from *which issuer it trusts*, so that
Authunnel can validate tokens from authorization servers that do not publish OIDC discovery
at the derived well-known path, and can start when the IdP is unreachable.

## Problem

`NewJWTTokenValidator` (`internal/tunnelserver/tunnelserver.go:64`) consumes exactly one field
from discovery — `jwks_uri` — but reaches it through `client.Discover`, which hardcodes
`issuer + "/.well-known/openid-configuration"` and hard-fails on `doc.issuer != issuer`.
Three consequences:

1. **RFC 8414 path construction is unreachable.** An authorization server at
   `https://as.example/tenant1` publishes metadata at
   `https://as.example/.well-known/oauth-authorization-server/tenant1` — well-known *inserted*,
   not appended. A pure OAuth2 AS with a path component cannot be configured at all.
2. **Exact issuer-string equality is brittle.** A trailing slash, or an AS behind a reverse
   proxy advertising a different issuer, prevents startup.
3. **Startup hard-depends on IdP reachability.** Discovery runs once at boot inside
   `startupAuthTimeout` (`server/server.go:42`, wired at `server/server.go:266-273`) and
   `os.Exit(1)`s on failure. IdP down at deploy time means the server will not start, even
   though steady-state validation only needs a cached JWKS.

## Goals

- Let the operator point at an arbitrary metadata document URL **without** weakening the
  issuer↔metadata binding that makes discovery safe.
- Let the operator bypass discovery entirely by pinning `jwks_uri`, removing the startup
  dependency on the IdP.
- Keep the default path byte-for-byte unchanged.

## Non-goals

- The client-side equivalent (`client/auth.go:193`). Separate workstream; the client needs
  `authorization_endpoint` + `token_endpoint` and has a different failure model.
- RFC 9728 protected-resource metadata and `WWW-Authenticate` challenges. Larger piece of
  work, tracked separately — it removes configuration from the client rather than adding it
  to the server.
- **Automatic RFC 8414 fallback.** Deliberately rejected: probing a second well-known path
  doubles startup requests and makes *which document is authoritative* depend on network
  timing. An explicit flag is auditable; a fallback chain is not.
- Any `--insecure-skip-issuer-check` escape hatch. See "Security invariants".

## Proposed changes

### 1. New configuration

| Flag | Env | Meaning |
| --- | --- | --- |
| `--oidc-metadata-url` | `OIDC_METADATA_URL` | Explicit metadata document URL, overriding the derived well-known path. Document is still validated against `--oidc-issuer`. |
| `--oidc-jwks-uri` | `OIDC_JWKS_URI` | Pinned JWKS endpoint. Skips metadata discovery entirely. |

**Mutually exclusive with each other.** Setting both is a startup error, not a silent
precedence rule. This matches the existing posture for `--ip-block` / `--no-ip-block` and the
TLS mode selection: ambiguous configuration fails closed rather than resolving quietly.

**Neither is mutually exclusive with `--oidc-issuer`, which stays required in all three
modes.** `--oidc-issuer` does two jobs: it is the identity anchor enforced as `iss` on every
token by `op.NewAccessTokenVerifier` (`tunnelserver.go:81`), and it is the base for deriving
the discovery URL. These overrides replace only the second job. The first is irreducible:

- under `--oidc-metadata-url` the issuer does *more* work than in the default path — it is
  both the `iss` enforcement value and the cross-check against `doc.issuer` inside
  `client.Discover`. Dropping it would delete the mix-up defence that justifies the override.
- under `--oidc-jwks-uri` there is no document to cross-check, so `iss` enforcement is the
  only thing binding tokens to an issuer at all. Without it the server would accept a token
  from *any* issuer whose signature verified against the pinned key set.

So the existing requirement at `server/server.go:729-731` is unchanged. This is a no-op in
code and therefore needs an explicit test — "if the JWKS is pinned, why is the issuer still
required?" is a plausible future simplification, and it would be a silent security
regression.

Empty string means unset, consistent with the other string flags.

Two adjacent constraints considered and **rejected**:

- *Relaxing the `https://` requirement on `--oidc-issuer` in pinned-JWKS mode*, on the grounds
  that the issuer URL is never dereferenced there. RFC 8414 §2 requires an issuer to be an
  https URL regardless of how its metadata is located, and making a security check
  conditional on an unrelated flag is more confusing than the mild redundancy.
- *Requiring (or warning when) the metadata/JWKS host differs from the issuer host.* This
  would break real deployments: Google's issuer is `accounts.google.com` while its JWKS is
  served from `www.googleapis.com`. Cross-host key sets are normal, and the `doc.issuer`
  check already covers the case that matters.

### 2. Validation (`parseServerConfig`, alongside `server/server.go:729-741`)

For each of the two new values, when non-empty:

- Must parse via `url.Parse` with a non-empty `Host` — same shape as the existing issuer
  check at `server/server.go:732-735`.
- Must be `https://` unless `--insecure-oidc-issuer` / `INSECURE_OIDC_ISSUER=true` is set.
- Any other scheme — notably `file://` — is rejected explicitly, with an error naming the
  scheme rather than the generic "not a valid URL". See "Decision: no `file://` JWKS".

Reuse the existing insecure flag rather than adding per-URL variants. An operator pointing at
a local Keycloak over plain HTTP wants all three URLs relaxed together, and the alternative is
three near-identical insecure flags. Update the flag's help text (`server/server.go:517-518`)
from "OIDC issuer URL" to cover the issuer, metadata and JWKS URLs.

### 3. Validator API

`NewJWTTokenValidator` currently takes four positional arguments; adding two more strings
would make five consecutive strings at the call site. Introduce a config struct, matching the
existing `AdmissionConfig` idiom:

```go
type JWTValidatorConfig struct {
    Issuer      string // required; the iss value enforced on every token
    Audience    string // required
    MetadataURL string // optional; overrides the derived well-known path
    JWKSURI     string // optional; skips discovery entirely
    HTTPClient  *http.Client
}
```

Resolution inside the constructor:

- `JWKSURI != ""` → skip discovery, go straight to `rp.NewRemoteKeySet`.
- otherwise → `client.Discover(ctx, cfg.Issuer, cfg.HTTPClient, cfg.MetadataURL)`. The
  variadic `wellKnownUrl` parameter already exists in zitadel v3.49.2 and is ignored when
  empty, so the default path needs no branching.
- The existing `discovery.JwksURI == ""` guard (`tunnelserver.go:75`) stays.

`op.NewAccessTokenVerifier(cfg.Issuer, keySet)` is unchanged in both branches.

**Migration cost:** 9 mechanical call-site edits — `server/server.go:268`, plus
`server/server_test.go` (7) and `client/keycloak_e2e_test.go:57`,
`client/oidc_e2e_test.go:447`. No behavioural change to any of them.

### 4. Startup observability

Emit a structured line recording which mode resolved, using the existing snake_case event
naming (`tls_key_file_unsafe`, `server_exited`):

- `token_validator_ready` with `discovery_mode` of `derived` | `metadata_url` | `pinned_jwks`.
- When `pinned_jwks`, log at warn level. Bypassing discovery is a deliberate reduction in
  what the server verifies for itself, and it should be visible in the log without diffing
  the deployment config.

## Security invariants

These are the load-bearing parts of the design; reviewers should check them specifically.

**Metadata URL does not weaken the issuer binding.** Routing through `client.Discover` keeps
zitadel's `doc.issuer == cfg.Issuer` check, which is what defends against a mix-up attack
where an attacker-influenced metadata URL hands back another AS's `jwks_uri`. The operator
chooses the *transport*; the document must still self-identify as the configured issuer.
This is why there is no skip-issuer-check flag — that would remove the only thing making the
override safe.

**Pinned JWKS is an operator assertion, and that is acceptable.** No metadata document exists
to cross-check, so the issuer↔keys binding comes from the operator. It stays safe because
every token still has `iss` verified against `cfg.Issuer` by the Zitadel verifier, `aud`
checked at `tunnelserver.go:97`, and the claim checks at `tunnelserver.go:100` applied
unchanged. The pinned URL is configuration from the same trust domain as `--oidc-issuer`
itself.

**Key rotation still works.** `rp.NewRemoteKeySet` caches and refetches on an unknown `kid`,
so pinning `jwks_uri` does not freeze the key material — only the endpoint.

**No transport downgrade on the key path** — *added during review; this plan originally missed
it.* The metadata document names the JWKS endpoint, so an https document advertising an
`http://` `jwks_uri` would put signing keys on the wire in clear text, where a network attacker
can substitute them and mint tokens that verify. Redirects are the same exposure by another
route: Go follows a cross-scheme redirect silently (verified — an https endpoint redirecting to
`http://` is followed without complaint). Two guards, both in `NewJWTTokenValidator`:
`checkNoSchemeDowngrade` rejects a resolved `jwks_uri` less protected than the document that
named it, and `refuseTransportDowngrade` wraps the HTTP client with a `CheckRedirect` that
refuses to leave https on either the metadata or the JWKS fetch.

The rule is judged against the scheme the *metadata itself* was fetched over rather than a new
config flag: if metadata already travelled in clear text there is no downgrade left to prevent,
and that case is exactly the local development setup `--insecure-oidc-issuer` already gates. That
choice also kept the fix from re-touching every existing test, which all use `http` issuers.

Note this exposure predates this plan — the previous code passed `discovery.JwksURI` to
`NewRemoteKeySet` unchecked in the same way. The overrides widen the reachable surface (the
operator now chooses which document is authoritative), which is what surfaced it.

**Tradeoff to document, not fix.** In `pinned_jwks` mode the constructor makes no network
call, so `startupAuthTimeout` is moot and the server starts with the IdP down — the stated
goal. The cost is that a wrong JWKS URL surfaces on the first protected request rather than
at boot. That is the correct trade for this mode, but it must be in the docs.

## Decision: no `file://` JWKS

`--oidc-jwks-uri` accepts `https://` (and `http://` under the insecure flag) only. Loading a
JWKS from disk is a reasonable thing to want — air-gapped sites, or a Kubernetes pod with a
ConfigMap-mounted key set and no egress at all — but overloading this flag's scheme is the
wrong way to get it.

**It does not work today, and fails late.** Go's default `http.Transport` rejects `file://`
with `unsupported protocol scheme "file"`. In pinned-JWKS mode the constructor makes no
network call, so an operator who sets a `file://` URI gets a clean startup and then a hard
failure on the first protected request.

**Making it work would hand a hostile issuer a local file read.** The only way to route
`file://` through `rp.NewRemoteKeySet` is `Transport.RegisterProtocol("file", …)` on the
client from `internal/authhttp` — which is shared by the server validator *and* the managed
client's discovery and token traffic. Registering the scheme makes it reachable from every
URL that transport handles, including redirect targets. Verified against Go's client: with
`file://` registered, an HTTPS endpoint returning `302 Location: file:///etc/hosts` is
followed and the file contents are returned as the response body. Narrowing the blast radius
would mean a second, separately-configured transport — at which point the shared-client
invariant in `internal/authhttp`'s package doc no longer holds.

**Rotation semantics differ enough to deserve a distinct flag.** Over HTTP, an IdP signing-key
rotation self-heals: `rp.NewRemoteKeySet` refetches on an unrecognised `kid`. Backed by a
static file it does not — rotation becomes a full authentication outage that presents as
"auth suddenly broke" rather than as anything obviously configuration-shaped. One flag whose
failure modes fork on URL scheme is a bad affordance.

**If a deployment genuinely needs it**, add a separate `--oidc-jwks-file` taking a filesystem
path, with its own code path that never touches the HTTP client. This is cheap: `oidc.KeySet`
is a one-method interface (`VerifySignature`), and `oidc.GetKeyIDAndAlg` and
`oidc.FindMatchingKey` are exported, so a static key set backed by a parsed
`jose.JSONWebKeySet` is on the order of 30 lines. It should re-read the file on an unknown
`kid` rather than parsing once at startup, so a ConfigMap update propagates without a restart
and most of the self-healing property is recovered. Deferred until a real deployment needs
it; the explicit scheme rejection above is what keeps the door open unambiguously.

## Test plan

**`server/` — config parsing.** Extend the existing `parseServerConfig` table tests:

- each flag and its env var, independently and with flag-over-env precedence;
- both set → error;
- `--oidc-issuer` omitted while either override is set → still an error, for each override
  independently. Pins the invariant that the overrides replace metadata *location* only.
- non-URL and host-less values → error;
- `http://` rejected by default, accepted under `--insecure-oidc-issuer`;
- `file:///path/to/jwks.json` rejected, with the scheme named in the error — and rejected
  under `--insecure-oidc-issuer` too, since that flag relaxes transport security, not the
  set of permitted schemes;
- neither set → resolved config identical to today.

**`internal/tunnelserver/` — validator behaviour.** Build on the `httptest` + `jose` helpers
already in `auth_bounds_test.go`:

- metadata served at a *non*-derived path (e.g. `/.well-known/oauth-authorization-server/tenant1`)
  resolves when `MetadataURL` points at it, and fails without it;
- **metadata document whose `issuer` disagrees with `cfg.Issuer` is rejected** — the key
  security test; assert this holds via the override path, not just the default one;
- an RFC 8414-shaped document carrying only `issuer` / `jwks_uri` / `authorization_endpoint` /
  `token_endpoint` unmarshals into `oidc.DiscoveryConfiguration` and yields a working
  validator;
- `JWKSURI` set → a counting handler on the metadata path records **zero** requests, and a
  token signed by the pinned key set validates end-to-end;
- `JWKSURI` set and the metadata endpoint returning 500 → validator still constructs.

## Documentation

- ~~`README.md:187` — add both flags to the server flag list.~~ **Wrong as planned, and the
  correction was initially wrong too.** Line 187 is in the *client* flag list, and AGENTS.md
  scopes README to "the security posture and client usage" with the server flag reference in
  DEPLOYMENT.md — so no flag-list change belonged there. But README also makes *architectural
  and security claims* that pinned-JWKS mode falsifies: "performs OIDC discovery once at
  startup" (server flow), "uses OIDC discovery to locate the issuer's JWKS endpoint" (workflow),
  and "server startup wraps OIDC discovery in a 30-second context, so a misconfigured issuer
  surfaces as a fast error" (security posture). Those were updated to describe all three modes.
  The lesson: "which file documents flags" and "which file makes claims this change falsifies"
  are separate questions, and only the first was asked.
- `server/server.go` `serverUsage` — **missed by this plan.** The server has a hand-maintained
  `--help` block separate from the `flag` package's own descriptions; both need the new entries,
  and `--insecure-oidc-issuer` needed its wording updated in both places.
- `docs/DEPLOYMENT.md` — full flag + env documentation, with the mutual exclusion and the
  startup-resilience tradeoff stated explicitly.
- `docs/DEPLOYMENT.md` hardening checklist — added, keyed to the `discovery_mode` field of the
  `token_validator_ready` startup line so the check is something an operator can actually read
  off a running server rather than infer from deployment config.
- `docs/DEVELOPMENT.md` — note that a local non-OIDC AS can be targeted with
  `--oidc-metadata-url`, and that neither override accepts `file://`.

## Sequencing

1. ✓ done — `JWTValidatorConfig` refactor + call-site migration, no new behaviour.
2. ✓ done — `MetadataURL` plumbing and tests.
3. ✓ done — `JWKSURI` plumbing, startup log line, and tests.
4. ✓ done — Docs.

Steps 2 and 3 are independent of each other and can land in either order.

## Outcome

Delivered as planned, with three deviations worth recording:

- **`NewJWTTokenValidator` returns a third value**, `DiscoveryMode`, rather than the caller
  re-deriving the mode from its own config. This keeps the "which path did we actually take"
  answer with the code that took it, which matters because the warn-vs-info decision on the
  startup log hangs off it.
- **The two documentation corrections above.**
- **`validateAuthURL` checks scheme before host.** `url.Parse("file:///path")` yields an empty
  host, so a host-first order would report `file://` as a malformed URL and never reach the
  scheme branch — the specific error the plan called for would have been unreachable.

Verification beyond `go test ./...`, run against the built binary:

- pinned JWKS with an unresolvable issuer starts and logs `discovery_mode=pinned_jwks` at warn;
  the same config in derived mode refuses to start, so the startup-resilience claim rests on an
  observed contrast rather than on the absence of a call;
- RFC 8414 metadata at a non-derived path: 404 without the override, `metadata_url` with it;
- the issuer binding was checked as a controlled pair against one metadata URL — matching
  issuer starts, mismatched issuer fails with `issuer does not match` — so the rejection is
  attributable to the mismatch and not to an unrelated fetch failure;
- `file://` refused with `--insecure-oidc-issuer` set, and both overrides together refused.

Findings from review after the above was written, all now fixed:

- **P1, JWKS transport downgrade** — see "Security invariants". Four tests in
  `discovery_override_test.go` cover it, using a plaintext mirror of the correct key set as the
  redirect target so a failure is attributable to the transport rather than to a missing key,
  plus an https-to-https control so the rejection is not just "TLS is broken in this test".
- **P2, stale README claims** — see "Documentation".
- **P2, injected redirect policy discarded** — `refuseTransportDowngrade` replaced
  `base.CheckRedirect` outright, so a caller that rejected cross-host or all redirects would
  silently start following them. It now layers: cap, then downgrade check, then delegate to the
  inherited callback when non-nil. The composed policy is the caller's AND ours, which can only
  be more restrictive than either alone. The cap stays unconditional so the auth path is bounded
  even when a caller's own policy has no ceiling — a stated contract rather than an accident. No
  caller in-tree sets `CheckRedirect` today, so this was latent, but the API is exported.
- **P2, "no further calls to the issuer" was false** — my own DEPLOYMENT prose claimed validation
  makes no issuer calls after startup, while a bullet twelve lines below described refetch-on-
  unknown-`kid`. Reading `rp.NewRemoteKeySet` settled it: construction stores only the URL, the
  first fetch happens on the first token verified, an unmatched `kid` forces a fetch, and there is
  no TTL, negative cache, or backoff — only in-flight coalescing. Corrected, and turned into the
  operational statement it should always have been: **the process needs outbound access to the
  JWKS endpoint for its whole lifetime, not just at startup.** Egress rules scoped to a startup
  window fail later, at the first rotation, looking like a token problem rather than a network
  one. The unrecognised-`kid` path also means junk tokens drive outbound fetches, which is a
  reason `--preauth-rate` matters; noted there. The same implication was corrected in README, in
  `docs/Notes.md`, and in the `NewJWTTokenValidator` doc comment, which had said tokens verify
  "locally against that key set" without noting the key set is fetched lazily.
- **P2, stale `JWTTokenValidator` type comment** — it still said tokens are validated "against
  issuer discovery and the issuer's JWKS", which under `pinned_jwks` describes something that
  did not happen. The audit risk is specific: a reader would assume the issuer-to-keys binding
  was *discovered* when it was *asserted*. Rewritten to distinguish the two and to state the part
  that does not vary — the verifier pins the configured issuer, so a pinned key set widens which
  keys are trusted, never which issuer is. This comment had been read and consciously left alone
  earlier in the work as "still broadly accurate"; it was not.
- **Sweep for the same class of defect** rather than waiting for it to be reported again. Two
  more found: `startupAuthTimeout`'s comment claimed to bound discovery without noting it bounds
  nothing under `--oidc-jwks-uri` and never bounded the lazy JWKS fetch in any mode; and
  `InsecureOIDCIssuer`'s field comment still described it as issuer-only.
- **P3, README over-claiming** — the fix was not only to correct the wording. README had grown a
  mode-by-mode description that duplicated DEPLOYMENT and would drift again on the next change.
  The detail now lives in one place, `docs/DEPLOYMENT.md` § "Issuer metadata and key discovery",
  with README reduced to a one-line accurate claim plus a link. The transport-downgrade bullet is
  also now explicitly scoped to the server validator, since the managed client is not covered.

Not done, unchanged from the non-goals: the client-side equivalent (`client/auth.go`) and
RFC 9728 protected-resource metadata. **The client shares
`internal/authhttp.NewBoundedClient` and fetches its own metadata and token endpoints without
the downgrade guard, which now lives in `tunnelserver`.** Worth considering whether that guard
belongs in `authhttp` so both sides inherit it — deliberately out of scope here rather than
overlooked.

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

- `README.md:187` — add both flags to the server flag list.
- `docs/DEPLOYMENT.md:102` — full flag + env documentation, with the mutual exclusion and the
  startup-resilience tradeoff stated explicitly.
- `docs/DEPLOYMENT.md:173` hardening checklist — add: prefer discovery; if `--oidc-jwks-uri`
  is set, confirm the URL belongs to the configured issuer, since the server can no longer
  verify that for itself.
- `docs/DEVELOPMENT.md:100,114` — no change required, but worth a note that a local
  non-OIDC AS can now be targeted with `--oidc-metadata-url`.

## Sequencing

1. `JWTValidatorConfig` refactor + call-site migration, no new behaviour. Reviewable alone.
2. `MetadataURL` plumbing and tests.
3. `JWKSURI` plumbing, startup log line, and tests.
4. Docs.

Steps 2 and 3 are independent of each other and can land in either order.

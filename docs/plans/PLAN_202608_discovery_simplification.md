# PLAN 2026-08: Discovery hardening simplification

Follow-up to [the server discovery plan](PLAN_202608_discovery_overrides.md) and
[the client discovery plan](PLAN_202608_client_discovery.md). Those changes are
functionally sound, but their implementation and explanation grew beyond what
is needed to keep the behavior auditable. This plan preserves the production
security properties while reducing duplicated policy, comments, tests, and
historical narrative.

## Outcome

Keep the three server discovery modes, with a clearer production purpose:

| Server mode | Production purpose | Required server egress |
| --- | --- | --- |
| `derived` | Default OIDC discovery rooted at the issuer | issuer metadata at startup; discovered JWKS for the process lifetime |
| `metadata_url` | Interoperability with a provider whose metadata is not at the derived OIDC path | configured metadata URL at startup; discovered JWKS for the process lifetime |
| `pinned_jwks` | Least-privilege resource-server isolation: validate JWTs without granting the server access to discovery, authorization, or token endpoints | configured JWKS endpoint for the process lifetime |

`pinned_jwks` is a **server-only** feature. The managed client still needs
metadata, authorization, and token endpoints to obtain credentials and must not
gain endpoint-pinning flags.

[Google demonstrates](https://developers.google.com/identity/openid-connect/openid-connect#discovery)
the useful host separation: its discovery document is at `accounts.google.com`,
while the current document advertises a JWKS endpoint at
`www.googleapis.com/oauth2/v3/certs`. A deployment can therefore deny the
Authunnel server access to the discovery host while allowing the key endpoint.
The exact endpoint remains operator configuration and must be checked against
the provider's current documentation before deployment.

Starting under `pinned_jwks` without a network call is a secondary property,
not an availability guarantee. The key cache is in-memory and initially empty,
so the first authenticated request and later key rotations still require the
JWKS endpoint to be reachable.

## Goals

- Preserve pinned JWKS as a least-privilege server-egress control.
- Preserve metadata overrides where a concrete authorization server requires
  them, without presenting client/server symmetry as a reason by itself.
- Keep HTTPS-by-default and downgrade refusal on metadata, JWKS, and token
  traffic.
- Make the discovered-endpoint invariant a single operation so callers cannot
  apply only half of it.
- Remove review history and repeated threat-model prose from production code.
- Make `docs/DEPLOYMENT.md` the canonical operational and security explanation;
  keep README and development guidance short and linked to it.
- Retain regression coverage for externally observable behavior while reducing
  repeated fixtures, assertions, and explanatory comments.

## Non-goals

- Removing `--oidc-jwks-uri` or changing its command-line/environment contract.
- Adding client-side authorization or token endpoint pinning.
- Persisting JWKS keys across server restarts.
- Adding token introspection, revocation checks, or a new discovery library.
- Weakening HTTPS requirements or permitting `file://` and custom schemes.
- Preventing HTTPS-to-HTTPS redirects. A request rooted at the issuer's
  authenticated HTTPS origin may follow an authenticated delegation; comments
  must not claim the final document necessarily came from the issuer's host.
- Broad production refactors unrelated to discovery and auth transport.

## Security invariants

The cleanup is behavior-preserving. These properties must remain true:

1. Operator-supplied issuer, metadata, and JWKS URLs use `https://` unless the
   explicit development-only insecure flag is set.
2. A metadata-advertised endpoint is an absolute `http(s)` URL with a host.
3. Metadata fetched from an HTTPS-rooted chain cannot advertise a plaintext
   endpoint, and metadata, JWKS, and token requests cannot redirect from HTTPS
   to plaintext.
4. Redirect policy supplied by an injected HTTP client remains in force; the
   Authunnel downgrade rule composes with it rather than replacing it.
5. The server always enforces the configured issuer as the token `iss` claim
   and the configured audience as `aud`, in every discovery mode.
6. In `pinned_jwks`, the operator is responsible for the issuer-to-key-endpoint
   binding. TLS authenticates the configured JWKS host; it does not prove that
   the host is authorized to sign for the configured issuer.
7. The client token-cache identity includes the metadata URL because it affects
   the destination to which a cached refresh token may be sent.
8. A client-side unsafe-transport refusal remains terminal and does not fall
   through to an interactive login using the same endpoint.
9. The plaintext PKCE loopback callback remains deliberately outside these
   rules.

## Workstream 1: Correct the production narrative

### Changes

- Reframe `--oidc-jwks-uri` in `README.md`, `docs/DEPLOYMENT.md`, server help,
  startup comments, and configuration comments:
  - primary purpose: restrict the resource server to JWKS-only egress;
  - secondary property: no metadata request during startup;
  - explicit limitation: no persistent keys, so JWKS is required on the first
    authenticated request and during rotation.
- Replace statements that derived discovery "fetches from the issuer's own
  host" with the precise property: the discovery chain is rooted at the
  issuer's authenticated HTTPS origin. Same-scheme redirects may delegate the
  final fetch to another HTTPS host.
- Add a compact server egress table to `docs/DEPLOYMENT.md`. Include the client
  separately so operators do not infer that pinning removes the client's need
  for discovery, authorization, and token traffic.
- Explain the boundary of network enforcement:
  - Authunnel itself requests only the configured JWKS URL in pinned mode;
  - a hostname-level firewall rule may grant more access than that single URL;
  - large providers may use shared or changing infrastructure, so strong
    restriction is better implemented with an egress proxy capable of hostname
    and, where available, path policy rather than static provider IPs.
- Keep provider endpoints illustrative and link to authoritative provider
  documentation rather than treating copied endpoint values as permanent.

### Acceptance

- No document describes `pinned_jwks` as continued authentication availability
  while JWKS is unreachable.
- A production operator can determine every required outbound connection from
  one table.
- README summarizes the posture and links to deployment guidance instead of
  duplicating it.

## Workstream 2: Consolidate discovered-endpoint validation

### Problem

Every discovered endpoint must pass two checks:

1. it is an absolute `http(s)` URL with a host; and
2. it is not a downgrade from the metadata source.

The current API exports these as `CheckEndpointURL` and
`CheckNoSchemeDowngrade`, then relies on every caller remembering to invoke both
in the correct order. Comments and tests repeatedly explain why they must stay
paired.

### Changes

- Introduce one exported operation with a name such as:

  ```go
  func CheckDiscoveredEndpoint(label, metadataSource, endpoint string) error
  ```

- Have it perform the shape/scheme check first and the relative downgrade check
  second.
- Make the lower-level helpers private unless a remaining caller genuinely
  needs one independently.
- Update the server JWKS resolution and the client's authorization/token
  endpoint loop to use the combined operation.
- Keep `CheckConfiguredURL` separate: configured URLs have an absolute HTTPS
  requirement controlled by `--insecure-oidc-issuer`, while discovered URLs are
  evaluated relative to their metadata source.
- Preserve `ErrUnsafeTransport`; it carries behavior used by the client to
  distinguish a terminal refusal from a refresh-token rejection.
- Keep redirect-policy composition and injected-client protection unchanged.
  Do not add machinery merely to avoid the harmless double wrapping of the
  default client; that cure would be more complex than the duplication.

### Acceptance

- There is one public call for validating a metadata-advertised endpoint.
- Server and client cannot accidentally omit either validation rule.
- Error messages still identify the metadata field and unsafe URL.
- `errors.Is(err, authhttp.ErrUnsafeTransport)` remains true for Authunnel's
  malformed, unsafe-scheme, downgrade, and redirect-limit refusals.

## Workstream 3: Reduce production comments

### Changes

- Remove phrases such as "an earlier version", "during review", and accounts of
  rejected approaches from production `.go` files.
- Keep comments local and invariant-focused:
  - what trust/configuration a field represents;
  - what credential or key material crosses the boundary;
  - why a non-obvious check or branch must remain.
- Condense the `JWTTokenValidator`, `JWTValidatorConfig`, `tokenCache`, redirect
  guard, and unsafe-error comments. Point to `docs/DEPLOYMENT.md` for the full
  threat model.
- Avoid repeating the same issuer/metadata self-assertion explanation on the
  config struct, runtime struct, cache struct, constructor, README, development
  guide, and both historical plans.

### Acceptance

- A maintainer can understand each security-sensitive function in one reading
  without reading a review transcript embedded in its comments.
- Removing commentary does not remove protocol or security rationale required
  to audit byte-, credential-, or trust-boundary behavior.

## Workstream 4: Compact tests without weakening them

### Tests to retain explicitly

- configured HTTP auth URLs rejected by default and accepted only under the
  development override;
- non-HTTP schemes and host-less discovered endpoints rejected in every mode;
- HTTPS metadata advertising a plaintext JWKS, authorization, or token endpoint
  rejected;
- metadata, JWKS, and credential-bearing token requests refuse HTTPS-to-HTTP
  redirects;
- the token redirect test uses 307 or 308 and proves the plaintext mirror
  received no credential;
- injected clients retain both their own redirect policy and Authunnel's
  downgrade guard;
- derived, metadata URL, and pinned JWKS server modes resolve correctly;
- pinned JWKS makes no startup request but fetches on first token validation;
- metadata override issuer mismatch is rejected;
- changing metadata URL invalidates an existing token cache before refresh;
- legacy caches without `metadata_url` continue to work on the derived path.

### Reductions

- Convert repeated config-parser cases to table-driven tests.
- Reuse server/client test helpers where doing so makes the scenario clearer;
  do not create a new production package solely for test reuse.
- Collapse duplicate tests that assert the same helper behavior at multiple
  layers, while retaining at least one production-wiring test for each injected
  client or config-to-runtime mapping seam.
- Shorten test comments to state the security property and why the fixture
  proves it. Remove mutation-testing history and accounts of earlier broken
  fixture versions.

### Acceptance

- Each invariant above has a direct regression test.
- The working-mirror controls still prove refusals occur before plaintext
  destinations receive requests.
- Test line reduction is not accepted if it makes failures ambiguous or removes
  coverage of production wiring.

## Workstream 5: Consolidate documentation and completed plans

### Changes

- Make `docs/DEPLOYMENT.md` canonical for:
  - discovery modes and required egress;
  - trust differences between derived, overridden metadata, and pinned JWKS;
  - auth-path transport rules;
  - production TLS requirements.
- Keep `docs/DEVELOPMENT.md` to concise invariants and testing guidance.
- Keep README to user-facing behavior and links.
- Replace the two completed discovery plan documents with short implemented
  decision summaries, or remove them after extracting any still-useful rationale
  into this plan and deployment documentation. Git retains the full history.
- Do not preserve crossed-out reasoning or chronological review notes in the
  maintained documentation set.

### Acceptance

- Every detailed security claim has one canonical maintained location.
- Links replace copied multi-paragraph explanations elsewhere.
- The maintained plan/document footprint is materially smaller without losing
  current operational requirements or rejected decisions that remain likely to
  recur.

## Sequencing

Keep the work reviewable as small behavior-preserving changes:

1. Correct pinned-JWKS purpose, availability wording, and the production egress
   matrix.
2. Add the combined discovered-endpoint validator and migrate both callers.
3. Compact the corresponding unit and integration tests.
4. Reduce production comments, with documentation links added in the same
   commit so rationale is not temporarily lost.
5. Consolidate README, development guidance, and the completed discovery plans.

Do not mix removal of a discovery mode or CLI flag into this cleanup. If a
metadata override later lacks a concrete production consumer, remove it in a
separate compatibility-reviewed change.

## Verification

Run after every behavior-affecting step:

```bash
gofmt -w <changed-go-files>
go test ./...
go vet ./...
make build
```

Before finalizing, also inspect the diff for accidental policy changes:

- all three server discovery modes still parse and log distinctly;
- server pinned mode performs no metadata request;
- client has no pinned endpoint option;
- all configured production auth URLs still require HTTPS;
- every metadata-advertised endpoint uses the combined validator;
- every auth HTTP client still has the redirect guard, including injected
  clients;
- cache identity still includes metadata URL.

## Completion criteria

- Production behavior and CLI compatibility are unchanged.
- Pinned JWKS is documented primarily as JWKS-only server egress, with its
  runtime reachability requirement explicit.
- The discovered-endpoint policy has one public entry point.
- Historical review narrative is removed from production code and maintained
  documentation.
- Duplicated documentation and test scaffolding are materially reduced.
- Full tests, vet, and build pass.

# Implemented decision: server discovery overrides

Status: implemented. Operational guidance is maintained in
[DEPLOYMENT.md](../DEPLOYMENT.md#issuer-metadata-and-key-discovery).

## Decision

The server supports three mutually exclusive ways to locate signing keys:

- derive OIDC metadata from `--oidc-issuer`;
- fetch metadata from `--oidc-metadata-url` / `OIDC_METADATA_URL`;
- use `--oidc-jwks-uri` / `OIDC_JWKS_URI` directly.

`--oidc-issuer` and the token audience remain required in every mode. An
override changes where keys are located; it does not change the `iss` or `aud`
claims enforced on tokens.

The metadata override provides interoperability with providers whose metadata
is not at the derived OIDC path. The pinned-JWKS mode is a server-side
least-privilege control: a resource server can be allowed to reach the public
key endpoint without being allowed to reach discovery, authorization, or token
endpoints.

Pinned JWKS does not make authentication independent of the network. Keys are
cached in memory and fetched lazily, so the JWKS endpoint must be reachable for
the first authenticated request and later key rotations.

## Security properties

- Configured auth URLs require HTTPS unless the development-only insecure flag
  is set; non-HTTP schemes remain forbidden.
- A metadata document must advertise the configured issuer exactly.
- Advertised `jwks_uri` values must be absolute HTTP(S) URLs with a host and
  may not downgrade an HTTPS metadata source to HTTP.
- Metadata and JWKS fetches refuse HTTPS-to-HTTP redirects while preserving a
  caller-supplied redirect policy.
- In pinned mode, the operator owns the issuer-to-key-endpoint binding. TLS
  authenticates the configured endpoint, not its authority for the issuer.

## Rejected alternatives

- Automatic RFC 8414 fallback: explicit metadata configuration is more
  deterministic and auditable than probing multiple documents.
- `file://` JWKS loading: the flag is deliberately a bounded HTTP(S) endpoint,
  not a general key-source abstraction.
- Removing the issuer in pinned mode: signature verification alone would no
  longer constrain the token's claimed issuer.
- Requiring the metadata/JWKS host to equal the issuer host: cross-host key
  publication is valid and used by major providers.

The follow-up cleanup is recorded in
[PLAN_202608_discovery_simplification.md](PLAN_202608_discovery_simplification.md).

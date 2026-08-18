# Implemented decision: client metadata and transport rules

Status: implemented. Operational guidance is maintained in
[DEPLOYMENT.md](../DEPLOYMENT.md#transport-rules-on-the-auth-path).

## Decision

The managed client accepts `--oidc-metadata-url` for authorization servers
whose metadata is not at the path derived from `--oidc-issuer`. The configured
issuer remains the expected identity, and the metadata document must advertise
that exact issuer.

The client does not accept pinned authorization or token endpoints. Unlike the
server's read-only JWKS endpoint, the token endpoint receives authorization
codes and refresh tokens. A typo, stale value, or compromised configuration
could disclose credentials rather than merely reject authentication.

Changing the metadata URL changes token-cache identity and forces a fresh
login. This prevents an existing refresh token from being silently sent to a
newly configured endpoint. Legacy caches without a metadata URL remain valid
for the default derived path.

## Security properties

- Configured issuer and metadata URLs require HTTPS unless the explicit
  development-only insecure flag is set.
- Advertised authorization and token endpoints must be absolute HTTP(S) URLs
  with a host.
- HTTPS metadata may not advertise plaintext endpoints.
- Metadata, JWKS, refresh, and code-exchange requests refuse HTTPS-to-HTTP
  redirects, including 307/308 redirects that preserve credentials in a POST.
- Authunnel's redirect guard composes with an injected client's redirect
  policy.
- Unsafe-transport failures are terminal; the client does not respond by
  opening a browser and retrying the same unsafe endpoint.
- The plaintext PKCE callback is limited to loopback and is intentionally
  outside the remote auth transport rule.

## Rejected alternatives

- Pinned client endpoints: the operational benefit is narrower than on the
  server and the credential-destination risk is substantially higher.
- Treating issuer equality as proof that an arbitrary metadata host is trusted:
  the document supplies its own issuer field, so operators must trust an
  explicit metadata URL as much as the issuer.
- Allowing custom or `file://` schemes under the insecure flag: that flag
  relaxes transport encryption for local development only.

The follow-up cleanup is recorded in
[PLAN_202608_discovery_simplification.md](PLAN_202608_discovery_simplification.md).

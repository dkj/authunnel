# PLAN 2026-08: Removing client configuration

Third in the sequence after [PLAN_202608_discovery_overrides.md](PLAN_202608_discovery_overrides.md)
(server) and [PLAN_202608_client_discovery.md](PLAN_202608_client_discovery.md) (client). Both of
those *added* configuration and both named RFC 9728 protected-resource metadata as the thing that
would take configuration away again. This is that work, plus the smaller redundancy those plans
left behind.

## Problem

A working managed-OIDC client invocation currently needs, at minimum:

```
authunnel-client --proxycommand \
  --tunnel-url https://tunnel.example/protected/tunnel \
  --oidc-issuer https://idp.example/realms/main \
  --oidc-client-id authunnel-cli \
  %h %p
```

and realistically also `--oidc-scopes`, and `--oidc-audience` or `--oidc-resource` depending on the
provider, and `--oidc-metadata-url` for an authorization server whose metadata is not at the derived
path. Every one of those values is already known to the authunnel server, which had to be configured
with the issuer and the audience to validate tokens at all. Each is transcribed by hand into an
`ssh_config` `ProxyCommand` line per user, per host block. Two failure modes follow:

1. **Transcription errors surface late and remotely.** A wrong issuer or client ID is not caught
   locally. It survives a full browser login and comes back as a 401 or 403 from the authunnel
   server, after user interaction, with the server's deliberately uninformative fixed message
   (`internal/tunnelserver/tunnelserver.go:881`). The user cannot tell a misconfigured client from a
   permissions problem.
2. **`--oidc-issuer` is required even where it does nothing.** With `--oidc-metadata-url` set, every
   endpoint the client uses comes from the document; the client validates no tokens. The issuer's
   only remaining jobs are a string comparison against a field the document asserts about itself,
   and cache identity. `client/client.go:242` nevertheless rejects the override without it.

## Goals

- A complete client configuration is `--tunnel-url` and nothing else. The remaining values come
  from the resource server that already has them.
- `--oidc-metadata-url` is usable without `--oidc-issuer`.
- Explicitly-configured values always win over discovered ones, and a fully-explicit invocation
  makes exactly the network calls it makes today — no new startup fetch on the fast path.
- The authunnel server is legible to a standard OAuth client: RFC 9728 metadata at the well-known
  location, and an RFC 6750 `WWW-Authenticate` challenge pointing at it.

## Non-goals

- **RFC 7591 dynamic client registration.** The client ID reaches the client as a hint published by
  the resource server (see item 3), not by registering at the authorization server. Dynamic
  registration is a different trust question and a much larger surface.
- **Discovery of the tunnel URL itself.** It is the entry point; something has to be typed.
- **Caching discovered endpoints across invocations.** Explicitly rejected in
  [PLAN_202608_client_discovery.md](PLAN_202608_client_discovery.md) § Rejected, on stale-credential-
  destination grounds. Nothing here changes that analysis: resource metadata is re-fetched whenever
  the client is about to send a credential anywhere.
- **Changing the server's status codes on auth failure.** The 403-for-invalid-token behaviour at
  `tunnelserver.go:881` is not RFC 6750's 401, but changing it changes what every existing client
  reports. The challenge header is added to the 401 paths only; the status codes stay as they are.

## The trust question, stated up front

This work makes the resource server the source of the authorization server's identity. That is a
real shift and it deserves to be named rather than buried in an item.

**What is given up.** Today `--oidc-issuer` is supplied out-of-band, so a compromised or
mistyped `--tunnel-url` cannot redirect the login: the client would still go to the configured IdP,
and the attacker would receive a token minted for an audience they do not control. After this
change, a hostile `--tunnel-url` names the authorization server, so it can send the user to a
credential-phishing page of its choosing.

**Why that is nevertheless acceptable here, and where it is not.**

- The tunnel URL is the thing the user chose to send a bearer token to. An attacker who controls it
  already receives every access token this client obtains. Directing the login elsewhere lets them
  phish the *IdP password* rather than merely harvest the tunnel's token — a genuine escalation,
  but from a position that is already lost.
- RFC 9728's mitigation is what makes the fetch trustworthy at all, and it is mandatory here: the
  document must be fetched from the resource server's own origin over https, and its `resource`
  value must match the resource the client is using. An attacker who cannot present a valid
  certificate for the tunnel host cannot supply the document. The transport rules in
  `internal/authhttp` are what enforce this, so this feature inherits them rather than restating
  them.
- The escalation is bounded to interactive login. Discovery cannot cause an *already-issued*
  refresh token to be posted somewhere new: item 5's post-resolution identity check discards the
  cache instead. That is the same rule, and the same reasoning, as the metadata-URL-in-cache-identity
  fix recorded in the previous plan.
- An operator who does not accept the trade keeps supplying `--oidc-issuer`; it then wins over the
  discovered value and the client will refuse a document that names a different one. There is no
  mode in which discovery silently overrides an explicit value.

One asymmetry worth noticing, because it runs the other way from the rest of this section:
**discovery eliminates a failure mode that `--oidc-issuer` exists to catch.** The previous plan
keeps the issuer required precisely to catch an *honest wrong* metadata URL — staging for
production, tenant A for tenant B. A resource server naming its own authorization server cannot
make that mistake on the user's behalf: the pairing comes from the party that enforces it. So for
the discovery path the consistency check is not weakened, it is superseded. That is *not* true of
item 1 below, where it is genuinely given up.

## Proposed changes

### 1. `--oidc-issuer` becomes optional when `--oidc-metadata-url` is set

Drop the check at `client/client.go:242` and the both-or-neither rule at `:237` in favour of: the
client needs *either* an issuer *or* a metadata URL *or* a resource-metadata document to work from.
When no issuer is configured, the one the document declares is adopted. When one is configured, the
existing comparison stands and a mismatch is still `oidc.ErrIssuerInvalid`.

This costs the consistency check described above, in the narrow case where an operator supplies a
metadata URL and no issuer. Say so in the flag help rather than implying the check is optional in
some deeper sense: without an issuer, a metadata URL pointing at the wrong tenant is discovered as
"correct" and fails after a browser login.

`oidcclient.Discover` cannot express this — it compares `discoveryConfig.Issuer != issuer`
unconditionally, so an empty issuer fails against every real document. The fetch therefore moves
into item 2, which needs its own metadata fetching anyway.

### 2. New package `internal/authmeta`

Two documents, one set of transport rules, one place:

| Function | Fetches | Notes |
| --- | --- | --- |
| `FetchAuthorizationServer(ctx, client, issuer, metadataURL)` | RFC 8414 / OIDC discovery | Derives the well-known path from the issuer when `metadataURL` is empty, exactly as `oidcclient.Discover` does. Adopts the declared issuer when `issuer` is empty; compares and returns `oidc.ErrIssuerInvalid` when it is not. |
| `FetchProtectedResource(ctx, client, resourceURL)` | RFC 9728 | Derives the well-known path per §3.1, validates the document, returns it. |

Both go through `authhttp.RefuseTransportDowngrade` and read through an `io.LimitReader`; neither
accepts a non-`http(s)` URL. `authhttp` keeps its current role — transport *policy* — and
`authmeta` is the caller of that policy for the two documents authunnel reads. Splitting them this
way avoids `authhttp` becoming the place where everything auth-shaped lands.

The response body cap is new and applies to both documents plus, by consequence, nothing else: the
JWKS fetch stays inside `rp.NewRemoteKeySet`. A metadata document is a few kilobytes; a resource
server that streams gigabytes at a client is not one worth being generous with.

### 3. The server publishes RFC 9728 metadata

`GET /.well-known/oauth-protected-resource`, and the same handler on the subtree
`/.well-known/oauth-protected-resource/…`, because §3.1 forms the URL by inserting that segment
before the resource's path — `https://tunnel.example/protected/tunnel` becomes
`https://tunnel.example/.well-known/oauth-protected-resource/protected/tunnel` — and a deployment
behind a path-rewriting proxy may present either shape. Unauthenticated, like `GET /`.

Standard fields, all derived from configuration the server already has:

| Field | Source |
| --- | --- |
| `resource` | Request scheme and host (honouring `X-Forwarded-Proto`/`-Host` under `--plaintext-behind-reverse-proxy`, via the existing `requestScheme`/`requestHost` helpers) plus the canonical tunnel path. |
| `authorization_servers` | `--oidc-issuer`. |
| `bearer_methods_supported` | `["header"]`. It is the only method the server accepts. |
| `scopes_supported` | `--client-scopes` when set. |

Deriving `resource` from the request rather than from a new `--public-url` flag is deliberate. The
Host header is client-controllable, so a caller can make the document describe a resource identifier
of its choosing — but only in the response to its own request, and the client then compares that
value against the URL it actually used and refuses a mismatch. The self-consistency check is what
makes the derived value safe, and it costs the operator nothing. A flag would add configuration to
the server in a plan about removing it, to defend against a caller lying to itself.

**Extension fields for the values RFC 9728 has no room for**, namespaced so they cannot be confused
with registered parameters:

| Field | Source | Fills |
| --- | --- | --- |
| `authunnel_client_id` | `--client-id` | `--oidc-client-id` |
| `authunnel_authorization_server_metadata_url` | the server's own `--oidc-metadata-url` | `--oidc-metadata-url` |
| `authunnel_audience` | `--client-audience` | `--oidc-audience` |
| `authunnel_resource` | `--client-resource` | `--oidc-resource` |

RFC 9728 §3 permits additional parameters, and a public client's ID is not a secret — it appears in
every authorization request and in the browser URL bar.

The audience hints are two flags rather than one derived from `--token-audience` because the server
knows *what* audience it requires but not *how* the authorization server wants it asked for:
`audience` is Auth0's parameter, `resource` is RFC 8707's, and providers ignore the other one
silently. Guessing produces a login that succeeds and yields a token the server then rejects. An
operator who needs either one knows which.

`authunnel_authorization_server_metadata_url` is derived rather than flagged because there is no case
where it differs: the client and the server read the same authorization server's metadata. A flag
here would exist only to be set inconsistently.

**Default on, with `--no-resource-metadata` to switch it off.** A feature that must be enabled on
both ends removes no configuration. The opt-out exists because the default *is* a change in what an
upgraded server tells anonymous callers — the issuer URL, and any hints configured — and an operator
who treats their IdP's identity as non-public deserves a switch rather than a patch. Note what the
switch does not buy: any client that can authenticate already knows the issuer, since it had to
obtain a token from it.

### 4. `WWW-Authenticate` on the 401 paths

`WWW-Authenticate: Bearer resource_metadata="https://…"` on the three 401 responses in
`validateRequestToken`, alongside the existing fixed bodies. Two reasons, neither of which is "the
authunnel client needs it":

- it is what makes the server discoverable to any RFC 9728 client, not just this one;
- it is the difference between "tunnel authentication rejected" and an error that can name where the
  configuration should have come from.

The authunnel client derives the well-known URL from the tunnel URL instead of probing for a
challenge, because it knows it is talking to an authunnel server and a deliberate 401 costs a round
trip and a hit on the pre-auth limiter. The header is not load-bearing for the flow in this repo,
and the code should say so, so nobody later "optimises" the derivation away in favour of it and
introduces the probe.

### 5. The client fills gaps from the resource server

**When.** Only when something essential is missing — no client ID, or neither issuer nor metadata
URL. A fully-explicit invocation makes no resource-metadata request at all, so today's flag sets
behave byte-for-byte as they do now. `ACCESS_TOKEN` mode is untouched.

**What.** Any value the operator did not set: client ID, issuer, AS metadata URL, audience,
resource, scopes. Explicit always wins, including when it contradicts the document — a configured
issuer that the document does not name is an error, not a silent override.

**Where in the flow.** Not at config-parse time, and not in `newAuthTokenSource`. Both run on every
`ssh` invocation, and `AccessToken` returns from cache at `client/auth.go:216` before any endpoint is
needed: the common ProxyCommand path makes zero network calls today and must keep doing so. Resource
metadata is therefore fetched lazily, inside `AccessToken`, on the paths that were already going to
talk to the IdP.

That ordering creates the one genuinely new problem in this plan. **Cache identity is computed from
values that are not known until after the fetch.** Resolved separately for the two comparisons:

- **At load**, the entry must match every value the operator configured explicitly, plus — in
  discovery mode only — the tunnel URL. `TunnelURL` is `omitempty` and left empty when discovery is
  not in use, so a cache written by an earlier version still matches a fully-explicit source and
  nobody is logged out by the upgrade. (Same mechanism as `MetadataURL` in the previous plan, for the
  same reason.)
- **After resolution and before the refresh token is used**, the entry must match the *resolved*
  identity in full. A tunnel URL that now names a different authorization server, client ID, or
  metadata URL discards the cache and falls through to interactive login.

The second check is the load-bearing one, and it is the same rule the previous plan arrived at the
hard way: **cache identity must include everything that determines where a credential gets sent,
not only what determines whether it is still valid.** Without it, discovery mode would take a
refresh token issued under one authorization server and post it to whatever token endpoint the
resource server names today, with no user interaction — which is precisely the credential-disclosure
bug that plan documents shipping and then fixing. Keying the cache on the tunnel URL is not
sufficient on its own, because the tunnel URL can keep pointing at the same host while the document
behind it changes.

**Validation of discovered values.** A discovered issuer or metadata URL is held to exactly the
rules a configured one gets — `authhttp.CheckConfiguredURL`, so https unless
`--insecure-oidc-issuer`, and `file://` refused either way — plus `CheckNoSchemeDowngrade` against
the tunnel URL, so an https tunnel cannot name a plaintext issuer. Remote input gets at least the
scrutiny a local flag does; the previous plan made that argument for discovered *endpoints* and it
applies unchanged here.

The hint fields need their own bounds, because they end up in places a URL check does not cover.
`authunnel_client_id` is interpolated into an authorization URL that is handed to the OS scheme
dispatcher, and `scopes_supported` into the same URL's query: both are length-capped and restricted
to the character sets RFC 6749 already defines for them (`client_id` as `*VSCHAR`, each scope token
as `NQCHAR`). `authunnel_resource` gets the RFC 8707 rule the flag already enforces — absolute URI,
no fragment.

## Security invariants

Everything in `PLAN_202608_client_discovery.md` § Security invariants still holds. Added:

- **Resource metadata is fetched from the resource server's own origin, over the transport the
  tunnel URL specifies, and is checked to describe that resource.** The origin comparison is what
  substitutes for the out-of-band issuer configuration this feature removes; without it the feature
  is an open redirect for logins.
- **Discovery never causes an already-issued refresh token to be sent somewhere new.** It may cause
  an interactive login to a newly-named authorization server, which the user sees; it may not cause
  a silent credential hand-off, which the user does not. Item 5's post-resolution check is the whole
  of that guarantee.
- **An explicitly-configured value is never overridden by a discovered one.** A contradiction is an
  error. This is what leaves an operator a way to decline the trust shift without declining the
  feature.
- **Discovered URLs are held to the configured-URL rules, not a weaker set.** In particular the
  insecure override stays transport-only on this path too: a discovered `file://` issuer is refused
  with `--insecure-oidc-issuer` set.

## Test plan

`internal/authmeta`:

- issuer adopted from the document when none is configured; compared and `oidc.ErrIssuerInvalid`
  when one is and it differs; unchanged happy path when it matches;
- protected-resource document whose `resource` names a different origin than the URL it was fetched
  from → refused, with the error naming both;
- well-known URL derivation per §3.1, including a resource URL with no path and one with a
  multi-segment path;
- a document larger than the body cap → refused rather than read;
- non-JSON, empty, and `null` bodies; a document with no `authorization_servers`;
- an https resource whose document names an `http://` authorization server → refused; the same under
  `--insecure-oidc-issuer` semantics → permitted, since the tunnel is then plaintext too;
- hint validation: over-long and out-of-charset `authunnel_client_id`, a scope token containing a
  space or a control character, `authunnel_resource` with a fragment or relative.

Server:

- the document is served at both the exact and subtree well-known paths, is valid JSON, and carries
  the configured issuer;
- `resource` reflects `X-Forwarded-Proto`/`-Host` under `--plaintext-behind-reverse-proxy` and
  ignores them otherwise — the same matrix `checkWebSocketRequest` already has tests for;
- hints appear only when their flags are set, and `authunnel_authorization_server_metadata_url`
  tracks `--oidc-metadata-url`;
- `--no-resource-metadata` gives 404 at both paths, and the challenge header is then absent;
- `WWW-Authenticate` present with a `resource_metadata` parameter on each of the three 401 paths,
  and the parameter's value is a URL that actually serves the document;
- the well-known path is not authenticated and is not covered by the pre-auth limiter — asserted,
  because "unauthenticated" and "unlimited" are different decisions and only one of them is
  intentional.

Client:

- `--oidc-metadata-url` with no `--oidc-issuer` parses, and reaches discovery **through
  `newAuthTokenSource`** rather than a directly-constructed source, so the mapping is covered;
- `--tunnel-url` alone parses, and a stub resource server drives a complete login;
- every combination of one explicit value plus discovery for the rest, asserting the explicit value
  survives;
- a document naming an issuer that contradicts `--oidc-issuer` → error, no browser opened;
- **the fast path makes no request**: a fully-explicit source with a valid cached token, against a
  resource-metadata endpoint that fails the test if it is called at all. This is the assertion that
  the lazy placement is actually lazy;
- **the post-resolution identity check**, by mutation: with a cached refresh token, change the
  document's `authunnel_client_id`, and assert the refresh grant is never sent and the cache is
  discarded. Remove the check and the test must fail — a collector endpoint recording what it
  receives, following the discipline that made the previous plan's redirect tests trustworthy;
- caches written before `TunnelURL` existed still match a fully-explicit source.

End-to-end against the real binaries: the local Keycloak environment in `docs/DEVELOPMENT.md` driven
with `--tunnel-url` as the only client flag, confirming a real login completes. A unit test proving
the fetch happens is not the same as proving the client logs in.

## Documentation

- `README.md` — the client flag list, and the "Components" claim that managed OIDC is a
  "public-client PKCE login with token cache + refresh" without saying where the configuration comes
  from. The primary use-case walkthrough at the top gains the discovery step.
- `docs/DEPLOYMENT.md` — the server flag reference, a section on the published document and the
  `--client-*` hints, and the hardening checklist (the trust shift belongs there, on both sides).
- `docs/DEVELOPMENT.md` — the auth-flow invariants list gains the post-resolution identity check;
  the Keycloak walkthrough loses most of its client flags.
- `docs/Notes.md` — check, it has drifted before.

Anchors verified programmatically, as in the previous plan.

## Sequencing

1. ✓ done — `internal/authmeta` with `FetchAuthorizationServer` only, replacing the
   `oidcclient.Discover` call in `client/auth.go`. Behaviour-neutral: same derivation, same
   comparison, same error identity, plus the body cap. Reviewable against the existing client suite.

   **Also moved the server onto it**, which the plan did not call for. Leaving
   `internal/tunnelserver` on `oidcclient.Discover` would have kept two code paths for the same
   document, and only one of them bounded — the whole argument for a shared package. Behaviour is
   unchanged: the derivation, the `iss` comparison, and `oidc.ErrIssuerInvalid` are all preserved,
   which the existing `discovery_override_test.go` suite pins.

   One error-identity decision arrived here rather than in the plan: a refusal
   (`authhttp.ErrUnsafeTransport`) is returned with its own identity rather than joined with
   `oidc.ErrDiscoveryFailed`. Joining them would tell a caller keying on "retrying cannot help"
   that the issuer was merely unreachable, which is the fall-through bug the previous plan fixed.

2. ✓ done — Item 1, issuer optional with `--oidc-metadata-url`.

   This is where the `configured` / `resolved` split arrived, earlier than the plan implies. It has
   to: once a value can be adopted, `cacheFor` must record the *resolved* one (or the entry matches
   any future document) while the load-time comparison can only use the *configured* one (or every
   invocation without `--oidc-issuer` discards its cache and logs the user in again). Both
   comparisons therefore exist as of this step, with `resourceURL` added in step 4.

3. ✓ done — Items 3 and 4, the server side. Two decisions taken during implementation:
   - **`--client-*` hints are rejected when combined with `--no-resource-metadata`.** Not in the
     plan. An operator who sets `--client-id` alongside it believes clients are being told
     something; silently publishing nothing is the kind of configuration that looks correct in a
     deployment file and fails per-user.
   - **Hint validation lives in `internal/authmeta` and runs on both sides.** The server validates
     what it is configured to publish, so a malformed value fails at startup for the operator who
     typed it; the client validates what it receives, because it must not trust a remote document
     to have been produced by a server that ran that check. One definition, two callers.

   Verified against the real binaries with `curl` before a consumer existed, as the ordering
   intended: both well-known shapes, the challenge header, and `resource` following
   `X-Forwarded-*` only under `--plaintext-behind-reverse-proxy`.

4. ✓ done — `FetchProtectedResource` and item 5, the client side, unsplit as planned.

   `ResourceURL` went *inside* `oidcIdentity` rather than beside it. It is the same kind of thing
   as the other six — something that determines where a credential goes — and putting it in the
   struct means `cacheFor`, both comparisons, and the JSON all pick it up without a seventh place
   to forget.

   The scopes default had to move. `parseClientConfig` applied `openid offline_access` whenever
   `--oidc-scopes` was unset, which makes "unset" and "explicitly the default" indistinguishable —
   and `scopes_supported` could then never win. The default is now applied at parse time only when
   nothing will be discovered, and by the resolver otherwise. Keeping it at parse time in the
   non-discovery case is deliberate: it leaves the load-time cache comparison strict there, exactly
   as before.

5. ✓ done — Docs, plus one correction the test plan needed.

   **The planned end-to-end test was not possible as written.** It called for driving the local
   Keycloak environment with `--tunnel-url` as the client's only flag — but that environment serves
   the tunnel over TLS while Keycloak runs over plain HTTP, and a discovered issuer is held to the
   same rules as a configured one, so an `https` resource naming an `http` authorization server is
   *correctly* refused. Nothing to fix in the code; the walkthrough now says so and explains that
   exercising discovery locally means `--plaintext-behind-reverse-proxy` so both legs are plaintext.

   The end-to-end coverage that replaced it is stronger than the plan asked for:
   `TestZeroConfigProxyCommandE2E` drives a client parsed from `--tunnel-url` alone through the
   *real* handler and a JWT-backed provider, completes a browser login, moves bytes, and then
   asserts the second invocation reuses the cache without touching either the metadata endpoint or
   the browser. The real binaries were also driven by hand against a stub issuer, confirming the
   client builds a PKCE authorization URL carrying the published `client_id`, `audience` and scopes.

### Added after the plan: a client-side opt-out

`--no-resource-metadata` on the client, refusing the lookup rather than merely not needing it.

The plan treated "supply everything" as the way to decline discovery, and mechanically it is —
a complete configuration produces no request. But that is an *outcome*, invisible in the
`ProxyCommand` line and undone by whoever next shortens it. As a flag it is a prohibition, and it
buys something the outcome cannot: with the lookup refused, completeness becomes decidable at parse
time, so an incomplete configuration fails before ssh has spawned anything rather than lazily, into
ssh's stderr, mid-connection. It is also the forward guarantee — if discovery ever grows the ability
to fill a non-essential gap, this flag already says no.

Three decisions worth recording:

- **The name is the server's, deliberately.** Same document, opposite direction: on the server it
  means do not publish, on the client do not read. The alternative, `--no-oidc-discovery`, overloads
  a word this codebase already uses for authorization-server metadata (`discovery_mode`,
  `DiscoveryModeDerived`, "issuer metadata discovery") and would need disambiguating prose forever.
- **Combining it with `ACCESS_TOKEN` is an error**, though there is no precedence ambiguity to
  resolve — manual mode looks nothing up. A flag that cannot take effect is a configuration error,
  the same rule the server applies to a `--client-*` hint it would never publish.
- **The completeness error is derived from `needsDiscovery`, not from a restatement of its
  condition.** This was a correction, and the mutation check is what found it. The first version
  restated the condition, which meant the suppression term in `needsDiscovery` was unobservable:
  a complete configuration makes no request either way, and an incomplete one hit the separately
  written error first. Removing the term broke nothing and no test noticed. With the error derived
  from the same expression that gates the lookup, breaking the suppression stops the error firing
  and the parse test fails. One definition, and a test that pins the mechanism rather than a
  coincidence.

The test named for the flag was retitled to match what it can actually prove
(`TestNoResourceMetadataCompletesWithoutContactingTheServer`): it is a composition guard, and its
comment says so and points at the parse test for the suppression itself. A test whose name claims
more than its assertions is how the previous plan's redirect tests went wrong.

### Review findings on the client-side work, all fixed

Four, two of them P1. Recorded in full because three were places where a *stated* trade-off turned
out to be the wrong one, which is more useful to a future reader than the diffs.

- **P1: the resource comparison was origin-only, and RFC 9728 §3.3 requires the whole identifier.**
  This plan argued for the weaker version explicitly — "a deployment behind a path-rewriting reverse
  proxy legitimately sees a different path, while the origin is the part that decides who could have
  served the document" — and the argument is wrong about what the check is *for*. It is not only
  "who served this"; it is "is this document about the resource I am using". One hostname can carry
  several protected resources, and an origin comparison lets a document about `/a/tunnel` hand its
  authorization server and client ID to a client asking about `/b/tunnel`. The path-rewriting case
  is real but is configuration, not grounds for weakening the check for everyone: the server gained
  `--resource-url` to declare its externally visible identifier, and the comparison is now exact
  after syntax-based normalisation only.
- **P1: discovered addresses were unfiltered (RFC 9728 §7.7).** Shape and transport were checked;
  where the name actually pointed was not, so a public tunnel server could aim the client's own auth
  traffic at loopback or `169.254.169.254`. Fixed at two layers, because neither covers the other:
  a resolution check — the only protection for `authorization_endpoint`, which goes to the OS URL
  dispatcher and through no client of ours — and a dial guard that connects to the address it
  verified, closing the rebinding gap the first leaves open, since the attacker chose the name and
  therefore controls its DNS. Two scoping decisions keep it from over-blocking: private networks are
  not refused (an internal IdP is an ordinary deployment, and the existing `ipblock.Default()` set
  already excludes RFC1918 for the same reason), and the guard is lifted when the tunnel server is
  itself internal, which is the local-development case. This is what moved the deny-list into
  `internal/ipblock`: the server asking about SOCKS destinations and the client asking about
  discovered addresses are the same question, and a second copy of the answer would drift.
- **P2: the tunnel URL's query was dropped from the resource identity.** The stated reason —
  avoiding forwarding "whatever a caller had appended" — holds for the fragment and fails for the
  query, which the WebSocket dial already sends to that same host. Dropping it disclosed nothing
  and instead collapsed distinct resources onto one identity, so `?tenant=a` and `?tenant=b` shared
  discovered configuration *and a cache entry*. The query is now carried through the §3.1
  derivation, compared, and part of the cache identity; the server echoes it, since it routes on
  path alone and a query is opaque routing information belonging to whatever sits in front.
- **P2: a stale-but-unexpired cached token was an unrecoverable lockout.** The fast path returns a
  cached access token without reading any metadata — by design — so a server that changes issuer,
  client ID or audience leaves every client presenting a credential it will keep refusing until the
  cache expires. The client now re-resolves once on a rejection and retries with a token obtained
  under the new configuration.

  **The trigger the review proposed does not fire in this codebase**, and it is worth writing down
  why. RFC 9728 §5.2 has the client react to the `resource_metadata` challenge on a 401 — but this
  server answers a token that *failed validation* with 403 and reserves 401 for a missing or
  malformed header. A 403 carries no challenge (RFC 7235), so the configuration-changed case would
  never have been seen. The recovery keys on 401 **or** 403 instead.

  Two guards make the retry safe: exactly one attempt, and only when re-resolution shows the
  configuration actually changed. Without the second, a disabled account or a revoked scope — which
  produce the same rejection and are fixed by neither re-resolution nor re-authentication — would
  open a browser on every ssh invocation.

### Second review round, all fixed

Four again, and the shape of them is the lesson: two were *incomplete* fixes from the round above,
which is the failure mode this plan should have expected of itself.

- **P1: the query was still dropped where it mattered.** The previous round corrected the §3.1
  derivation and the comparison, and left `resourceURLForTunnel` — the client's own derivation, and
  the thing that actually produces the cache key — untouched, with a comment asserting "query and
  fragment are dropped by the derivation itself" that had just stopped being true. So `?tenant=a`
  and `?tenant=b` still shared discovered configuration and a cache entry while the dial still sent
  the query.

  **Every test missed it because every test assigned `source.resourceURL` by hand.** That is the
  same gap recorded two rounds earlier about `newAuthTokenSource` — a config-to-source mapping that
  no test crossed — and it recurred because the fix then was one test, not a rule. The rule:
  **a value the production config path computes must be asserted through that path.** The new tests
  go through `parseClientConfig`, and the mutation now fails.
- **P1: the dial guard was bypassed by an HTTP proxy.** `NewBoundedClient` sets
  `Proxy: http.ProxyFromEnvironment`, and `Transport.Clone` preserves it, so with a proxy configured
  the transport dials the *proxy*: the guard inspected the proxy's address while the destination went
  unchecked. Two things were wrong at once, because the naive repair is also wrong — checking the
  proxy hop would refuse a loopback proxy, which is a common corporate shape.

  Fixed by adding the layer that can see the destination: a RoundTripper check on every request,
  which also covers each redirect hop, plus a context marker that exempts the proxy hop from the
  dialer. The honest scope, now stated in the code and the docs rather than implied: a proxied
  client's destination is resolved *by the proxy*, so there is no address for us to pin and rebinding
  is narrowed, not prevented.
- **P2: the challenge omitted the query.** The document echoes it, so a standards-following client
  that followed the challenge fetched the query-less document and then failed its own equality check
  — a challenge leading somewhere self-defeating, which is worse than sending none. The test follows
  the challenge and asserts the document at the far end describes the resource that was requested,
  which is the property that matters rather than the header's spelling.
- **P2: `--resource-url` accepted unusable schemes.** `ftp://host/path` normalised fine and would
  have been published as an identifier no client can retrieve. Fixed at the root by making http(s)
  part of `NormalizeResourceIdentifier` — the single identifier rule the derivation is built on —
  rather than adding a second check at the flag.

  One consequence recorded because it cuts against an instinct: the fix first routed the flag through
  `ProtectedResourceURL` "to prove the derivation runs", and the mutation check showed that
  indirection was undetectable, since that function adds no rejection the normaliser does not already
  make. Reverted to the normaliser. A distinction no test can see is not defence in depth.

A behaviour change fell out of the identifier rule and is worth flagging: a fragment is now
**refused** by the derivation rather than silently stripped. The client strips its own first — a
fragment in `--tunnel-url` is inert, never sent, so failing discovery over it would be the worse
answer — while a fragment arriving in a *document* is refused, because quietly discarding part of a
value that is about to be compared for equality is how the derived and compared values drift apart.

### Third review round, all fixed

Three, all P1, and two of them were *my* fixes from the round above being wrong rather than
incomplete — which is a different and more uncomfortable failure than the last round's.

- **The condition that relaxed the guard was attacker-supplied.** The previous round decided
  "internal targets are acceptable when the resource server is itself internal" by *resolving the
  tunnel host* and treating any blocked answer as internal. The tunnel host belongs to the party the
  guard exists to constrain, so its DNS is theirs: two A records, one public and one loopback,
  classified their server as local and switched every downstream check off, after which the document
  could name any internal address it liked. A guard whose activation condition is chosen by its
  adversary is not a guard, and I built one while writing a comment about how carefully it was
  scoped.

  Now decided from the spelling alone — a literal address in the protected set, or a name RFC 6761
  reserves for loopback — and resolving nothing. The cost is a development host that reaches its
  tunnel through a private alias, which must pass `--oidc-issuer`; the benefit is a condition no
  remote party can satisfy. All resolution in `internal/authhttp` now goes through one seam so a
  test can assert which paths resolve and which must not, because the first version of that test
  could not tell the two apart and the mutation check passed.
- **Documenting the proxy exposure was not a fix — and refusing every proxied request was not the
  right one either.** Recorded as one item because the second correction came from a question about
  the first, and the pair is more instructive than either half.

  The round-two version kept the proxy, checked the destination per request, and wrote down that a
  proxied client's rebinding window was narrowed rather than closed. That is a guard advertised in the
  README which silently does not hold for a whole class of users, so round three refused every
  proxied request. The review asked, reasonably, whether rebinding is a problem at all when the
  authunnel server is https — and it is not.

  **For an https destination the certificate is the binding, and it survives a proxy.** The transport
  issues `CONNECT` and then performs its own TLS handshake with the origin, validating against the
  name it asked for; the proxy is a blind relay. A rebound internal service cannot complete that
  handshake, because the attacker owns the name but not that service's key. Address pinning was only
  ever standing in for the thing TLS already does. Verified rather than reasoned about: a test relays
  every tunnel to one origin regardless of the name requested, and the mismatched name fails on the
  certificate before a single request is served.

  So the refusal is now scoped to **plaintext** through a proxy, where nothing binds the origin and a
  proxy fetching an internal `http` endpoint is precisely the §7.7 pivot. On the proxied https path the
  address checks are *skipped* rather than applied, because a proxied network frequently resolves
  external names only at the proxy and demanding a local answer would break exactly the clients that
  can reach the destination. The same reasoning fixed the client's static endpoint check, which had
  been treating "cannot resolve" as grounds for refusal.

  What that recovers: zero-configuration discovery works behind a proxy again, and since a plaintext
  discovered endpoint already requires `--insecure-oidc-issuer`, the remaining refusal does not arise
  in a normal deployment. What it does not cover, stated rather than glossed: a TLS-terminating proxy
  with its CA installed *is* the origin as far as validation goes, and the control for that is the
  proxy's own egress policy.

  The lesson worth keeping is not about proxies. Twice in a row the error was reaching for a
  client-side check without first asking what the transport already guarantees — once by under-scoping
  the guard and once by over-scoping it. **Establish what TLS is already binding before deciding what
  needs pinning.**

- **Escaped path segments were collapsed.** Every derivation carried `url.URL.Path`, the decoded
  form, so `String()` re-encoded it and `/tenant%2Fone/tunnel` came back as `/tenant/one/tunnel` —
  two identifiers RFC 3986 §2.2 keeps distinct, merged into one discovery result and one cache entry,
  while the code and the docs promised a verbatim path comparison. Fixed at all three sites by
  carrying the escaped form.

  One limitation now stated rather than left implicit: equivalent percent-encodings (`%7E` and `~`)
  are not folded together, so they compare unequal. That errs toward refusing a legitimate document
  rather than accepting a foreign one, which is the correct side to be wrong on, and both values are
  quoted in the error.

### Fourth review round: the issuer pin was hollow

One finding, and it invalidated a claim this plan makes in its own opening section.

**`--oidc-issuer` did not pin where the metadata came from.** The check compared the configured
issuer against `authorization_servers` and then, separately, adopted
`authunnel_authorization_server_metadata_url` whenever the operator had not supplied one. Both fields
come from the same tunnel server. So a hostile server echoed the expected issuer, pointed the client
at its own metadata document — whose `issuer` field is self-asserted, as the `metadataURL` comment in
`client/auth.go` has said since the first round — and named the authorization and token endpoints from
there. The browser went to its authorization endpoint; the code, the PKCE verifier and any refresh
token went to its token endpoint.

Every element of that was already written down here. "The trust question, stated up front" says an
operator who does not accept the trade "keeps supplying `--oidc-issuer`", and the invariants say an
explicit value is never overridden by a discovered one. Both were false in this case, and the reason
is worth more than the fix: **I reasoned field by field.** Explicit issuer beats published issuer,
explicit metadata URL beats published metadata URL — each true, and together not enough, because one
field determines what another field guarantees. "Explicit wins" has to be evaluated per *guarantee*.
The issuer's guarantee is "the endpoints come from this issuer", and the document's location is what
decides that.

Fixed by bounding the published location: accepted when no issuer is configured (nothing to
undermine, and that is the trade the feature makes), and otherwise only when it shares an origin with
the configured issuer — where TLS makes the issuer's own host answer for the document. That keeps the
case the flag exists for, since an authorization server publishing RFC 8414 metadata at a
non-derivable path serves it from its own host. A cross-origin location with an issuer pinned is
announced and ignored rather than treated as an error: it is not necessarily an attack, and silence
would leave an operator debugging a 404 on the derived path while the server advertises a location the
client declined.

The gate reads the *configured* `s.issuer`, not `identity.Issuer`, which may have just been adopted
from the document being judged. That distinction is not cosmetic and the first version of the test
could not see it — see the mutation notes.

**What a pinned issuer still does not pin**, now stated in README and DEPLOYMENT rather than left to
be inferred: the audience and the RFC 8707 resource. Those are adopted when the client supplies
neither, so a tunnel server can influence what the token is *for* even when it cannot influence where
the login happens. An operator pinning the issuer out of distrust should pin `--oidc-audience` or
`--oidc-resource` as well. Not gated automatically, because a mixed configuration — pin the IdP,
discover the audience — is a legitimate thing to want, and the flag to express distrust already
exists.

### Fifth review round: the relaxation set was the refusal set

One finding, and it is the same mistake as the fourth round in a different costume.

**Link-local, IMDS, multicast and unspecified literals disabled every guard.** The classification
reused `ipblock.Default()` — the list of addresses a remote party may not send this client to — to
answer a different question: is this host the machine we are running on. Loopback answers yes to both.
The others answer yes to the first and no to the second, so a tunnel URL of
`http://169.254.169.254/protected/tunnel` was classified as local and switched off every check,
including the one protecting the instance metadata service. "The tunnel server is IMDS" is the last
circumstance in which to start trusting what it says.

Narrowed to loopback literals plus `localhost`/`*.localhost`. Every documented development path in
this repo uses `localhost`, so the narrowing costs nothing real; `0.0.0.0` and `::` are excluded as
well, even though a connection to them cannot leave the host, because no documented setup spells it
that way and one clear refusal is cheaper than a standing question about why an unspecified address
counts as an identity.

The recurring error, now twice: **two questions answered by one artefact.** Round four was one
guarantee (a pinned issuer) undermined by a different field (the metadata URL). This is one list
serving both "refuse" and "trust". In both cases the individual pieces were right and the coupling
was wrong, and in both cases the comment above the code described the narrower intent while the code
did the broader thing. The test written for this is deliberately a *property* — every member of the
refusal set is checked, and only loopback may also relax — rather than a list of examples, so a future
entry in `ipblock.Default()` cannot inherit "local" by being added in one place.

### Sixth review round: the pin held only until the first redirect

One finding, and it is the third consecutive instance of the same underlying error.

**A same-origin open redirect defeated the round-four issuer pin.** That fix checked the published
metadata URL against the configured issuer's origin — and then the fetch followed redirects anywhere,
provided they stayed on https. So a hostile tunnel publishes a URL that *does* start on the issuer's
origin and happens to be an open redirect, which is not a rare thing to find on an IdP host, and the
document actually read comes from wherever it points. Every check written so far still passed.

Fixed by refusing to leave the origin a metadata fetch started on, unconditionally rather than only
when something is pinned: a conditional rule needs a reader to work out which case they are in, and the
unconditional one makes true a claim this documentation already made about *both* documents — that each
comes from the origin it describes.

Two decisions inside that, both of which the tests forced rather than confirmed:

- **Origin, not hostname.** The first version compared hostnames, which is the exact statement of what
  TLS guarantees, since a certificate answers for a host on any port. The regression fixture walked
  straight through it: two `httptest` servers share the hostname `127.0.0.1` and differ only by port.
  That is not merely a fixture artefact — in plaintext mode there is no certificate to appeal to and a
  different port is a different service. The stricter rule costs only an http-to-https upgrade of the
  same document, which an operator can express by spelling the metadata URL as its final location.
- **The pin is nested inside the downgrade guard**, so an https-to-http hop still reports "transport
  downgrade on the auth path" rather than the origin message. A downgrade is nearly always an origin
  change too, and the sharper diagnosis should win — the same ordering argument as the proxy check.
  Two existing tests caught this by asserting on the reason, which is the value of asserting on
  messages an operator will read.

**Extended beyond the finding to the token request**, where the same gap had a worse consequence: a
307 or 308 preserves method and body, so a cross-origin redirect there forwards a refresh token or an
authorization code to another host, and the downgrade rule does not notice an https-to-https hop. The
test uses a *working* https token endpoint on the other origin, recording what it receives, so the
refusal is attributable to the policy rather than to a broken target.

**The pattern, now three for three.** Round four: one guarantee undermined by a different field. Round
five: one list answering two questions. Round six: a property established at check time and dissolved
at use time. None was a wrong rule in isolation — each was a *coupling* between a rule and a mechanism
elsewhere. The question that finds these is not "is this check correct" but "what else can change the
thing this check just established", and it is the question to ask first on any further pass.

### Seventh review round: policy keyed on the wrong question

Two findings, both P2, both the same misattribution: discovery-input policy applied on the basis of
*whether discovery ran* rather than *what the tunnel server actually chose*.

- **A configured issuer was filtered as discovered input.** Discovery runs when any essential value is
  missing — including when only `--oidc-client-id` is — and the advertised issuer was then put through
  the transport and address rules, and the shared HTTP client wrapped with the address guard. So an
  operator's own loopback issuer worked or failed depending on whether an unrelated flag was supplied,
  contradicting a promise this documentation makes in three places.

  Fixed with one predicate, `authorizationServerIsRemotelyChosen`: false whenever `--oidc-issuer` or
  `--oidc-metadata-url` fixes the authorization server's location. In that mode nothing the client
  fetches was located by the tunnel server — the resource URL is typed by the operator, the
  authorization server's document comes from the operator's own issuer or metadata URL, and a
  *published* metadata URL is adopted only within that issuer's origin — and what the tunnel server may
  still supply, a client ID and an audience, names no address at all. The shape rule still applies to
  everything, since a value that is not a usable http(s) URL is worth refusing whoever chose it.

- **A hint was judged before the decision not to use it.** With an issuer configured, a cross-origin
  published metadata URL that was also plaintext or internal failed the transport and address rules and
  became a hard error, so the documented "announced and ignored" outcome was unreachable for exactly
  the values a hostile server would choose — turning a hint into a denial of service against a client
  that had pinned its issuer and should have been immune. Now the same-origin comparison comes first
  and nothing is validated that is not about to be adopted.

Two notes on the tests, because both mutations initially passed and the reasons were different:

- the ordering fix was invisible against a hint that fails only the *discovery* rules, since those are
  skipped anyway once an issuer is configured. It is detectable against a hint that fails the **shape**
  rule, which applies regardless of who chose the value — so the test now covers a `file://` hint as
  well as an internal one;
- the early return in `adoptAuthorizationServer` turned out to be genuinely unobservable: the only
  value that reaches the check there is the configured issuer itself, which passed the same shape rule
  at parse time. The guarantee lives in the predicate, and the comment now says so instead of claiming
  the return as a mechanism. Same discipline as the `--resource-url` indirection removed in round two,
  applied to a comment rather than to code, because the return does make the function clearer to read.

The recurring lesson, in its fourth form: **a rule is only as good as the question it is keyed on.**
Rounds four to six were rules undermined by a coupling elsewhere; this one is a rule keyed on a
correlate of its subject — "discovery ran" instead of "the tunnel server chose this" — which is the
same error one level up.

### Eighth review round: unparsed remote text reaching a terminal

One finding, and an instructive interaction with the previous round.

**Values a document chose were printed raw.** The published metadata URL is announced when it loses the
same-origin comparison, and round seven had deliberately moved that announcement *ahead* of validation
so an unusable hint could be ignored rather than fail the flow. The consequence was not obvious: the
values that reach that line are precisely the ones no parser accepted — `url.Parse` refuses control
characters, so a hint carrying them fails `SameOrigin` and takes exactly that branch. Raw, an escape
sequence can erase or rewrite the line reporting it, and a carriage return can overwrite it, so a
refusal can be made to read as a success; the same bytes forge a neighbouring record in a log
aggregator. The bounded HTTP error body had the same shape.

Fixed with `%q` at each sink. The audit found three sinks beyond the two reported, all the same class:

- the issuer-mismatch comparison, which prints a document's self-declared issuer — a string that is
  compared but never parsed, so nothing else would reject anything in it;
- the OIDC callback's `error` parameter, chosen by whoever answered the authorization request;
- the three control-message reasons logged by `handleControlMessages`, chosen outright by the tunnel
  server. Those predate this work, and were fixed anyway: leaving known sinks of the same class while
  fixing two would be an odd place to stop.

Deliberately *not* quoted: values that came through `url.Parse` (which refuses control bytes) or
through the client-ID, scope and audience charset checks, since those cannot carry any; and the
authorization URL printed for the user to copy into a browser, where quoting would break what the line
is for.

The interaction is the part worth remembering. Round seven's fix — decide before validating — was
right, and it *moved an unvalidated value to an output sink*. Neither change was wrong on its own; the
hazard existed only in their combination. Which is the same lesson as rounds four to seven in yet
another form, and the reason the question to ask of a change is not only "is this correct" but "what
does this newly expose, and to whom".

### Ninth review round: the sink that is not ours

Two findings, and together they show why round eight's approach was necessary but not sufficient.

- **A dependency renders untrusted bytes for us.** `golang.org/x/oauth2` embeds a non-conforming token
  endpoint response body — and the HTTP reason phrase with it — directly in
  `RetrieveError.Error()`. Wrapping that with `%w` and printing it with `%v` puts whatever the endpoint
  chose on the terminal, and in zero-configuration mode the tunnel server chooses that endpoint. There
  is no format verb in this repository to correct: the bytes appear when the dependency renders itself.

  Round eight quoted each site where *this code* formats a remote value. That was the right fix for
  those sites and it cannot reach this one, so the escaping now also happens at the boundary where text
  reaches a person: the client's standard logger writes through `safeLogWriter`, which escapes control
  characters and preserves one trailing newline so records stay one to a line. That covers every log
  call in the binary, including ones in code not yet written. The two mechanisms are complementary —
  per-site quoting delimits a value that is known to be remote, the boundary catches what we do not
  format — and each has its own test.

  The server needs no equivalent, and this is worth knowing rather than assuming: it routes the
  standard logger into slog's JSON handler, and JSON encoding escapes control characters as a matter of
  course.

- **The HTTP reason phrase was still from the wire.** `response.Status` is `"403 Forbidden"` as the
  *server* wrote it, and Go's client parser passes control bytes there straight through — verified with
  a raw listener rather than assumed, since it is the part of a response that looks least
  attacker-influenced. Errors now describe a response with the numeric code plus Go's own `StatusText`.

Three things this round corrected in my own understanding, all worth recording:

- **The refresh path does not display its error.** The finding cited both the refresh and the exchange;
  driving the real binary showed a failed refresh is swallowed, because `tokenForResolvedIdentity`
  treats anything that is not a refusal as grounds for interactive login — the client sat waiting for a
  browser callback rather than reporting. The exchange path does display it, and so does a refresh with
  no fallback available. The boundary covers all of them, which is the argument for a boundary.
- **`git checkout` on a staged file is not a revert to my edits.** Used twice in mutation scripts, it
  silently reverted files to their staged versions and dropped that round's work — caught by a full run
  both times, but the lesson is to back up with `cp` and never `git checkout` during a mutation check.
- **A mutation found an untested production link.** Deleting the installation from `main` broke no
  test, because every test installed the writer itself — the same shape as the
  `newAuthTokenSource` and `parseClientConfig` gaps from rounds two and seven. Extracted
  `installSafeLogging` so the wiring has a name a test can reach, and stated plainly what remains
  uncovered: main's single call to it, which no test can reach.

### Mutation checks run

Every security-relevant assertion in this work was verified by breaking the code and confirming the
test fails — the discipline the previous plan arrived at after shipping tests that proved nothing:

- redirect guard removed from `authmeta.fetchDocument` → the plaintext mirror serves a *valid*
  document, so the fetch succeeds and the test fails on "want the redirect refused" rather than on a
  coincidental mismatch;
- `cacheMatchesResolved` removed → the refresh token reaches the token endpoint, caught by the
  collector rather than by an error value;
- the per-field exemption in `cacheMatchesConfigured` widened to every unconfigured field → a token
  minted for another audience is reused;
- the origin check in `FetchProtectedResource` removed → a document describing `elsewhere.example`
  is accepted;
- resolution moved above the cache check → `TestCacheHitMakesNoRequestAtAll` fails, which is the
  only thing standing between this feature and an HTTP request per `ssh` invocation;
- the client's `--no-resource-metadata` no longer suppressing the lookup → the parse test fails.
  This one initially *passed*, which is what exposed the restated-condition problem above; it is
  recorded because a mutation check that passes is the useful outcome, not the wasted one;
- the static internal-address check neutered → the direct test of it fails; the dial guard removed
  → the integration test fails on the metadata endpoint having been reached. Split into two tests
  after a single one passed under the first mutation: with the guard active the dial is refused
  before the static check is ever consulted, so one test could not cover both layers and the name
  it carried claimed otherwise;
- the origin-only comparison restored → the differing-path and differing-query tests fail;
- the retry disabled → the token source is never consulted; the changed-configuration guard removed
  → a replacement is offered when nothing changed, which is the browser-on-every-invocation bug;
- the query dropped from `resourceURLForTunnel` again → both `parseClientConfig` tests fail, where
  the previous round's tests had stayed green;
- the RoundTripper destination check removed → the proxied internal destination is reached; the
  proxy-hop exemption removed → a public destination through a loopback proxy is refused, which is
  the false positive the exemption exists for;
- the challenge query dropped → the follow-the-challenge test fails. This one initially passed for
  want of any test at all, which is why the test was written before the fix was believed;
- http(s) removed from the identifier rule → the derivation and normaliser tests fail. The
  `--resource-url` indirection through `ProtectedResourceURL`, by contrast, could *not* be caught,
  and was removed for that reason;
- the local classification made to resolve again → the resolver seam test fails. The first version of
  that test passed under the mutation, because a hermetic fixture has no non-reserved name that
  resolves to loopback; the seam is what made the property assertable at all, and the limit is
  recorded in the test's own comment;
- the plaintext-via-proxy refusal disabled → that test fails on the public destination, which no
  address rule would have refused; and the refusal widened back to *every* proxied request → the
  https-through-a-proxy tests fail, so the scoping is pinned from both sides;
- the proxy-hop dial exemption removed → proxied https fails on the loopback proxy's own address,
  which is the false positive that exemption exists for;
- the escaped path dropped at either site → the `%2F` tests fail, including the one asserting the two
  spellings do not share an identity;
- the escaping writer made a pass-through → the writer and boundary tests fail; `installSafeLogging`
  made a no-op → the wiring test fails; the wire reason phrase restored → the raw-listener test fails;
- every `%q` sink reverted to `%s` at once → the announcement, the HTTP body, the mismatch and the
  control-message tests each fail on raw control bytes, so no sink is covered only by another's test;
- the predicate widened to "discovery ran at all" → both configured-value tests fail; forced false
  entirely → the zero-config filtering tests fail, so the boundary is pinned from both sides;
- the metadata redirect pin removed → the open-redirect test adopts the attacker's endpoints again;
  the token-leg pin removed → the credential reaches the other origin; the origin comparison relaxed
  to ignore ports → both fail, which is how the hostname-only version was caught in the first place;
- the relaxation widened back to the whole refusal set → the property test fails, naming IMDS; and
  narrowed too far, with `localhost` dropped → the documented development path fails, so the set is
  pinned from both sides;
- the metadata-URL gate removed → the relocated-document test fails on the adopted URL. Gating on
  `identity.Issuer` instead of `s.issuer` initially passed, because the exploit test's document echoes
  the configured issuer and the two values are equal there; the case that separates them is an
  *unpinned* client accepting a cross-origin location, which must keep working. Both are now pinned.

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
| `authunnel_default_scopes` | `--client-default-scopes` when set. Round twelve moved this off the registered `scopes_supported`; see that section for why. |

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
dispatcher, and the published scope list into the same URL's query: both are length-capped and restricted
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
   and the server-published default could then never win. The default is now applied at parse time only when
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

### Review rounds, all findings fixed

Ten rounds, 21 findings. The invariants they produced live in DEPLOYMENT.md and DEVELOPMENT.md;
what is kept here is the finding, the fix, and the pattern that connects them.

| # | Finding | Fix |
|---|---------|-----|
| 1 | Resource comparison was origin-only; RFC 9728 §3.3 requires the whole identifier, so a document about `/a/tunnel` could configure a client asking about `/b/tunnel` | Exact comparison after syntax normalisation; `--resource-url` declares an externally visible identifier for path-rewriting proxies |
| 1 | Discovered addresses unfiltered (§7.7): a public tunnel server could aim the client's auth traffic at loopback or IMDS | Resolution check plus a dial guard that connects to the address it verified; deny-list moved to `internal/ipblock` so client and server share one answer |
| 1 | The tunnel URL's query was dropped from the resource identity, collapsing `?tenant=a` and `?tenant=b` onto one cache entry | Query carried through the §3.1 derivation, the comparison and the cache key |
| 1 | A stale-but-unexpired cached token was an unrecoverable lockout after a server reconfiguration | One re-resolve and retry, gated on the configuration having actually changed; keyed on 401 **or** 403, since this server answers a failed token with 403 and a 403 carries no challenge |
| 2 | The query was still dropped in `resourceURLForTunnel` — the function that actually produces the cache key | Fixed, and the tests moved to run through `parseClientConfig` |
| 2 | The dial guard was bypassed by an HTTP proxy: it inspected the proxy's address while the destination went unchecked | A RoundTripper destination check (which also covers each redirect hop) plus a context marker exempting the proxy hop, so a loopback proxy is not refused |
| 2 | The `WWW-Authenticate` challenge omitted the query, so a conforming client fetched a document that failed its own equality check | Challenge and document derived from one accessor |
| 2 | `--resource-url ftp://…` normalised fine and would publish an unretrievable identifier | http(s) folded into `NormalizeResourceIdentifier`, the single identifier rule |
| 3 | The condition that relaxed the address guard was attacker-supplied: it resolved the tunnel host and treated a blocked answer as internal | Decided from the spelling alone, resolving nothing; all resolution moved behind one seam a test can assert on |
| 3 | Documenting the proxy exposure was not a fix — and refusing every proxied request was not the right one | Refusal scoped to *plaintext* via a proxy; proxied https is allowed because the certificate binds the origin, verified with a relay fixture rather than reasoned about |
| 3 | Escaped path segments were collapsed, merging `/tenant%2Fone` with `/tenant/one` | Escaped form carried at all three derivation sites |
| 4 | `--oidc-issuer` did not pin where the metadata came from: the issuer and the published metadata URL both come from the tunnel server | A published metadata URL is adopted only within the configured issuer's origin, gated on the *configured* value rather than one just adopted |
| 5 | Link-local, IMDS, multicast and unspecified literals disabled every guard, because the relaxation set was the refusal set | Narrowed to loopback plus `localhost`/`*.localhost`, pinned by a property test over the whole refusal set |
| 6 | A same-origin open redirect defeated the round-four pin: the fetch followed redirects anywhere on https | Metadata fetch pinned to its starting origin, and the same pin extended to the token requests, where a 307 preserves the credential-bearing body |
| 7 | A configured issuer was filtered as discovered input, so an operator's own loopback issuer worked or failed depending on an unrelated flag | One predicate, `authorizationServerIsRemotelyChosen`, keyed on who chose the authorization server |
| 7 | A hint was validated before the decision not to use it, turning "announced and ignored" into a denial of service against a client that had pinned its issuer | Same-origin comparison first; nothing validated that is not about to be adopted |
| 8 | Values a document chose were printed raw, so an escape sequence could rewrite the line reporting a refusal | `%q` at each of five sinks; deliberately not applied to values that came through `url.Parse` or the charset checks, nor to the authorization URL a user must copy |
| 9 | `golang.org/x/oauth2` renders a non-conforming token response body inside its own error, so there is no format verb here to correct | Escaping added at the boundary as well: the client's logger writes through `safeLogWriter`. The server needs no equivalent — slog's JSON handler escapes as a matter of course |
| 9 | The HTTP reason phrase was still from the wire; Go's parser passes control bytes through | Errors report the numeric code plus Go's own `StatusText`, verified with a raw listener |
| 10 | An empty fragment stopped being rejected: a sweep called `strings.Contains(rawURL, "#")` a dead disjunct and I removed it | Restored, with the asymmetry recorded next to it — a bare `?` records itself in `url.URL.ForceQuery`, and there is no `ForceFragment` |

**The pattern, in seven forms.** None of these was a wrong rule in isolation; each was a *coupling*
between a rule and a mechanism elsewhere. One guarantee undermined by a different field (4). One list
answering two questions (5). A property established at check time and dissolved at use time (6). A
rule keyed on a correlate of its subject (7). A correct change newly exposing an unvalidated value
(8). A sink owned by a dependency (9). And a check deleted because a claim about it sounded right
(10). The question that finds these is not "is this check correct" but "what else can change the
thing this check just established" — and, before deleting anything, "state what it was for and
construct the input it was guarding against".

Two process notes worth keeping:

- **Twice the error was reaching for a client-side check without first asking what the transport
  already guarantees** — once by under-scoping the address guard and once by over-scoping it.
  Establish what TLS is already binding before deciding what needs pinning.
- **`git checkout` on a staged file is not a revert to your edits.** Used twice in mutation scripts,
  it silently restored the staged version and dropped that round's work. Back up with `cp`.

### Mutation checks run

Every security-relevant assertion here was verified by breaking the code and confirming a test
fails. The full list is in the git history of this file; what is worth keeping is the checks that
initially **passed**, since each exposed a test that proved less than its name claimed:

- `--no-resource-metadata` no longer suppressing the lookup. The parse error restated
  `needsDiscovery`'s condition instead of deriving from it, so the suppression term was
  unobservable. One expression now gates both.
- The static internal-address check neutered. With the dial guard active the dial is refused before
  the static check is consulted, so one test could not cover both layers; split in two.
- The `--resource-url` indirection through `ProtectedResourceURL`. Genuinely undetectable — that
  function adds no rejection the normaliser does not already make — so the indirection was removed.
  A distinction no test can see is not defence in depth.
- The local classification made to resolve again. A hermetic fixture has no non-reserved name that
  resolves to loopback; the resolver seam is what made the property assertable at all.
- The early return in `adoptAuthorizationServer`. Verified unobservable: the only value reaching it
  is the configured issuer, already shape-checked at parse time. The code stayed for readability and
  the comment now attributes the guarantee to the predicate instead of claiming the return.
- `installSafeLogging` deleted from `main`. Every test installed the writer itself — the same shape
  as the `newAuthTokenSource` and `parseClientConfig` gaps. Extracted so the wiring has a name a
  test can reach; `main`'s single call to it remains uncovered, which DEVELOPMENT.md records.
- Gating the metadata pin on `identity.Issuer` rather than `s.issuer`. The exploit fixture's document
  echoes the configured issuer, so the two are equal there; the case that separates them is an
  *unpinned* client accepting a cross-origin location, which must keep working.

### Merging main, and one reversal

Main landed PR #68, a behaviour-preserving simplification of this same area. Its API is adopted here:
`CheckDiscoveredEndpoint` (shape and downgrade fused), `CheckHTTPURL`, `CheckConfiguredURL`.

One of its non-goals is in direct tension with round six: *"Preventing HTTPS-to-HTTPS redirects. A
request rooted at the issuer's authenticated HTTPS origin may follow an authenticated delegation."*
Round six made the origin pin unconditional, arguing that a conditional rule forces a reader to work
out which case they are in. That argument loses to a stated non-goal, so the pin is now split:

- **Metadata fetches** — pinned only for a *published* location adopted under a configured
  `--oidc-issuer`. Everywhere else main's delegation case is permitted: an unpinned client has no
  origin to hold a redirect to, an operator's own `--oidc-metadata-url` is a location they chose, and
  the derived well-known path is the issuer's own. In the one remaining case the same-origin check on
  the published URL is the whole of the round-four fix, and an open redirect on the issuer's host
  would defeat it.
- **Token requests** — pinned unconditionally. Main's non-goal is about where a *document* may come
  from, and a document is not a credential. A 307 preserves method and body: with the pin removed,
  `TestTokenEndpointCrossOriginRedirectIsRefused` records the other origin receiving
  `grant_type=refresh_token&refresh_token=…` verbatim. That was re-verified during the merge rather
  than taken on trust from the round-six note.

The composition order was also inverted while merging: the caller's inherited `CheckRedirect` is now
consulted **before** the origin pin, so a redirect that is both a downgrade and an origin change is
reported as the downgrade — the more specific fault. The composed verdict is unchanged.

**Round eleven, second finding: an empty query was dropped from the identity.** A `--tunnel-url`
ending in a bare `?` is recorded by `url.Parse` in `ForceQuery`, not `RawQuery`, so all four
reconstructions on this path — the client's derivation, the §3.1 derivation, the identifier rule and
the server's published identifier — carried only `RawQuery` and lost the delimiter. Verified on the
wire rather than argued: Go's client sends `RequestURI="/protected/tunnel?"`, so the dial and the
cache key were describing different resources, and because `--resource-url` is published *verbatim* a
declared identifier ending in `?` would have failed the client's exact §3.3 comparison outright.

This is round ten's asymmetry collecting its debt. That round wrote down that a bare `?` records
itself in `ForceQuery` while a bare `#` does not — as an argument for keeping the fragment's
raw-string check — and did not ask whether anything *used* the record it had just described. Fixed
with one exported `CarryQuery(dst, src)` called at all four sites, rather than a fifth restatement of
the query rule; each site's mutation now fails a test on its own.

**Round eleven, first finding — the split's own bug, and round six's pattern again.** The pin was recorded
on the source when the published URL was adopted, and `TokenAfterRejection` discards `s.effective` and
re-resolves — so a server that stopped publishing a metadata URL left a stale pin on the *derived*
fetch, refusing the very delegation this split exists to permit. Fixed by deleting the field:
`metadataOriginIsPinned()` derives the answer from `s.effective`, which is the state that gets reset,
so there is nothing left to forget. A property established at one moment and stored outlives the thing
it described — the fix for that is to compute it from the state it is a property *of*, not to add
another line to a reset.

## Round twelve: external review before the PR

An external review of the branch raised five P2 findings and a simplification recommendation. All
five were verified against the code before any decision was taken; two of them contradict choices
recorded earlier in this plan, and those were put back to the operator rather than settled here.
Two of the five are cases where a *comment in this repository argued for the wrong behaviour*, which
is the failure mode rounds four to eleven kept finding, so they are treated as such.

### Verified verdicts

| # | Finding | Verdict |
|---|---------|---------|
| 1 | `scopes_supported` treated as "request all of these" | **True.** `applyResourceMetadata` adopts `strings.Join(document.ScopesSupported, " ")` verbatim — no intersection, no cap beyond `maxScopeBytes`. Under RFC 9728 §7.2 the field is the *protected resource* disclosing the scopes it supports; it does not mean every listed scope should be requested, and a client asks only for what it needs. The wire field's own doc comment read "the scopes a client should request", which is the reading §7.2 warns against. |
| 2 | Server validation config coupled to client publication | **True, and unavoidable today.** `--oidc-metadata-url` and `--oidc-jwks-uri` are mutually exclusive (`server.go:885`), and the published hint is `cfg.OIDCMetadataURL` verbatim (`server.go:1029`), so pinned-JWKS isolation forces the hint to be absent. The comment defending this ("a separate value could only ever be set inconsistently") rests on a premise `pinned_jwks` mode explicitly breaks — and `DEVELOPMENT.md` already says so elsewhere. |
| 3 | Proxied HTTPS bypasses the address guard | **True. Deliberate in code; incompletely described in the deployment documentation** — which is what work item E exists to correct, so "documented" would contradict this plan's own remedy. TLS authenticates a hostname, which is not proof the address is public. |
| 4 | Guard stacking on re-resolution | **True, and worse than reported.** The second wrap finds a `*destinationGuard` rather than an `*http.Transport`, takes the fallback branch with `proxyFor == nil`, and so applies `CheckPublicAddress` to *proxied HTTPS* — the one check that path exists to skip. Behind a CONNECT proxy the lockout recovery therefore fails on local DNS. Zero test coverage: the only double-resolution test never installs the guard. |
| 5 | §3.1 trailing-slash derivation | **True, and internally inconsistent.** `TrimSuffix(EscapedPath(), "/")` sends `/tenant` and `/tenant/` to one metadata location, while `protected_resource_test.go:220` pins those two as identifiers that must *not* collapse. Masked against authunnel's own server by subtree routing; it bites a conformant third-party resource server. |

The reviewer also confirmed the empty-query finding as already fixed at head, and re-raised guard
stacking and the trailing slash as previously-noted-but-open. Both were open. That is the cost of
recording a finding without a failing test.

### Decisions taken

1. **Scopes — publish a namespaced field.** `scopes_supported` is dropped from the document, and
   note *why* rather than only that it was misread: §7.2's field is a disclosure by the resource of
   the scopes it supports, and authunnel supports no scope requirement at all — it reads no `scope`
   claim — so it has nothing truthful to put there. What it can offer is advice about the request;
   `authunnel_default_scopes` replaces it, and only that field is adopted. The registered field's
   meaning is left to the registry. The flag is renamed `--client-default-scopes` so the operator
   interface mirrors the wire field, and "default" says what the precedence already does: a client's
   own `--oidc-scopes` still wins.
2. **Split the metadata URL by *question*, not by process.** New `--client-oidc-metadata-url` for
   publication, falling back to `--oidc-metadata-url` when unset, and permitted alongside
   `--oidc-jwks-uri`. The two flags answer "where does *this process* fetch keys" and "where should
   *clients* fetch metadata"; the mutual exclusion is right for the first and was wrongly extended
   to the second.
3. **Proxied HTTPS stays allowed, on stated preconditions.** A non-intercepting CONNECT proxy
   preserves end-to-end certificate verification, and that — not the proxy's egress policy — is what
   the trust rests on. The residual discovery-driven SSRF case is an internal endpoint presenting a
   certificate trusted for its requested hostname.

   **What `--oidc-issuer` does and does not answer.** It stops the *resource server* from selecting
   that hostname, which is the only part of this a client-side flag can reach. It is **not** a
   defence against TLS interception: a proxy holding a client-trusted CA can forge metadata carrying
   the configured issuer, so an intercepting proxy is trusted with the OAuth exchange and must either
   be accepted as such or bypassed for these destinations. Nor does it make an operator-configured
   internal issuer *safe* — that is simply a destination the operator has chosen to trust, which is
   the documented position on configured values everywhere else in this work. No code change; the
   documentation stops implying the guard covers this path.
4. **Keep the 401/403 recovery; fix the wrapper.** The requirement it meets, stated so the
   complexity is auditable: **seamless server-configuration rotation during the lifetime of a cached
   access token.** It is not an unbounded lockout — once the cached access token expires the ordinary
   slow path re-resolves and recovers on its own, so what the recovery buys is the window before
   that, not eventual recovery. If seamless mid-token rotation is not a requirement, this remains
   the largest removable piece of complexity in the branch, and that is the trade to revisit first.

   The bug is separate from the question of whether to keep it: the accidental second wrapper, whose
   local DNS check breaks otherwise valid proxy-side resolution — the very thing decision 3's trust
   model depends on. Fixed by making `httpClient` immutable and building the guarded client once.
5. **One PR.** The safe-logging boundary is a prerequisite of this feature rather than a tangent:
   zero-config means the tunnel server chooses the token endpoint whose errors reach the terminal,
   and a dependency renders some of that text itself. The `internal/ipblock` move exists because
   client and server now ask one question. Splitting either would land discovery with a known
   unescaped-output path.

### Work items

**A. Scopes (finding 1).** Rename the wire field to `authunnel_default_scopes` in
`internal/authmeta/protected_resource.go` and correct its doc comment to say what it is — a default
the publisher suggests, not a capability list. Rename `ResourceMetadataConfig.Scopes` usage in
`internal/tunnelserver/resourcemeta.go:112`, and the flag/env in `server/server.go` (`--client-scopes`
→ `--client-default-scopes`, `CLIENT_SCOPES` → `CLIENT_DEFAULT_SCOPES`), including the usage text and
the `--no-resource-metadata` hint-rejection list. The client's hint-table entry in
`applyResourceMetadata` (`client/auth.go:597`) changes field and label only — the precedence chain,
the validate-the-slice-not-the-joined-string note, and the `defaultOIDCScopes` fallback all stand.
Update the `scopes_supported` row in `docs/DEPLOYMENT.md:223`.

**B. Metadata URL split (finding 2).** Add `ClientOIDCMetadataURL` to `serverConfig` with flag and
env, validated by the same `authhttp.CheckConfiguredURL` rule as the server's own. In
`resourceMetadata()` (`server/server.go:1029`) publish `cfg.ClientOIDCMetadataURL` when set, else
`cfg.OIDCMetadataURL`. Delete the "could only ever be set inconsistently" comment and rewrite
`TestAuthorizationServerMetadataURLHintTracksServerConfig`'s premise; add cases for the new flag
alone, the fallback, and the previously impossible `--oidc-jwks-uri` + published-hint combination.
Remove the pinned-JWKS caveat from `docs/DEPLOYMENT.md` § *Issuer metadata and key discovery*.

**C. Client HTTP-client lifecycle (finding 4).** `httpClient` becomes write-once; add a `guarded`
field and one accessor:

```go
func (s *managedOIDCTokenSource) fetchClient() *http.Client {
	if s.allowInternalTargets || !s.authorizationServerIsRemotelyChosen() {
		return s.httpClient
	}
	if s.guarded == nil {
		s.guarded = authhttp.RefuseInternalAddresses(s.httpClient)
	}
	return s.guarded
}
```

Delete the assignment at `client/auth.go:430`; route the protected-resource fetch, the
authorization-server fetch (`:495`, still origin-pinned on top where applicable) and
`credentialClient()` (`:916`) through it. The condition is a pure function of *configured* fields —
`authorizationServerIsRemotelyChosen` reads only `s.resourceURL`/`s.issuer`/`s.metadataURL`, none
assigned after construction, and `allowInternalTargets` comes from the syntactic
`HostIsAlwaysLocal` — so one client is correct for every resolution. Memoise only the positive
verdict: a cached "no guard needed" is the one way this shape could silently disable the guard. No
extra synchronisation — every path already holds `s.mu`. Add a paragraph to
`RefuseInternalAddresses`' doc saying it must be applied to a base client and never to its own
output, because `authmeta.fetchDocument` documents the opposite rule for the `CheckRedirect`
wrappers and that is what invited this.

**D. Trailing slash (finding 5).** In `deriveProtectedResourceURL`, strip the path only when it is
exactly `/` — §3.1 removes the terminating slash *following the host component*, which is also why
it mentions the query case. Table-drive the derivation over `/`, `/tenant`, `/tenant/`, `/a/b/`, and
assert that the two identifiers the must-not-collapse list keeps distinct derive distinct locations.
`NormalizeResourceIdentifier` is already correct and does not change.

**E. Documentation (finding 3 and the comment sweep).** In `docs/DEPLOYMENT.md` § *Discovered
addresses and the internal-address guard*, replace the current proxy passage with decision 3 as
written above: allowed because a non-intercepting CONNECT proxy preserves end-to-end certificate
verification; the residual case is an internal endpoint with a certificate trusted for its requested
hostname; `--oidc-issuer` removes the resource server's ability to *name* that host and is not a
defence against interception, which is a separate trust decision about the proxy itself.

Three specific sentences to correct, all already located: `DEPLOYMENT.md:301` ("TLS is the binding")
overstates what a certificate proves — it binds the hostname; `DEPLOYMENT.md:391` ("Three layers,
because each sees something the others cannot") is true only of the direct path and must say so; and
`DEPLOYMENT.md:413` offers "the proxy's own egress policy" as the control for a TLS-terminating proxy,
which is the wrong control — an intercepting proxy is trusted with the OAuth exchange itself, and the
choice is to accept that or bypass it for these destinations. `README.md`'s "Enforced at three
layers" bullet inherits the same overstatement, as does `docs/DEVELOPMENT.md`'s summary. The three
preconditions belong in DEPLOYMENT as the conditions under which the model holds, not as a footnote.

Then the comment sweep: `internaladdr.go`'s package doc and `protected_resource.go` still argue cases
rather than state invariants, and `internaladdr.go`'s claim that "TLS binds the origin" needs the
same correction as the prose — it binds the *hostname*, which is a different and weaker statement.

### Verification

Per work item, and every security-relevant assertion mutation-checked as in the rounds above:

- **A**: a client configured with `--oidc-scopes` still overrides; a document with no
  `authunnel_default_scopes` falls back to `openid offline_access`; a document carrying only the old
  `scopes_supported` is *ignored* — that last one is the mutation that proves the field rename took
  effect rather than both being read.
- **B**: `--oidc-jwks-uri` with `--client-oidc-metadata-url` starts, publishes the hint, and makes
  no startup metadata fetch. Assert the fetch count, not just the config.
- **C**: two tests, because "the recovery succeeded" and "the guard was installed at all" are
  different claims and success alone can satisfy the first while failing the second.

  *Structural.* After the first resolution, `s.guarded` is non-nil — the guard really was installed,
  so nothing below is vacuous. After `TokenAfterRejection`, it is the **same pointer**, and
  `s.httpClient.Transport` is unchanged from construction. Note what each assertion is worth, so a
  later reader does not mistake one for the other: the base being untouched is the *correctness*
  invariant, since rebuilding from a wrapper is what produced the bug. Pointer reuse is not — a
  rebuild from the immutable base would yield an equivalent policy — and it is pinned for two
  narrower reasons: one connection pool across resolutions, and a guard that later acquires state of
  its own would otherwise be silently re-created. The test says which is which.

  *Functional*, and retained because it is what makes pointer reuse matter rather than merely hold:
  `TestTokenAfterRejectionKeepsTheAddressGuardUnwrapped` — resolve, then recover through the real
  `TokenAfterRejection`, every request via a blind CONNECT relay to a loopback `httptest` server. One
  wrap: the proxy branch skips the checks and both fetches succeed. Two wraps: `CheckPublicAddress`
  refuses `127.0.0.1`. No resolver stub needed, which is what makes this assertable from package
  `main` at all. Two anti-vacuity mutations: drop `resourceIsLocal` (the control must fail) and drop
  `transport.Proxy` (the *first* resolution must fail).
- **D**: the derivation table above, plus the existing exact-comparison test still passing.
- Whole tree: `gofmt`, `go vet`, `go test ./...`, `-race`, `make lint`, link/anchor check, `make
  build` help output for the two renamed/added flags, and the zero-config e2e.

### Outcome

All five items landed, each mutation-verified. What the mutations showed, beyond "the tests fail":

- **C**: restoring the cumulative wrap fails the two new tests and **nothing else in the repo** —
  which is exactly why the bug survived review twice. The functional test reproduces the reported
  failure verbatim: `refusing to reach an internal address named by a remote metadata document` on
  the *second* resolution, for a proxied request whose address should never have been checked.
  Rebuilding the guard from the base rather than from its own output leaves the functional test green
  and trips only the pointer-reuse assertion, confirming those two assertions pin different
  properties — as the test comments now say.
- **A**: the field rename is caught by `TestRegisteredScopesSupportedIsNotAdopted` (client) and
  `TestPublishedWireKeysAreTheAgreedOnes` (server). The latter was added because every other server
  test decodes into the Go type and would follow a renamed tag anywhere; it asserts JSON keys, and
  that `scopes_supported` is absent. The client fixture gained a raw-JSON hook, since publishing a
  field the Go type does not carry is the only way to assert that such a field is *not* read.
- **B**: pinned both directions — dropping the new flag fails three tests, dropping the fallback to
  `--oidc-metadata-url` fails the fourth. `TestPinnedJWKSSkipsDiscovery` already pinned zero metadata
  fetches in that mode, and the published value never reaches `NewJWTTokenValidator`, so the
  isolation property is untouched; the new test asserts that explicitly.
- **D**: pinned from both sides — the blanket `TrimSuffix` fails the derivation and distinctness
  tests, and stripping nothing fails the root case.

`gofmt`, `go vet`, full suite, `-race`, `make lint` (0 gosec issues), link/anchor check, complexity
gate, both binaries' help text, and the e2e suite all pass; only the Keycloak e2e skips, as it always
does without a live server.

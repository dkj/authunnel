# PLAN 2026-08: Client-side metadata location and transport rules

Follow-on to [PLAN_202608_discovery_overrides.md](PLAN_202608_discovery_overrides.md), which
decoupled metadata *location* from issuer *identity* on the server and left the client as an
explicit non-goal. This plan covers the client — but it is not a mirror image, and the
differences matter more than the similarities.

## Problem

`managedOIDCTokenSource.oauthConfig` (`client/auth.go:191-209`) calls
`oidcclient.Discover(ctx, s.issuer, s.httpClient)` with no `wellKnownUrl`, takes
`authorization_endpoint` and `token_endpoint` from the result, and uses them without inspecting
them. The HTTP client is `authhttp.NewBoundedClient()` (`client/auth.go:99`), which sets no
redirect policy. So:

1. **A downgrade on the client path discloses a credential.** An https metadata document may
   advertise `http://` endpoints, and any fetch may be redirected off https — Go follows
   cross-scheme redirects silently. The server-side version of this bug (now fixed) let an
   attacker substitute *public* signing keys. The client version puts the **refresh token** on
   the wire in clear text during the refresh grant, and the **authorization code** during code
   exchange. That is direct theft of a long-lived credential, not key substitution, and it is
   the most serious item in this plan.
2. **The same RFC 8414 interop gap exists.** An authorization server publishing metadata at
   `https://as.example/.well-known/oauth-authorization-server/tenant1` is unreachable by the
   OIDC derivation, so the client cannot be pointed at it at all.
3. **Issuer URL validation is duplicated and weaker.** `client/client.go:262-269` repeats the
   shape/scheme checks that `server/server.go` now centralises in `validateAuthURL`, and still
   reports `file://` as "not a valid URL" rather than naming the scheme.

## Goals

- Close the credential-disclosure path: the metadata and token requests this client issues may
  not be downgraded off https, and advertised endpoints must be valid `http(s)` URLs. The PKCE
  loopback callback stays plaintext by design — see "Security invariants" for the scope and why.
- Reach the same authorization servers the server can reach.
- Stop maintaining two copies of the same URL policy.

## Non-goals

- **Endpoint pinning.** There *is* an analogous case client-side — metadata unavailable while the
  endpoints still work — so this is rejected on cost, not for want of a use case: a pinned
  endpoint is a hand-typed credential destination, and a wrong one receives the refresh token
  rather than failing closed. See "Rejected" below for the full argument and for why caching
  discovered endpoints is the more promising direction, with its own risks.
- RFC 9728 protected-resource metadata. Still separate, still the thing that would remove client
  configuration rather than add to it.
- Any change to the token cache format or the PKCE flow itself.

## Why this is not a mirror of the server plan

Three asymmetries drive every decision below.

**The client's "start without the IdP" case is much narrower.** `--oidc-jwks-uri` exists because
the server can validate tokens indefinitely from a cached key set, so an unreachable issuer at
startup is an artificial failure. The client's position is weaker: on a cache hit `AccessToken`
returns at `client/auth.go:163-165` **before `oauthConfig` is ever reached**, so the common
ProxyCommand path already makes zero IdP calls and needs no endpoint at all; and when the cache
misses, the client needs the token endpoint *reachable*, not merely *known*.

There is nevertheless one state where a pinned endpoint would help, and an earlier draft of this
plan wrongly claimed there was none: **metadata unavailable while the token endpoint is still
reachable**, with a valid refresh token cached. Discovery failure currently blocks the refresh
grant even though the grant itself would succeed. That is not far-fetched — metadata and token
endpoints are often on different hosts or behind different rules, and a metadata document that
starts failing *validation* after a provider config change produces the same state. The rejection
below stands, but on cost, not on the absence of a use case.

**The failure model is interactive and per-invocation.** The server resolves metadata once per
process lifetime and fails at startup, where an operator is watching. The client is spawned per
`ssh` invocation, resolves lazily, memoises only within the process (`client/auth.go:69`,
`:192`), and surfaces errors into ssh's stderr mid-connection. A misconfiguration therefore
shows up as an intermittent ssh failure rather than a service that will not start, which argues
for validating what we can at config-parse time rather than at first use.

**What is on the wire differs.** The server fetches public keys; disclosure is not the risk,
substitution is. The client transmits a refresh token and an authorization code. Identical
downgrade mechanics, materially different consequence — which is why the security fix (item 2)
is sequenced ahead of the interop work, and why item 1 exists only to make item 2 reviewable.

## Proposed changes

### 1. Move the transport guards into `internal/authhttp` (do this first)

`refuseTransportDowngrade` and `checkNoSchemeDowngrade` are currently unexported in
`internal/tunnelserver` (`tunnelserver.go:214`, `:235`). Promote both to `internal/authhttp` as
exported helpers. Nothing else: **existing code only, moving package, keeping its existing
caller.**

In particular the new scheme-and-host allowlist helper does *not* belong here. An earlier draft
put it in this step "defined but called by nobody new", reasoning that an uncalled function
cannot change behaviour. True, and beside the point: a helper with no callers is also a helper no
test exercises, so it would land unverified in a step whose stated verification is that the
existing suite still passes. Splitting a new function from its callers buys nothing and costs its
coverage. It arrives in item 2, with both call sites and its tests.

**Scope this step to the move only. Do not change `NewBoundedClient`'s default here.** An earlier
draft had this step add the redirect guard to `NewBoundedClient` and called the result a pure
refactor. It is not: the client already uses that constructor (`client/auth.go:99`), so the
default change would alter client behaviour the moment it lands — shipping half the security fix
under a label that invites a light review, ahead of the tests and documentation that belong with
it. Moving the helpers with `tunnelserver` as their only caller genuinely is behaviour-neutral;
that is the version worth landing alone.

Changing the `NewBoundedClient` default is therefore part of item 2, with its own test and doc
changes. Keep the explicit call in `tunnelserver` regardless of what the constructor does: tests
inject their own `*http.Client` (`client/keycloak_e2e_test.go:57`, `server/server_test.go`), and
a guarantee that evaporates when a caller supplies a client is not a guarantee. Double-wrapping
is harmless — the outer guard checks, then delegates to the inner one, which checks again and
returns nil.

### 2. Reject downgraded endpoints in the client

In `oauthConfig`, after `Discover` returns, apply **two** checks to **both**
`authorization_endpoint` and `token_endpoint`:

**(a) A full URL check, not a scheme check.** Each endpoint must be an absolute `http`/`https`
URL *with a non-empty host*. Any other scheme is rejected outright, in every mode including under
`--insecure-oidc-issuer`.

Checking only the scheme is not enough, and the obvious tightening does not work either:
`url.Parse("https:relative-path")` yields `Scheme: "https"`, `Host: ""`, `Opaque: "relative-path"`
— and **`IsAbs()` returns `true`**, because it reports only that a scheme is present. `https:`
and `https:///path` are likewise scheme-`https`, host-empty. The condition that actually holds is
`Scheme ∈ {http, https} && Host != "" && Opaque == ""`.

This is the same check `validateAuthURL` (`server/server.go:387`) already performs on
config-supplied URLs, which sharpens item 4 below: the shared helper should validate **discovered**
endpoints, not only configured ones. Metadata is remote input and deserves at least the scrutiny
a local flag gets — arguably more.

This is not covered by the downgrade check and must not be folded into it. `CheckNoSchemeDowngrade`
only fires when the source is https; when metadata is fetched over `http` — the development path
`--insecure-oidc-issuer` gates — *every* resolved scheme passes, `file://` and custom schemes
included. That path is precisely the one where the document is attacker-modifiable in transit,
which is the entire premise of the downgrade concern.

The consequence is worst on `authorization_endpoint`, and worse than "handed to the OS opener"
suggests. `defaultBrowserOpener` passes the URL to `open` (`client/browser_other.go:17`),
`xdg-open` (`:21`), or `ShellExecute` (`client/browser_windows.go:26`) — all three are **scheme
dispatchers** that launch whatever application is registered for the scheme, not browsers.
The existing `#nosec G204` justification at `client/browser_other.go:26-29` reads "the url itself
is the OIDC auth URL constructed from the configured IDP; trusting the IDP is an inherent
assumption of the OIDC flow." That is sound for https metadata from a verified issuer and
unsound over http, where the supplier is whoever is on the network path. **Update that comment
as part of this work** — the annotation currently asserts a property the allowlist will be the
thing actually providing.

On `token_endpoint` the same gap is milder: a non-http(s) scheme fails inside `http.Client` with
`unsupported protocol scheme`, so it fails closed. Reject it early anyway, for a comprehensible
error and one rule rather than two.

**(b) `CheckNoSchemeDowngrade`**, judged against the URL the metadata was fetched from — the same
rule and rationale as the server: if metadata already travelled in clear text there is no
downgrade left to prevent.

Apply the redirect guard to `s.httpClient` at `client/auth.go:92-100`, covering the injected-
client path as well as the default.

The redirect guard covers the *discovery* and *token* fetches only. The `authorization_endpoint`
is dispatched to the OS, not fetched by us, so for that endpoint the allowlist in (a) is the
whole of the protection — state this in the code comment so nobody later mistakes the redirect
guard for covering the browser leg.

**This gap also exists in already-shipped server code.**
`checkNoSchemeDowngrade(metadataSource, discovery.JwksURI)` (`internal/tunnelserver/tunnelserver.go:179`)
has the identical shape: with an `http` issuer, a `file://` `jwks_uri` passes. There it fails
safely — Go's default transport refuses `file://`, verified during the server work — so it is an
error-quality and consistency gap rather than a security hole. Close it in **item 2**, alongside
the client-side check, so both callers adopt one rule together. It cannot ride along with the
helper move in item 1: wiring the allowlist into the server's discovery path changes what the
server accepts, which is precisely what item 1 must not do.

### 3. `--oidc-metadata-url` on the client (flag only — see the note in Sequencing)

Same flag name, same semantics, same mutual-exclusion-free simplicity as the server minus the
pinning half. `oidcclient.Discover` already takes the variadic `wellKnownUrl`, so this is one
argument at `client/auth.go:193` plus config plumbing. The document's `issuer` is still verified
against `--oidc-issuer` by zitadel, so it changes where metadata is fetched, never which issuer
is trusted.

Carry it in `managedOIDCTokenSource` alongside `issuer` (`client/auth.go:55`).

**Cache implication to decide during implementation:** `tokenCache` scopes entries by issuer,
client ID, audience, resource, and scopes (`client/auth.go:75-85`) — deliberately, to avoid
cross-provider reuse. The metadata URL does *not* belong in that key: it changes where endpoints
are found, not which issuer minted the token, and adding it would invalidate every cached token
the first time an operator sets the flag. Verify this reasoning holds before implementing; if a
metadata URL can ever change which token you get back for the same issuer, it belongs in the key
after all.

### 4. Share the URL validation helper

Lift `validateAuthURL` (`server/server.go:387`) into a shared location and use it for the
client's `--oidc-issuer` and the new `--oidc-metadata-url`. This picks up the explicit `file://`
rejection on the client for free.

`internal/authhttp` is the natural home given items 1–2 also land there, though it is arguably a
config-validation concern rather than an HTTP one — if `authhttp` starts looking like a grab bag,
a small `internal/authurl` is the alternative. Decide when the shape is visible, not now.

## Rejected: `--oidc-authorization-endpoint` / `--oidc-token-endpoint`

There is a real operational state these would serve — metadata unavailable, token endpoint
reachable, refresh token cached — so this is a cost/benefit rejection, not a "no use case" one.
Against:

- **A wrong value fails dangerously, not closed.** A bad `--oidc-jwks-uri` rejects tokens. A bad
  `--oidc-token-endpoint` *sends the refresh token to it*. A typo, or a stale value after a
  provider migration, becomes credential disclosure rather than a failed login. Given this plan
  exists largely to stop refresh tokens reaching the wrong transport, adding a flag whose failure
  mode is "refresh token goes to an operator-specified URL" cuts against its purpose.
- **They come in pairs.** Pinning one and discovering the other is incoherent, so the real cost
  is two flags, their interaction with `--oidc-metadata-url`, and the mutual-exclusion rules
  that follow.
- **It is configuration standing in for something already known.** Both endpoints were, at some
  point, successfully discovered and verified against the issuer. Asking an operator to
  re-supply them by hand — permanently, to cover an outage — converts verified data into
  hand-typed data, with the failure mode above.

**Caching discovered endpoints is the more promising answer to that state**, but it is not a free
one, and an earlier draft of this plan wrongly said it carried "no new credential-disclosure
surface". It does. The client already persists a token cache scoped to the issuer
(`client/auth.go:75-85`); persisting the resolved `authorization_endpoint` and `token_endpoint`
next to it would cover the same outage — including interactive login, since caching both
endpoints serves the browser leg exactly as pinning both would — with no new configuration and no
operator action. What it does *not* remove is the stale-endpoint risk:

**A cached endpoint is a credential destination that was verified once and is trusted later.** If
a provider migrates and the old token-endpoint hostname lapses or is reassigned — dangling DNS,
subdomain takeover, a decommissioned host someone else can claim — the fallback sends the refresh
token there. The sharp part is the correlation: **the event that makes the cached value stale is
the same event that triggers the fallback.** A provider migration is one of the likeliest reasons
metadata at the old location stops resolving, so the design is most likely to use its cache
precisely when the cache is most likely to be wrong.

Against pinning, caching is better on staleness *window* — auto-refreshed on every successful
discovery, rather than stale until a human edits a flag — and better on typo risk, since the value
was machine-acquired and issuer-verified. Both share the underlying exposure. So the rejection of
pinning above stands, but on the narrower grounds actually listed there, not on caching being
risk-free.

Any future caching design therefore needs, at minimum:

- **a freshness limit** — refuse to fall back to endpoints cached longer than some bound, so an
  arbitrarily old value cannot become a credential destination;
- **an explicit stale-endpoint threat model**, covering provider migration, DNS reassignment, and
  subdomain takeover, rather than treating "it came from discovery once" as durable provenance;
- **a visible degraded mode**, so falling back to cached endpoints is something the user can see
  rather than a silent behaviour change on the credential path.

Out of scope here; worth its own plan if the outage case ever becomes real. These requirements are
the point of recording it — the idea is cheap to have and easy to implement badly.

## Security invariants

- **Issuer identity is unchanged.** `--oidc-issuer` remains required and remains the value
  zitadel checks the metadata document against. `--oidc-metadata-url` moves the fetch, never the
  trust anchor — identical to the server.
- **No auth traffic *that this client makes over HTTP* leaves https once it has started there.**
  Scope matters here, because one part of the flow is deliberately plaintext. The invariant
  covers the metadata and token fetches issued by our `*http.Client`, and the advertised
  `authorization_endpoint`. Enforced at two layers — a static check on advertised endpoints and a
  redirect policy on the chain — because neither catches the other's case.

  **Deliberately outside it:** the PKCE loopback callback, `http://` + the listener address
  (`client/auth.go:301`). That is RFC 8252's native-app pattern, it never leaves the host, and the
  browser leg between the user and the authorization endpoint is the browser's business, not
  ours. Stating the invariant without this carve-out would make it visibly false to anyone
  reading the code, which is worse than stating a narrower one — a security invariant that is
  wrong in an obvious case trains readers to discount it everywhere.
- **The insecure override stays transport-only.** It permits `http://`, it does not widen
  permitted schemes; `file://` stays refused on both sides.

## Test plan

Client-side, mirroring `internal/tunnelserver/discovery_override_test.go`:

- https metadata advertising an `http://` `token_endpoint` → refresh fails, with the error
  naming the downgrade. Assert on `token_endpoint` specifically, since it is the credential-
  bearing one;
- same for `authorization_endpoint`;
- a token endpoint that 302s from https to http → refused. Use a plaintext **mirror of a working
  token endpoint** as the redirect target, so the failure is attributable to the transport and
  not to a broken endpoint — the pattern that made the server-side tests trustworthy;
- an https→https control for both, so rejections are not just "TLS is broken in the fixture";
- an `http://` issuer with `http://` endpoints still works, i.e. the local Keycloak flow in
  `docs/DEVELOPMENT.md` is untouched;
- **under `--insecure-oidc-issuer` with an `http` metadata source**, a document advertising
  `file:///…` or a custom scheme for either endpoint is refused. Assert this for
  `authorization_endpoint` specifically with a fake opener that records what it was handed, and
  fail the test if the opener is invoked at all — the guarantee is that the URL never reaches the
  OS scheme dispatcher, which an error-only assertion would not prove;
- the same for the server: an `http` issuer whose metadata advertises a `file://` `jwks_uri` is
  refused at startup with an error naming the scheme, rather than failing later inside the
  transport;
- **host-less endpoints are refused**: `https:relative-path`, `https:`, and `https:///path` for
  each of `authorization_endpoint`, `token_endpoint`, and the server's `jwks_uri`. Worth explicit
  cases because all three pass a scheme check *and* `IsAbs()`, so a plausible-looking
  implementation admits them;
- the loopback callback stays `http://` and the interactive flow still completes, so the carve-out
  in the invariant above is exercised rather than merely asserted;
- metadata at a non-derived path resolves with `--oidc-metadata-url` and fails without it;
- a metadata document advertising a different issuer is refused (assert `oidc.ErrIssuerInvalid`,
  not just any error);
- config parsing: the flag (there is no env var — the client has none for OIDC settings),
  `file://` refused including under `--insecure-oidc-issuer`, malformed URLs, and the override
  rejected without `--oidc-issuer`;
- the override reaching discovery **through `newAuthTokenSource`**, not only through a directly
  constructed token source. Setting the field on the source bypasses the config-to-source mapping
  entirely, so a test that does that cannot detect the mapping being removed.

Plus, **for item 2**: a test that `authhttp.NewBoundedClient()` refuses an https→http redirect, so
the constructor default is covered independently of either caller. This belongs with item 2
because that is where the default changes — asserting it against item 1 would either fail, since
item 1 deliberately leaves the constructor alone, or drag the behaviour change back into a step
whose whole value is being behaviour-neutral.

**Item 1 adds no tests, and that is the point.** Its verification is that the existing
`internal/tunnelserver` suite passes untouched: the guards keep their current sole caller and only
change package. A move that needs new assertions to prove it is safe is not the move being
described here.

End-to-end against the real binaries, following the same discipline as the server work: drive
the local Keycloak flow in `docs/DEVELOPMENT.md` to confirm the happy path is unchanged, and
confirm a deliberately downgraded metadata document is refused. A unit test proving the check
fires is not the same as proving the client still logs in.

## Documentation

- `README.md` — the client flag list (`:176-188`) gains `--oidc-metadata-url`. The
  transport-downgrade bullet currently says the guard covers the server only; that scoping must
  be removed once it does not.
- `docs/DEPLOYMENT.md` § "Transport rules on the key path" — same: it explicitly states the
  managed client is unguarded. Update in the same commit as the code, not after.
- `docs/DEVELOPMENT.md` — note that the client can target a non-OIDC AS.
- Check `docs/Notes.md` too; it has drifted before.

Every one of these files currently contains a claim that this work falsifies. On the server
plan, stale prose was the entire content of four review rounds while the code itself drew none —
treat the docs as part of the change, not as a follow-up.

## Sequencing

1. ✓ done — Promote the two existing guards to `internal/authhttp`, keeping `tunnelserver` as
   their only caller. Nothing new is written in this step — no constructor default change, no new
   helper, no new call sites — so the existing suite passing unchanged is a complete check.
   Reviewable alone.
2. ✓ done — **The security fix.** The new scheme-and-host allowlist helper *and both its call
   sites*, client scheme allowlist + downgrade enforcement, the redirect guard
   applied to the client's HTTP client, the `NewBoundedClient` default change, the `#nosec G204`
   justification updated at `client/browser_other.go:26-29`, the server-side allowlist gap at
   `tunnelserver.go:179` closed, plus tests and the doc scoping corrections for all of it. Land
   before item 3; this is one change because every part of it alters behaviour on the same path.
3. ✓ done — `--oidc-metadata-url` plumbing + tests. Two decisions resolved during
   implementation:
   - **No `OIDC_METADATA_URL` env var**, contrary to this plan as first written (the section
     heading above has been corrected). The client has no
     environment variables for any OIDC flag — `--oidc-issuer` included; only `ACCESS_TOKEN` and
     `AUTHUNNEL_TUNNEL_URL` come from the environment. Adding one here alone would invite "why
     does this have an env var and the issuer does not". The plan assumed symmetry with the
     server, which does use env for everything.
   - **The metadata URL stays out of the token cache key**, as reasoned above and confirmed
     against `loadCache` (`client/auth.go:261`), which discards the cache on any mismatch of
     issuer, client ID, audience, resource, or scopes. A token obtained through the override is
     the same token — the document's issuer is verified against the configured issuer either way
     — so keying on it would discard every cached token the first time an operator set the flag.
     Recorded as a deliberate exclusion in the `tokenCache` doc comment.

   One consequence worth noting: the downgrade check is now judged against the metadata URL when
   set, not the issuer, since it is the document's own transport that decides whether an endpoint
   is a downgrade. `TestDowngradeIsJudgedAgainstMetadataURLNotIssuer` pins it.
4. ✓ done — Shared URL validation helper for config-time checks.
   - **Home: `internal/authhttp`**, the decision this plan deferred until the shape was visible.
     It earns its place by sharing code, not just space: `CheckConfiguredURL` and
     `CheckEndpointURL` now both build on one unexported `parseAuthURL` holding the single
     definition of a usable auth URL, so the rule cannot drift between configured and discovered
     values. A separate `internal/authurl` would have split the auth-URL rules across two
     packages and required moving the item-2 code as well.
   - `server/validateAuthURL` deleted (three call sites) and the client's inline copy from item 3
     replaced (two call sites). The client gains `file://`-rejected-by-name on `--oidc-issuer`,
     which it did not have.
   - **Error messages no longer append the sentinel.** Wrapping with `%w` had been putting
     ": unsafe auth transport" on the end of every message, including startup config errors an
     operator reads — noise on a line that already says what to fix. Refusals are now built by
     `refusef`, which returns a type whose `Is` matches `ErrUnsafeTransport` without contributing
     text. Identity for code, message for people; a test pins both halves.
   - One regression caught during implementation rather than review: sharing the core initially
     gave `CheckEndpointURL` a scheme message mentioning `--insecure-oidc-issuer`, which is
     meaningless for a discovered endpoint. The shared message is now neutral and
     `CheckConfiguredURL` adds the flag hint itself.
   - Small deliberate loss: the server's plaintext-rejection message no longer names
     `INSECURE_OIDC_ISSUER=true` alongside the flag, since the client has no such env var. The
     flag it does name is actionable on both, and the env var stays documented in
     `docs/DEPLOYMENT.md`.
5. Remaining docs.

Items 3 and 4 are independent. Item 2 depends only on item 1.

### Not planned, added during item 2

Writing the token-endpoint redirect test surfaced a failure mode the plan had not considered: a
refusal is an *error* to `AccessToken`, and its existing fallback chain treats any refresh error as
grounds for interactive login. So refusing a downgraded token endpoint opened a browser, would have
walked the user through authenticating, and then failed identically at the same endpoint — the
test caught it because its fake opener fails when invoked at all, which is the reason that
assertion was specified rather than an error-only check.

Fixed by adding `authhttp.ErrUnsafeTransport`, wrapped by every error the package's own policy
generates, with `AccessToken` returning immediately when it sees it. The distinction is
"retrying cannot help":
an expired or revoked refresh token *should* fall through to interactive login, a refused endpoint
should not. `errors.Is` reaches the sentinel through `net/http`'s `*url.Error` wrapping, verified
before relying on it.

### Review findings on item 2, all fixed

- **The redirect test used 302, which cannot leak.** Go rewrites 301/302/303 to GET and drops the
  body, so the refresh token would not have been forwarded even unguarded — the test exercised the
  guard but not the scenario it claimed. Now 307, with the mirror recording what it receives: the
  control test asserts the body really does carry `refresh_token=…`, and the guarded test asserts
  the plaintext endpoint received nothing at all.
- **Tests pre-wrapped the injected client**, so none of them covered the wrapping in
  `newAuthTokenSource`; deleting it left them all green. Added a test that goes through
  `newAuthTokenSource` with an unguarded client, and confirmed by mutation that it fails when the
  production wrapping is removed while the older test still passes.
- **The redirect-cap error did not wrap `ErrUnsafeTransport`**, contradicting the sentinel's
  documented contract and meaning a redirect loop during refresh fell through to interactive
  login. Wrapped, with a test covering the package's own refusals.
- **The two malformed-URL errors in `CheckNoSchemeDowngrade` did not wrap the sentinel either**,
  so the contract was still false after the fix above. Wrapped rather than narrowed here: an
  endpoint that will not parse is a refusal in exactly the sentinel's sense, since retrying cannot
  repair it, and leaving it unwrapped reproduces the fall-through bug one layer down.
- **"Every error in the file" was the wrong contract**, because `RefuseTransportDowngrade`
  delegates to a caller's own `CheckRedirect` and returns that verdict unchanged. Narrowed to
  "every error generated by this package's own policy" — the opposite fix from the two above, and
  deliberately so: wrapping an inherited error would report the caller's policy as ours and assert
  a "retrying cannot help" semantic we have no basis for. A test now pins **both** directions: our
  refusals carry the sentinel, an inherited error keeps its own identity and does not acquire it.
  Three rounds of drift on one comment, all because it described a property nothing checked.
- **DEPLOYMENT claimed all server refusals happen at startup.** The endpoint checks do; the
  redirect rule cannot, because the key set is fetched lazily. Corrected to say a redirecting JWKS
  endpoint surfaces on the first authenticated request as a rejected token.
- **"during auth metadata fetch"** was wrong once the guard covered JWKS, refresh and code
  exchange. Reworded, and the function doc now states which traffic carries credentials and why
  307/308 make that a disclosure.

Item 2 is deliberately larger than a tidy commit would be. Splitting it further means landing a
partial transport guarantee — and a doc set that describes a guarantee the code does not yet
make, which is the failure this plan's Documentation section already warns about.

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"authunnel/internal/authhttp"
	"authunnel/internal/authmeta"
	"authunnel/internal/safefs"

	"golang.org/x/oauth2"
)

const tokenReuseWindow = time.Minute

// authTokenSource hides how the client obtains an access token so tunnel setup
// can stay identical for manual tokens and managed OIDC login.
type authTokenSource interface {
	// AccessToken returns a usable access token. When useCache is true, a
	// cached token that passes the reuse window is returned immediately.
	// When false, the cache-reuse check is skipped, forcing a refresh-token
	// grant — used when the server warns that the current token is expiring.
	AccessToken(ctx context.Context, useCache bool) (string, error)

	// TokenAfterRejection returns a replacement token when the server has
	// rejected the last one *because the configuration it was obtained under is
	// no longer the configuration in force*, and "" when that is not the case.
	//
	// A cached token still valid by its own `exp` bypasses resolution — the fast path
	// working as intended — so a server that changes issuer, client ID or audience
	// keeps refusing every such client until its cache expires. The rejection is the
	// only signal available, and this turns that window into one extra round trip.
	//
	// Returning "" when nothing changed is the discipline: a disabled account or a
	// revoked scope produces the same rejection and re-authenticating fixes neither,
	// so a client that logged in on every rejection would open a browser on every ssh
	// invocation for as long as the real problem lasted.
	TokenAfterRejection(ctx context.Context) (string, error)
}

type staticTokenSource struct {
	token string
}

func (s staticTokenSource) AccessToken(_ context.Context, _ bool) (string, error) {
	return s.token, nil
}

// TokenAfterRejection has nothing to offer: ACCESS_TOKEN is one value supplied
// from outside, and this process cannot obtain a different one.
func (s staticTokenSource) TokenAfterRejection(context.Context) (string, error) {
	return "", nil
}

type browserOpener func(context.Context, string) error

// oidcIdentity is the set of values that decide *where a credential goes and
// what it is minted for*: which authorization server, located how, on behalf of
// which client, for which audience and scopes.
//
// It exists as a type because the same seven values are needed in three places
// that must not drift apart — the token cache's identity, the comparison that
// decides whether a cached refresh token may be reused, and the parameters of
// the authorization request. Enumerating them at each site is how a seventh gets
// added and missed at one of them.
type oidcIdentity struct {
	// ResourceURL is the resource identifier discovery ran against, and empty
	// when nothing was discovered. It belongs here because in discovery mode it
	// is the *only* configured input: everything else was derived from it, so it
	// is what a cached credential is actually scoped to.
	//
	// Empty rather than "always the tunnel URL" outside discovery mode: recording it
	// unconditionally would key every existing cache on a value it does not contain,
	// and would require a login per tunnel URL for configurations that legitimately
	// share one issuer and client across several.
	ResourceURL string
	Issuer      string
	MetadataURL string
	ClientID    string
	Audience    string
	Resource    string
	Scopes      string
}

// defaultOIDCScopes is the fallback when neither --oidc-scopes nor the resource
// server's authunnel_default_scopes supplies one. offline_access is in it because
// without a refresh token every ssh invocation past the access token's lifetime
// would open a browser.
const defaultOIDCScopes = "openid offline_access"

// managedOIDCTokenSource implements the native-app flow used by ProxyCommand
// mode. It serializes cache access across concurrent ssh invocations, reuses
// cached tokens when they are still safely valid, refreshes when possible, and
// only falls back to interactive PKCE when needed.
//
// The fields below hold what the *operator configured*, which may be less than
// what the flow needs: an issuer can be adopted from the authorization server's
// own metadata document. Resolution fills the gaps and lands in effective, and
// everything after resolution reads effective rather than these — a distinction
// the cache comparisons depend on, since the cache has to be matched before
// resolution has happened.
type managedOIDCTokenSource struct {
	issuer string
	// metadataURL overrides derived discovery, and makes issuer optional: with no
	// issuer configured, the one the document declares is adopted. Its
	// self-asserted issuer is a consistency check; the operator must trust the URL
	// that supplies the authorization and token endpoints.
	metadataURL string
	clientID    string
	audience    string
	resource    string
	scopes      string
	// resourceURL is the tunnel endpoint's resource identifier, set only when some
	// essential value above is missing. Its emptiness is the switch: a
	// fully-configured source fetches no protected-resource metadata.
	resourceURL string
	// insecureOIDCIssuer relaxes the https requirement for discovered URLs as well
	// as configured ones, since remote input is held to the same rule as a flag.
	insecureOIDCIssuer bool
	// allowInternalTargets permits internal addresses named by the document,
	// because the tunnel URL itself names this machine. See resolveIdentity.
	allowInternalTargets bool
	// resourceIsLocal is that decision, injectable because a test server is always
	// on loopback. nil means authhttp.HostIsAlwaysLocal.
	resourceIsLocal func(string) bool
	cachePath       string
	noBrowser       bool
	redirectPort    int
	// httpClient is the base for every fetch this source makes, and nothing reassigns
	// it: each policy wrapper applies to *this* client, never to another wrapper's
	// output. See authhttp.RefuseInternalAddresses for why that is a requirement.
	httpClient *http.Client
	// guarded is httpClient with the internal-address guard layered on, built at most
	// once so every resolution shares one connection pool. Read through fetchClient.
	guarded     *http.Client
	output      io.Writer
	openBrowser browserOpener
	now         func() time.Time

	mu sync.Mutex
	// effective is the configured identity plus whatever resolution supplied. nil
	// until resolve has succeeded once; memoised for one ssh invocation.
	effective *oidcIdentity
	discovery oauth2.Endpoint
}

// tokenCache is scoped by every setting that determines credential validity or
// destination. MetadataURL is included because its document chooses the token
// endpoint; ResourceURL because in discovery mode everything else derives from it.
// Changing either must not silently send an existing refresh token to a new
// destination. Empty values preserve compatibility with caches created before those
// fields existed.
type tokenCache struct {
	// ResourceURL records the resource identifier this entry's configuration was
	// discovered from. Omitted, and left empty, when nothing was discovered, so
	// caches written before this field existed still match a fully-configured
	// source.
	ResourceURL string `json:"resource_url,omitempty"`
	Issuer      string `json:"issuer"`
	// MetadataURL records which metadata document produced the endpoints these
	// tokens were obtained through. Omitted when discovery used the derived
	// well-known path, so caches written before this field existed still match.
	MetadataURL  string    `json:"metadata_url,omitempty"`
	ClientID     string    `json:"client_id"`
	Audience     string    `json:"audience,omitempty"`
	Resource     string    `json:"resource,omitempty"`
	Scopes       string    `json:"scopes"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	Expiry       time.Time `json:"expiry"`
}

func (c tokenCache) identity() oidcIdentity {
	return oidcIdentity{
		ResourceURL: c.ResourceURL,
		Issuer:      c.Issuer,
		MetadataURL: c.MetadataURL,
		ClientID:    c.ClientID,
		Audience:    c.Audience,
		Resource:    c.Resource,
		Scopes:      normalizeScopes(c.Scopes),
	}
}

func newAuthTokenSource(cfg clientConfig) (authTokenSource, error) {
	switch cfg.AuthMode {
	case authModeManual:
		return staticTokenSource{token: cfg.AccessToken}, nil
	case authModeOIDC:
		client := cfg.AuthHTTPClient
		if client == nil {
			// Bounded default mirrors the server-side validator HTTP
			// client: discovery, refresh, and code exchange all serve
			// small static responses, so a stalled IdP is the only thing
			// these long timeouts would protect. Tests inject their own
			// client through cfg.AuthHTTPClient.
			client = authhttp.NewBoundedClient()
		}
		// Apply explicitly so injected clients cannot bypass the credential-
		// bearing path's downgrade policy.
		client = authhttp.RefuseTransportDowngrade(client)
		output := cfg.Stderr
		if output == nil {
			output = io.Discard
		}
		opener := cfg.BrowserOpener
		if opener == nil {
			opener = defaultBrowserOpener
		}
		return &managedOIDCTokenSource{
			issuer:             cfg.OIDCIssuer,
			metadataURL:        cfg.OIDCMetadataURL,
			clientID:           cfg.OIDCClientID,
			audience:           cfg.OIDCAudience,
			resource:           cfg.OIDCResource,
			scopes:             normalizeScopes(cfg.OIDCScopes),
			resourceURL:        cfg.ResourceURL,
			insecureOIDCIssuer: cfg.InsecureOIDCIssuer,
			cachePath:          cfg.OIDCCache,
			noBrowser:          cfg.OIDCNoBrowser,
			redirectPort:       cfg.OIDCRedirectPort,
			httpClient:         client,
			output:             output,
			openBrowser:        opener,
			now:                time.Now,
		}, nil
	default:
		return nil, errors.New("unknown authentication mode")
	}
}

func defaultOIDCCachePath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}
	return filepath.Join(configDir, "authunnel", "tokens.json"), nil
}

func normalizeScopes(scopes string) string {
	return strings.Join(strings.Fields(scopes), " ")
}

// AccessToken is the single entry point for managed authentication. When
// useCache is true the order is: cache first, then refresh, then browser-based
// login — keeping repeat ssh invocations fast. When useCache is false (e.g.
// responding to a server expiry_warning), the cache-reuse check is skipped so
// the refresh-token grant produces a token with a later expiry.
func (s *managedOIDCTokenSource) AccessToken(ctx context.Context, useCache bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := safefs.EnsurePrivateDir(filepath.Dir(s.cachePath)); err != nil {
		return "", fmt.Errorf("prepare cache directory: %w", err)
	}

	release, err := acquireFileLock(ctx, s.cachePath+".lock")
	if err != nil {
		return "", err
	}
	defer release()

	cache, err := s.loadCache()
	if err != nil {
		return "", err
	}
	if useCache && tokenUsable(cache.asOAuth2Token(), s.now()) {
		return cache.AccessToken, nil
	}

	// Everything past the cache hit needs endpoints, so this is where
	// resolution belongs: the fast path above must stay free of network calls,
	// because it is the one every ssh invocation takes.
	if err := s.resolve(ctx); err != nil {
		return "", err
	}
	// The refresh grant posts the refresh token to the token endpoint the
	// just-resolved metadata names. If resolution produced a different identity
	// than the one this credential was issued under, that is a hand-off to a
	// destination the user never approved — discard the cache and make them log
	// in instead. The access-token fast path above is deliberately not held to
	// this: it sends an already-minted token to the same resource it was minted
	// for, and re-resolving to check would cost the network call the fast path
	// exists to avoid.
	token, err := s.tokenForResolvedIdentity(ctx, cache)
	if err != nil {
		return "", err
	}
	if err := s.saveCache(s.cacheFor(token)); err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

// tokenForResolvedIdentity obtains a token under the resolved identity: the
// cached refresh token when that credential belongs to this identity, and an
// interactive login otherwise. resolve must have run; the caller saves the cache.
func (s *managedOIDCTokenSource) tokenForResolvedIdentity(ctx context.Context, cache tokenCache) (*oauth2.Token, error) {
	if cache.RefreshToken != "" && s.cacheMatchesResolved(cache) {
		refreshed, err := s.refreshToken(ctx, cache)
		if err == nil {
			return refreshed, nil
		}
		// Falling through to interactive login is right for an expired or
		// revoked refresh token: a fresh login fixes it. It is wrong for a
		// refusal to use the endpoint at all — the interactive flow ends at
		// the same token endpoint, so it would open a browser, walk the user
		// through authenticating, and then fail identically. Surface the
		// real reason instead.
		if errors.Is(err, authhttp.ErrUnsafeTransport) {
			return nil, err
		}
	}
	return s.interactiveToken(ctx)
}

// TokenAfterRejection re-resolves from scratch and, if the configuration turns
// out to have changed under the credential the server just rejected, obtains a
// token under the new one.
//
// "Changed" is judged against the cache entry, not against what this process
// resolved earlier: the point is to compare the configuration the *rejected
// credential* was obtained under with the configuration in force now. When they
// agree, the rejection is about the credential or the user rather than the
// configuration, and "" is returned so the caller surfaces the original error
// instead of starting a login that would end the same way.
func (s *managedOIDCTokenSource) TokenAfterRejection(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	release, err := acquireFileLock(ctx, s.cachePath+".lock")
	if err != nil {
		return "", err
	}
	defer release()

	cache, err := s.loadCache()
	if err != nil {
		return "", err
	}
	// Forget everything resolution produced. Memoised values are what make the
	// rest of an invocation cheap; here they are precisely what must not be
	// trusted, since the server has just told us they are wrong.
	s.effective, s.discovery = nil, oauth2.Endpoint{}
	if err := s.resolve(ctx); err != nil {
		return "", err
	}
	if s.cacheMatchesResolved(cache) {
		return "", nil
	}

	token, err := s.tokenForResolvedIdentity(ctx, cache)
	if err != nil {
		return "", err
	}
	if err := s.saveCache(s.cacheFor(token)); err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

// resolve completes the source's configuration and locates the authorization
// server's endpoints. It is idempotent and memoised, and the caller holds s.mu.
//
// Nothing before this point may depend on its results, which is the whole reason
// it is a separate step rather than part of the constructor: it makes network
// calls, and the cache-hit path must not.
func (s *managedOIDCTokenSource) resolve(ctx context.Context) error {
	if s.effective == nil {
		identity, err := s.resolveIdentity(ctx)
		if err != nil {
			return err
		}
		s.effective = identity
	}
	if s.discovery.AuthURL != "" && s.discovery.TokenURL != "" {
		return nil
	}
	return s.resolveEndpoints(ctx)
}

// resolveIdentity produces the configured identity completed by whatever the
// resource server publishes, and refuses a configuration that is still unusable.
func (s *managedOIDCTokenSource) resolveIdentity(ctx context.Context) (*oidcIdentity, error) {
	identity := oidcIdentity{
		ResourceURL: s.resourceURL,
		Issuer:      s.issuer,
		MetadataURL: s.metadataURL,
		ClientID:    s.clientID,
		Audience:    s.audience,
		Resource:    s.resource,
		Scopes:      s.scopes,
	}
	if s.resourceURL != "" {
		// Decided before anything is fetched, from the tunnel URL alone, and
		// without resolving it. A client whose tunnel URL names this machine
		// outright is a development or on-host setup where a local authorization
		// server is the expected answer; a client reaching a public tunnel
		// server has no business being sent to 127.0.0.1 or an
		// instance-metadata address, which is the RFC 9728 §7.7 case.
		//
		// Not resolved, because the tunnel host's DNS belongs to the party this
		// guard constrains: answering both publicly and on loopback would
		// otherwise classify an attacker's server as local and switch off every
		// check below. See authhttp.HostIsAlwaysLocal.
		isLocal := s.resourceIsLocal
		if isLocal == nil {
			isLocal = authhttp.HostIsAlwaysLocal
		}
		s.allowInternalTargets = isLocal(s.resourceURL)
		document, err := authmeta.FetchProtectedResource(ctx, s.fetchClient(), s.resourceURL)
		if err != nil {
			// The hint matters because reaching here at all means the client had
			// nothing else to go on: the likeliest cause is a server running
			// --no-resource-metadata, which looks from here like a 404 on a path
			// the operator has never heard of.
			//
			// Withheld for a refusal, which already says what is wrong and what to
			// do about it. Appending a second, vaguer version of the same advice to
			// a message an operator is trying to read is the noise this codebase
			// took trouble to remove from the transport refusals themselves.
			if errors.Is(err, authhttp.ErrUnsafeTransport) {
				return nil, fmt.Errorf("discover configuration from %s: %w", s.resourceURL, err)
			}
			return nil, fmt.Errorf("discover configuration from %s: %w (pass --oidc-client-id and either --oidc-issuer or --oidc-metadata-url if this server does not publish protected-resource metadata)", s.resourceURL, err)
		}
		if err := s.applyResourceMetadata(ctx, &identity, document); err != nil {
			return nil, fmt.Errorf("discover configuration from %s: %w", s.resourceURL, err)
		}
	}
	if identity.Scopes == "" {
		identity.Scopes = normalizeScopes(defaultOIDCScopes)
	}
	// Checked after discovery has had its turn, and phrased as the flags an
	// operator would reach for, because at this point the possibilities are
	// exhausted: the resource server either did not publish a hint or is not
	// publishing metadata at all.
	if identity.ClientID == "" {
		return nil, errors.New("no OIDC client ID: pass --oidc-client-id, or configure --client-id on the authunnel server so it publishes one")
	}
	if identity.Issuer == "" && identity.MetadataURL == "" {
		return nil, errors.New("no OIDC issuer: pass --oidc-issuer or --oidc-metadata-url, or configure --oidc-issuer on the authunnel server so it publishes one")
	}
	return &identity, nil
}

// resolveEndpoints reads the authorization server's own metadata and records the
// endpoints, after validating both. s.effective must be set.
func (s *managedOIDCTokenSource) resolveEndpoints(ctx context.Context) error {
	// Downgrade is judged against wherever the metadata actually came from, not
	// against the issuer: with --oidc-metadata-url those differ, and it is the
	// document's own transport that determines whether a plaintext endpoint is a
	// downgrade. It doubles as the label for every error below, so a failure
	// names the URL that was actually fetched.
	metadataSource := s.effective.Issuer
	if s.effective.MetadataURL != "" {
		metadataSource = s.effective.MetadataURL
	}
	refuse := func(err error) error {
		return fmt.Errorf("discover authorization server via %s: %w", metadataSource, err)
	}
	// FetchAuthorizationServer derives the well-known path from the issuer when
	// the metadata URL is empty, so the default path needs no branch. With an
	// issuer configured it compares the document's own against it — a
	// consistency check against an honest wrong URL, not a defence against a
	// hostile one, since the document asserts that field about itself. With no
	// issuer configured the declared one is adopted and that check is gone. See
	// the metadataURL field comment.
	// A published metadata URL adopted under a configured issuer is the one fetch
	// whose origin is load-bearing: the same-origin check on that value is the whole
	// of the pin, and an open redirect on the issuer's host would defeat it.
	// Elsewhere an HTTPS-rooted chain may delegate to another HTTPS host, which the
	// discovery simplification plan lists as a non-goal to prevent.
	metadataClient := s.fetchClient()
	if s.metadataOriginIsPinned() {
		metadataClient = authhttp.PinRedirectOrigin(metadataClient)
	}
	document, err := authmeta.FetchAuthorizationServer(ctx, metadataClient, s.effective.Issuer, s.effective.MetadataURL)
	if err != nil {
		return refuse(err)
	}
	// Recorded before the endpoint checks so the value that ends up in the cache
	// identity is the one this document declared, whether it was configured or
	// adopted.
	s.effective.Issuer = document.Issuer
	// Validate both endpoints before use. token_endpoint receives credentials;
	// authorization_endpoint is handed to the OS URL dispatcher and is not covered
	// by the HTTP client's redirect guard, so the shape check is the whole of the
	// protection there.
	for _, endpoint := range []struct{ label, value string }{
		{"authorization_endpoint", document.AuthorizationEndpoint},
		{"token_endpoint", document.TokenEndpoint},
	} {
		if err := authhttp.CheckDiscoveredEndpoint(endpoint.label, metadataSource, endpoint.value); err != nil {
			return refuse(err)
		}
		if err := s.checkDiscoveredAddress(ctx, endpoint.label, endpoint.value); err != nil {
			return refuse(err)
		}
	}
	s.discovery = oauth2.Endpoint{
		AuthURL:   document.AuthorizationEndpoint,
		TokenURL:  document.TokenEndpoint,
		AuthStyle: oauth2.AuthStyleInParams,
	}
	return nil
}

// authorizationServerIsRemotelyChosen reports whether the *tunnel server* decided
// where this client's authorization server is.
//
// It governs discovery-input policy, and is keyed on what the tunnel server got to
// *choose* rather than on whether discovery ran: discovery may run only to collect a
// client ID while --oidc-issuer or --oidc-metadata-url fixes the authorization
// server's location. Keying it on "discovery ran" would make the promise that a
// configured issuer is not filtered depend on whether an unrelated flag was supplied.
//
// When false, nothing the client fetches was located by the tunnel server: the
// resource URL was typed by the operator, the authorization server's document comes
// from their issuer or metadata URL, and a published metadata URL is adopted only
// within that issuer's origin (adoptMetadataURL). What the tunnel server may still
// supply — client ID, audience, scopes — names no address.
func (s *managedOIDCTokenSource) authorizationServerIsRemotelyChosen() bool {
	return s.resourceURL != "" && s.issuer == "" && s.metadataURL == ""
}

// applyResourceMetadata fills unconfigured fields of identity from the resource
// server's document, validating each as remote input.
//
// Two rules, and the difference between them is deliberate:
//
//   - **A configured value wins over every published field that could undermine what
//     it guarantees**, not merely over the field of the same name. "Explicit wins" is
//     evaluated per guarantee: a pinned --oidc-issuer guarantees the endpoints come
//     from that issuer, and the published *metadata URL* decides which document they
//     are read from, so it is part of that guarantee. Gated in adoptMetadataURL.
//   - **A contradicted issuer is an error, a contradicted metadata URL is not.** An
//     issuer is an identity: two different answers means one is wrong, and continuing
//     costs a browser login that ends in a rejected token. A location is not, so an
//     operator override there is a workaround rather than a contradiction.
//
// Every URL from the document is shape-checked whoever chose it; the transport,
// downgrade and address rules apply on top only when the tunnel server chose where the
// authorization server is. See authorizationServerIsRemotelyChosen.
func (s *managedOIDCTokenSource) applyResourceMetadata(ctx context.Context, identity *oidcIdentity, document *authmeta.ProtectedResource) error {
	if err := s.adoptAuthorizationServer(ctx, identity, document.AuthorizationServer()); err != nil {
		return err
	}
	for _, hint := range []struct {
		label     string
		target    *string
		published string
		validate  func(string) error
	}{
		{"authunnel_client_id", &identity.ClientID, document.ClientID, authmeta.ValidateClientID},
		{"authunnel_audience", &identity.Audience, document.Audience, authmeta.ValidateAudience},
		{"authunnel_resource", &identity.Resource, document.ResourceIndicator, authmeta.ValidateResourceIndicator},
		{
			label:  "authunnel_default_scopes",
			target: &identity.Scopes,
			// The extension field, not the registered scopes_supported. Under RFC 9728
			// §7.2 that one is a resource *disclosing* the scopes it supports, which
			// is not the same question as which of them this client should request —
			// reading it as the latter is how a client ends up asking for more
			// privilege than the job needs. This field is the recommendation, so it is
			// the one that may be adopted. See the DefaultScopes field comment.
			published: normalizeScopes(strings.Join(document.DefaultScopes, " ")),
			// Validated against the original slice rather than the joined
			// string: joining and re-splitting would turn a scope containing a
			// space into two valid ones, which is the malformed case worth
			// catching.
			validate: func(string) error { return authmeta.ValidateScopes(document.DefaultScopes) },
		},
	} {
		if *hint.target != "" || hint.published == "" {
			continue
		}
		if err := hint.validate(hint.published); err != nil {
			return fmt.Errorf("%s: %w", hint.label, err)
		}
		*hint.target = hint.published
	}
	return s.adoptMetadataURL(ctx, identity, document.AuthorizationServerMetadataURL)
}

// adoptMetadataURL takes the published location of the authorization server's
// metadata document, unless doing so would let the resource server decide which
// endpoints a *pinned* issuer resolves to.
//
// Accepted when no issuer was configured — nothing to undermine, and that is the
// trade the feature makes — and when it shares an origin with the configured issuer,
// where TLS makes the issuer's own host answer for the document. That keeps the case
// the flag exists for: RFC 8414 metadata at a path the OIDC derivation cannot
// construct still sits on the issuer's host, so it is same-origin.
//
// A cross-origin value under a configured issuer is disregarded rather than refused —
// it may be a legitimate deployment, and --oidc-metadata-url is how an operator says
// so — but announced, since the alternative is debugging a 404 on the derived path
// while the server advertises a location the client silently declined.
func (s *managedOIDCTokenSource) adoptMetadataURL(ctx context.Context, identity *oidcIdentity, published string) error {
	if identity.MetadataURL != "" || published == "" {
		return nil
	}
	// Whether the value will be used at all is decided before it is judged, which
	// is the opposite of the original order and the reason that mattered: a
	// cross-origin hint that is also plaintext or internal failed the transport and
	// address rules and became a hard error, so a hostile or merely misconfigured
	// tunnel server could break a client that had pinned its issuer and should have
	// been immune. Nothing is validated that is not about to be adopted.
	//
	// s.issuer, not identity.Issuer: the latter may have just been adopted from this
	// very document, in which case there is no pin to respect.
	if s.issuer != "" {
		sameOrigin, err := authhttp.SameOrigin(s.issuer, published)
		if err != nil || !sameOrigin {
			reason := "it is not on the same origin as"
			if err != nil {
				reason = "it could not be compared with"
			}
			// %q on the published value, which is the one thing here that has not
			// been through url.Parse, because the decision to ignore it deliberately
			// precedes validation. A value that fails SameOrigin
			// *because* it contains control characters is precisely the one that
			// reaches this line, so it is quoted; the operator's own resource URL
			// and issuer passed CheckConfiguredURL and cannot carry any.
			fmt.Fprintf(s.output,
				"Ignoring the metadata URL published by %s (%q): %s the configured --oidc-issuer %s, so the issuer's own metadata is used instead. Pass --oidc-metadata-url to use it deliberately.\n",
				s.resourceURL, published, reason, s.issuer)
			return nil
		}
	}
	if err := s.checkDiscoveredURL(ctx, "authunnel_authorization_server_metadata_url", published); err != nil {
		return fmt.Errorf("authunnel_authorization_server_metadata_url: %w", err)
	}
	identity.MetadataURL = published
	return nil
}

// metadataOriginIsPinned reports whether the metadata fetch must refuse to leave the
// origin it starts on: true only for a location this tunnel server published, adopted
// under a configured --oidc-issuer. There the same-origin comparison in
// adoptMetadataURL is the whole of the pin, and an open redirect on the issuer's host
// would defeat it. An operator's own --oidc-metadata-url is not pinned — they chose
// that location — and neither is the derived well-known path, so HTTPS-to-HTTPS
// delegation stays permitted as the discovery simplification plan's non-goals require.
//
// Derived from s.effective rather than recorded when the value is adopted, because it
// is a property of the resolution in force. Stored, it outlived the state it described:
// TokenAfterRejection discards s.effective and re-resolves, so a server that stopped
// publishing a metadata URL left a stale pin on the derived fetch.
func (s *managedOIDCTokenSource) metadataOriginIsPinned() bool {
	if s.issuer == "" || s.effective == nil {
		return false
	}
	// The comparison with s.metadataURL is what separates adopted from
	// operator-supplied: resolveIdentity seeds the field from the configured flag, so
	// any other value arrived from the document.
	return s.effective.MetadataURL != "" && s.effective.MetadataURL != s.metadataURL
}

// adoptAuthorizationServer applies the issuer half of applyResourceMetadata, which
// is the half with a rule of its own — see that function's comment for why a
// contradiction here is an error rather than an override.
func (s *managedOIDCTokenSource) adoptAuthorizationServer(ctx context.Context, identity *oidcIdentity, advertised string) error {
	if advertised == "" {
		return nil
	}
	// Compared before anything is validated. What keeps the operator's own issuer out
	// of discovery-input policy is authorizationServerIsRemotelyChosen inside
	// checkDiscoveredURL — not this early return, which is unobservable beside it and
	// is here only for readability: an advertised value equal to a configured one is
	// nothing to adopt, so nothing to judge. Verified unobservable, not assumed —
	// removing it changes no test, since the only value reaching the check is the
	// configured issuer, already validated at parse
	// time.
	//
	// The comparison itself is observable, and worth doing first: an unusable value
	// advertised alongside --oidc-issuer means the server disagrees with the
	// operator, and saying that beats reporting the value's shape.
	if s.issuer != "" {
		if s.issuer != advertised {
			return fmt.Errorf("--oidc-issuer is %q but this resource names %q as its authorization server; one of them is wrong",
				s.issuer, advertised)
		}
		return nil
	}
	if err := s.checkDiscoveredURL(ctx, "authorization_servers[0]", advertised); err != nil {
		return err
	}
	identity.Issuer = advertised
	return nil
}

func (s *managedOIDCTokenSource) checkDiscoveredURL(ctx context.Context, label, value string) error {
	// Shape always: a value that is not a usable http(s) URL is worth refusing
	// whoever chose it, and this is the check the OS URL dispatcher depends on.
	if err := authhttp.CheckHTTPURL(label, value); err != nil {
		return err
	}
	if !s.authorizationServerIsRemotelyChosen() {
		return nil
	}
	if err := authmeta.CheckDiscoveredURL(label, s.resourceURL, value, s.insecureOIDCIssuer); err != nil {
		return err
	}
	return s.checkDiscoveredAddress(ctx, label, value)
}

// checkDiscoveredAddress refuses a remotely-named URL that resolves to an
// internal address. A no-op outside discovery, and when the resource server is
// itself internal.
//
// The dial guard fetchClient installs covers the same ground for fetches we make, and
// covers it better, since it cannot be beaten by re-resolution. This static check
// is not redundant with it: authorization_endpoint is never dialled by us — it
// goes to the OS URL dispatcher — so for that endpoint this is the only check
// there is.
func (s *managedOIDCTokenSource) checkDiscoveredAddress(ctx context.Context, label, value string) error {
	if !s.authorizationServerIsRemotelyChosen() || s.allowInternalTargets {
		return nil
	}
	err := authhttp.CheckPublicAddress(ctx, label, value)
	if err == nil || errors.Is(err, authhttp.ErrUnsafeTransport) {
		return err
	}
	// Only a refusal counts. Failing to resolve is not evidence of an internal
	// address, and in a proxied network there may be no local answer to get: DNS
	// for external names is often the proxy's job, in which case treating "cannot
	// resolve" as "refuse" would block every discovered endpoint for exactly the
	// clients that can reach them. An address that turns out to be unreachable
	// fails on its own merits a moment later, and the dial guard re-checks
	// whatever it does resolve to.
	return nil
}

// oauthConfig builds the OAuth2 config from the already-resolved identity and
// endpoints; resolve must have run. AuthStyleInParams is used because the test
// Keycloak public client rejects the default client-auth style negotiation.
func (s *managedOIDCTokenSource) oauthConfig(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:    s.effective.ClientID,
		RedirectURL: redirectURL,
		Scopes:      strings.Fields(s.effective.Scopes),
		Endpoint:    s.discovery,
	}
}

func (s *managedOIDCTokenSource) loadCache() (tokenCache, error) {
	cache := tokenCache{}
	if err := safefs.EnsurePrivateFile(s.cachePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cache, nil
		}
		return cache, fmt.Errorf("validate OIDC token cache: %w", err)
	}
	data, err := os.ReadFile(s.cachePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cache, nil
		}
		return cache, fmt.Errorf("read OIDC token cache: %w", err)
	}
	if err := json.Unmarshal(data, &cache); err != nil {
		return tokenCache{}, fmt.Errorf("parse OIDC token cache: %w", err)
	}
	if !s.cacheMatchesConfigured(cache) {
		return tokenCache{}, nil
	}
	return cache, nil
}

// cacheMatchesConfigured decides whether a cache entry belongs to this source,
// using only what is known *before* resolution — which is all the cache-hit fast
// path can afford to consult, since resolving means a network call.
//
// Every configured value must match. An unconfigured one is exempt only when a
// resolver will supply it, and the exemption is per-field for a reason: without
// it, an entry recording `audience: "https://api.example"` would satisfy an
// invocation that asked for no audience at all, and a token minted for one
// resource would be handed to another. The exempted fields are re-checked in
// full against the resolved identity before any refresh token is used.
//
// MetadataURL is part of this identity, not an incidental detail: it determines
// the token endpoint these credentials get posted to. See the tokenCache doc
// comment.
func (s *managedOIDCTokenSource) cacheMatchesConfigured(cache tokenCache) bool {
	cached := cache.identity()
	if cached.ResourceURL != s.resourceURL {
		return false
	}
	// In discovery mode every field below can come from the resource server's
	// document, so an unconfigured one is not knowable yet. An issuer is also
	// resolvable from the authorization server's own document whenever a metadata
	// URL locates it.
	discovering := s.resourceURL != ""
	for _, field := range []struct {
		cached, configured string
		resolvable         bool
	}{
		{cached.Issuer, s.issuer, discovering || s.metadataURL != ""},
		{cached.MetadataURL, s.metadataURL, discovering},
		{cached.ClientID, s.clientID, discovering},
		{cached.Audience, s.audience, discovering},
		{cached.Resource, s.resource, discovering},
		{cached.Scopes, s.scopes, discovering},
	} {
		if field.configured == "" && field.resolvable {
			continue
		}
		if field.cached != field.configured {
			return false
		}
	}
	return true
}

// cacheMatchesResolved is the strict comparison: every field of the entry's
// identity against the resolved one, no exemptions. resolve must have run.
//
// This is the check that stands between a resolvable configuration and a
// credential-disclosure bug. A refresh grant posts the refresh token to whatever
// token endpoint resolution just named; if that resolution differs from the one
// the credential was issued under — a different authorization server, a
// different client, a metadata document that moved — then reusing the credential
// hands it to a party the user never authorised, with no interaction to notice.
// Failing this comparison discards the cache, which costs one login.
func (s *managedOIDCTokenSource) cacheMatchesResolved(cache tokenCache) bool {
	return cache.identity() == *s.effective
}

func (s *managedOIDCTokenSource) saveCache(cache tokenCache) error {
	if err := safefs.EnsurePrivateDir(filepath.Dir(s.cachePath)); err != nil {
		return fmt.Errorf("prepare cache directory: %w", err)
	}
	// #nosec G117 -- this is an accepted tradeoff, not a false positive.
	// authunnel persists access and refresh tokens as plaintext JSON so that
	// subsequent client invocations can reuse them without a fresh browser
	// login. Confidentiality relies entirely on POSIX filesystem permissions:
	// the file is written 0o600 via atomic rename into a directory that
	// ensurePrivateDir has validated as 0o700, owned by the current user,
	// with every ancestor safe against peer rename(2). This does NOT defend
	// against root on the host, offline access to an unencrypted disk image,
	// or a backup of the config directory. See the "Token cache at rest"
	// section of the README for the explicit threat model.
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal OIDC token cache: %w", err)
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(s.cachePath), "tokens-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp cache file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp cache file: %w", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp cache file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp cache file: %w", err)
	}
	if err := os.Rename(tmpPath, s.cachePath); err != nil {
		return fmt.Errorf("replace OIDC token cache: %w", err)
	}
	return nil
}

// fetchClient is the client every fetch this source makes goes through: httpClient
// guarded by authhttp.RefuseInternalAddresses when the *tunnel server* chose the
// addresses being reached, and httpClient itself otherwise — a configured issuer or
// metadata URL is the operator's own decision and is not filtered. See
// authorizationServerIsRemotelyChosen.
//
// Three invariants, each load-bearing:
//
//   - the guard is built from httpClient, never from what this returns. See that
//     field, and RefuseInternalAddresses, for what a second application produces.
//   - it is kept, so every resolution in a process shares one connection pool.
//   - only the *positive* verdict is memoised. A cached "no guard needed" is the one
//     shape here that could silently disable the guard, and a caller arriving before
//     allowInternalTargets is set should get a guard rather than a lasting absence.
//
// Callers hold s.mu on every path, so the memo needs no synchronisation of its own.
func (s *managedOIDCTokenSource) fetchClient() *http.Client {
	if s.allowInternalTargets || !s.authorizationServerIsRemotelyChosen() {
		return s.httpClient
	}
	if s.guarded == nil {
		s.guarded = authhttp.RefuseInternalAddresses(s.httpClient)
	}
	return s.guarded
}

// credentialClient is the client for the two requests that carry a credential in
// their body — the refresh and the code exchange. Layered on fetchClient, since the
// token endpoint was named by a document the tunnel server located, and pinned to the
// origin it starts on: a 307 preserves method and body, so an open redirect on the
// token endpoint's own host would otherwise post the refresh token or the
// authorization code to a third party, and https-to-https is not a downgrade for the
// transport rule to catch. Verified by TestTokenEndpointCrossOriginRedirectIsRefused,
// which records the body the other origin would have received.
func (s *managedOIDCTokenSource) credentialClient() *http.Client {
	return authhttp.PinRedirectOrigin(s.fetchClient())
}

func (s *managedOIDCTokenSource) refreshToken(ctx context.Context, cache tokenCache) (*oauth2.Token, error) {
	// Idempotent and already done by AccessToken on the normal path. Repeated
	// here, and in interactiveToken, so neither carries an unenforced
	// precondition: reading s.effective before resolution would be a nil
	// dereference, and a memoised no-op is a cheaper guarantee than a comment.
	if err := s.resolve(ctx); err != nil {
		return nil, err
	}
	config := s.oauthConfig("")
	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.credentialClient())
	token := cache.asOAuth2Token()
	refreshed, err := config.TokenSource(ctx, token).Token()
	if err != nil {
		return nil, fmt.Errorf("refresh OIDC token: %w", err)
	}
	return refreshed, nil
}

func (s *managedOIDCTokenSource) interactiveToken(ctx context.Context) (*oauth2.Token, error) {
	// See refreshToken: idempotent, and here so this entry point stands alone.
	if err := s.resolve(ctx); err != nil {
		return nil, err
	}
	listenAddr := "127.0.0.1:0"
	if s.redirectPort != 0 {
		listenAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(s.redirectPort))
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen for OIDC callback: %w", err)
	}
	defer listener.Close()

	redirectURL := "http://" + listener.Addr().String() + "/callback"
	config := s.oauthConfig(redirectURL)

	state, err := randomToken()
	if err != nil {
		return nil, fmt.Errorf("generate OIDC state: %w", err)
	}
	verifier, err := randomToken()
	if err != nil {
		return nil, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	challenge := sha256.Sum256([]byte(verifier))
	challengeValue := base64.RawURLEncoding.EncodeToString(challenge[:])

	resultCh := make(chan callbackResult, 1)
	server := &http.Server{
		// Defence in depth: even though this server is only bound to a
		// 127.0.0.1 loopback listener during an interactive OIDC login, a
		// ReadHeaderTimeout defeats a local attacker who could otherwise keep
		// the listener occupied by dribbling headers forever.
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result := callbackResult{}
			query := r.URL.Query()
			if oauthErr := query.Get("error"); oauthErr != "" {
				// Chosen by whoever answered the authorization request, and
				// unparsed, so it is quoted before it can reach a terminal.
				result.err = fmt.Errorf("OIDC authorization failed: %q", oauthErr)
				http.Error(w, "Authentication failed. Return to the terminal.", http.StatusBadRequest)
			} else if query.Get("state") != state {
				result.err = errors.New("OIDC callback state mismatch")
				http.Error(w, "Authentication failed. Return to the terminal.", http.StatusBadRequest)
			} else if code := query.Get("code"); code == "" {
				result.err = errors.New("OIDC callback missing authorization code")
				http.Error(w, "Authentication failed. Return to the terminal.", http.StatusBadRequest)
			} else {
				result.code = code
				_, _ = io.WriteString(w, "Authentication complete. Return to your terminal.\n")
			}
			select {
			case resultCh <- result:
			default:
			}
		}),
	}

	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case resultCh <- callbackResult{err: fmt.Errorf("OIDC callback server failed: %w", err)}:
			default:
			}
		}
	}()

	authCodeOptions := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", challengeValue),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	if s.effective.Audience != "" {
		authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam("audience", s.effective.Audience))
	}
	// RFC 8707 resource indicator. Providers that bind the access-token `aud`
	// claim to a requested resource (e.g. AWS Cognito) require this parameter;
	// the Auth0-style `audience` parameter above is ignored by them.
	if s.effective.Resource != "" {
		authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam("resource", s.effective.Resource))
	}
	authURL := config.AuthCodeURL(state, authCodeOptions...)
	fmt.Fprintf(s.output, "Open this URL to authenticate:\n%s\n", authURL)
	if !s.noBrowser {
		if err := s.openBrowser(ctx, authURL); err != nil {
			fmt.Fprintf(s.output, "Browser launch failed, open the URL manually: %v\n", err)
		}
	}

	var callback callbackResult
	select {
	case <-ctx.Done():
		callback.err = ctx.Err()
	case callback = <-resultCh:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)

	if callback.err != nil {
		return nil, callback.err
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.credentialClient())
	token, err := config.Exchange(ctx, callback.code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	return token, nil
}

// tokenUsable keeps a small reuse window so the client does not start a tunnel
// with a token that is about to expire mid-handshake.
func tokenUsable(token *oauth2.Token, now time.Time) bool {
	if token == nil || token.AccessToken == "" {
		return false
	}
	if token.Expiry.IsZero() {
		return false
	}
	return token.Expiry.After(now.Add(tokenReuseWindow))
}

// cacheFor builds a cache entry stamped with this source's *resolved* identity.
// A method rather than a function taking each field: the identity is what the
// cache comparisons run against, and enumerating it at every call site is how a
// new field gets added to the struct and missed at one of them.
//
// Resolved rather than configured, because the resolved values are what the
// credential was actually obtained under — an entry recording an empty issuer
// would match any document later declaring any issuer, which is the check in
// cacheMatchesResolved defeated.
func (s *managedOIDCTokenSource) cacheFor(token *oauth2.Token) tokenCache {
	cache := tokenCache{
		ResourceURL:  s.effective.ResourceURL,
		Issuer:       s.effective.Issuer,
		MetadataURL:  s.effective.MetadataURL,
		ClientID:     s.effective.ClientID,
		Audience:     s.effective.Audience,
		Resource:     s.effective.Resource,
		Scopes:       s.effective.Scopes,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry,
	}
	if cache.TokenType == "" {
		cache.TokenType = "Bearer"
	}
	return cache
}

func (c tokenCache) asOAuth2Token() *oauth2.Token {
	if c.AccessToken == "" && c.RefreshToken == "" {
		return nil
	}
	return &oauth2.Token{
		AccessToken:  c.AccessToken,
		RefreshToken: c.RefreshToken,
		TokenType:    c.TokenType,
		Expiry:       c.Expiry,
	}
}

type callbackResult struct {
	code string
	err  error
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

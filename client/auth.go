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
	// It exists because a cached token that is still valid by its own `exp`
	// bypasses resolution entirely — that is the fast path working as intended —
	// so a server that changes issuer, client ID or audience leaves every client
	// presenting a credential it will keep refusing until the cache expires. The
	// rejection is the only signal available, and re-resolving on it is what
	// turns a lockout into one extra round trip.
	//
	// Returning "" rather than a fresh token when nothing changed is the whole
	// discipline here: an account that was disabled, or a scope that was revoked,
	// also produces a rejection, and re-authenticating cannot fix either. A
	// client that logged in again on every rejection would open a browser on
	// every ssh invocation for as long as the real problem lasted.
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
	// Deliberately empty rather than "always the tunnel URL" outside discovery
	// mode. Recording it unconditionally would key every existing cache on a
	// value it does not contain, logging every user out once on upgrade, and
	// would newly require one login per tunnel URL for configurations that
	// legitimately share an issuer and client across several.
	ResourceURL string
	Issuer      string
	MetadataURL string
	ClientID    string
	Audience    string
	Resource    string
	Scopes      string
}

// defaultOIDCScopes is the fallback when neither --oidc-scopes nor the resource
// server's scopes_supported supplies one. offline_access is in it because
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
	// metadataURL, when set, replaces the well-known path derived from
	// issuer, and makes issuer optional: with no issuer configured, the one
	// the document declares is adopted.
	//
	// When both are set, discovery compares the document's `issuer` field
	// against issuer, but that field is supplied by the document about itself
	// and proves nothing about the host serving it. Treat the check as
	// catching an honest wrong URL — staging for production, one tenant for
	// another, which a legitimate AS reveals by declaring its own issuer — not
	// as a boundary. A hostile or mistyped URL can echo the expected issuer
	// and name any endpoints it likes; only trusting this value prevents that.
	//
	// With no issuer configured, that check is given up along with it. A
	// metadata URL naming the wrong tenant is then indistinguishable from the
	// right one until a browser login has already happened and the authunnel
	// server rejects the resulting token.
	metadataURL string
	clientID    string
	audience    string
	resource    string
	scopes      string
	// resourceURL is the tunnel endpoint's resource identifier, and is set only
	// when something essential is missing from the configuration above. Its
	// emptiness is therefore the switch: a fully-configured source never fetches
	// protected-resource metadata, so existing invocations make exactly the
	// network calls they made before.
	resourceURL string
	// insecureOIDCIssuer relaxes the https requirement for *discovered* URLs as
	// well as configured ones. Remote input is held to the same rule a flag is,
	// which means the same override too — a developer pointing at a local
	// Keycloak over http needs the discovered issuer to be permitted as well.
	insecureOIDCIssuer bool
	// allowInternalTargets records that the resource server is itself at an
	// internal address, so the addresses it names may be internal too. Decided
	// once, before any fetch, from the tunnel URL; see resolveIdentity.
	allowInternalTargets bool
	// resourceIsLocal is the decision above, injectable because a test server is
	// always on loopback and could otherwise not exercise the public-resource
	// case at all. nil means authhttp.HostIsAlwaysLocal.
	resourceIsLocal func(string) bool
	cachePath       string
	noBrowser       bool
	redirectPort    int
	httpClient      *http.Client
	output          io.Writer
	openBrowser     browserOpener
	now             func() time.Time

	mu sync.Mutex
	// effective is the configured identity plus whatever resolution supplied.
	// nil until resolve has succeeded once; memoised for the process lifetime,
	// which is one ssh invocation.
	effective *oidcIdentity
	discovery oauth2.Endpoint
}

// tokenCache is intentionally a single JSON document so developers can inspect
// and delete it easily during debugging. Cache entries are scoped to the resource
// URL discovery ran against, the issuer, the metadata URL, the client ID, the
// audience, the resource, and the scopes — to avoid reusing a credential in a context
// it was not obtained for.
//
// The metadata URL belongs in that identity, and an earlier version of this
// comment argued the opposite — that the override only relocates the document,
// so a token obtained through it is "the same token". That reasoning asks
// whether the credential is still *valid*, which is the wrong question. The
// question is who receives it. The metadata document names the token endpoint
// the refresh token is posted to, and the only check on that document is that
// its `issuer` field equals the configured issuer — a plain string comparison
// against a value the document supplies about itself. Nothing binds the
// metadata host to the issuer it claims, so a mistyped or hostile metadata URL
// can echo the right issuer and name any token endpoint it likes.
//
// Left out of the identity, adding or changing --oidc-metadata-url would keep an
// existing refresh token valid and post it to whatever that new document
// advertises, with no user interaction. Including it means the cache is
// discarded instead and the user re-authenticates.
//
// What that does and does not buy, precisely: it prevents the **silent reuse of
// an already-issued refresh token**. It is not a general defence against a
// hostile metadata URL. If the user goes on to complete the fallback login, the
// authorization code and its PKCE verifier are still sent to the token endpoint
// that document names — and a document can pair the *real* authorization
// endpoint with an attacker's token endpoint, so the user sees a genuine IdP
// page and the code that comes back is a real, redeemable one. Nothing here
// stops that; only trusting the metadata URL does.
//
// The cost is one interactive login the first time an operator sets the flag,
// and again if they change it. That is the correct trade. Caches written before
// this field existed unmarshal with an empty MetadataURL and still match a
// source that uses the derived path, so no one is logged out by the upgrade.
//
// The identity recorded here is the *resolved* one, so an entry written by a
// source that adopted its issuer from a metadata document records that issuer
// rather than the empty configured value. That is what makes the comparison in
// cacheMatchesResolved meaningful; see cacheMatchesConfigured for why matching
// cannot simply be deferred until after resolution.
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
		// Applied here rather than relying on NewBoundedClient, which sets
		// the same policy: an injected client must not be able to opt out of
		// it. This path carries the refresh token and the authorization code,
		// so a redirect off https would disclose a credential rather than
		// merely weaken a fetch of public material.
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
		// Guarded only when the tunnel server is the one choosing where this
		// client's auth traffic goes. With --oidc-issuer or --oidc-metadata-url
		// supplied it is not, and wrapping the shared client would then refuse the
		// operator's own loopback issuer — contingently, depending on whether
		// --oidc-client-id happened to be missing too.
		if !s.allowInternalTargets && s.authorizationServerIsRemotelyChosen() {
			s.httpClient = authhttp.RefuseInternalAddresses(s.httpClient)
		}
		document, err := authmeta.FetchProtectedResource(ctx, s.httpClient, s.resourceURL)
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
			return nil, fmt.Errorf("discover configuration from %s: %w (pass --oidc-issuer and --oidc-client-id if this server does not publish protected-resource metadata)", s.resourceURL, err)
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
	document, err := authmeta.FetchAuthorizationServer(ctx, s.httpClient, s.effective.Issuer, s.effective.MetadataURL)
	if err != nil {
		return refuse(err)
	}
	// Recorded before the endpoint checks so the value that ends up in the cache
	// identity is the one this document declared, whether it was configured or
	// adopted.
	s.effective.Issuer = document.Issuer
	// Validate both endpoints before either is used. token_endpoint receives the
	// refresh token and the authorization code; authorization_endpoint is handed
	// to the OS URL dispatcher, which will launch whatever application claims
	// the scheme, so CheckEndpointURL is the whole of the protection there — the
	// redirect guard on s.httpClient never sees that leg.
	for _, endpoint := range []struct{ label, value string }{
		{"authorization_endpoint", document.AuthorizationEndpoint},
		{"token_endpoint", document.TokenEndpoint},
	} {
		if err := authhttp.CheckEndpointURL(endpoint.label, endpoint.value); err != nil {
			return refuse(err)
		}
		if err := authhttp.CheckNoSchemeDowngrade(endpoint.label, metadataSource, endpoint.value); err != nil {
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
// It is the condition that governs discovery-input policy, and it is deliberately
// about what the tunnel server got to choose rather than about whether discovery
// ran. Discovery may run only to collect a client ID while --oidc-issuer or
// --oidc-metadata-url fixes the authorization server's location; the addresses
// reached thereafter are then the operator's own choice or the choice of the
// authorization server the operator named, and this documentation's promise that a
// configured issuer "is not filtered" has to hold whether or not some other flag
// happened to be supplied too.
//
// When it is false, nothing the client fetches was located by the tunnel server:
// the resource URL is typed by the operator, the authorization server's document
// comes from the operator's issuer or metadata URL, and a *published* metadata URL
// is only adopted within that issuer's own origin (see adoptMetadataURL). What the
// tunnel server may still supply in that mode — client ID, audience, scopes — names
// no address at all.
func (s *managedOIDCTokenSource) authorizationServerIsRemotelyChosen() bool {
	return s.resourceURL != "" && s.issuer == "" && s.metadataURL == ""
}

// applyResourceMetadata fills unconfigured fields of identity from the resource
// server's document, validating each as remote input.
//
// Two rules, and the difference between them is deliberate:
//
//   - **A configured value always wins**, and — the part that was missing —
//     wins over every published field that could undermine what it guarantees,
//     not merely over the field of the same name. A pinned --oidc-issuer
//     guarantees "the endpoints come from this issuer", so the published
//     *metadata URL* is part of that guarantee: it decides which document the
//     endpoints are read from. Gated in adoptMetadataURL below.
//
//     The earlier version reasoned field by field — explicit issuer beats
//     published issuer, explicit metadata URL beats published metadata URL — and
//     that is how a hostile tunnel server echoed the expected issuer, relocated
//     its document, and chose the endpoints anyway. "Explicit wins" has to be
//     evaluated per guarantee, not per field.
//
//   - **A contradicted issuer is an error, a contradicted metadata URL is not.**
//     The issuer is an identity: if the operator names one and the resource
//     server names another, one of them is wrong, and continuing means a browser
//     login that ends in a token this very server rejects. Failing locally with
//     both values is strictly better than that. A metadata URL is a location, so
//     an operator override there is a legitimate workaround rather than a
//     contradiction — but a *published* one is now bounded, which is the point
//     above.
//
// Every URL taken from the document is checked for shape — a usable http(s) URL —
// whoever chose it. The transport, downgrade and address rules apply on top of that
// only when the tunnel server is the party that chose where the authorization server
// is; see authorizationServerIsRemotelyChosen for why that distinction is the subject
// of the rule rather than an exemption from it.
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
			label:     "scopes_supported",
			target:    &identity.Scopes,
			published: normalizeScopes(strings.Join(document.ScopesSupported, " ")),
			// Validated against the original slice rather than the joined
			// string: joining and re-splitting would turn a scope containing a
			// space into two valid ones, which is the malformed case worth
			// catching.
			validate: func(string) error { return authmeta.ValidateScopes(document.ScopesSupported) },
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
// The published value is accepted when no issuer was configured — there is then
// nothing for it to undermine, and the trade is the one the whole feature makes —
// and when it shares an origin with the configured issuer, which is where TLS makes
// the issuer's own host answer for the document. That keeps the case the flag
// exists for: an authorization server publishing RFC 8414 metadata at a path the
// OIDC derivation cannot construct puts it on its own host, so it is same-origin.
//
// A cross-origin value with an issuer configured is disregarded rather than
// treated as an error. It is not necessarily an attack — a deployment may
// legitimately host metadata elsewhere — and the operator's own
// --oidc-metadata-url is the way to say so. It is said out loud, because the
// alternative is an operator debugging a 404 on the derived path while the server
// publishes a location the client silently declined to use.
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
			// been through url.Parse — deliberately, since round seven moved the
			// decision ahead of the validation. A value that fails SameOrigin
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

// adoptAuthorizationServer applies the issuer half of applyResourceMetadata, which
// is the half with a rule of its own — see that function's comment for why a
// contradiction here is an error rather than an override.
func (s *managedOIDCTokenSource) adoptAuthorizationServer(ctx context.Context, identity *oidcIdentity, advertised string) error {
	if advertised == "" {
		return nil
	}
	// Compared before anything is validated. What keeps the operator's own issuer
	// out of discovery-input policy is authorizationServerIsRemotelyChosen, inside
	// checkDiscoveredURL — not this early return, which is unobservable next to it
	// and is here only because an advertised value equal to a configured one is
	// nothing to adopt and so nothing to judge. Verified unobservable rather than
	// assumed: with the return removed, no test changes, because the only value
	// that reaches the check is the configured issuer, which was validated at parse
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
	if err := authhttp.CheckEndpointURL(label, value); err != nil {
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
// The dial guard on s.httpClient covers the same ground for fetches we make, and
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

func (s *managedOIDCTokenSource) refreshToken(ctx context.Context, cache tokenCache) (*oauth2.Token, error) {
	// Idempotent and already done by AccessToken on the normal path. Repeated
	// here, and in interactiveToken, so neither carries an unenforced
	// precondition: reading s.effective before resolution would be a nil
	// dereference, and a memoised no-op is a cheaper guarantee than a comment.
	if err := s.resolve(ctx); err != nil {
		return nil, err
	}
	config := s.oauthConfig("")
	// Pinned to the token endpoint's origin as well as guarded against a
	// downgrade. A 307 or 308 preserves method and body, so a cross-origin
	// redirect here posts the refresh token — or, on the exchange, the
	// authorization code and its PKCE verifier — to another host, and the
	// downgrade rule alone does not notice an https-to-https hop.
	//
	// Nested in this order, matching authmeta's fetch, so the downgrade check runs
	// first: a downgrade is nearly always an origin change too, and "transport
	// downgrade on the auth path" is the sharper diagnosis of the two. The
	// innermost policy re-checks the downgrade, which is harmless.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, authhttp.RefuseTransportDowngrade(authhttp.PinRedirectOrigin(s.httpClient)))
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

	// Pinned to the token endpoint's origin as well as guarded against a
	// downgrade. A 307 or 308 preserves method and body, so a cross-origin
	// redirect here posts the refresh token — or, on the exchange, the
	// authorization code and its PKCE verifier — to another host, and the
	// downgrade rule alone does not notice an https-to-https hop.
	//
	// Nested in this order, matching authmeta's fetch, so the downgrade check runs
	// first: a downgrade is nearly always an origin change too, and "transport
	// downgrade on the auth path" is the sharper diagnosis of the two. The
	// innermost policy re-checks the downgrade, which is harmless.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, authhttp.RefuseTransportDowngrade(authhttp.PinRedirectOrigin(s.httpClient)))
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

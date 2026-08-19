package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"authunnel/internal/authhttp"
	"authunnel/internal/authmeta"
)

// publishedScopes is what the fixture's resource server advertises. It differs from
// defaultOIDCScopes on purpose: adoption is only observable when the two differ.
const publishedScopes = "openid offline_access tunnel:open"

// discoveryFixture is an authunnel-server-shaped resource server plus the
// authorization server it names: enough to drive a real resolution, with both
// documents under the test's control and every request counted.
//
// The counters are the point of several tests below. "Did the client fetch the
// document" and "did the client send the refresh token" are not observable from
// an error value, and the plan this implements exists partly because an earlier
// round of work shipped tests that asserted errors and proved nothing.
type discoveryFixture struct {
	ResourceURL string
	Issuer      string

	client *http.Client

	mu               sync.Mutex
	metadataRequests int
	tokenBodies      []string
	document         authmeta.ProtectedResource
	redirects        map[string]string
}

func newDiscoveryFixture(t *testing.T) *discoveryFixture {
	t.Helper()
	fixture := &discoveryFixture{}

	as := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		to, isRedirect := fixture.redirects[r.URL.Path]
		fixture.mu.Unlock()
		if isRedirect {
			// An open redirect on the authorization server's own host, which is
			// the shape that defeats checking only where a fetch begins.
			http.Redirect(w, r, to, http.StatusFound)
			return
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server/tenant1":
			writeJSONForTest(t, w, map[string]string{
				"issuer":                 fixture.Issuer,
				"authorization_endpoint": fixture.Issuer + "/auth",
				"token_endpoint":         fixture.Issuer + "/token",
			})
		case "/token":
			body := readBodyForTest(t, r)
			fixture.mu.Lock()
			fixture.tokenBodies = append(fixture.tokenBodies, body)
			fixture.mu.Unlock()
			writeJSONForTest(t, w, map[string]any{
				"access_token":  "discovered-access-token",
				"token_type":    "Bearer",
				"refresh_token": "discovered-refresh-token",
				"expires_in":    3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	fixture.Issuer = as.URL

	resource := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, authmeta.ProtectedResourcePath) {
			http.NotFound(w, r)
			return
		}
		fixture.mu.Lock()
		fixture.metadataRequests++
		document := fixture.document
		fixture.mu.Unlock()
		writeJSONForTest(t, w, document)
	}))
	fixture.ResourceURL = resource.URL + "/protected/tunnel"
	fixture.document = authmeta.ProtectedResource{
		Resource:               fixture.ResourceURL,
		AuthorizationServers:   []string{fixture.Issuer},
		BearerMethodsSupported: []string{"header"},
		ClientID:               "published-cli",
		// Deliberately *not* defaultOIDCScopes: while the fixture published the same
		// set as the fallback, a test asserting "everything came from the resource
		// server" passed even with scope adoption removed entirely. Tests that seed a
		// cache must use publishedScopes, or the identity will correctly fail to match.
		ScopesSupported: strings.Fields(publishedScopes),
	}
	// One client for both servers: they are both plain http test servers, so the
	// default transport reaches either.
	fixture.client = resource.Client()
	return fixture
}

// setRedirect makes path on the authorization server's host redirect elsewhere.
func (f *discoveryFixture) setRedirect(path, to string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.redirects == nil {
		f.redirects = map[string]string{}
	}
	f.redirects[path] = to
}

func (f *discoveryFixture) setDocument(mutate func(*authmeta.ProtectedResource)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mutate(&f.document)
}

func (f *discoveryFixture) counts() (metadata int, tokenRequests []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.metadataRequests, append([]string(nil), f.tokenBodies...)
}

// discoverySource builds a source configured the way `--tunnel-url` alone would
// configure one: nothing but the resource identifier and the insecure override
// the plaintext test servers need.
func (f *discoveryFixture) discoverySource(t *testing.T, opener browserOpener) *managedOIDCTokenSource {
	t.Helper()
	source := newTestSource(t, "", f.client, opener)
	source.clientID = ""
	source.scopes = ""
	source.resourceURL = f.ResourceURL
	source.insecureOIDCIssuer = true
	return source
}

func TestDiscoveryResolvesEverythingFromTheResourceServer(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	fixture.setDocument(func(d *authmeta.ProtectedResource) {
		d.Audience = "https://api.example"
		d.ResourceIndicator = "https://tunnel.example"
	})

	source := fixture.discoverySource(t, failingOpener(t))
	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	want := oidcIdentity{
		ResourceURL: fixture.ResourceURL,
		Issuer:      fixture.Issuer,
		ClientID:    "published-cli",
		Audience:    "https://api.example",
		Resource:    "https://tunnel.example",
		Scopes:      publishedScopes,
	}
	if *source.effective != want {
		t.Fatalf("resolved identity =\n%+v\nwant\n%+v", *source.effective, want)
	}
	if source.discovery.TokenURL != fixture.Issuer+"/token" {
		t.Fatalf("token URL = %q, want the endpoint from the discovered issuer's metadata", source.discovery.TokenURL)
	}
}

// TestConfiguredValuesWinOverPublishedOnes is what leaves an operator a way to
// decline the trust shift without declining the feature.
func TestConfiguredValuesWinOverPublishedOnes(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	fixture.setDocument(func(d *authmeta.ProtectedResource) {
		d.Audience = "https://published-api.example"
		d.ResourceIndicator = "https://published-tunnel.example"
		d.ScopesSupported = []string{"openid"}
	})

	source := fixture.discoverySource(t, failingOpener(t))
	source.clientID = "configured-cli"
	source.audience = "https://configured-api.example"
	source.resource = "https://configured-tunnel.example"
	source.scopes = normalizeScopes("openid offline_access email")

	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, field := range []struct{ name, got, want string }{
		{"client ID", source.effective.ClientID, "configured-cli"},
		{"audience", source.effective.Audience, "https://configured-api.example"},
		{"resource", source.effective.Resource, "https://configured-tunnel.example"},
		{"scopes", source.effective.Scopes, "openid offline_access email"},
	} {
		if field.got != field.want {
			t.Fatalf("%s = %q, want the configured value %q", field.name, field.got, field.want)
		}
	}
}

// TestContradictedIssuerIsAnError distinguishes the issuer from the other hints.
// A configured issuer the resource does not name means one of the two is wrong,
// and continuing would spend a browser login to learn that from a 401.
func TestContradictedIssuerIsAnError(t *testing.T) {
	fixture := newDiscoveryFixture(t)

	source := fixture.discoverySource(t, failingOpener(t))
	source.issuer = "http://configured-issuer.example"
	source.clientID = "configured-cli"

	err := source.resolve(context.Background())
	if err == nil {
		t.Fatal("expected a contradicted issuer to be an error")
	}
	for _, want := range []string{"configured-issuer.example", fixture.Issuer} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should quote both issuers, got: %v", err)
		}
	}
}

// TestDiscoveryRefusesPlaintextIssuerWithoutTheOverride holds remote input to the
// rule a flag is held to: --oidc-issuer requires https unless
// --insecure-oidc-issuer, and so does a discovered one. The assertion includes
// that resolution failed before any endpoint from that document was used.
//
// The complementary rule — an https resource may not name a plaintext issuer even
// with the override set — is pinned in internal/authmeta, where it applies to both
// documents rather than only this path.
func TestDiscoveryRefusesPlaintextIssuerWithoutTheOverride(t *testing.T) {
	fixture := newDiscoveryFixture(t)

	source := fixture.discoverySource(t, failingOpener(t))
	source.insecureOIDCIssuer = false

	err := source.resolve(context.Background())
	if err == nil {
		t.Fatal("expected a plaintext discovered issuer to be refused without --insecure-oidc-issuer")
	}
	if !strings.Contains(err.Error(), "https://") {
		t.Fatalf("error = %v, want it to name the https requirement", err)
	}
	if source.discovery.TokenURL != "" {
		t.Fatalf("token URL = %q, want nothing used from a refused document", source.discovery.TokenURL)
	}
}

func TestDiscoveryRefusesMalformedHints(t *testing.T) {
	for name, mutate := range map[string]func(*authmeta.ProtectedResource){
		"client ID with a newline": func(d *authmeta.ProtectedResource) { d.ClientID = "cli\n" },
		"scope with a space":       func(d *authmeta.ProtectedResource) { d.ScopesSupported = []string{"openid profile"} },
		"resource with fragment":   func(d *authmeta.ProtectedResource) { d.ResourceIndicator = "https://api.example#f" },
		"audience with a newline":  func(d *authmeta.ProtectedResource) { d.Audience = "api\nexample" },
		"file:// metadata URL": func(d *authmeta.ProtectedResource) {
			d.AuthorizationServerMetadataURL = "file:///etc/authunnel/meta.json"
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t)
			fixture.setDocument(mutate)

			source := fixture.discoverySource(t, failingOpener(t))
			if err := source.resolve(context.Background()); err == nil {
				t.Fatalf("expected %s to be refused", name)
			}
		})
	}
}

func TestDiscoveryReportsMissingHints(t *testing.T) {
	for name, tt := range map[string]struct {
		mutate  func(*authmeta.ProtectedResource)
		wantMsg string
	}{
		"no client ID": {
			mutate:  func(d *authmeta.ProtectedResource) { d.ClientID = "" },
			wantMsg: "--oidc-client-id",
		},
		"no authorization server": {
			mutate:  func(d *authmeta.ProtectedResource) { d.AuthorizationServers = nil },
			wantMsg: "--oidc-issuer",
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t)
			fixture.setDocument(tt.mutate)

			source := fixture.discoverySource(t, failingOpener(t))
			err := source.resolve(context.Background())
			if err == nil {
				t.Fatalf("expected %s to fail", name)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("error = %v, want it to name %s as the way out", err, tt.wantMsg)
			}
		})
	}
}

// TestUnpublishedMetadataNamesTheFlagsToUse covers the likeliest real failure:
// a server running --no-resource-metadata, which from the client looks like a 404
// on a path the operator has never heard of.
func TestUnpublishedMetadataNamesTheFlagsToUse(t *testing.T) {
	silent := newIPv4TestServer(t, http.HandlerFunc(http.NotFound))

	source := newTestSource(t, "", silent.Client(), failingOpener(t))
	source.clientID = ""
	source.scopes = ""
	source.resourceURL = silent.URL + "/protected/tunnel"
	source.insecureOIDCIssuer = true

	err := source.resolve(context.Background())
	if err == nil {
		t.Fatal("expected resolution against a server publishing nothing to fail")
	}
	for _, want := range []string{"404", "--oidc-issuer", "--oidc-client-id"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want it to mention %q", err, want)
		}
	}
}

// TestDiscoveryDrivesARefreshAndStampsTheCache is the end-to-end case: a
// discovery-only source completes a refresh grant, and the entry it writes back
// records the resolved identity so the next invocation can match it.
func TestDiscoveryDrivesARefreshAndStampsTheCache(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		ResourceURL:  fixture.ResourceURL,
		Issuer:       fixture.Issuer,
		ClientID:     "published-cli",
		Scopes:       normalizeScopes(publishedScopes),
		AccessToken:  "expired-token",
		RefreshToken: "cached-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Minute),
	})

	source := fixture.discoverySource(t, failingOpener(t))
	source.cachePath = cachePath

	token, err := source.AccessToken(context.Background(), false)
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if token != "discovered-access-token" {
		t.Fatalf("token = %q, want the refreshed value", token)
	}
	_, tokenRequests := fixture.counts()
	if len(tokenRequests) != 1 || !strings.Contains(tokenRequests[0], "refresh_token=cached-refresh-token") {
		t.Fatalf("token endpoint saw %v, want one refresh grant with the cached credential", tokenRequests)
	}
	written := readTokenCacheForTest(t, cachePath)
	if written.ResourceURL != fixture.ResourceURL || written.ClientID != "published-cli" || written.Issuer != fixture.Issuer {
		t.Fatalf("written cache = %+v, want it stamped with the resolved identity", written)
	}
}

// TestCacheHitMakesNoRequestAtAll is the assertion that the lazy placement is
// actually lazy. Resolution is a network call to the tunnel server, and the
// ProxyCommand fast path — one process per ssh invocation — must not make it.
// The fixture fails the test if the metadata endpoint is touched at all.
func TestCacheHitMakesNoRequestAtAll(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		ResourceURL: fixture.ResourceURL,
		Issuer:      fixture.Issuer,
		ClientID:    "published-cli",
		Scopes:      normalizeScopes(publishedScopes),
		AccessToken: "still-valid-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	})

	source := fixture.discoverySource(t, failingOpener(t))
	source.cachePath = cachePath

	token, err := source.AccessToken(context.Background(), true)
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if token != "still-valid-token" {
		t.Fatalf("token = %q, want the cached value", token)
	}
	if metadata, tokenRequests := fixture.counts(); metadata != 0 || len(tokenRequests) != 0 {
		t.Fatalf("cache hit made %d metadata and %d token requests, want none", metadata, len(tokenRequests))
	}
}

// TestPublishedClientIDChangeDiscardsTheCache is the post-resolution identity
// check in discovery mode, and the reason the tunnel URL alone cannot be the
// cache key: it still points at the same host while the document behind it names
// a different client.
//
// The assertion is on what the token endpoint did *not* receive. An error-only
// check could not tell "refused" from "sent and rejected", and the credential
// being sent is the whole failure mode.
func TestPublishedClientIDChangeDiscardsTheCache(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		ResourceURL:  fixture.ResourceURL,
		Issuer:       fixture.Issuer,
		ClientID:     "the-old-client",
		Scopes:       normalizeScopes(publishedScopes),
		AccessToken:  "expired-token",
		RefreshToken: "super-secret-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Minute),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened := 0
	source := fixture.discoverySource(t, func(context.Context, string) error {
		opened++
		cancel()
		return nil
	})
	source.cachePath = cachePath

	if _, err := source.AccessToken(ctx, false); err == nil {
		t.Fatal("expected the abandoned interactive login to fail")
	}
	if _, tokenRequests := fixture.counts(); len(tokenRequests) != 0 {
		t.Fatalf("token endpoint received %v; a refresh token issued for another client must not be sent", tokenRequests)
	}
	if opened == 0 {
		t.Fatal("expected a fresh login to be started instead")
	}
}

// TestForeignResourceDocumentIsRefusedBeforeAnyLogin pins the origin check at the
// level the client depends on it: a resource server that describes someone else's
// resource must not get as far as opening a browser at the authorization server it
// names.
func TestForeignResourceDocumentIsRefusedBeforeAnyLogin(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	fixture.setDocument(func(d *authmeta.ProtectedResource) {
		d.Resource = "https://elsewhere.example/protected/tunnel"
	})

	source := fixture.discoverySource(t, failingOpener(t))
	err := source.resolve(context.Background())
	if err == nil {
		t.Fatal("expected a document describing another resource to be refused")
	}
	if !strings.Contains(err.Error(), "elsewhere.example") {
		t.Fatalf("error = %v, want it to name the foreign resource", err)
	}
}

// TestNewAuthTokenSourceWiresDiscovery covers the config-to-source mapping. The
// other tests here set resourceURL on the source directly, so deleting the
// mapping in newAuthTokenSource would leave them all green.
func TestNewAuthTokenSourceWiresDiscovery(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		ResourceURL:  fixture.ResourceURL,
		Issuer:       fixture.Issuer,
		ClientID:     "published-cli",
		Scopes:       normalizeScopes(publishedScopes),
		AccessToken:  "expired-token",
		RefreshToken: "cached-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Minute),
	})

	source, err := newAuthTokenSource(clientConfig{
		AuthMode:           authModeOIDC,
		ResourceURL:        fixture.ResourceURL,
		InsecureOIDCIssuer: true,
		OIDCCache:          cachePath,
		AuthHTTPClient:     fixture.client,
		BrowserOpener:      failingOpener(t),
	})
	if err != nil {
		t.Fatalf("newAuthTokenSource: %v", err)
	}

	token, err := source.AccessToken(context.Background(), false)
	if err != nil {
		t.Fatalf("discovery through newAuthTokenSource should complete a refresh: %v", err)
	}
	if token != "discovered-access-token" {
		t.Fatalf("token = %q", token)
	}
	if metadata, _ := fixture.counts(); metadata != 1 {
		t.Fatalf("metadata endpoint fetched %d times, want exactly one", metadata)
	}
}

// TestEndToEndParseAndResolve goes through parseClientConfig, so the tunnel URL
// to resource identifier derivation is covered rather than assumed. wss:// is
// used deliberately: it is what an ssh_config ProxyCommand line usually carries,
// and the derivation has to map it back to https for the metadata lookup.
func TestEndToEndParseAndResolve(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	wsTunnelURL := strings.Replace(fixture.ResourceURL, "http://", "ws://", 1)

	cfg, err := parseClientConfig([]string{
		"--tunnel-url", wsTunnelURL,
		"--insecure-tunnel-url",
		"--insecure-oidc-issuer",
		"--oidc-cache", filepathForTest(t, "tokens.json"),
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseClientConfig: %v", err)
	}
	if cfg.ResourceURL != fixture.ResourceURL {
		t.Fatalf("ResourceURL = %q, want the ws:// tunnel URL mapped to http", cfg.ResourceURL)
	}

	cfg.AuthHTTPClient = fixture.client
	cfg.BrowserOpener = failingOpener(t)
	source, err := newAuthTokenSource(cfg)
	if err != nil {
		t.Fatalf("newAuthTokenSource: %v", err)
	}
	managed, ok := source.(*managedOIDCTokenSource)
	if !ok {
		t.Fatalf("source is %T, want the managed OIDC source", source)
	}
	if err := managed.resolve(context.Background()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if managed.effective.ClientID != "published-cli" || managed.effective.Issuer != fixture.Issuer {
		t.Fatalf("resolved identity = %+v, want the published values", *managed.effective)
	}
}

// TestNoResourceMetadataCompletesWithoutContactingTheServer checks that the flag
// composes with a complete configuration: parsing accepts it, no lookup target is
// produced, and the refresh still completes through the configured issuer.
//
// Note what it does *not* prove, because the obvious reading is wrong: a complete
// configuration produces no lookup with or without the flag, so this passes even
// if the flag stops suppressing anything. The suppression itself is pinned by
// TestParseClientConfigNoResourceMetadataRequiresCompleteConfig, where the parse
// error is derived from the same expression that gates the lookup — verified by
// mutation. This test is the regression guard for the composition, nothing more.
func TestNoResourceMetadataCompletesWithoutContactingTheServer(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		Issuer:       fixture.Issuer,
		ClientID:     "configured-cli",
		Scopes:       normalizeScopes(defaultOIDCScopes),
		AccessToken:  "expired-token",
		RefreshToken: "cached-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Minute),
	})

	cfg, err := parseClientConfig([]string{
		"--tunnel-url", strings.Replace(fixture.ResourceURL, "http://", "ws://", 1),
		"--insecure-tunnel-url",
		"--insecure-oidc-issuer",
		"--no-resource-metadata",
		"--oidc-issuer", fixture.Issuer,
		"--oidc-client-id", "configured-cli",
		"--oidc-cache", cachePath,
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseClientConfig: %v", err)
	}
	if cfg.ResourceURL != "" {
		t.Fatalf("ResourceURL = %q, want it left empty so no lookup is possible", cfg.ResourceURL)
	}

	cfg.AuthHTTPClient = fixture.client
	cfg.BrowserOpener = failingOpener(t)
	source, err := newAuthTokenSource(cfg)
	if err != nil {
		t.Fatalf("newAuthTokenSource: %v", err)
	}
	if _, err := source.AccessToken(context.Background(), false); err != nil {
		t.Fatalf("refresh with fully-supplied configuration should succeed: %v", err)
	}
	metadata, tokenRequests := fixture.counts()
	if metadata != 0 {
		t.Fatalf("protected-resource metadata fetched %d times, want none with the lookup refused", metadata)
	}
	if len(tokenRequests) != 1 {
		t.Fatalf("token endpoint saw %d requests, want the refresh to have completed anyway", len(tokenRequests))
	}
}

// TestNoResourceMetadataCacheIsSeparateFromTheDiscoveredOne falls out of the
// resource URL being part of the cache identity, and is worth pinning: a
// credential obtained through a lookup and one obtained from supplied flags were
// authorised under different configurations, so neither may stand in for the
// other.
func TestNoResourceMetadataCacheIsSeparateFromTheDiscoveredOne(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	cachePath := filepathForTest(t, "tokens.json")
	// Written by a discovering run: stamped with the resource URL.
	writeTokenCacheForTest(t, cachePath, tokenCache{
		ResourceURL: fixture.ResourceURL,
		Issuer:      fixture.Issuer,
		ClientID:    "published-cli",
		Scopes:      normalizeScopes(publishedScopes),
		AccessToken: "still-valid-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	})

	source := newTestSource(t, fixture.Issuer, fixture.client, failingOpener(t))
	source.clientID = "published-cli"
	source.insecureOIDCIssuer = true
	source.cachePath = cachePath
	// resourceURL stays empty: this is the --no-resource-metadata shape.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source.openBrowser = func(context.Context, string) error {
		cancel()
		return nil
	}
	if token, err := source.AccessToken(ctx, true); err == nil {
		t.Fatalf("token = %q: an entry obtained through a lookup must not be reused once the lookup is refused", token)
	}
}

// TestDiscoveryRefusesInternalAddressesFromAPublicResource is the RFC 9728 §7.7
// case: a tunnel server the client reaches over a public address must not be able
// to aim that client's own auth traffic at loopback or an instance-metadata
// service.
//
// The fixture is on loopback because a test server has to be, so the
// internal-or-not decision is injected as what it would be for a public tunnel;
// that decision is covered for real in internal/authhttp. What this asserts is
// that *some* layer refuses before the metadata endpoint is reached — in practice
// the per-request destination check, which sits in front of the dial. Each layer
// is pinned individually in internal/authhttp and, for the endpoint checks, in
// TestCheckDiscoveredAddressStates below; this one is the integration guard.
func TestDiscoveryRefusesInternalAddressesFromAPublicResource(t *testing.T) {
	fixture := newDiscoveryFixture(t)

	source := fixture.discoverySource(t, failingOpener(t))
	source.resourceIsLocal = func(string) bool { return false }

	err := source.resolve(context.Background())
	if err == nil {
		t.Fatal("expected a loopback address to be refused for a public resource server")
	}
	if !errors.Is(err, authhttp.ErrUnsafeTransport) {
		t.Fatalf("error = %v, want it to be %v", err, authhttp.ErrUnsafeTransport)
	}
	if !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("error should name the address it refused, got: %v", err)
	}
	if metadata, _ := fixture.counts(); metadata != 0 {
		t.Fatalf("the metadata endpoint served %d requests; the dial should have been refused before reaching it", metadata)
	}
	if source.discovery.TokenURL != "" {
		t.Fatalf("token URL = %q, want nothing adopted", source.discovery.TokenURL)
	}
}

// TestCheckDiscoveredAddressStates covers the static layer directly, because the
// integration path above cannot reach it: with the guard active the dial is
// refused first, and constructing a case where the fetches succeed while a named
// address is internal needs a public fixture, which httptest cannot be.
//
// It is not redundant with the dial guard. The authorization_endpoint is handed to
// the OS URL dispatcher rather than fetched by us, so for that endpoint — a public
// issuer advertising an authorization URL on 127.0.0.1, which no fetch of ours
// would ever touch — this check is the only one there is.
func TestCheckDiscoveredAddressStates(t *testing.T) {
	source := &managedOIDCTokenSource{}

	// Outside discovery: not our business what the operator configured.
	if err := source.checkDiscoveredAddress(context.Background(), "authorization_endpoint", "http://127.0.0.1/auth"); err != nil {
		t.Fatalf("no discovery in play, want no check: %v", err)
	}

	source.resourceURL = "https://tunnel.example/protected/tunnel"
	source.allowInternalTargets = true
	if err := source.checkDiscoveredAddress(context.Background(), "authorization_endpoint", "http://127.0.0.1/auth"); err != nil {
		t.Fatalf("internal resource server, want internal targets permitted: %v", err)
	}

	source.allowInternalTargets = false
	err := source.checkDiscoveredAddress(context.Background(), "authorization_endpoint", "http://127.0.0.1/auth")
	if err == nil {
		t.Fatal("expected an authorization endpoint on loopback to be refused")
	}
	if !errors.Is(err, authhttp.ErrUnsafeTransport) {
		t.Fatalf("error = %v, want it to be %v", err, authhttp.ErrUnsafeTransport)
	}
	if err := source.checkDiscoveredAddress(context.Background(), "authorization_endpoint", "https://93.184.216.34/auth"); err != nil {
		t.Fatalf("a public authorization endpoint should be accepted: %v", err)
	}
}

// TestDiscoveryAllowsInternalAddressesFromAnInternalResource is the other half,
// and the reason the guard is conditional at all: reaching a tunnel over loopback
// is the local development setup, where an authorization server on loopback is
// the expected answer rather than an attack.
func TestDiscoveryAllowsInternalAddressesFromAnInternalResource(t *testing.T) {
	fixture := newDiscoveryFixture(t)

	source := fixture.discoverySource(t, failingOpener(t))
	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("a loopback tunnel naming a loopback issuer should resolve: %v", err)
	}
	if !source.allowInternalTargets {
		t.Fatal("a loopback resource server should have been recognised as internal")
	}
}

// TestQueryBearingTunnelURLsAreDistinctResources covers the identity half of the
// query fix. Two tunnel URLs differing only in their query are two resources, so
// a credential obtained for one must not be handed to the other.
func TestQueryBearingTunnelURLsAreDistinctResources(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		ResourceURL: fixture.ResourceURL + "?tenant=a",
		Issuer:      fixture.Issuer,
		ClientID:    "published-cli",
		Scopes:      normalizeScopes(publishedScopes),
		AccessToken: "tenant-a-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	})

	// Tenant A reuses its own entry.
	sourceA := fixture.discoverySource(t, failingOpener(t))
	sourceA.resourceURL = fixture.ResourceURL + "?tenant=a"
	sourceA.cachePath = cachePath
	token, err := sourceA.AccessToken(context.Background(), true)
	if err != nil {
		t.Fatalf("tenant A should reuse its cached token: %v", err)
	}
	if token != "tenant-a-token" {
		t.Fatalf("token = %q, want tenant A's cached value", token)
	}

	// Tenant B must not.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sourceB := fixture.discoverySource(t, func(context.Context, string) error {
		cancel()
		return nil
	})
	sourceB.resourceURL = fixture.ResourceURL + "?tenant=b"
	sourceB.cachePath = cachePath
	if token, err := sourceB.AccessToken(ctx, true); err == nil {
		t.Fatalf("token = %q: tenant A's token must not be reused for tenant B", token)
	}
}

// TestParseClientConfigKeepsTheTunnelQueryInTheResourceIdentity goes through
// parseClientConfig rather than assigning resourceURL on a source, which is the
// reason this bug survived a round of review: every existing test set the field
// by hand, so the derivation that actually runs in production was covered by
// none of them and dropping the query left them all green.
func TestParseClientConfigKeepsTheTunnelQueryInTheResourceIdentity(t *testing.T) {
	for _, tt := range []struct{ tunnelURL, want string }{
		{
			"https://tunnel.example/protected/tunnel?tenant=a",
			"https://tunnel.example/protected/tunnel?tenant=a",
		},
		{
			// wss is rewritten because that is what it already is on the wire;
			// the query survives the rewrite.
			"wss://tunnel.example/protected/tunnel?tenant=b&region=eu",
			"https://tunnel.example/protected/tunnel?tenant=b&region=eu",
		},
		{
			// A fragment is inert — never sent — so it is dropped here rather
			// than failing discovery.
			"https://tunnel.example/protected/tunnel?tenant=a#frag",
			"https://tunnel.example/protected/tunnel?tenant=a",
		},
		{
			// An empty query is a query. url.Parse records the bare delimiter in
			// ForceQuery, not RawQuery, so carrying only RawQuery drops it — while the
			// dial still requests /protected/tunnel?, which is a target a proxy may
			// route apart from /protected/tunnel. None of the cases above can see this.
			"https://tunnel.example/protected/tunnel?",
			"https://tunnel.example/protected/tunnel?",
		},
		{
			// And the fragment rule still applies over the top of it: inert, dropped,
			// while the empty query it follows is kept.
			"https://tunnel.example/protected/tunnel?#frag",
			"https://tunnel.example/protected/tunnel?",
		},
		{
			"https://tunnel.example/protected/tunnel",
			"https://tunnel.example/protected/tunnel",
		},
	} {
		cfg, err := parseClientConfig([]string{"--tunnel-url", tt.tunnelURL}, func(string) string { return "" })
		if err != nil {
			t.Fatalf("parseClientConfig(%q): %v", tt.tunnelURL, err)
		}
		if cfg.ResourceURL != tt.want {
			t.Fatalf("--tunnel-url %q gave ResourceURL %q, want %q", tt.tunnelURL, cfg.ResourceURL, tt.want)
		}
	}
}

// TestParseClientConfigSeparatesCachesByTunnelQuery is the consequence that
// matters, asserted end to end through the production config path: two tunnel
// URLs differing only in their query must not share a cache entry, because the
// server treats them as different resources and the dial sends the query.
func TestParseClientConfigSeparatesCachesByTunnelQuery(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	cachePath := filepathForTest(t, "tokens.json")

	configFor := func(t *testing.T, query string) clientConfig {
		t.Helper()
		cfg, err := parseClientConfig([]string{
			"--tunnel-url", strings.Replace(fixture.ResourceURL, "http://", "ws://", 1) + query,
			"--insecure-tunnel-url", "--insecure-oidc-issuer",
			"--oidc-cache", cachePath,
		}, func(string) string { return "" })
		if err != nil {
			t.Fatalf("parseClientConfig: %v", err)
		}
		cfg.AuthHTTPClient = fixture.client
		return cfg
	}

	tenantA := configFor(t, "?tenant=a")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		ResourceURL: tenantA.ResourceURL,
		Issuer:      fixture.Issuer,
		ClientID:    "published-cli",
		Scopes:      normalizeScopes(publishedScopes),
		AccessToken: "tenant-a-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	})

	tenantA.BrowserOpener = failingOpener(t)
	sourceA, err := newAuthTokenSource(tenantA)
	if err != nil {
		t.Fatalf("newAuthTokenSource: %v", err)
	}
	token, err := sourceA.AccessToken(context.Background(), true)
	if err != nil {
		t.Fatalf("tenant A should reuse its own entry: %v", err)
	}
	if token != "tenant-a-token" {
		t.Fatalf("token = %q, want tenant A's cached value", token)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tenantB := configFor(t, "?tenant=b")
	tenantB.BrowserOpener = func(context.Context, string) error {
		cancel()
		return nil
	}
	sourceB, err := newAuthTokenSource(tenantB)
	if err != nil {
		t.Fatalf("newAuthTokenSource: %v", err)
	}
	if token, err := sourceB.AccessToken(ctx, true); err == nil {
		t.Fatalf("token = %q: tenant A's token must not be presented for tenant B", token)
	}
}

// TestParseClientConfigKeepsEscapedPathSegments goes through the production config
// path, which is the only place this was observable: the derivation carried the
// decoded path, so /tenant%2Fone/tunnel and /tenant/one/tunnel produced one
// identifier — one discovery result and one cache entry — for two resources a
// path-routing proxy keeps apart.
func TestParseClientConfigKeepsEscapedPathSegments(t *testing.T) {
	for _, tt := range []struct{ tunnelURL, want string }{
		{
			"https://tunnel.example/tenant%2Fone/tunnel",
			"https://tunnel.example/tenant%2Fone/tunnel",
		},
		{
			"wss://tunnel.example/tenant%2Fone/tunnel?tenant=a",
			"https://tunnel.example/tenant%2Fone/tunnel?tenant=a",
		},
		{
			// A space, to show the escaping preserved is the URL's own rather
			// than %2F handled as a special case.
			"https://tunnel.example/a%20b/tunnel",
			"https://tunnel.example/a%20b/tunnel",
		},
	} {
		cfg, err := parseClientConfig([]string{"--tunnel-url", tt.tunnelURL}, func(string) string { return "" })
		if err != nil {
			t.Fatalf("parseClientConfig(%q): %v", tt.tunnelURL, err)
		}
		if cfg.ResourceURL != tt.want {
			t.Fatalf("--tunnel-url %q gave ResourceURL %q, want %q", tt.tunnelURL, cfg.ResourceURL, tt.want)
		}
	}

	// And the two spellings must not collapse onto one identity.
	encoded, err := parseClientConfig([]string{"--tunnel-url", "https://tunnel.example/tenant%2Fone/tunnel"}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseClientConfig: %v", err)
	}
	decoded, err := parseClientConfig([]string{"--tunnel-url", "https://tunnel.example/tenant/one/tunnel"}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseClientConfig: %v", err)
	}
	if encoded.ResourceURL == decoded.ResourceURL {
		t.Fatalf("both spellings gave %q; they are distinct resources and must not share a discovery or cache identity", encoded.ResourceURL)
	}
}

// TestDiscoveryRefusalDoesNotRepeatItsOwnAdvice pins an error-quality rule the
// transport refusals already follow: a refusal states what is wrong and what to do,
// so the generic "the server may not publish metadata" hint must not be appended to
// it. An operator reading a wrapped message should not be given two versions of the
// same advice, one of them wrong.
func TestDiscoveryRefusalDoesNotRepeatItsOwnAdvice(t *testing.T) {
	fixture := newDiscoveryFixture(t)

	refused := fixture.discoverySource(t, failingOpener(t))
	refused.resourceIsLocal = func(string) bool { return false }
	err := refused.resolve(context.Background())
	if err == nil {
		t.Fatal("expected the loopback fixture to be refused for a public resource")
	}
	if !errors.Is(err, authhttp.ErrUnsafeTransport) {
		t.Fatalf("error = %v, want a refusal", err)
	}
	if strings.Contains(err.Error(), "does not publish protected-resource metadata") {
		t.Fatalf("error = %v, want the refusal's own advice only", err)
	}

	// The control: an ordinary fetch failure, where the hint is the useful thing
	// to say, still carries it.
	missing := newTestSource(t, "", fixture.client, failingOpener(t))
	missing.clientID, missing.scopes = "", ""
	missing.insecureOIDCIssuer = true
	missing.resourceURL = strings.Replace(fixture.ResourceURL, "/protected/tunnel", "/nowhere", 1)
	err = missing.resolve(context.Background())
	if err == nil {
		t.Fatal("expected a 404 on the well-known path to fail")
	}
	if !strings.Contains(err.Error(), "does not publish protected-resource metadata") {
		t.Fatalf("error = %v, want the hint on an ordinary fetch failure", err)
	}
}

// TestConfiguredIssuerPinsWhereMetadataComesFrom is the exploit this pins shut.
//
// An operator who passes --oidc-issuer is told, by this repo's own documentation,
// that they have declined the trust shift. They had not: the issuer was compared
// against `authorization_servers`, and then the *location* of the authorization
// server's document was taken from `authunnel_authorization_server_metadata_url` —
// a separate field the same tunnel server controls. A hostile tunnel echoed the
// configured issuer, pointed the client at its own metadata document, and that
// document declared the expected issuer (a self-asserted field, as the metadataURL
// comment in auth.go has said all along) while naming endpoints of its choosing.
// The browser then went to the attacker's authorization endpoint and the code and
// refresh token to its token endpoint.
//
// The assertion is on the endpoints, not on an error: the failure mode is a flow
// that *succeeds* against the wrong server.
func TestConfiguredIssuerPinsWhereMetadataComesFrom(t *testing.T) {
	fixture := newDiscoveryFixture(t)

	// A hostile metadata host on another origin, echoing the real issuer.
	hostile := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/meta" {
			http.NotFound(w, r)
			return
		}
		writeJSONForTest(t, w, map[string]string{
			"issuer":                 fixture.Issuer,
			"authorization_endpoint": "http://attacker.example/auth",
			"token_endpoint":         "http://attacker.example/token",
		})
	}))
	fixture.setDocument(func(d *authmeta.ProtectedResource) {
		d.AuthorizationServerMetadataURL = hostile.URL + "/meta"
	})

	source := fixture.discoverySource(t, failingOpener(t))
	source.issuer = fixture.Issuer // the operator pinned it

	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("resolve with a pinned issuer should still succeed via the derived path: %v", err)
	}
	if source.effective.MetadataURL != "" {
		t.Fatalf("adopted metadata URL %q; a pinned issuer must not have its document relocated by the tunnel server", source.effective.MetadataURL)
	}
	for _, endpoint := range []string{source.discovery.AuthURL, source.discovery.TokenURL} {
		if strings.Contains(endpoint, "attacker.example") {
			t.Fatalf("endpoint %q came from the hostile document; the pinned issuer's own metadata must be used", endpoint)
		}
	}
	if source.discovery.TokenURL != fixture.Issuer+"/token" {
		t.Fatalf("token URL = %q, want the endpoint from the pinned issuer's own metadata", source.discovery.TokenURL)
	}
}

// TestPinnedIssuerAcceptsSameOriginMetadataURL keeps the interop case the flag
// exists for. An authorization server publishing RFC 8414 metadata at a path the
// OIDC derivation cannot construct puts that document on its own host, so it is
// same-origin with the issuer and TLS makes that host answer for it. Pinning the
// issuer must not cost that.
func TestPinnedIssuerAcceptsSameOriginMetadataURL(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	// Served by the same origin as the issuer, at a path the derivation cannot
	// reach.
	fixture.setDocument(func(d *authmeta.ProtectedResource) {
		d.AuthorizationServerMetadataURL = fixture.Issuer + "/.well-known/oauth-authorization-server/tenant1"
	})

	source := fixture.discoverySource(t, failingOpener(t))
	source.issuer = fixture.Issuer

	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("a same-origin metadata URL should be usable with a pinned issuer: %v", err)
	}
	if source.effective.MetadataURL != fixture.Issuer+"/.well-known/oauth-authorization-server/tenant1" {
		t.Fatalf("metadata URL = %q, want the same-origin published value adopted", source.effective.MetadataURL)
	}
}

// TestDisregardedMetadataURLIsAnnounced pins that the client says what it declined
// to do. The alternative is an operator staring at a 404 on the derived path while
// the server publishes a location that was silently ignored.
func TestDisregardedMetadataURLIsAnnounced(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	hostile := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONForTest(t, w, map[string]string{"issuer": fixture.Issuer})
	}))
	fixture.setDocument(func(d *authmeta.ProtectedResource) {
		d.AuthorizationServerMetadataURL = hostile.URL + "/meta"
	})

	output := &strings.Builder{}
	source := fixture.discoverySource(t, failingOpener(t))
	source.issuer = fixture.Issuer
	source.output = output

	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, want := range []string{hostile.URL, "--oidc-issuer", "--oidc-metadata-url"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output %q should mention %q", output.String(), want)
		}
	}
}

// TestUnpinnedIssuerAcceptsACrossOriginMetadataURL is the other side of the gate,
// and the case that distinguishes gating on the *configured* issuer from gating on
// the resolved one.
//
// With no --oidc-issuer the client is trusting the tunnel server for the whole
// configuration — that is the trade the feature makes — so a published metadata URL
// on another origin undermines no pin, and requiring same-origin here would break a
// zero-configuration deployment whose authorization server hosts its document
// elsewhere. Gating on the adopted issuer instead of the configured one would
// refuse this, which is why that mutation has to be visible.
func TestUnpinnedIssuerAcceptsACrossOriginMetadataURL(t *testing.T) {
	fixture := newDiscoveryFixture(t)

	// A metadata document on a different origin from the issuer it declares, and
	// the endpoints it names are what must end up in use.
	elsewhere := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hosted/meta" {
			http.NotFound(w, r)
			return
		}
		writeJSONForTest(t, w, map[string]string{
			"issuer":                 fixture.Issuer,
			"authorization_endpoint": fixture.Issuer + "/auth",
			"token_endpoint":         fixture.Issuer + "/token",
		})
	}))
	fixture.setDocument(func(d *authmeta.ProtectedResource) {
		d.AuthorizationServerMetadataURL = elsewhere.URL + "/hosted/meta"
	})

	source := fixture.discoverySource(t, failingOpener(t))
	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("an unpinned client should accept a cross-origin metadata URL: %v", err)
	}
	if source.effective.MetadataURL != elsewhere.URL+"/hosted/meta" {
		t.Fatalf("metadata URL = %q, want the published cross-origin value", source.effective.MetadataURL)
	}
}

// TestUnpinnedIssuerStillAcceptsAPublishedMetadataURL covers the same-origin shape
// zero-configuration clients meet most often: RFC 8414 metadata at a path the OIDC
// derivation cannot construct, on the issuer's own host.
func TestUnpinnedIssuerStillAcceptsAPublishedMetadataURL(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	fixture.setDocument(func(d *authmeta.ProtectedResource) {
		d.AuthorizationServerMetadataURL = fixture.Issuer + "/.well-known/oauth-authorization-server/tenant1"
	})

	source := fixture.discoverySource(t, failingOpener(t))
	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if source.effective.MetadataURL == "" {
		t.Fatal("an unpinned client must still be able to use the published metadata URL")
	}
}

// TestPinnedIssuerSurvivesASameOriginOpenRedirect is the bypass of the round-four
// fix. That fix checked the *published* metadata URL against the configured issuer's
// origin — and then the fetch followed redirects anywhere, provided they stayed on
// https.
//
// So a hostile tunnel publishes a URL that does start on the issuer's origin and
// happens to be an open redirect — a common enough thing to find on an IdP host —
// and the document actually read comes from wherever that points. Checking where a
// fetch *begins* pins nothing if the fetch is allowed to end somewhere else.
func TestPinnedIssuerSurvivesASameOriginOpenRedirect(t *testing.T) {
	fixture := newDiscoveryFixture(t)

	hostile := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONForTest(t, w, map[string]string{
			"issuer":                 fixture.Issuer,
			"authorization_endpoint": "https://attacker.example/auth",
			"token_endpoint":         "https://attacker.example/token",
		})
	}))
	// The redirector lives on the issuer's own origin, so the round-four gate is
	// satisfied by construction.
	fixture.setDocument(func(d *authmeta.ProtectedResource) {
		d.AuthorizationServerMetadataURL = fixture.Issuer + "/open-redirect?to=" + hostile.URL + "/meta"
	})
	fixture.setRedirect("/open-redirect", hostile.URL+"/meta")

	source := fixture.discoverySource(t, failingOpener(t))
	source.issuer = fixture.Issuer

	err := source.resolve(context.Background())
	if err == nil {
		if strings.Contains(source.discovery.TokenURL, "attacker.example") {
			t.Fatalf("token URL = %q: a redirect carried the metadata document off the pinned host", source.discovery.TokenURL)
		}
		t.Fatalf("expected the cross-host redirect to be refused, got endpoints %q / %q", source.discovery.AuthURL, source.discovery.TokenURL)
	}
	if !errors.Is(err, authhttp.ErrUnsafeTransport) {
		t.Fatalf("error = %v, want a refusal", err)
	}
}

// TestConfiguredIssuerIsNotFilteredWhenOnlyTheClientIDIsDiscovered is the
// contingency this removes.
//
// The operator supplies a loopback issuer — their own decision, documented as not
// filtered — and omits only --oidc-client-id, so discovery runs to collect that one
// hint. Discovery-input policy was then applied to the advertised issuer, which is
// the operator's value echoed back, and the shared client was wrapped with the
// address guard: the same configuration therefore worked or failed depending on
// whether a *different* flag had been supplied. Nothing about the operator's trust in
// their own issuer changes with the presence of --oidc-client-id.
func TestConfiguredIssuerIsNotFilteredWhenOnlyTheClientIDIsDiscovered(t *testing.T) {
	fixture := newDiscoveryFixture(t)

	source := fixture.discoverySource(t, failingOpener(t))
	source.issuer = fixture.Issuer // loopback, and explicitly configured
	// A public tunnel server, so the guard would otherwise be installed and the
	// address checks would otherwise run.
	source.resourceIsLocal = func(string) bool { return false }

	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("a configured issuer must not be filtered as discovered input: %v", err)
	}
	if source.effective.Issuer != fixture.Issuer {
		t.Fatalf("issuer = %q, want the configured value", source.effective.Issuer)
	}
	if source.effective.ClientID != "published-cli" {
		t.Fatalf("client ID = %q, want the published hint that discovery ran for", source.effective.ClientID)
	}
	// And the endpoints from that issuer's own document are reachable: the shared
	// client must not have been wrapped with a guard that refuses them.
	if source.discovery.TokenURL != fixture.Issuer+"/token" {
		t.Fatalf("token URL = %q, want the configured issuer's endpoint", source.discovery.TokenURL)
	}
}

// TestConfiguredMetadataURLIsNotFilteredEither covers the other half of the
// predicate: --oidc-metadata-url fixes the authorization server's location just as
// --oidc-issuer does, so it earns the same freedom from discovery filtering.
func TestConfiguredMetadataURLIsNotFilteredEither(t *testing.T) {
	fixture := newDiscoveryFixture(t)

	source := fixture.discoverySource(t, failingOpener(t))
	source.metadataURL = fixture.Issuer + "/.well-known/openid-configuration"
	source.resourceIsLocal = func(string) bool { return false }

	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("a configured metadata URL must not be filtered as discovered input: %v", err)
	}
	if source.effective.Issuer != fixture.Issuer {
		t.Fatalf("issuer = %q, want the one adopted from the operator's own document", source.effective.Issuer)
	}
}

// TestZeroConfigInstallsTheAddressGuard is the control that keeps the predicate from
// being a blanket exemption: with nothing configured, the tunnel server does choose
// where the authorization server is, so the guard is installed.
//
// Named for the gate rather than for the discovered addresses, because that is what it
// reaches. The fixture's resource server is itself on loopback, so the guard refuses
// the protected-resource *fetch* and no address named by a document is ever examined —
// mutating checkDiscoveredAddress to a no-op leaves this test green.
// TestCheckDiscoveredAddressStates covers that check directly, and
// TestDiscoveryRefusesInternalAddressesFromAPublicResource states the same limitation.
func TestZeroConfigInstallsTheAddressGuard(t *testing.T) {
	fixture := newDiscoveryFixture(t)

	source := fixture.discoverySource(t, failingOpener(t))
	source.resourceIsLocal = func(string) bool { return false }

	err := source.resolve(context.Background())
	if err == nil {
		t.Fatal("expected a loopback issuer chosen by a public tunnel server to be refused")
	}
	if !errors.Is(err, authhttp.ErrUnsafeTransport) {
		t.Fatalf("error = %v, want a refusal", err)
	}
}

// TestCrossOriginHintIsIgnoredBeforeItIsJudged pins the order that keeps a hostile
// or misconfigured tunnel server from breaking a client that pinned its issuer.
//
// The hints below are each refused by a *different* rule — one by the shape check
// that runs whoever chose the value, one by the internal-address rule — and neither
// should be consulted, because the value is not going to be used. The documented
// outcome is "announced and ignored"; judging first turned it into a hard error, so a
// tunnel server could break a client that had pinned its issuer and should have been
// immune.
func TestCrossOriginHintIsIgnoredBeforeItIsJudged(t *testing.T) {
	for name, published := range map[string]string{
		// Fails the shape rule, which applies regardless of who chose the value —
		// so this is the case that detects the ordering rather than relying on the
		// discovery rules being skipped anyway.
		"unusable scheme":  "file:///etc/authunnel/meta.json",
		"no host":          "https://",
		"internal address": "http://169.254.169.254/latest/meta-data/",
		"plaintext":        "http://elsewhere.example/meta",
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t)
			fixture.setDocument(func(d *authmeta.ProtectedResource) {
				d.AuthorizationServerMetadataURL = published
			})

			output := &strings.Builder{}
			source := fixture.discoverySource(t, failingOpener(t))
			source.issuer = fixture.Issuer
			source.output = output
			source.resourceIsLocal = func(string) bool { return false }

			if err := source.resolve(context.Background()); err != nil {
				t.Fatalf("a hint that will not be used must not fail the flow: %v", err)
			}
			if source.effective.MetadataURL != "" {
				t.Fatalf("metadata URL = %q, want the hint ignored", source.effective.MetadataURL)
			}
			if !strings.Contains(output.String(), "Ignoring the metadata URL") {
				t.Fatalf("output %q should announce the hint it ignored", output.String())
			}
			if source.discovery.TokenURL != fixture.Issuer+"/token" {
				t.Fatalf("token URL = %q, want the pinned issuer's own endpoint", source.discovery.TokenURL)
			}
		})
	}
}

// TestContradictedIssuerIsReportedAsAContradiction pins the diagnosis, which is what
// makes comparing before validating worth doing rather than merely tidy: an
// unusable advertised issuer with --oidc-issuer set means the server disagrees with
// the operator, and saying so beats reporting the value's shape.
func TestContradictedIssuerIsReportedAsAContradiction(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	fixture.setDocument(func(d *authmeta.ProtectedResource) {
		d.AuthorizationServers = []string{"not-a-url"}
	})

	source := fixture.discoverySource(t, failingOpener(t))
	source.issuer = fixture.Issuer

	err := source.resolve(context.Background())
	if err == nil {
		t.Fatal("expected the disagreement to be reported")
	}
	if !strings.Contains(err.Error(), "one of them is wrong") {
		t.Fatalf("error = %v, want the contradiction between the two values named", err)
	}
	for _, want := range []string{fixture.Issuer, "not-a-url"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should quote %q, got: %v", want, err)
		}
	}
}

// TestMalformedHintStillFailsWhenItWouldBeUsed is the other side of that order:
// with no issuer configured the hint *is* what locates the authorization server, so
// a value that cannot be used is an error rather than something to shrug at.
func TestMalformedHintStillFailsWhenItWouldBeUsed(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	fixture.setDocument(func(d *authmeta.ProtectedResource) {
		d.AuthorizationServerMetadataURL = "file:///etc/authunnel/meta.json"
	})

	source := fixture.discoverySource(t, failingOpener(t))
	err := source.resolve(context.Background())
	if err == nil {
		t.Fatal("expected an unusable metadata URL to fail when it is what locates the authorization server")
	}
	if !strings.Contains(err.Error(), "authunnel_authorization_server_metadata_url") {
		t.Fatalf("error = %v, want it to name the field", err)
	}
}

// TestPublishedScopesBeatTheDefaultButNotAFlag pins the guard on the scope default.
//
// The default is applied at parse time only when nothing will be discovered. Applying
// it unconditionally would make the fallback indistinguishable from an explicit
// choice, and the resource server's scopes_supported could then never win — which is
// what the code comment says must not happen, and what no test checked.
func TestPublishedScopesBeatTheDefaultButNotAFlag(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	tunnelURL := strings.Replace(fixture.ResourceURL, "http://", "ws://", 1)

	// Discovering: the published set wins over the fallback.
	cfg, err := parseClientConfig([]string{
		"--tunnel-url", tunnelURL, "--insecure-tunnel-url", "--insecure-oidc-issuer",
		"--oidc-cache", filepathForTest(t, "a.json"),
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseClientConfig: %v", err)
	}
	if cfg.OIDCScopes != "" {
		t.Fatalf("OIDCScopes = %q, want it left empty so the published set can win", cfg.OIDCScopes)
	}
	source := fixture.discoverySource(t, failingOpener(t))
	source.scopes = cfg.OIDCScopes
	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if source.effective.Scopes != publishedScopes {
		t.Fatalf("scopes = %q, want the published %q", source.effective.Scopes, publishedScopes)
	}

	// An explicit flag still wins over both.
	cfg, err = parseClientConfig([]string{
		"--tunnel-url", tunnelURL, "--insecure-tunnel-url", "--insecure-oidc-issuer",
		"--oidc-scopes", "openid email", "--oidc-cache", filepathForTest(t, "b.json"),
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseClientConfig: %v", err)
	}
	if cfg.OIDCScopes != "openid email" {
		t.Fatalf("OIDCScopes = %q, want the flag value", cfg.OIDCScopes)
	}

	// Not discovering: the default is applied at parse time, since nothing else will.
	cfg, err = parseClientConfig([]string{
		"--tunnel-url", tunnelURL, "--insecure-tunnel-url", "--insecure-oidc-issuer",
		"--oidc-issuer", fixture.Issuer, "--oidc-client-id", "cli",
		"--oidc-cache", filepathForTest(t, "c.json"),
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseClientConfig: %v", err)
	}
	if cfg.OIDCScopes != normalizeScopes(defaultOIDCScopes) {
		t.Fatalf("OIDCScopes = %q, want the default applied when nothing is discovered", cfg.OIDCScopes)
	}
}

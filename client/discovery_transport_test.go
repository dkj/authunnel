package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"authunnel/internal/authhttp"
)

// metadataIssuer serves only an OIDC discovery document, with the advertised
// endpoints under the test's control. It is deliberately minimal: these tests
// are about whether an endpoint is accepted, not about completing a flow.
type metadataIssuer struct {
	URL string
}

func newMetadataIssuer(t *testing.T, useTLS bool, authEndpoint, tokenEndpoint func(base string) string) (*metadataIssuer, *http.Client) {
	t.Helper()
	issuer := &metadataIssuer{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		writeJSONForTest(t, w, map[string]string{
			"issuer":                 issuer.URL,
			"authorization_endpoint": authEndpoint(issuer.URL),
			"token_endpoint":         tokenEndpoint(issuer.URL),
		})
	})

	var server = newIPv4TestServer(t, handler)
	if useTLS {
		server = newIPv4TLSTestServer(t, handler)
	}
	issuer.URL = server.URL
	return issuer, server.Client()
}

func sameHost(suffix string) func(string) string {
	return func(base string) string { return base + suffix }
}

func literal(value string) func(string) string {
	return func(string) string { return value }
}

// failingOpener fails the test if the browser is ever launched. Asserting only
// on the returned error would still pass if the URL had already been handed to
// the OS dispatcher, which is the thing that must not happen.
func failingOpener(t *testing.T) browserOpener {
	t.Helper()
	return func(_ context.Context, url string) error {
		t.Fatalf("browser opener must not be invoked; was handed %q", url)
		return nil
	}
}

func newTestSource(t *testing.T, issuerURL string, client *http.Client, opener browserOpener) *managedOIDCTokenSource {
	t.Helper()
	return &managedOIDCTokenSource{
		issuer:      issuerURL,
		clientID:    "authunnel-cli",
		scopes:      normalizeScopes("openid offline_access"),
		cachePath:   filepathForTest(t, "tokens.json"),
		httpClient:  authhttp.RefuseTransportDowngrade(client),
		output:      io.Discard,
		openBrowser: opener,
		now:         time.Now,
	}
}

// TestDiscoveryRejectsPlaintextTokenEndpoint covers the credential-bearing
// endpoint: an https metadata document must not be able to send the refresh
// token and authorization code to a plaintext endpoint.
func TestDiscoveryRejectsPlaintextTokenEndpoint(t *testing.T) {
	plain, _ := newMetadataIssuer(t, false, sameHost("/auth"), sameHost("/token"))
	issuer, client := newMetadataIssuer(t, true, sameHost("/auth"), literal(plain.URL+"/token"))

	source := newTestSource(t, issuer.URL, client, failingOpener(t))
	_, err := source.oauthConfig(context.Background(), "http://127.0.0.1:0/callback")
	if err == nil {
		t.Fatal("expected an https issuer advertising a plaintext token_endpoint to be rejected")
	}
	if !strings.Contains(err.Error(), "non-https token_endpoint") {
		t.Fatalf("error = %v, want the token_endpoint downgrade check", err)
	}
}

func TestDiscoveryRejectsPlaintextAuthorizationEndpoint(t *testing.T) {
	plain, _ := newMetadataIssuer(t, false, sameHost("/auth"), sameHost("/token"))
	issuer, client := newMetadataIssuer(t, true, literal(plain.URL+"/auth"), sameHost("/token"))

	source := newTestSource(t, issuer.URL, client, failingOpener(t))
	_, err := source.oauthConfig(context.Background(), "http://127.0.0.1:0/callback")
	if err == nil {
		t.Fatal("expected an https issuer advertising a plaintext authorization_endpoint to be rejected")
	}
	if !strings.Contains(err.Error(), "non-https authorization_endpoint") {
		t.Fatalf("error = %v, want the authorization_endpoint downgrade check", err)
	}
}

// TestDiscoveryAcceptsHTTPSEndpoints is the control for the two above: the same
// TLS setup with https endpoints must succeed, so their rejections are
// attributable to the scheme rather than to TLS handling in the fixture.
func TestDiscoveryAcceptsHTTPSEndpoints(t *testing.T) {
	issuer, client := newMetadataIssuer(t, true, sameHost("/auth"), sameHost("/token"))

	source := newTestSource(t, issuer.URL, client, failingOpener(t))
	config, err := source.oauthConfig(context.Background(), "http://127.0.0.1:0/callback")
	if err != nil {
		t.Fatalf("https endpoints should be accepted: %v", err)
	}
	if config.Endpoint.TokenURL != issuer.URL+"/token" {
		t.Fatalf("token URL = %q, want the discovered https endpoint", config.Endpoint.TokenURL)
	}
}

// TestDiscoveryRejectsNonHTTPEndpointsOverPlaintextMetadata is the case the
// downgrade check alone cannot catch. With an http metadata source there is no
// downgrade, so every scheme passes that check — including file://, which would
// otherwise reach the OS URL dispatcher via the browser opener.
func TestDiscoveryRejectsNonHTTPEndpointsOverPlaintextMetadata(t *testing.T) {
	for _, tt := range []struct {
		name              string
		auth, token       func(string) string
		wantErrorContains string
	}{
		{
			name:              "file authorization endpoint",
			auth:              literal("file:///etc/passwd"),
			token:             sameHost("/token"),
			wantErrorContains: `authorization_endpoint "file:///etc/passwd" uses unsupported scheme "file"`,
		},
		{
			name:              "custom scheme authorization endpoint",
			auth:              literal("myapp://launch"),
			token:             sameHost("/token"),
			wantErrorContains: `uses unsupported scheme "myapp"`,
		},
		{
			name:              "host-less authorization endpoint",
			auth:              literal("https:relative-path"),
			token:             sameHost("/token"),
			wantErrorContains: "absolute URL with a host",
		},
		{
			name:              "file token endpoint",
			auth:              sameHost("/auth"),
			token:             literal("file:///tmp/token"),
			wantErrorContains: `token_endpoint "file:///tmp/token" uses unsupported scheme "file"`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Plain http issuer: the local-development posture the config
			// layer gates behind --insecure-oidc-issuer.
			issuer, client := newMetadataIssuer(t, false, tt.auth, tt.token)

			source := newTestSource(t, issuer.URL, client, failingOpener(t))
			_, err := source.oauthConfig(context.Background(), "http://127.0.0.1:0/callback")
			if err == nil {
				t.Fatal("expected a non-http(s) endpoint to be rejected even over plaintext metadata")
			}
			if !strings.Contains(err.Error(), tt.wantErrorContains) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErrorContains)
			}
		})
	}
}

// plaintextTokenMirror is a working token endpoint served over plain http,
// which records what it actually received. Tests use it as a redirect target so
// the only thing wrong with the exchange is the transport: reached directly it
// completes a refresh and captures the credential (see the control test below),
// so a failure through the redirect is the guard firing rather than a broken
// endpoint — and what it captured shows what a downgrade would have disclosed.
type plaintextTokenMirror struct {
	URL string

	mu       sync.Mutex
	requests int
	bodies   []string
}

func newPlaintextTokenMirror(t *testing.T) *plaintextTokenMirror {
	t.Helper()
	mirror := &plaintextTokenMirror{}
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mirror.mu.Lock()
		mirror.requests++
		mirror.bodies = append(mirror.bodies, string(body))
		mirror.mu.Unlock()

		writeJSONForTest(t, w, map[string]any{
			"access_token":  "mirrored-access-token",
			"token_type":    "Bearer",
			"refresh_token": "mirrored-refresh-token",
			"expires_in":    3600,
		})
	}))
	mirror.URL = server.URL + "/token"
	return mirror
}

func (m *plaintextTokenMirror) received() (int, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests, append([]string(nil), m.bodies...)
}

func newRefreshableSource(t *testing.T, issuerURL string, client *http.Client) *managedOIDCTokenSource {
	t.Helper()
	source := newTestSource(t, issuerURL, client, failingOpener(t))
	writeTokenCacheForTest(t, source.cachePath, tokenCache{
		Issuer:       issuerURL,
		ClientID:     "authunnel-cli",
		Scopes:       normalizeScopes("openid offline_access"),
		AccessToken:  "expired-token",
		RefreshToken: "refresh-token-1",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Minute),
	})
	return source
}

// newRedirectingTokenIssuer serves https metadata whose token_endpoint is
// https — so it passes the static checks — and then redirects the exchange to
// target with the given status.
//
// The status matters. Go rewrites 301/302/303 to GET and drops the request
// body, so those would not carry the refresh token onward even unguarded; 307
// and 308 preserve method and body, which is what makes a downgrade here a
// credential disclosure rather than a failed request. Tests use 307 so the
// guard is exercised against the case that actually leaks.
func newRedirectingTokenIssuer(t *testing.T, target string, status int) (string, *http.Client) {
	t.Helper()
	var issuerURL string
	server := newIPv4TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSONForTest(t, w, map[string]string{
				"issuer":                 issuerURL,
				"authorization_endpoint": issuerURL + "/auth",
				"token_endpoint":         issuerURL + "/token",
			})
		case "/token":
			http.Redirect(w, r, target, status)
		default:
			http.NotFound(w, r)
		}
	}))
	issuerURL = server.URL
	return issuerURL, server.Client()
}

// TestTokenEndpointRedirectDowngradeIsRefused covers the half the static
// endpoint check cannot: the advertised token_endpoint is https and passes
// validation, then redirects to plaintext at exchange time. Go follows
// cross-scheme redirects silently, so only the client's redirect policy stops
// the refresh token being posted in clear text.
func TestTokenEndpointRedirectDowngradeIsRefused(t *testing.T) {
	mirror := newPlaintextTokenMirror(t)
	issuerURL, client := newRedirectingTokenIssuer(t, mirror.URL, http.StatusTemporaryRedirect)

	source := newRefreshableSource(t, issuerURL, client)
	_, err := source.AccessToken(context.Background(), false)
	if err == nil {
		t.Fatal("expected a token exchange redirected from https to http to be refused")
	}
	if !strings.Contains(err.Error(), "transport downgrade") {
		t.Fatalf("error = %v, want the redirect downgrade guard", err)
	}
	// The credential must not have reached the plaintext endpoint at all.
	// Asserting only on the error would pass even if the body had already
	// been sent and the failure came afterwards.
	if requests, bodies := mirror.received(); requests != 0 {
		t.Fatalf("plaintext endpoint received %d request(s) with bodies %q, want none", requests, bodies)
	}
}

// TestTokenMirrorCompletesRefreshDirectlyAndSeesTheCredential is the control
// for the test above, and it does double duty: it proves the mirror is a
// working token endpoint, so the failure there is attributable to the redirect,
// and it shows the refresh token really is in the request body — which is what
// a 307 downgrade would have carried to a plaintext endpoint.
func TestTokenMirrorCompletesRefreshDirectlyAndSeesTheCredential(t *testing.T) {
	mirror := newPlaintextTokenMirror(t)
	issuer, client := newMetadataIssuer(t, false, sameHost("/auth"), literal(mirror.URL))

	source := newRefreshableSource(t, issuer.URL, client)
	token, err := source.AccessToken(context.Background(), false)
	if err != nil {
		t.Fatalf("refresh against the mirror should succeed: %v", err)
	}
	if token != "mirrored-access-token" {
		t.Fatalf("token = %q, want the mirror's token", token)
	}

	requests, bodies := mirror.received()
	if requests != 1 {
		t.Fatalf("mirror received %d requests, want 1", requests)
	}
	if !strings.Contains(bodies[0], "refresh_token=refresh-token-1") {
		t.Fatalf("request body = %q, want it to carry the refresh token", bodies[0])
	}
}

// TestNewAuthTokenSourceGuardsInjectedClient exercises the production wiring
// rather than the test helper's.
//
// Every other test here builds managedOIDCTokenSource directly and applies
// RefuseTransportDowngrade itself, which means none of them would notice if the
// wrapping in newAuthTokenSource were deleted. This one passes an *unguarded*
// client through clientConfig.AuthHTTPClient — the seam real callers and tests
// use to inject one — so it fails if the production code stops wrapping.
func TestNewAuthTokenSourceGuardsInjectedClient(t *testing.T) {
	mirror := newPlaintextTokenMirror(t)
	issuerURL, client := newRedirectingTokenIssuer(t, mirror.URL, http.StatusTemporaryRedirect)

	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		Issuer:       issuerURL,
		ClientID:     "authunnel-cli",
		Scopes:       normalizeScopes("openid offline_access"),
		AccessToken:  "expired-token",
		RefreshToken: "refresh-token-1",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Minute),
	})

	source, err := newAuthTokenSource(clientConfig{
		AuthMode:       authModeOIDC,
		OIDCIssuer:     issuerURL,
		OIDCClientID:   "authunnel-cli",
		OIDCScopes:     normalizeScopes("openid offline_access"),
		OIDCCache:      cachePath,
		AuthHTTPClient: client, // deliberately not pre-wrapped
		Stderr:         io.Discard,
		BrowserOpener:  failingOpener(t),
	})
	if err != nil {
		t.Fatalf("newAuthTokenSource: %v", err)
	}

	if _, err := source.AccessToken(context.Background(), false); err == nil {
		t.Fatal("expected newAuthTokenSource to guard the injected client against a downgrade redirect")
	} else if !strings.Contains(err.Error(), "transport downgrade") {
		t.Fatalf("error = %v, want the redirect downgrade guard", err)
	}
	if requests, bodies := mirror.received(); requests != 0 {
		t.Fatalf("plaintext endpoint received %d request(s) with bodies %q, want none", requests, bodies)
	}
}

// TestPlaintextIssuerWithPlaintextEndpointsStillWorks pins the development
// path: an http issuer with http endpoints is unaffected by any of the above.
func TestPlaintextIssuerWithPlaintextEndpointsStillWorks(t *testing.T) {
	issuer, client := newMetadataIssuer(t, false, sameHost("/auth"), sameHost("/token"))

	source := newTestSource(t, issuer.URL, client, failingOpener(t))
	config, err := source.oauthConfig(context.Background(), "http://127.0.0.1:0/callback")
	if err != nil {
		t.Fatalf("plaintext development issuer should still work: %v", err)
	}
	if config.Endpoint.AuthURL != issuer.URL+"/auth" {
		t.Fatalf("auth URL = %q, want the discovered endpoint", config.Endpoint.AuthURL)
	}
}

package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"authunnel/internal/authhttp"
)

// metadataIssuer serves discovery with test-controlled endpoints.
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

// failingOpener proves rejected authorization URLs never reach OS dispatch.
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

func TestDiscoveryRejectsPlaintextEndpoints(t *testing.T) {
	plain, _ := newMetadataIssuer(t, false, sameHost("/auth"), sameHost("/token"))
	for _, tt := range []struct {
		name, field string
		auth, token func(string) string
	}{
		{name: "authorization", field: "authorization_endpoint", auth: literal(plain.URL + "/auth"), token: sameHost("/token")},
		{name: "token", field: "token_endpoint", auth: sameHost("/auth"), token: literal(plain.URL + "/token")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			issuer, client := newMetadataIssuer(t, true, tt.auth, tt.token)
			source := newTestSource(t, issuer.URL, client, failingOpener(t))
			_, err := source.oauthConfig(context.Background(), "http://127.0.0.1:0/callback")
			if err == nil || !strings.Contains(err.Error(), "non-https "+tt.field) {
				t.Fatalf("error = %v, want %s downgrade rejection", err, tt.field)
			}
		})
	}
}

// Control: the same TLS fixture succeeds when both endpoints remain HTTPS.
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

// Plaintext development metadata still cannot advertise non-network schemes.
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

// plaintextTokenMirror is a working token endpoint that records request bodies.
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

// newRedirectingTokenIssuer advertises HTTPS, then redirects token exchange.
// Tests use 307 because it preserves the credential-bearing request body.
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

// A 307 downgrade must be refused before the refresh token reaches plaintext.
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
	if requests, bodies := mirror.received(); requests != 0 {
		t.Fatalf("plaintext endpoint received %d request(s) with bodies %q, want none", requests, bodies)
	}
}

// Control: the mirror works directly and receives the refresh token.
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

// Production wiring must guard an injected, initially unguarded client.
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

// newTenantIssuer serves metadata only at an RFC 8414 path.
func newTenantIssuer(t *testing.T, advertisedIssuer func(base string) string) (string, string, *http.Client) {
	t.Helper()
	const tenantPath = "/.well-known/oauth-authorization-server/tenant1"

	var base string
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case tenantPath:
			writeJSONForTest(t, w, map[string]string{
				"issuer":                 advertisedIssuer(base),
				"authorization_endpoint": base + "/auth",
				"token_endpoint":         base + "/token",
			})
		case "/token":
			writeJSONForTest(t, w, map[string]any{
				"access_token":  "tenant-access-token",
				"token_type":    "Bearer",
				"refresh_token": "tenant-refresh-token",
				"expires_in":    3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	base = server.URL
	return base + "/tenant1", base + tenantPath, server.Client()
}

func TestMetadataURLReachesNonDerivedPath(t *testing.T) {
	issuer, metadataURL, client := newTenantIssuer(t, func(base string) string { return base + "/tenant1" })

	source := newTestSource(t, issuer, client, failingOpener(t))
	if _, err := source.oauthConfig(context.Background(), "http://127.0.0.1:0/callback"); err == nil {
		t.Fatal("expected discovery to fail when metadata is not at the derived path")
	}

	source = newTestSource(t, issuer, client, failingOpener(t))
	source.metadataURL = metadataURL
	config, err := source.oauthConfig(context.Background(), "http://127.0.0.1:0/callback")
	if err != nil {
		t.Fatalf("discovery with --oidc-metadata-url should succeed: %v", err)
	}
	if config.Endpoint.TokenURL == "" {
		t.Fatal("expected the token endpoint to be resolved from the override")
	}
}

// Production wiring must carry the metadata override into discovery.
func TestNewAuthTokenSourceAppliesMetadataURL(t *testing.T) {
	issuer, metadataURL, client := newTenantIssuer(t, func(base string) string { return base + "/tenant1" })

	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		Issuer: issuer,
		// Stamped with the same metadata URL the source uses: this entry was
		// obtained through that document, so reusing it is legitimate.
		MetadataURL:  metadataURL,
		ClientID:     "authunnel-cli",
		Scopes:       normalizeScopes("openid offline_access"),
		AccessToken:  "expired-token",
		RefreshToken: "refresh-token-1",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Minute),
	})

	source, err := newAuthTokenSource(clientConfig{
		AuthMode:        authModeOIDC,
		OIDCIssuer:      issuer,
		OIDCMetadataURL: metadataURL,
		OIDCClientID:    "authunnel-cli",
		OIDCScopes:      normalizeScopes("openid offline_access"),
		OIDCCache:       cachePath,
		AuthHTTPClient:  client,
		Stderr:          io.Discard,
		// If the override does not reach discovery, the derived path 404s,
		// the refresh fails, and the flow falls through to interactive
		// login — which this opener turns into a failure.
		BrowserOpener: failingOpener(t),
	})
	if err != nil {
		t.Fatalf("newAuthTokenSource: %v", err)
	}

	token, err := source.AccessToken(context.Background(), false)
	if err != nil {
		t.Fatalf("refresh through the metadata override should succeed: %v", err)
	}
	if token != "tenant-access-token" {
		t.Fatalf("token = %q, want the token issued via the non-derived metadata path", token)
	}
}

// A legitimate but wrong metadata document is rejected by issuer comparison.
func TestClientMetadataURLRejectsIssuerMismatch(t *testing.T) {
	issuer, metadataURL, client := newTenantIssuer(t, func(string) string { return "https://attacker.example" })

	source := newTestSource(t, issuer, client, failingOpener(t))
	source.metadataURL = metadataURL
	_, err := source.oauthConfig(context.Background(), "http://127.0.0.1:0/callback")
	if err == nil {
		t.Fatal("expected a document advertising a different issuer to be rejected")
	}
	if !errors.Is(err, oidc.ErrIssuerInvalid) {
		t.Fatalf("error = %v, want %v (the issuer binding check)", err, oidc.ErrIssuerInvalid)
	}
}

// Endpoint transport is judged against the metadata URL, not the issuer string.
func TestDowngradeIsJudgedAgainstMetadataURLNotIssuer(t *testing.T) {
	plain, _ := newMetadataIssuer(t, false, sameHost("/auth"), sameHost("/token"))

	var httpsBase string
	server := newIPv4TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/meta" {
			http.NotFound(w, r)
			return
		}
		writeJSONForTest(t, w, map[string]string{
			"issuer":                 plain.URL,
			"authorization_endpoint": plain.URL + "/auth",
			"token_endpoint":         plain.URL + "/token",
		})
	}))
	httpsBase = server.URL

	source := newTestSource(t, plain.URL, server.Client(), failingOpener(t))
	source.metadataURL = httpsBase + "/meta"
	_, err := source.oauthConfig(context.Background(), "http://127.0.0.1:0/callback")
	if err == nil {
		t.Fatal("expected https-fetched metadata advertising plaintext endpoints to be refused")
	}
	if !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("error = %v, want the downgrade check judged against the metadata URL", err)
	}
}

// The explicit development posture still permits an all-HTTP local IdP.
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

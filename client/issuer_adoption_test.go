package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingAS serves an authorization server metadata document at /meta only —
// never at the derived well-known path, so nothing here can succeed by accident
// through the derivation — and records every request its token endpoint receives.
//
// Recording the token endpoint is the point: the tests below are about whether a
// refresh token is *sent*, and an error-only assertion cannot tell "refused" from
// "sent and rejected".
type recordingAS struct {
	URL         string
	MetadataURL string
	client      *http.Client

	mu           sync.Mutex
	tokenBodies  []string
	declaredIssu string
}

func newRecordingAS(t *testing.T, declaredIssuer func(base string) string) *recordingAS {
	t.Helper()
	as := &recordingAS{}
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/meta":
			writeJSONForTest(t, w, map[string]string{
				"issuer":                 as.declaredIssuer(),
				"authorization_endpoint": as.URL + "/auth",
				"token_endpoint":         as.URL + "/token",
			})
		case "/token":
			body := readBodyForTest(t, r)
			as.mu.Lock()
			as.tokenBodies = append(as.tokenBodies, body)
			as.mu.Unlock()
			writeJSONForTest(t, w, map[string]any{
				"access_token":  "adopted-access-token",
				"token_type":    "Bearer",
				"refresh_token": "adopted-refresh-token",
				"expires_in":    3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	as.URL = server.URL
	as.MetadataURL = server.URL + "/meta"
	as.client = server.Client()
	as.declaredIssu = declaredIssuer(server.URL)
	return as
}

func (as *recordingAS) declaredIssuer() string {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.declaredIssu
}

func (as *recordingAS) tokenRequests() []string {
	as.mu.Lock()
	defer as.mu.Unlock()
	return append([]string(nil), as.tokenBodies...)
}

// TestResolveAdoptsIssuerFromMetadataDocument is the core of making
// --oidc-issuer optional: with only a metadata URL, the declared issuer becomes
// the source's own.
func TestResolveAdoptsIssuerFromMetadataDocument(t *testing.T) {
	as := newRecordingAS(t, func(base string) string { return base + "/realms/main" })

	source := newTestSource(t, "", as.client, failingOpener(t))
	source.metadataURL = as.MetadataURL

	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("resolve with only a metadata URL should succeed: %v", err)
	}
	if source.effective.Issuer != as.URL+"/realms/main" {
		t.Fatalf("resolved issuer = %q, want the declared value adopted", source.effective.Issuer)
	}
	if source.discovery.TokenURL != as.URL+"/token" {
		t.Fatalf("token URL = %q, want the document's endpoint", source.discovery.TokenURL)
	}
}

// TestNewAuthTokenSourceAdoptsIssuer goes through the production config mapping
// rather than setting fields on the source, so the absence of OIDCIssuer is
// covered end to end: a refresh has to complete, and the entry written back has
// to record the adopted issuer rather than the empty configured one.
func TestNewAuthTokenSourceAdoptsIssuer(t *testing.T) {
	as := newRecordingAS(t, func(base string) string { return base + "/realms/main" })
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		Issuer:       as.URL + "/realms/main",
		MetadataURL:  as.MetadataURL,
		ClientID:     "authunnel-cli",
		Scopes:       normalizeScopes("openid offline_access"),
		AccessToken:  "expired-token",
		RefreshToken: "refresh-token-1",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Minute),
	})

	source, err := newAuthTokenSource(clientConfig{
		AuthMode:        authModeOIDC,
		OIDCMetadataURL: as.MetadataURL,
		OIDCClientID:    "authunnel-cli",
		OIDCScopes:      normalizeScopes("openid offline_access"),
		OIDCCache:       cachePath,
		AuthHTTPClient:  as.client,
		Stderr:          io.Discard,
		BrowserOpener:   failingOpener(t),
	})
	if err != nil {
		t.Fatalf("newAuthTokenSource: %v", err)
	}

	token, err := source.AccessToken(context.Background(), false)
	if err != nil {
		t.Fatalf("refresh with an adopted issuer should succeed: %v", err)
	}
	if token != "adopted-access-token" {
		t.Fatalf("token = %q, want the refreshed value", token)
	}
	if requests := as.tokenRequests(); len(requests) != 1 || !strings.Contains(requests[0], "refresh_token=refresh-token-1") {
		t.Fatalf("token endpoint saw %v, want exactly one refresh grant carrying the cached credential", requests)
	}
	if written := readTokenCacheForTest(t, cachePath); written.Issuer != as.URL+"/realms/main" {
		t.Fatalf("cached issuer = %q, want the resolved value, not the empty configured one", written.Issuer)
	}
}

// TestCacheSurvivesAcrossRunsWithAdoptedIssuer covers the load-time exemption in
// cacheMatchesConfigured. The entry records an issuer the source has not been
// configured with, and must still be usable — otherwise every invocation without
// --oidc-issuer would discard the cache and log the user in again, which is the
// fast path gone.
func TestCacheSurvivesAcrossRunsWithAdoptedIssuer(t *testing.T) {
	as := newRecordingAS(t, func(base string) string { return base + "/realms/main" })
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		Issuer:      as.URL + "/realms/main",
		MetadataURL: as.MetadataURL,
		ClientID:    "authunnel-cli",
		Scopes:      normalizeScopes("openid offline_access"),
		AccessToken: "still-valid-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	})

	source := newTestSource(t, "", as.client, failingOpener(t))
	source.metadataURL = as.MetadataURL
	source.cachePath = cachePath

	token, err := source.AccessToken(context.Background(), true)
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if token != "still-valid-token" {
		t.Fatalf("token = %q, want the cached value reused", token)
	}
	if requests := as.tokenRequests(); len(requests) != 0 {
		t.Fatalf("token endpoint saw %v, want the cache hit to reach no network at all", requests)
	}
}

// TestCacheDiscardedWhenDocumentChangesIssuer is the post-resolution identity
// check. The cached refresh token was issued under one issuer; the document now
// declares another. Reusing it would post a credential to a token endpoint the
// user never approved — so the assertion is on what the token endpoint *did not*
// receive, plus the login prompt appearing instead.
func TestCacheDiscardedWhenDocumentChangesIssuer(t *testing.T) {
	as := newRecordingAS(t, func(base string) string { return base + "/realms/moved" })
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		Issuer:       as.URL + "/realms/original",
		MetadataURL:  as.MetadataURL,
		ClientID:     "authunnel-cli",
		Scopes:       normalizeScopes("openid offline_access"),
		AccessToken:  "expired-token",
		RefreshToken: "super-secret-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Minute),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var opened []string
	source := newTestSource(t, "", as.client, func(_ context.Context, url string) error {
		opened = append(opened, url)
		// Abandon the flow at the browser leg: completing a login is covered
		// elsewhere, and this test is about what the token endpoint never saw.
		cancel()
		return nil
	})
	source.metadataURL = as.MetadataURL
	source.cachePath = cachePath

	if _, err := source.AccessToken(ctx, false); err == nil {
		t.Fatal("expected the abandoned interactive login to fail")
	}
	if requests := as.tokenRequests(); len(requests) != 0 {
		t.Fatalf("token endpoint received %v; the refresh token must not be sent after the issuer changed", requests)
	}
	if len(opened) == 0 {
		t.Fatal("expected the flow to fall through to interactive login")
	}
}

// TestCacheDiscardedWhenAudienceIsNoLongerConfigured pins the per-field part of
// cacheMatchesConfigured. Audience is not resolvable from an authorization server
// document, so an entry minted for one must not satisfy an invocation that asks
// for none: exempting every unconfigured field, rather than only the resolvable
// ones, would hand a token scoped to one resource to a request for another.
func TestCacheDiscardedWhenAudienceIsNoLongerConfigured(t *testing.T) {
	as := newRecordingAS(t, func(base string) string { return base + "/realms/main" })
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		Issuer:      as.URL + "/realms/main",
		MetadataURL: as.MetadataURL,
		ClientID:    "authunnel-cli",
		Audience:    "https://other-api.example",
		Scopes:      normalizeScopes("openid offline_access"),
		AccessToken: "token-for-another-audience",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := newTestSource(t, "", as.client, func(context.Context, string) error {
		cancel()
		return nil
	})
	source.metadataURL = as.MetadataURL
	source.cachePath = cachePath

	token, err := source.AccessToken(ctx, true)
	if err == nil {
		t.Fatalf("token = %q: a cached entry for another audience must not be reused", token)
	}
}

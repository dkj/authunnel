package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// hostileMetadata serves a document that echoes the configured issuer — which is
// all the discovery check compares — while pointing the token endpoint at a
// collector. It stands in for a mistyped metadata URL just as well as a
// malicious one; the client cannot tell them apart, which is the point.
func hostileMetadata(t *testing.T, issuer string) (metadataURL string, collector *plaintextTokenMirror, client *http.Client) {
	t.Helper()
	collector = newPlaintextTokenMirror(t)

	var base string
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metadata" {
			http.NotFound(w, r)
			return
		}
		writeJSONForTest(t, w, map[string]string{
			"issuer":                 issuer, // echoed verbatim; nothing binds this host to it
			"authorization_endpoint": base + "/auth",
			"token_endpoint":         collector.URL,
		})
	}))
	base = server.URL
	return base + "/metadata", collector, server.Client()
}

// TestCachedRefreshTokenIsNotSentToANewMetadataSource is the regression test for
// the disclosure this cache scoping exists to prevent.
//
// A refresh token cached under the derived discovery path must not be posted to
// the token endpoint named by a *different* metadata document. Checking that the
// document's `issuer` matches proves nothing about the host serving it, so
// without scoping the cache, adding or mistyping --oidc-metadata-url would hand
// an existing credential to whatever that document names — no user interaction
// required.
func TestCachedRefreshTokenIsNotSentToANewMetadataSource(t *testing.T) {
	const issuer = "https://issuer.example"
	metadataURL, collector, client := hostileMetadata(t, issuer)

	cachePath := filepathForTest(t, "tokens.json")
	// Obtained earlier through the derived path: no MetadataURL recorded.
	writeTokenCacheForTest(t, cachePath, tokenCache{
		Issuer:       issuer,
		ClientID:     "authunnel-cli",
		Scopes:       normalizeScopes("openid offline_access"),
		AccessToken:  "expired-token",
		RefreshToken: "super-secret-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Minute),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Reaching the browser is the proof that the cache was discarded *and*
	// that discovery got far enough to build an authorization URL. Asserting
	// only "the collector saw nothing" would also pass if the fixture broke
	// and nothing was ever attempted. Cancelling here ends the wait for a
	// callback that will never arrive, instead of a fixed sleep.
	browserCalls := 0
	source := &managedOIDCTokenSource{
		issuer:      issuer,
		metadataURL: metadataURL,
		clientID:    "authunnel-cli",
		scopes:      normalizeScopes("openid offline_access"),
		cachePath:   cachePath,
		httpClient:  client,
		output:      io.Discard,
		openBrowser: func(context.Context, string) error {
			browserCalls++
			cancel()
			return nil
		},
		now: time.Now,
	}

	_, err := source.AccessToken(ctx, false)

	// The defect assertion comes first so a regression reports the leak
	// itself. Checking the browser first would instead report "the flow did
	// not reach interactive login", which reads like a broken fixture — the
	// cache having been reused is exactly why interactive login is skipped.
	requests, bodies := collector.received()
	for _, body := range bodies {
		if strings.Contains(body, "super-secret-refresh-token") {
			t.Fatalf("refresh token disclosed to the new metadata source: %q", body)
		}
	}
	if requests != 0 {
		t.Fatalf("token endpoint named by the new metadata document received %d request(s): %q", requests, bodies)
	}

	// Then the liveness assertions: without these the test would also pass if
	// the fixture broke and nothing was ever attempted.
	if browserCalls != 1 {
		t.Fatalf("browser opened %d times, want 1 — the flow did not reach interactive login, so this test proved nothing", browserCalls)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want the cancellation this test triggers", err)
	}
}

// TestCacheIsScopedToMetadataURL covers the identity rule directly, in both
// directions, so the behaviour is pinned independently of the attack scenario.
func TestCacheIsScopedToMetadataURL(t *testing.T) {
	const issuer = "https://issuer.example"

	newSource := func(metadataURL, cachePath string) *managedOIDCTokenSource {
		return &managedOIDCTokenSource{
			issuer:      issuer,
			metadataURL: metadataURL,
			clientID:    "authunnel-cli",
			scopes:      normalizeScopes("openid offline_access"),
			cachePath:   cachePath,
			output:      io.Discard,
			now:         time.Now,
		}
	}

	for _, tt := range []struct {
		name             string
		cached, resolved string
		wantReuse        bool
	}{
		{name: "both derived", cached: "", resolved: "", wantReuse: true},
		{name: "same override", cached: "https://as.example/meta", resolved: "https://as.example/meta", wantReuse: true},
		{name: "override added", cached: "", resolved: "https://as.example/meta"},
		{name: "override removed", cached: "https://as.example/meta", resolved: ""},
		{name: "override changed", cached: "https://as.example/meta", resolved: "https://other.example/meta"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cachePath := filepathForTest(t, "tokens.json")
			writeTokenCacheForTest(t, cachePath, tokenCache{
				Issuer:       issuer,
				MetadataURL:  tt.cached,
				ClientID:     "authunnel-cli",
				Scopes:       normalizeScopes("openid offline_access"),
				AccessToken:  "cached-access-token",
				RefreshToken: "cached-refresh-token",
				TokenType:    "Bearer",
				Expiry:       time.Now().Add(time.Hour),
			})

			cache, err := newSource(tt.resolved, cachePath).loadCache()
			if err != nil {
				t.Fatalf("loadCache: %v", err)
			}
			reused := cache.RefreshToken != ""
			if reused != tt.wantReuse {
				t.Fatalf("cached=%q resolved=%q: reuse = %v, want %v", tt.cached, tt.resolved, reused, tt.wantReuse)
			}
		})
	}
}

// TestCacheWrittenBeforeMetadataFieldStillLoads pins the upgrade path: an
// existing cache file has no metadata_url key, and an operator not using the
// flag must not be logged out by adding the field.
func TestCacheWrittenBeforeMetadataFieldStillLoads(t *testing.T) {
	const issuer = "https://issuer.example"
	cachePath := filepathForTest(t, "tokens.json")

	legacy := `{
  "issuer": "https://issuer.example",
  "client_id": "authunnel-cli",
  "scopes": "openid offline_access",
  "access_token": "legacy-access-token",
  "refresh_token": "legacy-refresh-token",
  "token_type": "Bearer",
  "expiry": "2999-01-01T00:00:00Z"
}`
	if err := os.WriteFile(cachePath, []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy cache: %v", err)
	}

	source := &managedOIDCTokenSource{
		issuer:    issuer,
		clientID:  "authunnel-cli",
		scopes:    normalizeScopes("openid offline_access"),
		cachePath: cachePath,
		output:    io.Discard,
		now:       time.Now,
	}
	cache, err := source.loadCache()
	if err != nil {
		t.Fatalf("loadCache: %v", err)
	}
	if cache.AccessToken != "legacy-access-token" {
		t.Fatalf("a cache written before metadata_url existed should still load, got %+v", cache)
	}
}

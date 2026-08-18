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

// hostileMetadata echoes the expected issuer but points tokens at a collector.
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

// A metadata override must not receive a refresh token cached under discovery.
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

	// Browser invocation proves the cache was discarded; cancellation ends the
	// otherwise interactive flow without a fixed sleep.
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

	requests, bodies := collector.received()
	for _, body := range bodies {
		if strings.Contains(body, "super-secret-refresh-token") {
			t.Fatalf("refresh token disclosed to the new metadata source: %q", body)
		}
	}
	if requests != 0 {
		t.Fatalf("token endpoint named by the new metadata document received %d request(s): %q", requests, bodies)
	}

	if browserCalls != 1 {
		t.Fatalf("browser opened %d times, want 1 — the flow did not reach interactive login, so this test proved nothing", browserCalls)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want the cancellation this test triggers", err)
	}
}

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

// A legacy derived-discovery cache has no metadata_url and remains compatible.
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

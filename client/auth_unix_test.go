//go:build !windows

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests rely on POSIX mode bits and unprivileged symlink creation.
// On Windows EnsurePrivateFile intentionally accepts any regular file
// (NTFS uses ACLs, not mode bits) and unprivileged symlink creation
// requires SeCreateSymbolicLink, so the same expectations would not hold.

func TestManagedOIDCTokenSourceRejectsGroupReadableTokenCache(t *testing.T) {
	// A pre-existing tokens.json with 0o644 (e.g. left over from a tool that
	// did not chmod) must be rejected before the contents are read. saveCache
	// itself writes 0o600, so this only fires for files the operator created
	// or modified outside authunnel.
	provider := newFakeOIDCProvider(t)
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		Issuer:      provider.issuer(),
		ClientID:    "authunnel-cli",
		Scopes:      normalizeScopes("openid offline_access"),
		AccessToken: "cached-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(5 * time.Minute),
	})
	if err := os.Chmod(cachePath, 0o644); err != nil {
		t.Fatalf("chmod cache: %v", err)
	}

	source := &managedOIDCTokenSource{
		issuer:      provider.issuer(),
		clientID:    "authunnel-cli",
		scopes:      normalizeScopes("openid offline_access"),
		cachePath:   cachePath,
		httpClient:  provider.server.Client(),
		output:      io.Discard,
		openBrowser: func(context.Context, string) error { return nil },
		now:         time.Now,
	}
	_, err := source.AccessToken(context.Background(), true)
	if err == nil || !strings.Contains(err.Error(), "validate OIDC token cache") {
		t.Fatalf("expected token-cache validation rejection, got %v", err)
	}
	if !strings.Contains(err.Error(), "group/world permission bits") {
		t.Fatalf("error should explain mode rejection, got %v", err)
	}
}

func TestManagedOIDCTokenSourceAcceptsOwnerOnlyTokenCache(t *testing.T) {
	// The companion to the rejection test: a 0o600 cache must be loaded and
	// reused without any rewrite.
	provider := newFakeOIDCProvider(t)
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		Issuer:      provider.issuer(),
		ClientID:    "authunnel-cli",
		Scopes:      normalizeScopes("openid offline_access"),
		AccessToken: "cached-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(5 * time.Minute),
	})

	source := &managedOIDCTokenSource{
		issuer:      provider.issuer(),
		clientID:    "authunnel-cli",
		scopes:      normalizeScopes("openid offline_access"),
		cachePath:   cachePath,
		httpClient:  provider.server.Client(),
		output:      io.Discard,
		openBrowser: func(context.Context, string) error { return nil },
		now:         time.Now,
	}
	token, err := source.AccessToken(context.Background(), true)
	if err != nil {
		t.Fatalf("0o600 cache should load: %v", err)
	}
	if token != "cached-access-token" {
		t.Fatalf("unexpected token: %q", token)
	}
}

func TestManagedOIDCTokenSourceRejectsSymlinkedTokenCache(t *testing.T) {
	// A symlink at the cache path can be re-pointed by anyone with write
	// access to the cache directory. Since the dir is already validated as
	// 0o700-owned, only the current user could plant such a symlink, but the
	// validator still refuses it: the dir's safety guarantees nothing about
	// the symlink target's parent. Token caches are user-scoped and never
	// expected to be symlinks; the strict refusal here is intentional.
	provider := newFakeOIDCProvider(t)
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	target := filepath.Join(dir, "real.json")
	cache := tokenCache{
		Issuer:      provider.issuer(),
		ClientID:    "authunnel-cli",
		Scopes:      normalizeScopes("openid offline_access"),
		AccessToken: "cached-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(5 * time.Minute),
	}
	writeTokenCacheForTest(t, target, cache)
	link := filepath.Join(dir, "tokens.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	source := &managedOIDCTokenSource{
		issuer:      provider.issuer(),
		clientID:    "authunnel-cli",
		scopes:      normalizeScopes("openid offline_access"),
		cachePath:   link,
		httpClient:  provider.server.Client(),
		output:      io.Discard,
		openBrowser: func(context.Context, string) error { return nil },
		now:         time.Now,
	}
	_, err := source.AccessToken(context.Background(), true)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

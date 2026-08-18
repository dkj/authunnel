package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"authunnel/internal/authmeta"
)

// TestTokenAfterRejectionReplacesTheTokenWhenConfigurationChanged is the lockout
// this exists to end.
//
// The cached access token is valid by its own expiry, so every invocation returns
// it without resolving anything — the fast path working as designed. The server
// has since moved to a different client ID, so it refuses that token on every
// invocation, and nothing in the flow would ever look at the server's metadata
// again. Re-resolving on the rejection is what makes the difference between one
// extra round trip and waiting out the cache.
func TestTokenAfterRejectionReplacesTheTokenWhenConfigurationChanged(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		ResourceURL:  fixture.ResourceURL,
		Issuer:       fixture.Issuer,
		ClientID:     "the-old-client",
		Scopes:       normalizeScopes(publishedScopes),
		AccessToken:  "token-the-server-now-refuses",
		RefreshToken: "refresh-token-for-the-old-client",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	})

	opened := 0
	source := fixture.discoverySource(t, completingOpener(&opened))
	source.cachePath = cachePath

	// The fast path hands back the stale token, having contacted nobody.
	token, err := source.AccessToken(context.Background(), true)
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if token != "token-the-server-now-refuses" {
		t.Fatalf("token = %q, want the cached one", token)
	}
	if metadata, _ := fixture.counts(); metadata != 0 {
		t.Fatalf("cache hit made %d metadata requests, want none", metadata)
	}

	// The server rejects it. Re-resolution finds a different client ID, so the
	// cached refresh token belongs to a configuration that is gone and a fresh
	// login is the only way forward.
	replacement, err := source.TokenAfterRejection(context.Background())
	if err != nil {
		t.Fatalf("TokenAfterRejection: %v", err)
	}
	if replacement == "" {
		t.Fatal("expected a replacement token once the published client ID changed")
	}
	if opened != 1 {
		t.Fatalf("browser logins = %d, want exactly one", opened)
	}
	if _, tokenRequests := fixture.counts(); len(tokenRequests) != 1 {
		t.Fatalf("token endpoint saw %d requests, want the code exchange only", len(tokenRequests))
	}
	for _, body := range mustTokenBodies(t, fixture) {
		if strings.Contains(body, "refresh-token-for-the-old-client") {
			t.Fatal("the old configuration's refresh token must not be posted to the new one")
		}
	}

	// And the entry written back is usable next time, so this is a recovery
	// rather than a per-invocation login.
	written := readTokenCacheForTest(t, cachePath)
	if written.ClientID != "published-cli" || written.AccessToken != replacement {
		t.Fatalf("written cache = %+v, want it stamped with the new identity", written)
	}
}

// completingOpener drives the loopback callback to completion, so a test about
// what happens *after* a login does not hang waiting for one. It reuses the
// existing helper rather than reimplementing the callback dance.
func completingOpener(count *int) browserOpener {
	return func(ctx context.Context, authURL string) error {
		*count++
		return completeTimeoutTestCallback(ctx, authURL)
	}
}

func mustTokenBodies(t *testing.T, fixture *discoveryFixture) []string {
	t.Helper()
	_, bodies := fixture.counts()
	return bodies
}

// TestTokenAfterRejectionDoesNothingWhenConfigurationIsUnchanged is the guard
// that keeps this from becoming a login prompt on every ssh invocation.
//
// A disabled account, a revoked scope and a clock problem all produce the same
// rejection, and none of them is fixed by authenticating again. When re-resolution
// finds the configuration intact, the caller must surface the server's original
// error rather than open a browser.
func TestTokenAfterRejectionDoesNothingWhenConfigurationIsUnchanged(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		ResourceURL:  fixture.ResourceURL,
		Issuer:       fixture.Issuer,
		ClientID:     "published-cli",
		Scopes:       normalizeScopes(publishedScopes),
		AccessToken:  "a-token-the-server-dislikes",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	})

	source := fixture.discoverySource(t, failingOpener(t))
	source.cachePath = cachePath

	replacement, err := source.TokenAfterRejection(context.Background())
	if err != nil {
		t.Fatalf("TokenAfterRejection: %v", err)
	}
	if replacement != "" {
		t.Fatalf("replacement = %q, want none when the configuration is unchanged", replacement)
	}
	if _, tokenRequests := fixture.counts(); len(tokenRequests) != 0 {
		t.Fatalf("token endpoint saw %v, want no grant attempted", tokenRequests)
	}
}

// TestTokenAfterRejectionNoticesAChangedIssuer covers the other field a server
// can move, and the one where reusing the refresh token would be a disclosure
// rather than merely useless.
func TestTokenAfterRejectionNoticesAChangedIssuer(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		ResourceURL:  fixture.ResourceURL,
		Issuer:       "http://issuer-that-has-since-moved.example",
		ClientID:     "published-cli",
		Scopes:       normalizeScopes(publishedScopes),
		AccessToken:  "stale-token",
		RefreshToken: "super-secret-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	})

	opened := 0
	source := fixture.discoverySource(t, completingOpener(&opened))
	source.cachePath = cachePath

	if _, err := source.TokenAfterRejection(context.Background()); err != nil {
		t.Fatalf("TokenAfterRejection: %v", err)
	}
	if opened != 1 {
		t.Fatalf("browser logins = %d, want a fresh login for the new issuer", opened)
	}
	for _, body := range mustTokenBodies(t, fixture) {
		if strings.Contains(body, "super-secret-refresh-token") {
			t.Fatal("a refresh token issued by another issuer must not be posted to this one")
		}
	}
}

// TestStaticTokenSourceHasNothingToRecover pins the manual-token contract: the
// value came from outside this process, so there is no other one to obtain.
func TestStaticTokenSourceHasNothingToRecover(t *testing.T) {
	replacement, err := staticTokenSource{token: "x"}.TokenAfterRejection(context.Background())
	if err != nil || replacement != "" {
		t.Fatalf("TokenAfterRejection = (%q, %v), want no replacement and no error", replacement, err)
	}
}

// rejectingTunnel answers the first upgrade attempt with status, and any later
// one only if the bearer token matches accepted.
type rejectingTunnel struct {
	URL      string
	client   *http.Client
	status   int
	accepted string
	attempts []string
}

func newRejectingTunnel(t *testing.T, status int, accepted string) *rejectingTunnel {
	t.Helper()
	tunnel := &rejectingTunnel{status: status, accepted: accepted}
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tunnel.attempts = append(tunnel.attempts, token)
		if token != tunnel.accepted {
			// Mirror the server's own shape: a rejected-but-well-formed token
			// gets 403, and the challenge rides on 401s only.
			http.Error(w, "forbidden", tunnel.status)
			return
		}
		http.Error(w, "not upgrading in this fixture", http.StatusTeapot)
	}))
	tunnel.URL = server.URL + "/protected/tunnel"
	tunnel.client = server.Client()
	return tunnel
}

// TestDialRetriesOnceAfterAConfigurationChange covers the wiring: a rejection
// reaches the token source, and the replacement it returns is used for exactly
// one more attempt.
func TestDialRetriesOnceAfterAConfigurationChange(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		tunnel := newRejectingTunnel(t, status, "the-new-token")
		source := &fakeTokenSource{token: "the-stale-token", afterRejection: "the-new-token"}
		cfg := clientConfig{TunnelURL: tunnel.URL, HTTPClient: tunnel.client}

		_, _, err := dialTunnelWithRecovery(context.Background(), cfg, source, "the-stale-token")
		// The fixture never completes an upgrade, so an error is expected; what
		// matters is which tokens were presented.
		if err == nil {
			t.Fatalf("status %d: expected the fixture's non-upgrade response to fail the dial", status)
		}
		if source.rejectionCalls != 1 {
			t.Fatalf("status %d: TokenAfterRejection called %d times, want once", status, source.rejectionCalls)
		}
		want := []string{"the-stale-token", "the-new-token"}
		if strings.Join(tunnel.attempts, ",") != strings.Join(want, ",") {
			t.Fatalf("status %d: tokens presented = %v, want %v", status, tunnel.attempts, want)
		}
	}
}

// TestDialDoesNotRetryWhenNothingChanged is the no-login-storm half: with no
// replacement offered, the server's original error is what the user sees, and no
// second attempt is made.
func TestDialDoesNotRetryWhenNothingChanged(t *testing.T) {
	tunnel := newRejectingTunnel(t, http.StatusForbidden, "never-matches")
	source := &fakeTokenSource{token: "stale", afterRejection: ""}
	cfg := clientConfig{TunnelURL: tunnel.URL, HTTPClient: tunnel.client}

	_, _, err := dialTunnelWithRecovery(context.Background(), cfg, source, "stale")
	if err == nil {
		t.Fatal("expected the rejection to be surfaced")
	}
	if !strings.Contains(err.Error(), "tunnel authorization rejected") {
		t.Fatalf("error = %v, want the server's own rejection reported", err)
	}
	if len(tunnel.attempts) != 1 {
		t.Fatalf("attempts = %v, want exactly one; retrying with the same token is a loop", tunnel.attempts)
	}
}

// TestDialDoesNotRetryOnAdmissionRejections keeps the recovery keyed on
// credentials. A 429 or 503 is capacity, and re-resolving configuration for it
// would be a metadata fetch per rate-limited request.
func TestDialDoesNotRetryOnAdmissionRejections(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		tunnel := newRejectingTunnel(t, status, "never-matches")
		source := &fakeTokenSource{token: "fine", afterRejection: "would-be-wrong-to-use"}
		cfg := clientConfig{TunnelURL: tunnel.URL, HTTPClient: tunnel.client}

		if _, _, err := dialTunnelWithRecovery(context.Background(), cfg, source, "fine"); err == nil {
			t.Fatalf("status %d: expected an error", status)
		}
		if source.rejectionCalls != 0 {
			t.Fatalf("status %d: re-resolved after a capacity rejection", status)
		}
		if len(tunnel.attempts) != 1 {
			t.Fatalf("status %d: attempts = %v, want one", status, tunnel.attempts)
		}
	}
}

// TestTokenAfterRejectionForgetsWhatItResolvedEarlier covers the line the recovery
// turns on, which nothing reached before: the reset of the memoised identity and
// endpoints.
//
// The other tests here call TokenAfterRejection on a source that has never resolved,
// so there is no memoised state to forget and deleting the reset left them green.
// This drives the production sequence instead — an expired cache forces AccessToken to
// resolve, *then* the server changes its published client ID, *then* the token is
// rejected — which is the only shape where the reset does anything.
func TestTokenAfterRejectionForgetsWhatItResolvedEarlier(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		ResourceURL:  fixture.ResourceURL,
		Issuer:       fixture.Issuer,
		ClientID:     "published-cli",
		Scopes:       normalizeScopes(publishedScopes),
		AccessToken:  "expired-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Minute),
	})

	opened := 0
	source := fixture.discoverySource(t, completingOpener(&opened))
	source.cachePath = cachePath

	// First: a real resolution, which memoises the identity and the endpoints.
	if _, err := source.AccessToken(context.Background(), true); err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if source.effective == nil || source.effective.ClientID != "published-cli" {
		t.Fatalf("expected the first call to memoise the published identity, got %+v", source.effective)
	}
	firstFetches, _ := fixture.counts()

	// The server moves to a different client, and the token is rejected.
	fixture.setDocument(func(d *authmeta.ProtectedResource) { d.ClientID = "the-new-client" })

	replacement, err := source.TokenAfterRejection(context.Background())
	if err != nil {
		t.Fatalf("TokenAfterRejection: %v", err)
	}
	if replacement == "" {
		t.Fatal("expected a replacement once the published client ID changed")
	}
	// The reset is what makes the second fetch happen at all: without it the
	// memoised identity is reused, the comparison finds nothing changed, and the
	// client stays locked out until the cache expires.
	laterFetches, _ := fixture.counts()
	if laterFetches <= firstFetches {
		t.Fatalf("metadata fetched %d times then %d; the recovery must re-read the document rather than reuse what it resolved", firstFetches, laterFetches)
	}
	if source.effective.ClientID != "the-new-client" {
		t.Fatalf("resolved client ID = %q, want the newly published one", source.effective.ClientID)
	}
	if opened != 1 {
		t.Fatalf("browser logins = %d, want exactly one", opened)
	}
}

package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"authunnel/internal/authhttp"
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

// TestTokenAfterRejectionDropsTheMetadataOriginPin covers state that outlived the
// resolution it described. The pin belongs to a *published* metadata URL adopted under
// a configured issuer; while it was recorded on the source at adoption time, discarding
// s.effective here did not discard it, so a server that stopped publishing one left the
// derived well-known fetch pinned to the issuer's origin — refusing the HTTPS-to-HTTPS
// delegation the discovery simplification plan's non-goals permit.
//
// Both legs are plaintext, which is what makes the assertion attributable: a
// plaintext-to-plaintext cross-host redirect is not a downgrade, so the origin pin is
// the only rule that would refuse it.
func TestTokenAfterRejectionDropsTheMetadataOriginPin(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	// A relocated document on the issuer's own origin: adopted, and the pin engages.
	const relocated = "/.well-known/oauth-authorization-server/tenant1"
	fixture.setDocument(func(d *authmeta.ProtectedResource) {
		d.AuthorizationServerMetadataURL = fixture.Issuer + relocated
	})

	source := fixture.discoverySource(t, completingOpener(new(int)))
	source.issuer = fixture.Issuer
	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("first resolution: %v", err)
	}
	if !source.metadataOriginIsPinned() {
		t.Fatal("adopting a published metadata URL under a configured issuer must pin its origin")
	}

	// The server stops publishing the relocation, and the issuer now delegates its
	// derived document to another host.
	delegate := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONForTest(t, w, map[string]string{
			"issuer":                 fixture.Issuer,
			"authorization_endpoint": fixture.Issuer + "/auth",
			"token_endpoint":         fixture.Issuer + "/token",
		})
	}))
	fixture.setDocument(func(d *authmeta.ProtectedResource) { d.AuthorizationServerMetadataURL = "" })
	fixture.setRedirect("/.well-known/openid-configuration", delegate.URL+"/meta")

	// Seeded to match what the second resolution finds, so TokenAfterRejection
	// re-resolves and then reports "nothing changed" without a login: this test is
	// about the resolution, not the recovery.
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		ResourceURL:  fixture.ResourceURL,
		Issuer:       fixture.Issuer,
		ClientID:     "published-cli",
		Scopes:       normalizeScopes(publishedScopes),
		AccessToken:  "token-the-server-now-refuses",
		RefreshToken: "refresh-token-1",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	})
	source.cachePath = cachePath

	replacement, err := source.TokenAfterRejection(context.Background())
	if err != nil {
		t.Fatalf("re-resolution after a rejection should follow the issuer's own delegation: %v", err)
	}
	if replacement != "" {
		t.Fatalf("replacement = %q, want none: the configuration is unchanged", replacement)
	}
	if source.metadataOriginIsPinned() {
		t.Fatal("with no published metadata URL in force the derived fetch must not be pinned")
	}
}

// TestRecoveryReusesOneGuardedClient is the structural half of the double-wrap
// finding: that the guard is installed at all, that recovery does not layer a second
// one, and that the base client never acquires the policy.
//
// Each assertion is worth something different, and conflating them is how the bug
// survived. The base being untouched is the *correctness* invariant — rebuilding the
// guard from a wrapper rather than from the base is precisely what produced the fault,
// since RefuseInternalAddresses reads the proxy policy off the transport it is handed.
// Pointer reuse is not a correctness property: rebuilding from the immutable base
// would yield an equivalent policy. It is pinned for two narrower reasons — one
// connection pool across resolutions, and a guard that later acquires state of its own
// would otherwise be silently re-created. TestTokenAfterRejectionKeepsTheAddressGuard
// covers what goes wrong behaviourally when the base is not the starting point.
func TestRecoveryReusesOneGuardedClient(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	source := fixture.discoverySource(t, completingOpener(new(int)))
	// A public tunnel server, so the guard is installed at all. Without this the
	// fixture's loopback resource URL classifies as local and every assertion below
	// passes vacuously — the reason the existing double-resolution test could not see
	// this bug.
	source.resourceIsLocal = func(string) bool { return false }
	base := source.httpClient
	baseTransport := base.Transport

	// The first resolution is refused: a loopback issuer chosen by a public tunnel
	// server is exactly what the guard exists to stop. The refusal is incidental here —
	// what matters is that the guard was built on the way to it.
	if err := source.resolve(context.Background()); !errors.Is(err, authhttp.ErrUnsafeTransport) {
		t.Fatalf("error = %v, want the guard to refuse the fixture's loopback issuer", err)
	}
	if source.guarded == nil {
		t.Fatal("guarded is nil after a resolution that needed filtering; nothing below would mean anything")
	}
	first := source.guarded

	// Recovery re-resolves from scratch. It fails for the same reason as above, which
	// is not what this test is about: the question is what the second resolution built.
	if _, err := source.TokenAfterRejection(context.Background()); err == nil {
		t.Fatal("expected the recovery's own resolution to be refused too")
	}
	if source.guarded != first {
		t.Fatal("recovery rebuilt the guarded client; one client and one connection pool should serve every resolution")
	}
	if source.httpClient != base || source.httpClient.Transport != baseTransport {
		t.Fatal("the base client acquired the guard; every wrapper must be layered on it, never onto another wrapper's output")
	}
	if source.fetchClient() == source.httpClient {
		t.Fatal("fetchClient returned the base client for a configuration that needs filtering")
	}
}

// TestTokenAfterRejectionKeepsTheAddressGuard is the functional half: what the stacked
// guard actually costs, and why the pointer reuse above matters rather than merely
// holding.
//
// RefuseInternalAddresses reads the proxy policy off the *http.Transport it is handed.
// Layered onto its own output it finds a destinationGuard there instead, keeps the
// destination check, and loses the classification that decides whether that check
// describes the connection. A proxied request then has its destination resolved
// locally — the one thing internal/authhttp's TestProxiedHTTPSNeedsNoLocalResolution
// says must never be required, because in a proxied network that name is the proxy's to
// resolve. So behind a CONNECT proxy the recovery's own resolution fails and the
// rotation window this path exists to cover never opens.
//
// No resolver stub is needed, which is what makes this assertable from package main at
// all: every request goes through a CONNECT relay, and the tunnel server's address is
// loopback, which is not merely unresolvable-locally but refused outright by the check
// that must not run.
func TestTokenAfterRejectionKeepsTheAddressGuard(t *testing.T) {
	const (
		// Reached through the relay, and covered by httptest's certificate, so the
		// handshake the proxy cannot see into still verifies. Not loopback, because
		// checkDiscoveredAddress inspects an advertised issuer statically and would
		// refuse one before any of this.
		issuer     = "https://example.com"
		directPath = "/left-direct-for-the-control"
	)
	var fetches atomic.Int64
	var resourceURL string
	server := newIPv4TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, authmeta.ProtectedResourcePath):
			fetches.Add(1)
			writeJSONForTest(t, w, authmeta.ProtectedResource{
				Resource:               resourceURL,
				AuthorizationServers:   []string{issuer},
				BearerMethodsSupported: []string{"header"},
				ClientID:               "published-cli",
				DefaultScopes:          strings.Fields(publishedScopes),
			})
		case r.URL.Path == "/.well-known/openid-configuration":
			writeJSONForTest(t, w, map[string]string{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/auth",
				"token_endpoint":         issuer + "/token",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	resourceURL = server.URL + "/protected/tunnel"

	// Installed before the source is built, because the guard clones the transport when
	// it is created and copies Proxy by value as it does.
	relay := connectRelayForTest(t, server.Listener.Addr().String())
	client := server.Client()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("fixture client should carry an *http.Transport")
	}
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		if req.URL.Path == directPath {
			return nil, nil // one destination left direct, for the control below
		}
		return relay, nil
	}

	source := newTestSource(t, "", client, failingOpener(t))
	source.clientID, source.scopes = "", ""
	source.resourceURL = resourceURL
	source.resourceIsLocal = func(string) bool { return false }

	// Seeded to match what resolution finds, so the recovery re-resolves and then
	// reports "nothing changed" without a login: this test is about the resolution.
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		ResourceURL:  resourceURL,
		Issuer:       issuer,
		ClientID:     "published-cli",
		Scopes:       normalizeScopes(publishedScopes),
		AccessToken:  "token-the-server-now-refuses",
		RefreshToken: "refresh-token-1",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	})
	source.cachePath = cachePath

	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("first resolution through the proxy: %v", err)
	}
	replacement, err := source.TokenAfterRejection(context.Background())
	if err != nil {
		t.Fatalf("the recovery must reach the same documents the first resolution did: %v", err)
	}
	if replacement != "" {
		t.Fatalf("replacement = %q, want none: the configuration is unchanged", replacement)
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("protected-resource document fetched %d times, want one per resolution", got)
	}

	// The control, so the two successes above are a proxied request being exempt rather
	// than no policy being in force at all: the proxy function declines this one
	// destination, and a direct request to a loopback address is refused on its address.
	if _, err := source.fetchClient().Get(server.URL + directPath); !errors.Is(err, authhttp.ErrUnsafeTransport) {
		t.Fatalf("direct request error = %v, want %v; the address guard must be installed", err, authhttp.ErrUnsafeTransport)
	}
}

// connectRelayForTest is a blind CONNECT proxy: every tunnel is relayed to one address,
// whatever host was asked for. internal/authhttp keeps an equivalent fixture for its own
// tests and cannot export it across packages, and a proxy is the only shape in which the
// address checks are *skipped* rather than merely satisfied — so a test about that skip
// needs one on this side too.
func connectRelayForTest(t *testing.T, to string) *url.URL {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the CONNECT relay: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			downstream, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = downstream.Close() }()
				if _, err := http.ReadRequest(bufio.NewReader(downstream)); err != nil {
					return
				}
				upstream, err := net.Dial("tcp", to)
				if err != nil {
					return
				}
				defer func() { _ = upstream.Close() }()
				if _, err := io.WriteString(downstream, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
					return
				}
				go func() { _, _ = io.Copy(upstream, downstream) }()
				_, _ = io.Copy(downstream, upstream)
			}()
		}
	}()
	relay, err := url.Parse("http://" + listener.Addr().String())
	if err != nil {
		t.Fatalf("parse relay URL: %v", err)
	}
	return relay
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

// newRejectingTunnel refuses every token but `accepted`, with a status and challenge
// the caller chooses, so a test can present the exact shape a real rejection has.
func newRejectingTunnel(t *testing.T, status int, challenge, accepted string) *rejectingTunnel {
	t.Helper()
	tunnel := &rejectingTunnel{status: status, accepted: accepted}
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tunnel.attempts = append(tunnel.attempts, token)
		if token != tunnel.accepted {
			if challenge != "" {
				w.Header().Set("WWW-Authenticate", challenge)
			}
			http.Error(w, "rejected by fixture", tunnel.status)
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
//
// The trigger is the RFC 6750 challenge, so the fixture sends one. The status is
// varied to show the challenge is what decides — a 403 carrying it still triggers the
// retry, even though this server would send 401.
func TestDialRetriesOnceAfterAConfigurationChange(t *testing.T) {
	const challenge = `Bearer error="invalid_token", resource_metadata="https://tunnel.example/.well-known/oauth-protected-resource/protected/tunnel"`
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		tunnel := newRejectingTunnel(t, status, challenge, "the-new-token")
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

// TestDialDoesNotRetryWithoutAnInvalidTokenChallenge is the reason the trigger moved
// off the status code. Each of these is a refusal the client can do nothing about by
// re-reading metadata: an origin check, a proxy demanding its own credentials, a WAF.
// Under the old rule every one of them cost a metadata fetch, and could cost a browser
// login; now none of them is mistaken for a configuration change.
func TestDialDoesNotRetryWithoutAnInvalidTokenChallenge(t *testing.T) {
	for name, tt := range map[string]struct {
		status    int
		challenge string
	}{
		"origin refusal":          {http.StatusForbidden, ""},
		"bare unauthorized":       {http.StatusUnauthorized, ""},
		"proxy asking for basic":  {http.StatusUnauthorized, `Basic realm="corp-proxy"`},
		"bearer without an error": {http.StatusUnauthorized, `Bearer resource_metadata="https://tunnel.example/.well-known/oauth-protected-resource/protected/tunnel"`},
		"a different error code":  {http.StatusForbidden, `Bearer error="insufficient_scope"`},
		"invalid_token in a URL":  {http.StatusForbidden, `Bearer resource_metadata="https://tunnel.example/invalid_token"`},
	} {
		t.Run(name, func(t *testing.T) {
			tunnel := newRejectingTunnel(t, tt.status, tt.challenge, "never-accepted")
			source := &fakeTokenSource{token: "the-stale-token", afterRejection: "the-new-token"}
			cfg := clientConfig{TunnelURL: tunnel.URL, HTTPClient: tunnel.client}

			if _, _, err := dialTunnelWithRecovery(context.Background(), cfg, source, "the-stale-token"); err == nil {
				t.Fatal("expected the dial to fail")
			}
			if source.rejectionCalls != 0 {
				t.Fatalf("TokenAfterRejection called %d times, want none", source.rejectionCalls)
			}
			if len(tunnel.attempts) != 1 {
				t.Fatalf("tokens presented = %v, want the one attempt", tunnel.attempts)
			}
		})
	}
}

// TestDialDoesNotRetryWhenNothingChanged is the no-login-storm half: with no
// replacement offered, the server's original error is what the user sees, and no
// second attempt is made.
func TestDialDoesNotRetryWhenNothingChanged(t *testing.T) {
	tunnel := newRejectingTunnel(t, http.StatusUnauthorized,
		`Bearer error="invalid_token"`, "never-matches")
	source := &fakeTokenSource{token: "stale", afterRejection: ""}
	cfg := clientConfig{TunnelURL: tunnel.URL, HTTPClient: tunnel.client}

	_, _, err := dialTunnelWithRecovery(context.Background(), cfg, source, "stale")
	if err == nil {
		t.Fatal("expected the rejection to be surfaced")
	}
	if !strings.Contains(err.Error(), "tunnel authentication rejected") {
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
		tunnel := newRejectingTunnel(t, status, "", "never-matches")
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

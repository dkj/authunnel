package tunnelserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/time/rate"
)

// preAuthTestClock is a tiny mutable clock for deterministic limiter tests,
// matching the pattern used in admission_test.go.
type preAuthTestClock struct {
	now atomic.Pointer[time.Time]
}

func newPreAuthTestClock(start time.Time) *preAuthTestClock {
	c := &preAuthTestClock{}
	c.now.Store(&start)
	return c
}

func (c *preAuthTestClock) Now() time.Time { return *c.now.Load() }
func (c *preAuthTestClock) Advance(d time.Duration) {
	t := c.now.Load().Add(d)
	c.now.Store(&t)
}

func TestNewPreAuthLimiterDisabledWhenRateZero(t *testing.T) {
	if got := NewPreAuthLimiter(PreAuthConfig{Rate: 0, Burst: 5}); got != nil {
		t.Fatalf("NewPreAuthLimiter with Rate=0 should return nil, got %#v", got)
	}
}

func TestPreAuthLimiterAllowsWithinBurst(t *testing.T) {
	clk := newPreAuthTestClock(time.Unix(1_700_000_000, 0))
	p := newPreAuthLimiterWithClock(PreAuthConfig{Rate: 1, Burst: 3}, clk.Now)

	for i := 0; i < 3; i++ {
		ok, retryAfter := p.Allow("203.0.113.10")
		if !ok {
			t.Fatalf("attempt %d: expected allow, got deny (retryAfter=%v)", i+1, retryAfter)
		}
	}
	ok, retryAfter := p.Allow("203.0.113.10")
	if ok {
		t.Fatalf("expected deny after burst, got allow")
	}
	if retryAfter <= 0 {
		t.Fatalf("expected positive retryAfter, got %v", retryAfter)
	}
}

func TestPreAuthLimiterTracksKeysIndependently(t *testing.T) {
	clk := newPreAuthTestClock(time.Unix(1_700_000_000, 0))
	p := newPreAuthLimiterWithClock(PreAuthConfig{Rate: 1, Burst: 1}, clk.Now)

	if ok, _ := p.Allow("203.0.113.10"); !ok {
		t.Fatal("first IP burst should be allowed")
	}
	if ok, _ := p.Allow("203.0.113.10"); ok {
		t.Fatal("first IP second request should be denied")
	}
	if ok, _ := p.Allow("198.51.100.42"); !ok {
		t.Fatal("second IP burst should be allowed")
	}
}

func TestPreAuthLimiterReapsIdleEntries(t *testing.T) {
	clk := newPreAuthTestClock(time.Unix(1_700_000_000, 0))
	p := newPreAuthLimiterWithClock(PreAuthConfig{Rate: rate.Limit(10), Burst: 2}, clk.Now)

	if ok, _ := p.Allow("203.0.113.10"); !ok {
		t.Fatal("first request should be allowed")
	}
	clk.Advance(time.Second)
	if ok, _ := p.Allow("198.51.100.42"); !ok {
		t.Fatal("unrelated key should be allowed")
	}

	p.mu.Lock()
	_, stillThere := p.entries["203.0.113.10"]
	p.mu.Unlock()
	if stillThere {
		t.Fatal("expected 203.0.113.10 to be reaped after bucket refilled to burst")
	}
}

func TestPreAuthLimiterEmptyKeyAdmits(t *testing.T) {
	p := NewPreAuthLimiter(PreAuthConfig{Rate: 1, Burst: 1})
	if ok, _ := p.Allow(""); !ok {
		t.Fatal("empty key should be admitted (cannot bucket safely)")
	}
}

func TestPreAuthLimiterNilAdmits(t *testing.T) {
	var p *PreAuthLimiter
	if ok, _ := p.Allow("203.0.113.10"); !ok {
		t.Fatal("nil limiter must admit every request")
	}
}

func TestParseForwardedForMode(t *testing.T) {
	cases := map[string]ForwardedForMode{
		"":            ForwardedForOff,
		"off":         ForwardedForOff,
		"OFF":         ForwardedForOff,
		"leftmost":    ForwardedForLeftmost,
		"rightmost":   ForwardedForRightmost,
		"single-hop":  ForwardedForSingleHop,
		"single_hop":  ForwardedForSingleHop,
		" Rightmost ": ForwardedForRightmost,
	}
	for in, want := range cases {
		got, err := ParseForwardedForMode(in)
		if err != nil {
			t.Fatalf("ParseForwardedForMode(%q) returned error: %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseForwardedForMode(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseForwardedForMode("nonsense"); err == nil {
		t.Fatal("expected error for invalid mode")
	}
	// String() must round-trip through ParseForwardedForMode for the real modes.
	for _, m := range []ForwardedForMode{ForwardedForOff, ForwardedForLeftmost, ForwardedForRightmost, ForwardedForSingleHop} {
		got, err := ParseForwardedForMode(m.String())
		if err != nil || got != m {
			t.Fatalf("round-trip failed for %v: got %v err %v", m, got, err)
		}
	}
}

func TestPreAuthClientKeyOffIgnoresForwardedFor(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	r.RemoteAddr = "203.0.113.10:54321"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")

	got, ok := preAuthClientKey(r, ForwardedForOff)
	if !ok {
		t.Fatal("off mode must always succeed")
	}
	if got != "203.0.113.10" {
		t.Fatalf("expected RemoteAddr host with mode off, got %q", got)
	}
}

func TestPreAuthClientKeyLeftmost(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	r.RemoteAddr = "203.0.113.10:54321"
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.10")

	got, ok := preAuthClientKey(r, ForwardedForLeftmost)
	if !ok || got != "198.51.100.7" {
		t.Fatalf("expected leftmost XFF entry, got %q ok=%v", got, ok)
	}
}

func TestPreAuthClientKeyRightmostIgnoresSpoofedLeftmost(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	r.RemoteAddr = "203.0.113.10:54321"
	// A client spoofs a leftmost entry; the trusted proxy appends the real
	// client to the right, so rightmost must pick the appended value.
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.7")

	got, ok := preAuthClientKey(r, ForwardedForRightmost)
	if !ok || got != "198.51.100.7" {
		t.Fatalf("expected rightmost XFF entry, got %q ok=%v", got, ok)
	}
}

func TestPreAuthClientKeyRejectsOnViolation(t *testing.T) {
	cases := []struct {
		name string
		mode ForwardedForMode
		xff  string // "" means header unset
	}{
		{"leftmost missing header", ForwardedForLeftmost, ""},
		{"leftmost blank first entry", ForwardedForLeftmost, "   ,198.51.100.7"},
		{"rightmost missing header", ForwardedForRightmost, ""},
		{"rightmost trailing comma", ForwardedForRightmost, "198.51.100.7,"},
		{"single-hop missing header", ForwardedForSingleHop, ""},
		{"single-hop multiple entries", ForwardedForSingleHop, "198.51.100.7, 203.0.113.10"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
			r.RemoteAddr = "203.0.113.10:54321"
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got, ok := preAuthClientKey(r, tc.mode); ok {
				t.Fatalf("expected violation (ok=false), got key=%q ok=true", got)
			}
		})
	}
}

// TestPreAuthClientKeyFlattensMultipleForwardedForLines is a regression for a
// finding that reading only the first X-Forwarded-For field line let a client
// spoof the value: the client sends its own X-Forwarded-For line and the proxy
// appends its trustworthy hop as a *second* line. The parser must flatten all
// field lines (RFC 7230 §3.2.2) so rightmost/single-hop read the proxy's value.
func TestPreAuthClientKeyFlattensMultipleForwardedForLines(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	r.RemoteAddr = "203.0.113.10:54321"
	// Line 1 is the client's spoofed claim; line 2 is what the trusted proxy
	// appended. Combined list is "1.2.3.4, 198.51.100.7".
	r.Header.Add("X-Forwarded-For", "1.2.3.4")
	r.Header.Add("X-Forwarded-For", "198.51.100.7")

	got, ok := preAuthClientKey(r, ForwardedForRightmost)
	if !ok || got != "198.51.100.7" {
		t.Fatalf("rightmost across field lines: got %q ok=%v, want 198.51.100.7", got, ok)
	}

	// single-hop must see two hops across the two lines and reject, rather than
	// trusting only the first line and accepting the spoofed value.
	if got, ok := preAuthClientKey(r, ForwardedForSingleHop); ok {
		t.Fatalf("single-hop must reject two field lines, got key=%q ok=true", got)
	}

	// leftmost still reads the genuine leftmost (the client's claim) — spoofable
	// by design, which is why leftmost is documented as trusted-network-only.
	if got, ok := preAuthClientKey(r, ForwardedForLeftmost); !ok || got != "1.2.3.4" {
		t.Fatalf("leftmost across field lines: got %q ok=%v, want 1.2.3.4", got, ok)
	}
}

// TestPreAuthClientKeyNormalizesPortInForwardedFor guards against a proxy that
// appends host:port entries (e.g. AWS ALB client port preservation). The limiter
// key must be the bare IP so a client cycling ephemeral ports cannot mint fresh
// per-IP buckets.
func TestPreAuthClientKeyNormalizesPortInForwardedFor(t *testing.T) {
	cases := []struct {
		name string
		mode ForwardedForMode
		xff  string
		want string
	}{
		{"rightmost ipv4:port", ForwardedForRightmost, "1.2.3.4, 198.51.100.7:54321", "198.51.100.7"},
		{"leftmost ipv4:port", ForwardedForLeftmost, "198.51.100.7:443, 1.2.3.4", "198.51.100.7"},
		{"single-hop ipv4:port", ForwardedForSingleHop, "198.51.100.7:65000", "198.51.100.7"},
		{"rightmost bracketed ipv6:port", ForwardedForRightmost, "[2001:db8::1]:443", "2001:db8::1"},
		{"rightmost bare ipv6 unchanged", ForwardedForRightmost, "2001:db8::1", "2001:db8::1"},
		{"rightmost bare ipv4 unchanged", ForwardedForRightmost, "198.51.100.7", "198.51.100.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
			r.RemoteAddr = "203.0.113.10:54321"
			r.Header.Set("X-Forwarded-For", tc.xff)
			got, ok := preAuthClientKey(r, tc.mode)
			if !ok || got != tc.want {
				t.Fatalf("got %q ok=%v, want %q", got, ok, tc.want)
			}
		})
	}
}

// TestHandlerPreAuthSamePortVaryingForwardedForBucketsByIP verifies that, with
// rightmost trust, two requests carrying the same forwarded IP but different
// ports share one bucket — so the limiter remains per-IP under ALB-style
// client-port preservation.
func TestHandlerPreAuthSamePortVaryingForwardedForBucketsByIP(t *testing.T) {
	clk := newPreAuthTestClock(time.Unix(1_700_000_000, 0))
	limiter := newPreAuthLimiterWithClock(PreAuthConfig{Rate: 1, Burst: 1}, clk.Now)
	mux := NewHandler(panicValidator{t: t}, NewObservedSOCKSServer(nil, nil, nil, 0), HandlerOptions{
		PreAuth:                 limiter,
		PreAuthForwardedForMode: ForwardedForRightmost,
	})

	req1 := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	req1.RemoteAddr = "203.0.113.10:54321"
	req1.Header.Set("X-Forwarded-For", "198.51.100.7:11111")
	rr1 := httptest.NewRecorder()
	mux.ServeHTTP(rr1, req1)
	if rr1.Code == http.StatusTooManyRequests {
		t.Fatalf("first request unexpectedly rate-limited: %d", rr1.Code)
	}

	// Same forwarded IP, different ephemeral port — must hit the same bucket.
	req2 := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	req2.RemoteAddr = "203.0.113.10:54321"
	req2.Header.Set("X-Forwarded-For", "198.51.100.7:22222")
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d: a varying source port minted a new bucket", rr2.Code, http.StatusTooManyRequests)
	}
}

func TestPreAuthClientKeySingleHopAcceptsOneEntry(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	r.RemoteAddr = "203.0.113.10:54321"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")

	got, ok := preAuthClientKey(r, ForwardedForSingleHop)
	if !ok || got != "198.51.100.7" {
		t.Fatalf("expected the single XFF entry, got %q ok=%v", got, ok)
	}
}

// panicValidator fails the test if its ValidateAccessToken is called. The
// pre-auth gate must reject denied requests before any token validation
// work happens; this guards that contract.
type panicValidator struct {
	t *testing.T
}

func (p panicValidator) ValidateAccessToken(_ context.Context, _ string) (*oidc.AccessTokenClaims, error) {
	p.t.Fatalf("validator must not be invoked when pre-auth limiter denies the request")
	return nil, nil
}

// TestHandlerPreAuthGatesAllProtectedPaths is a regression for a finding
// that the limiter only covered /protected/tunnel, leaving the shared
// protected smoke-test path (and any /protected/* subpath) reachable for
// junk-bearer floods. Every protected route must share the gate.
func TestHandlerPreAuthGatesAllProtectedPaths(t *testing.T) {
	for _, path := range []string{"/protected", "/protected/", "/protected/foo", "/protected/tunnel"} {
		t.Run(path, func(t *testing.T) {
			clk := newPreAuthTestClock(time.Unix(1_700_000_000, 0))
			limiter := newPreAuthLimiterWithClock(PreAuthConfig{Rate: 1, Burst: 1}, clk.Now)
			mux := NewHandler(panicValidator{t: t}, NewObservedSOCKSServer(nil, nil, nil, 0), HandlerOptions{
				PreAuth: limiter,
			})

			// Burn the burst with one request.
			req1 := httptest.NewRequest(http.MethodGet, path, nil)
			req1.RemoteAddr = "203.0.113.10:54321"
			rr1 := httptest.NewRecorder()
			mux.ServeHTTP(rr1, req1)

			// The next request must be denied at the pre-auth gate before
			// the validator (or the path-mismatch 404 in the smoke handler)
			// can be reached.
			req2 := httptest.NewRequest(http.MethodGet, path, nil)
			req2.RemoteAddr = "203.0.113.10:54321"
			rr2 := httptest.NewRecorder()
			mux.ServeHTTP(rr2, req2)
			if rr2.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want %d (body: %q)", rr2.Code, http.StatusTooManyRequests, rr2.Body.String())
			}
			if got := rr2.Header().Get("Retry-After"); got == "" {
				t.Fatal("Retry-After header missing on pre-auth denial")
			}
		})
	}
}

func TestHandlerPreAuthDeniedBeforeValidator(t *testing.T) {
	clk := newPreAuthTestClock(time.Unix(1_700_000_000, 0))
	limiter := newPreAuthLimiterWithClock(PreAuthConfig{Rate: 1, Burst: 1}, clk.Now)

	mux := NewHandler(panicValidator{t: t}, NewObservedSOCKSServer(nil, nil, nil, 0), HandlerOptions{
		PreAuth: limiter,
	})

	// First request consumes the burst and falls through to the missing-auth
	// check (panicValidator never sees the call because no token is present).
	req1 := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	req1.RemoteAddr = "203.0.113.10:54321"
	rr1 := httptest.NewRecorder()
	mux.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusUnauthorized {
		t.Fatalf("first request: status = %d, want %d (body: %q)", rr1.Code, http.StatusUnauthorized, rr1.Body.String())
	}

	// Second request from the same IP must be denied at the pre-auth gate
	// before the missing-token check runs.
	req2 := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	req2.RemoteAddr = "203.0.113.10:54321"
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: status = %d, want %d (body: %q)", rr2.Code, http.StatusTooManyRequests, rr2.Body.String())
	}
	if !strings.Contains(rr2.Body.String(), "rate limit exceeded") {
		t.Fatalf("body = %q, want it to contain rate-limit message", rr2.Body.String())
	}
	if got := rr2.Header().Get("Retry-After"); got == "" {
		t.Fatal("Retry-After header missing on pre-auth denial")
	}
}

// TestHandlerPreAuthSpoofedForwardedForCannotMintBucketUnderDefault is the
// headline regression for decoupling forwarded-for trust from plaintext-proxy
// mode. With the default ForwardedForOff (the posture even under
// --plaintext-behind-reverse-proxy), a client must not be able to evade the
// per-IP limiter by varying a client-supplied X-Forwarded-For: every request
// from one TCP peer must share a single bucket regardless of the header.
func TestHandlerPreAuthSpoofedForwardedForCannotMintBucketUnderDefault(t *testing.T) {
	clk := newPreAuthTestClock(time.Unix(1_700_000_000, 0))
	limiter := newPreAuthLimiterWithClock(PreAuthConfig{Rate: 1, Burst: 1}, clk.Now)
	mux := NewHandler(panicValidator{t: t}, NewObservedSOCKSServer(nil, nil, nil, 0), HandlerOptions{
		PreAuth: limiter,
		// PreAuthForwardedForMode left as the zero value (ForwardedForOff).
	})

	// First request burns the single-token burst for this TCP peer.
	req1 := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	req1.RemoteAddr = "203.0.113.10:54321"
	req1.Header.Set("X-Forwarded-For", "10.0.0.1")
	rr1 := httptest.NewRecorder()
	mux.ServeHTTP(rr1, req1)
	if rr1.Code == http.StatusTooManyRequests {
		t.Fatalf("first request unexpectedly rate-limited: %d", rr1.Code)
	}

	// Second request from the same TCP peer but a *different* spoofed
	// X-Forwarded-For must still hit the same RemoteAddr bucket and be denied.
	req2 := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	req2.RemoteAddr = "203.0.113.10:54321"
	req2.Header.Set("X-Forwarded-For", "10.0.0.2")
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d: a spoofed X-Forwarded-For minted a new bucket under the default posture", rr2.Code, http.StatusTooManyRequests)
	}
}

// TestHandlerPreAuthRejectsForwardedForViolation verifies that, in a trusting
// mode, a request whose X-Forwarded-For violates the configured expectation is
// refused with 400 at the gate, before any token validation runs.
func TestHandlerPreAuthRejectsForwardedForViolation(t *testing.T) {
	clk := newPreAuthTestClock(time.Unix(1_700_000_000, 0))
	limiter := newPreAuthLimiterWithClock(PreAuthConfig{Rate: 1, Burst: 5}, clk.Now)
	mux := NewHandler(panicValidator{t: t}, NewObservedSOCKSServer(nil, nil, nil, 0), HandlerOptions{
		PreAuth:                 limiter,
		PreAuthForwardedForMode: ForwardedForSingleHop,
	})

	// single-hop with two entries is a violation -> 400, validator never runs.
	req := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	req.RemoteAddr = "203.0.113.10:54321"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.10")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %q)", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}

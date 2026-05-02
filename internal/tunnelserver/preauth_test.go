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

func TestPreAuthClientKeyDefaultsToRemoteAddr(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	r.RemoteAddr = "203.0.113.10:54321"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")

	if got := preAuthClientKey(r, false); got != "203.0.113.10" {
		t.Fatalf("expected 203.0.113.10 (RemoteAddr) without trust, got %q", got)
	}
}

func TestPreAuthClientKeyTrustsForwardedForWhenEnabled(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	r.RemoteAddr = "203.0.113.10:54321"
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.10")

	if got := preAuthClientKey(r, true); got != "198.51.100.7" {
		t.Fatalf("expected leftmost XFF entry, got %q", got)
	}
}

func TestPreAuthClientKeyFallsBackToRemoteAddrWhenForwardedForEmpty(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	r.RemoteAddr = "203.0.113.10:54321"

	if got := preAuthClientKey(r, true); got != "203.0.113.10" {
		t.Fatalf("expected RemoteAddr fallback, got %q", got)
	}
}

func TestPreAuthClientKeyIgnoresWhitespaceOnlyForwardedFor(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	r.RemoteAddr = "203.0.113.10:54321"
	r.Header.Set("X-Forwarded-For", "   ,198.51.100.7")

	if got := preAuthClientKey(r, true); got != "203.0.113.10" {
		t.Fatalf("expected RemoteAddr when first XFF entry is whitespace, got %q", got)
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

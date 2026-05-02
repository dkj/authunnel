package tunnelserver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/time/rate"
)

func TestAdmit_DisabledConfig(t *testing.T) {
	a := NewAdmitter(AdmissionConfig{})
	for i := 0; i < 5; i++ {
		decision, release, _ := a.Admit("alice")
		if decision != AdmitOK {
			t.Fatalf("attempt %d: expected AdmitOK, got %v", i, decision)
		}
		release()
	}
}

func TestAdmit_NilReceiverAdmits(t *testing.T) {
	var a *Admitter
	decision, release, _ := a.Admit("alice")
	if decision != AdmitOK {
		t.Fatalf("nil admitter must admit, got %v", decision)
	}
	release() // must be safe
}

func TestAdmit_GlobalCap(t *testing.T) {
	a := NewAdmitter(AdmissionConfig{GlobalMax: 2})

	d1, r1, _ := a.Admit("alice")
	d2, r2, _ := a.Admit("bob")
	if d1 != AdmitOK || d2 != AdmitOK {
		t.Fatalf("first two admits should succeed, got %v %v", d1, d2)
	}

	d3, _, retry := a.Admit("carol")
	if d3 != AdmitDeniedGlobal {
		t.Fatalf("third admit should hit global cap, got %v", d3)
	}
	if retry <= 0 {
		t.Fatalf("expected positive retry-after, got %v", retry)
	}

	r1()
	d4, r4, _ := a.Admit("carol")
	if d4 != AdmitOK {
		t.Fatalf("admit after release should succeed, got %v", d4)
	}
	r4()
	r2()
}

func TestAdmit_PerUserCap(t *testing.T) {
	a := NewAdmitter(AdmissionConfig{PerUserMax: 1})

	da, ra, _ := a.Admit("alice")
	if da != AdmitOK {
		t.Fatalf("first alice admit should succeed, got %v", da)
	}

	// Alice's second attempt denied.
	da2, _, retry := a.Admit("alice")
	if da2 != AdmitDeniedPerUser {
		t.Fatalf("alice second admit should hit per-user cap, got %v", da2)
	}
	if retry <= 0 {
		t.Fatalf("expected positive retry-after, got %v", retry)
	}

	// Bob unaffected.
	db, rb, _ := a.Admit("bob")
	if db != AdmitOK {
		t.Fatalf("bob admit should succeed, got %v", db)
	}

	ra()
	rb()

	// Alice can now admit again.
	da3, ra3, _ := a.Admit("alice")
	if da3 != AdmitOK {
		t.Fatalf("alice admit after release should succeed, got %v", da3)
	}
	ra3()
}

func TestAdmit_RateLimitDeterministic(t *testing.T) {
	var now atomic.Pointer[time.Time]
	start := time.Unix(1_700_000_000, 0)
	now.Store(&start)
	clock := func() time.Time { return *now.Load() }
	advance := func(d time.Duration) {
		t2 := now.Load().Add(d)
		now.Store(&t2)
	}

	a := newAdmitterWithClock(AdmissionConfig{
		PerUserRate:  rate.Every(time.Second),
		PerUserBurst: 2,
	}, clock)

	// Burst of 2 available immediately.
	d1, r1, _ := a.Admit("alice")
	d2, r2, _ := a.Admit("alice")
	if d1 != AdmitOK || d2 != AdmitOK {
		t.Fatalf("burst admits should succeed, got %v %v", d1, d2)
	}
	r1()
	r2()

	// Third admit exhausts the bucket.
	d3, _, retry := a.Admit("alice")
	if d3 != AdmitDeniedRate {
		t.Fatalf("third admit should hit rate limit, got %v", d3)
	}
	if retry <= 0 {
		t.Fatalf("rate-limit retry-after should be positive, got %v", retry)
	}

	// Advance past the refill and verify admission resumes.
	advance(2 * time.Second)
	d4, r4, _ := a.Admit("alice")
	if d4 != AdmitOK {
		t.Fatalf("admit after refill should succeed, got %v", d4)
	}
	r4()
}

func TestAdmit_UserEntryGC(t *testing.T) {
	a := NewAdmitter(AdmissionConfig{PerUserMax: 2})

	_, release, _ := a.Admit("alice")
	release()

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.users["alice"]; ok {
		t.Fatalf("idle user entry should have been GC'd; users = %v", a.users)
	}
	if a.global != 0 {
		t.Fatalf("global counter should be 0 after release, got %d", a.global)
	}
}

func TestAdmit_UserEntryGCPreservesPartialBucket(t *testing.T) {
	a := NewAdmitter(AdmissionConfig{
		PerUserRate:  rate.Every(time.Second),
		PerUserBurst: 2,
	})

	_, release, _ := a.Admit("alice")
	release()

	// Bucket drained one token by the successful admit; entry must persist
	// so the next admit still sees the reduced token count.
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.users["alice"]; !ok {
		t.Fatalf("partially drained user entry must be preserved")
	}
}

// TestAdmit_IdleEntryReapedAfterBucketRefills pins the invariant that
// user entries left behind with a partially drained bucket (which
// maybeRemoveIdleLocked intentionally preserves at release time) are later
// evicted by the Admit-side sweep once the bucket has refilled. Without the
// sweep, every unique short-lived subject would leave a limiter behind
// forever and the users map would grow with historical cardinality.
func TestAdmit_IdleEntryReapedAfterBucketRefills(t *testing.T) {
	var now atomic.Pointer[time.Time]
	start := time.Unix(1_700_000_000, 0)
	now.Store(&start)
	clock := func() time.Time { return *now.Load() }
	advance := func(d time.Duration) {
		t2 := now.Load().Add(d)
		now.Store(&t2)
	}

	a := newAdmitterWithClock(AdmissionConfig{
		PerUserRate:  rate.Every(time.Second),
		PerUserBurst: 1,
	}, clock)

	_, release, _ := a.Admit("alice")
	release()

	// Bucket drained by the successful admit; entry must persist until the
	// bucket refills so the rate limit can't be defeated by close/reopen.
	a.mu.Lock()
	_, present := a.users["alice"]
	a.mu.Unlock()
	if !present {
		t.Fatal("alice entry should persist immediately after release while bucket is partially drained")
	}

	// Alice never returns. Fast-forward well past the refill interval — her
	// bucket is now at burst, so the entry is cold-path reapable but there
	// is no release callback left to do it.
	advance(10 * time.Second)

	// A single admission from a different subject triggers the opportunistic
	// sweep at the top of Admit. With only a handful of entries in the map
	// the sweep is guaranteed to visit alice.
	_, releaseBob, _ := a.Admit("bob")
	t.Cleanup(releaseBob)

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.users["alice"]; ok {
		t.Fatalf("fully refilled idle entry should have been reaped during sweep; users = %v", a.users)
	}
}

// TestAdmit_SweepPreservesPartialBuckets guards against a regression where
// the opportunistic sweep could rescue memory at the cost of letting a
// returning user skip past accumulated rate-limit state by simply waiting
// out a close/reopen cycle.
func TestAdmit_SweepPreservesPartialBuckets(t *testing.T) {
	a := NewAdmitter(AdmissionConfig{
		PerUserRate:  rate.Every(time.Second),
		PerUserBurst: 2,
	})

	_, releaseAlice, _ := a.Admit("alice")
	releaseAlice()

	// Trigger the sweep via a second, unrelated admission. Alice's bucket
	// still owes a token (burst 2, one consumed), so the sweep must leave
	// her entry alone even though active == 0.
	_, releaseBob, _ := a.Admit("bob")
	t.Cleanup(releaseBob)

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.users["alice"]; !ok {
		t.Fatalf("partially drained idle entry must survive sweep; users = %v", a.users)
	}
}

func TestAdmit_ReleaseIdempotent(t *testing.T) {
	a := NewAdmitter(AdmissionConfig{GlobalMax: 1})
	_, release, _ := a.Admit("alice")
	release()
	release() // must not underflow global counter or corrupt state

	d, r, _ := a.Admit("bob")
	if d != AdmitOK {
		t.Fatalf("admit after double-release should succeed, got %v", d)
	}
	r()
}

func TestHandler_RejectsWhenGlobalCapExceeded(t *testing.T) {
	validator := &mockValidator{tokens: map[string]*oidc.AccessTokenClaims{
		"alice": {TokenClaims: oidc.TokenClaims{Subject: "alice"}},
	}}
	admitter := NewAdmitter(AdmissionConfig{GlobalMax: 1})
	// Pre-fill the admitter so the handler's attempt is the one that
	// trips the cap; this avoids racing an actual WebSocket upgrade.
	_, releaseFirst, _ := admitter.Admit("placeholder")
	t.Cleanup(releaseFirst)

	mux := NewHandler(validator, NewObservedSOCKSServer(nil, nil, nil, 0), HandlerOptions{
		Admission: admitter,
	})

	req := httptest.NewRequest(http.MethodGet, "https://example.test/protected/tunnel", nil)
	req.Header.Set("Authorization", "Bearer alice")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Origin", "https://example.test")
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d (body: %q)", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Fatalf("expected Retry-After header to be set")
	}
	if !strings.Contains(rr.Body.String(), "capacity") {
		t.Fatalf("expected capacity message, got %q", rr.Body.String())
	}
}

func TestObservedSOCKSDial_DoesNotBlockPastConfiguredTimeout(t *testing.T) {
	// A listener that accepts connections but never reads drives the dial
	// straight into timeout territory. SYN-then-idle is the closest local
	// stand-in for a blackholed destination.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	// A half-open TCP handshake is tricky to simulate locally — the local
	// stack completes the handshake. To exercise the timeout guardrail we
	// target an unroutable address (RFC5737 TEST-NET-1) with a tight
	// timeout. Different kernels and routing tables may fail fast with
	// "network is unreachable" before timeout, so the assertion below only
	// requires that the dial returns promptly and with an error.
	dial := observedSOCKSDial(nil, 50*time.Millisecond)
	start := time.Now()
	conn, err := dial(context.Background(), "tcp", "192.0.2.1:65000")
	elapsed := time.Since(start)

	if err == nil {
		conn.Close()
		t.Fatalf("expected timeout error, got nil (dial succeeded?)")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("dial took %v, timeout not enforced", elapsed)
	}
	// Timeout is preferred, but some environments fail earlier with an
	// unroutable-network error. Both outcomes are acceptable as long as
	// the call respects the configured upper bound.
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return
	}
	errText := strings.ToLower(err.Error())
	if !strings.Contains(errText, "unreachable") && !strings.Contains(errText, "no route") {
		t.Fatalf("expected timeout or unreachable-network error, got %v", err)
	}
}

func TestAdmit_ConcurrentSafety(t *testing.T) {
	a := NewAdmitter(AdmissionConfig{GlobalMax: 50, PerUserMax: 5})

	const workers = 20
	const perWorker = 200

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		subject := "user-" + string(rune('a'+w%5))
		go func(subj string) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				d, release, _ := a.Admit(subj)
				if d == AdmitOK {
					release()
				}
			}
		}(subject)
	}
	wg.Wait()

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.global != 0 {
		t.Fatalf("global counter leaked: %d", a.global)
	}
	for k, v := range a.users {
		if v.active != 0 {
			t.Fatalf("user %q active counter leaked: %d", k, v.active)
		}
	}
}

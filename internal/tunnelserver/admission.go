package tunnelserver

import (
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// AdmissionConfig is the per-process tunnel-admission policy. A zero value in
// any field disables the corresponding control, so the zero-value config is
// "admit everything" and existing deployments that do not set any flags keep
// their current behaviour. Per-user policy is keyed by the stable subject
// identity from the validated access token.
type AdmissionConfig struct {
	// GlobalMax bounds the total number of concurrent tunnels across all
	// users. 0 disables the global cap.
	GlobalMax int
	// PerUserMax bounds the number of concurrent tunnels for a single
	// subject. 0 disables the per-user cap.
	PerUserMax int
	// PerUserRate is the sustained tunnel-open rate per subject. 0 disables
	// rate limiting.
	PerUserRate rate.Limit
	// PerUserBurst is the burst size for the per-user token bucket. Ignored
	// when PerUserRate == 0. Must be >= 1 when PerUserRate > 0.
	PerUserBurst int
}

// AdmitDecision describes the outcome of a single admission attempt.
type AdmitDecision int

const (
	AdmitOK AdmitDecision = iota
	AdmitDeniedGlobal
	AdmitDeniedPerUser
	AdmitDeniedRate
)

// String returns the structured-log reason for the decision.
func (d AdmitDecision) String() string {
	switch d {
	case AdmitOK:
		return "ok"
	case AdmitDeniedGlobal:
		return "global"
	case AdmitDeniedPerUser:
		return "per_user"
	case AdmitDeniedRate:
		return "rate"
	default:
		return "unknown"
	}
}

type userEntry struct {
	active  int
	limiter *rate.Limiter // nil when rate limiting is disabled
}

// Admitter tracks active tunnels and enforces AdmissionConfig. It is safe for
// concurrent use by many handler goroutines. A nil *Admitter admits every
// request, which lets callers treat admission as optional without sprinkling
// nil checks through the handler.
type Admitter struct {
	cfg   AdmissionConfig
	clock func() time.Time

	mu     sync.Mutex
	global int
	users  map[string]*userEntry
}

// NewAdmitter returns an Admitter enforcing cfg. If cfg is the zero value the
// returned Admitter still functions but admits every call.
func NewAdmitter(cfg AdmissionConfig) *Admitter {
	return newAdmitterWithClock(cfg, time.Now)
}

// newAdmitterWithClock is the test entry point; production code uses
// NewAdmitter and the real clock.
func newAdmitterWithClock(cfg AdmissionConfig, clock func() time.Time) *Admitter {
	if clock == nil {
		clock = time.Now
	}
	return &Admitter{
		cfg:   cfg,
		clock: clock,
		users: make(map[string]*userEntry),
	}
}

// Admit attempts to reserve a tunnel slot for the given subject. On success
// the returned decision is AdmitOK and release must be called exactly once
// when the tunnel ends (the caller typically defers it in the handler).
//
// On rejection, release is a no-op (always safe to call) and retryAfter is a
// caller-facing hint suitable for an HTTP Retry-After header. For rate-limit
// denials retryAfter reflects the underlying token-bucket reservation delay;
// for capacity denials it is a conservative default.
func (a *Admitter) Admit(subject string) (decision AdmitDecision, release func(), retryAfter time.Duration) {
	if a == nil {
		return AdmitOK, func() {}, 0
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Opportunistically reap entries whose buckets have fully refilled since
	// they went idle. maybeRemoveIdleLocked intentionally preserves partially
	// drained buckets at release time to keep returning users rate-limited;
	// without a later sweep those entries would linger forever once the
	// subject stopped coming back, so the users map would grow with
	// historical subject cardinality. A tiny per-call sweep amortises that
	// cleanup without introducing a background goroutine.
	a.reapIdleLocked(admitReapSweep)

	if a.cfg.GlobalMax > 0 && a.global >= a.cfg.GlobalMax {
		return AdmitDeniedGlobal, func() {}, 30 * time.Second
	}

	entry := a.users[subject]
	if entry == nil {
		entry = &userEntry{}
		if a.cfg.PerUserRate > 0 {
			burst := a.cfg.PerUserBurst
			if burst < 1 {
				burst = 1
			}
			entry.limiter = rate.NewLimiter(a.cfg.PerUserRate, burst)
		}
		a.users[subject] = entry
	}

	if a.cfg.PerUserMax > 0 && entry.active >= a.cfg.PerUserMax {
		a.maybeRemoveIdleLocked(subject, entry)
		return AdmitDeniedPerUser, func() {}, 10 * time.Second
	}

	if entry.limiter != nil {
		now := a.clock()
		r := entry.limiter.ReserveN(now, 1)
		if !r.OK() {
			// Burst is smaller than the requested tokens; should not happen
			// for n=1 with burst>=1 but handled defensively.
			a.maybeRemoveIdleLocked(subject, entry)
			return AdmitDeniedRate, func() {}, time.Second
		}
		delay := r.DelayFrom(now)
		if delay > 0 {
			// Cancel the reservation so the tokens are returned to the
			// bucket rather than consumed by a call that will fail.
			r.CancelAt(now)
			a.maybeRemoveIdleLocked(subject, entry)
			return AdmitDeniedRate, func() {}, delay
		}
	}

	entry.active++
	a.global++
	return AdmitOK, a.releaseFunc(subject), 0
}

// releaseFunc returns a closure that decrements the active counters for the
// given subject exactly once, regardless of how many times it is invoked.
// Idempotency protects against accidental double-release from composed defers.
func (a *Admitter) releaseFunc(subject string) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			defer a.mu.Unlock()

			if a.global > 0 {
				a.global--
			}
			entry, ok := a.users[subject]
			if !ok {
				return
			}
			if entry.active > 0 {
				entry.active--
			}
			a.maybeRemoveIdleLocked(subject, entry)
		})
	}
}

// writeAdmissionDenied emits a single structured warning and sends an
// appropriate HTTP error. It centralises the mapping from decision to status
// code so the handler stays readable and the log shape matches
// socks_connect_denied for operators building queries across rejection paths.
func writeAdmissionDenied(w http.ResponseWriter, r *http.Request, decision AdmitDecision, retryAfter time.Duration, subject string) {
	logger := loggerFromContext(r.Context())

	status, msg := admissionHTTPStatus(decision)
	attrs := []any{
		slog.String("event", "tunnel_admission_denied"),
		slog.String("reason", decision.String()),
		slog.String("remote_ip", requestRemoteIP(r)),
	}
	if subject != "" {
		attrs = append(attrs, slog.String("subject", subject))
	}
	if retryAfter > 0 {
		attrs = append(attrs, slog.Int64("retry_after_ms", retryAfter.Milliseconds()))
	}
	logger.Warn("tunnel_admission_denied", attrs...)

	if retryAfter > 0 {
		// Retry-After is specified in whole seconds; round up so a tiny
		// reservation delay is not reported as 0.
		secs := int64(math.Ceil(retryAfter.Seconds()))
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
	}
	http.Error(w, msg, status)
}

func admissionHTTPStatus(decision AdmitDecision) (int, string) {
	switch decision {
	case AdmitDeniedGlobal:
		return http.StatusServiceUnavailable, "server at tunnel capacity"
	case AdmitDeniedPerUser:
		return http.StatusTooManyRequests, "per-user tunnel limit reached"
	case AdmitDeniedRate:
		return http.StatusTooManyRequests, "tunnel-open rate limit exceeded"
	default:
		return http.StatusInternalServerError, "admission denied"
	}
}

// maybeRemoveIdleLocked removes the per-user entry when it is both inactive
// and has no rate-limit state worth preserving. Called under a.mu from the
// hot paths (release and rejected-admit) where we already have the entry in
// hand. It deliberately keeps partially drained buckets so a returning user
// stays rate-limited across a close/reopen cycle; the later cold-path sweep
// (reapIdleLocked) takes care of entries once their buckets refill.
func (a *Admitter) maybeRemoveIdleLocked(subject string, entry *userEntry) {
	if entry.active != 0 {
		return
	}
	if entry.limiter != nil {
		burst := float64(entry.limiter.Burst())
		if entry.limiter.TokensAt(a.clock()) < burst {
			// The bucket is partially drained; keep the entry so the next
			// admission sees the accurate token count.
			return
		}
	}
	delete(a.users, subject)
}

// admitReapSweep caps the number of user entries inspected per Admit call.
// Map iteration in Go starts at a randomised position, so successive
// admissions visit different slices of the map and every long-idle entry is
// evicted within roughly O(n/admitReapSweep) calls while keeping each
// Admit's worst-case work O(1).
const admitReapSweep = 8

// reapIdleLocked evicts up to `limit` user entries that are inactive and
// whose rate-limit buckets (if any) have refilled to burst. Called under
// a.mu. Partially drained buckets are skipped here for the same reason
// maybeRemoveIdleLocked preserves them: dropping such an entry would hand a
// returning user a fresh full bucket and effectively bypass their
// accumulated rate-limit history.
func (a *Admitter) reapIdleLocked(limit int) {
	if limit <= 0 || len(a.users) == 0 {
		return
	}
	visited := 0
	now := a.clock()
	for subject, entry := range a.users {
		if visited >= limit {
			return
		}
		visited++
		if entry.active != 0 {
			continue
		}
		if entry.limiter != nil {
			if entry.limiter.TokensAt(now) < float64(entry.limiter.Burst()) {
				continue
			}
		}
		delete(a.users, subject)
	}
}

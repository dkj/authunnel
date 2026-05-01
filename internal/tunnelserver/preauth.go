package tunnelserver

import (
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// PreAuthConfig configures the per-IP rate limiter that runs before bearer
// token parsing. The zero value is the off posture: no limiter is constructed
// and the gate is skipped entirely. Operators opt in by setting a positive
// Rate.
//
// Client-IP extraction is a handler-level concern (see
// HandlerOptions.PreAuthTrustForwardedFor); the limiter itself is purely
// rate-bucketing logic over a caller-supplied key.
type PreAuthConfig struct {
	// Rate is the sustained per-IP rate (requests per second) for the
	// protected route. 0 disables the limiter.
	Rate rate.Limit
	// Burst is the per-IP token-bucket burst. Should be set to at least 1
	// when Rate > 0. Callers that want ceil(Rate) defaulting must compute
	// it themselves before passing the config in; the constructor floors
	// to 1 if a non-positive Burst is supplied alongside a positive Rate,
	// rather than silently picking a different shape.
	Burst int
}

// PreAuthLimiter enforces a per-source-IP rate limit before bearer token
// parsing. It is structurally similar to Admitter (mutex + per-key entry map
// + opportunistic cleanup) but keyed by client IP and intended to bound the
// pre-auth attack surface (oversized headers, junk JWTs, unknown-kid floods)
// rather than per-subject usage.
//
// A nil *PreAuthLimiter admits every request, mirroring Admitter, so the
// handler can treat the gate as optional without scattered nil checks.
type PreAuthLimiter struct {
	cfg   PreAuthConfig
	clock func() time.Time

	mu      sync.Mutex
	entries map[string]*rate.Limiter
}

// NewPreAuthLimiter returns a limiter enforcing cfg. If cfg.Rate <= 0 the
// returned value is nil so the handler can skip the gate without allocating.
func NewPreAuthLimiter(cfg PreAuthConfig) *PreAuthLimiter {
	return newPreAuthLimiterWithClock(cfg, time.Now)
}

func newPreAuthLimiterWithClock(cfg PreAuthConfig, clock func() time.Time) *PreAuthLimiter {
	if cfg.Rate <= 0 {
		return nil
	}
	if cfg.Burst < 1 {
		cfg.Burst = 1
	}
	if clock == nil {
		clock = time.Now
	}
	return &PreAuthLimiter{
		cfg:     cfg,
		clock:   clock,
		entries: make(map[string]*rate.Limiter),
	}
}

// Allow records an attempt from the given client key (IP). It returns ok=true
// when the request may proceed. When ok is false, retryAfter is a positive
// duration suitable for an HTTP Retry-After hint.
func (p *PreAuthLimiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	if p == nil {
		return true, 0
	}
	if key == "" {
		// Unparseable RemoteAddr means we cannot bucket safely; let the
		// request through and rely on later layers. The handler logs the
		// raw address so this stays visible.
		return true, 0
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.reapIdleLocked(preAuthReapSweep)

	limiter := p.entries[key]
	if limiter == nil {
		limiter = rate.NewLimiter(p.cfg.Rate, p.cfg.Burst)
		p.entries[key] = limiter
	}

	now := p.clock()
	r := limiter.ReserveN(now, 1)
	if !r.OK() {
		return false, time.Second
	}
	delay := r.DelayFrom(now)
	if delay > 0 {
		r.CancelAt(now)
		return false, delay
	}
	return true, 0
}

// preAuthReapSweep caps the number of entries inspected per Allow call. The
// sweep amortises map cleanup so we do not need a background goroutine.
const preAuthReapSweep = 8

// reapIdleLocked drops entries whose buckets have refilled to burst, freeing
// memory for IPs that have stopped hitting the gate.
func (p *PreAuthLimiter) reapIdleLocked(limit int) {
	if limit <= 0 || len(p.entries) == 0 {
		return
	}
	visited := 0
	now := p.clock()
	burst := float64(p.cfg.Burst)
	for key, limiter := range p.entries {
		if visited >= limit {
			return
		}
		visited++
		if limiter.TokensAt(now) < burst {
			continue
		}
		delete(p.entries, key)
	}
}

// WritePreAuthDenied emits a structured warning and a 429 with Retry-After,
// matching the shape used by the per-subject admission path.
func WritePreAuthDenied(w http.ResponseWriter, r *http.Request, key string, retryAfter time.Duration) {
	logger := loggerFromContext(r.Context())
	logger.Warn("preauth_rate_limited",
		slog.String("event", "preauth_rate_limited"),
		slog.String("client_key", key),
		slog.String("remote_ip", requestRemoteIP(r)),
		slog.Int64("retry_after_ms", retryAfter.Milliseconds()),
	)
	if retryAfter > 0 {
		secs := int64(math.Ceil(retryAfter.Seconds()))
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
	}
	http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
}

// preAuthClientKey extracts the key the limiter buckets by. When
// trustForwardedFor is set, the leftmost X-Forwarded-For entry takes
// precedence over the TCP peer address, falling back to RemoteAddr if XFF is
// absent or empty. Otherwise the function always returns the TCP peer host.
func preAuthClientKey(r *http.Request, trustForwardedFor bool) string {
	if trustForwardedFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); first != "" {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

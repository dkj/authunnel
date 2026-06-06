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
// HandlerOptions.PreAuthForwardedForMode); the limiter itself is purely
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
	attrs := []any{
		slog.String("event", "preauth_rate_limited"),
		slog.String("client_key", key),
		slog.String("remote_ip", requestRemoteIP(r)),
		slog.Int64("retry_after_ms", retryAfter.Milliseconds()),
	}
	if fwd := forwardedClientIPFromContext(r.Context()); fwd != "" {
		attrs = append(attrs, slog.String("forwarded_client_ip", fwd))
	}
	logger.Warn("preauth_rate_limited", attrs...)
	if retryAfter > 0 {
		secs := int64(math.Ceil(retryAfter.Seconds()))
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
	}
	http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
}

// WriteForwardedForRejected emits a structured warning and a 400 when an
// X-Forwarded-For header fails to satisfy the configured ForwardedForMode
// (absent, empty, or the wrong hop count). The request is refused rather than
// silently bucketed by RemoteAddr so a misconfigured proxy or a spoofing
// client is surfaced instead of quietly evading the pre-auth limiter.
func WriteForwardedForRejected(w http.ResponseWriter, r *http.Request) {
	logger := loggerFromContext(r.Context())
	logger.Warn("preauth_forwarded_for_rejected",
		slog.String("event", "preauth_forwarded_for_rejected"),
		slog.String("remote_ip", requestRemoteIP(r)),
		// Join all field lines so the log reflects what the parser saw, not
		// just the first (possibly client-supplied) X-Forwarded-For line.
		slog.String("forwarded_for", strings.Join(r.Header.Values("X-Forwarded-For"), ", ")),
	)
	http.Error(w, "invalid X-Forwarded-For", http.StatusBadRequest)
}

// ForwardedForMode selects how the pre-auth limiter derives a client key from
// a request that may have transited a reverse proxy. Forwarded-for trust is
// deliberately decoupled from the plaintext/TLS listening mode: the only safe
// default is to ignore X-Forwarded-For entirely, and operators opt in
// explicitly once they know an upstream proxy populates the header reliably.
type ForwardedForMode int

const (
	// ForwardedForOff ignores X-Forwarded-For and always buckets by the TCP
	// peer (RemoteAddr). This is the default and the only safe posture when a
	// client can reach the server directly: a spoofed header cannot mint a new
	// bucket.
	ForwardedForOff ForwardedForMode = iota
	// ForwardedForLeftmost trusts the leftmost X-Forwarded-For entry. That
	// entry is the original client's own claim and is spoofable by the client,
	// so enable this only on a fully trusted network where the leftmost value
	// is sanitised upstream.
	ForwardedForLeftmost
	// ForwardedForRightmost trusts the rightmost X-Forwarded-For entry: the
	// address the immediately-upstream trusted proxy observed and appended.
	// This is spoof-resistant for a single reverse proxy that appends the
	// client IP, since a client-injected leftmost value is pushed left of the
	// real one. (Multi-proxy chains would need an N-hop count; not modelled.)
	ForwardedForRightmost
	// ForwardedForSingleHop trusts X-Forwarded-For only when it carries exactly
	// one entry, rejecting zero or multiple hops. It defends a single trusted
	// proxy against a client injecting extra hops.
	ForwardedForSingleHop
)

// String renders the mode using the same tokens ParseForwardedForMode accepts.
func (m ForwardedForMode) String() string {
	switch m {
	case ForwardedForOff:
		return "off"
	case ForwardedForLeftmost:
		return "leftmost"
	case ForwardedForRightmost:
		return "rightmost"
	case ForwardedForSingleHop:
		return "single-hop"
	default:
		return fmt.Sprintf("ForwardedForMode(%d)", int(m))
	}
}

// ParseForwardedForMode maps a config token to a ForwardedForMode. An empty
// string maps to ForwardedForOff so an unset flag keeps the safe default.
func ParseForwardedForMode(s string) (ForwardedForMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off":
		return ForwardedForOff, nil
	case "leftmost":
		return ForwardedForLeftmost, nil
	case "rightmost":
		return ForwardedForRightmost, nil
	case "single-hop", "single_hop", "singlehop":
		return ForwardedForSingleHop, nil
	default:
		return ForwardedForOff, fmt.Errorf("invalid forwarded-for mode %q (want off, leftmost, rightmost, or single-hop)", s)
	}
}

// preAuthClientKey derives the limiter bucket key for r under mode. For
// ForwardedForOff it returns the TCP peer host with ok=true. For the trusting
// modes it returns the selected X-Forwarded-For entry with ok=true on success,
// or ok=false when the header violates the mode's expectation (absent, empty,
// the selected entry blank, or — for single-hop — not exactly one entry).
// Callers MUST reject (HTTP 400) when ok is false rather than silently
// bucketing by RemoteAddr: that implicit fallback is exactly what lets a client
// evade the limiter by withholding or padding the header.
func preAuthClientKey(r *http.Request, mode ForwardedForMode) (key string, ok bool) {
	if mode == ForwardedForOff {
		return requestRemoteIP(r), true
	}
	entries := splitForwardedFor(r)
	switch mode {
	case ForwardedForLeftmost:
		if len(entries) > 0 && entries[0] != "" {
			return entries[0], true
		}
	case ForwardedForRightmost:
		if n := len(entries); n > 0 && entries[n-1] != "" {
			return entries[n-1], true
		}
	case ForwardedForSingleHop:
		if len(entries) == 1 && entries[0] != "" {
			return entries[0], true
		}
	}
	return "", false
}

// splitForwardedFor flattens every X-Forwarded-For field line on r into its
// ordered, comma-separated entries, trimming surrounding whitespace but
// preserving position (including empty positions from stray commas) so callers
// can reason about hop count and which end of the chain they are reading. An
// absent/blank header yields nil.
//
// All field lines are joined, in received order, before splitting. RFC 7230
// §3.2.2 treats repeated field lines as equivalent to a single comma-joined
// value, and proxies vary: some append their hop onto the client's existing
// X-Forwarded-For line, others emit a second line. Reading only the first line
// (http.Header.Get) would let a client send its own X-Forwarded-For so the
// proxy's appended, trustworthy hop lands on a second line the parser ignores —
// defeating the rightmost/single-hop guarantees. Joining all lines closes that.
func splitForwardedFor(r *http.Request) []string {
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return nil
	}
	joined := strings.Join(values, ",")
	if strings.TrimSpace(joined) == "" {
		return nil
	}
	parts := strings.Split(joined, ",")
	for i := range parts {
		parts[i] = normalizeForwardedForEntry(strings.TrimSpace(parts[i]))
	}
	return parts
}

// normalizeForwardedForEntry reduces a single X-Forwarded-For entry to its bare
// host so the limiter buckets per-IP. Some proxies append entries as host:port
// (e.g. AWS ALB with client port preservation), and the ephemeral source port
// changes on every client reconnect; keying on the raw entry would hand the
// same client a fresh bucket per port and defeat the per-IP rate limit. Bare
// IPv4/IPv6 entries (the common case) are returned unchanged; a portless
// bracketed IPv6 literal is unwrapped to match the RemoteAddr form.
func normalizeForwardedForEntry(entry string) string {
	if entry == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(entry); err == nil {
		return host
	}
	if strings.HasPrefix(entry, "[") && strings.HasSuffix(entry, "]") {
		return entry[1 : len(entry)-1]
	}
	return entry
}

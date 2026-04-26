// Package tunnelserver contains the reusable HTTP, token-validation, and
// connection-longevity logic for the Authunnel server. Keeping this separate
// from main makes the security-sensitive request flow easier to test without
// needing to boot the TLS server.
package tunnelserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"authunnel/internal/wsconn"
)

type TokenValidator interface {
	ValidateAccessToken(ctx context.Context, token string) (*oidc.AccessTokenClaims, error)
}

// tokenClockSkew is the allowance applied to time-based token checks (nbf,
// iat) to accommodate modest clock drift between the IdP and this server.
// Kept deliberately small and compile-time constant; if operators report
// problems it can be promoted to a flag later.
const tokenClockSkew = 30 * time.Second

// JWTTokenValidator validates bearer access tokens against issuer discovery and
// the issuer's JWKS, then applies an explicit audience check for the protected
// resource.
type JWTTokenValidator struct {
	audience string
	verifier *op.AccessTokenVerifier
}

// NewJWTTokenValidator performs OIDC discovery once at startup, using it only
// to locate the issuer's JWKS endpoint. All subsequent token validation is
// done locally against that key set. Configuration errors fail at startup
// rather than on the first protected request.
func NewJWTTokenValidator(ctx context.Context, issuer, audience string, httpClient *http.Client) (*JWTTokenValidator, error) {
	if issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if audience == "" {
		return nil, errors.New("token audience is required")
	}
	discovery, err := client.Discover(ctx, issuer, httpClient)
	if err != nil {
		return nil, fmt.Errorf("discover issuer metadata: %w", err)
	}
	if discovery.JwksURI == "" {
		return nil, errors.New("issuer discovery did not advertise jwks_uri")
	}
	keySet := rp.NewRemoteKeySet(httpClient, discovery.JwksURI)
	return &JWTTokenValidator{
		audience: audience,
		verifier: op.NewAccessTokenVerifier(issuer, keySet),
	}, nil
}

// ValidateAccessToken verifies signature, issuer and expiry via the Zitadel
// verifier, enforces the configured resource audience, and applies the
// authenticity-adjacent claim checks in validateStandardClaims (non-empty
// sub, sane iat, nbf <= exp). Whether the token is usable *now* versus only
// in the future is a caller concern — admission requires "usable now" via
// checkTokenUsableBy, while the refresh path may tolerate a token that
// becomes valid before the current connection deadline.
func (v *JWTTokenValidator) ValidateAccessToken(ctx context.Context, token string) (*oidc.AccessTokenClaims, error) {
	claims, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, token, v.verifier)
	if err != nil {
		return nil, err
	}
	if err := oidc.CheckAudience(claims, v.audience); err != nil {
		return nil, err
	}
	if err := validateStandardClaims(claims, time.Now()); err != nil {
		return nil, err
	}
	return claims, nil
}

// validateStandardClaims enforces authenticity-adjacent claims that are
// independent of when the token is evaluated: subject must be non-empty
// (Authunnel pins tunnel identity to sub on refresh), iat must not be
// meaningfully in the future, and nbf must not be after exp (a token that
// would never be valid). The "is this token usable yet?" temporal policy
// is separate — see checkTokenUsableBy.
func validateStandardClaims(claims *oidc.AccessTokenClaims, now time.Time) error {
	if claims.Subject == "" {
		return errors.New("token missing subject")
	}
	if iat := claims.IssuedAt.AsTime(); !iat.IsZero() && iat.After(now.Add(tokenClockSkew)) {
		return fmt.Errorf("token iat %s is in the future", iat.Format(time.RFC3339))
	}
	nbf := claims.NotBefore.AsTime()
	exp := claims.GetExpiration()
	if !nbf.IsZero() && !exp.IsZero() && nbf.After(exp) {
		return fmt.Errorf("token nbf %s is after exp %s", nbf.Format(time.RFC3339), exp.Format(time.RFC3339))
	}
	return nil
}

// checkTokenUsableBy enforces that the token's not-before claim is at or
// before usableBy — a strict comparison, with no implicit skew. The caller
// picks usableBy to match the policy boundary it is enforcing:
//
//   - admission passes time.Now().Add(tokenClockSkew) so IdP clock drift
//     does not reject tokens whose nbf is a few seconds ahead of the
//     server's wall clock;
//   - refresh passes the current connection deadline (exp + ExpiryGrace)
//     as-is, because that deadline is a server-chosen policy point, not a
//     wall-clock measurement — applying skew there would silently extend
//     the configured enforcement window past exp + grace.
func checkTokenUsableBy(claims *oidc.AccessTokenClaims, usableBy time.Time) error {
	nbf := claims.NotBefore.AsTime()
	if nbf.IsZero() {
		return nil
	}
	if nbf.After(usableBy) {
		return fmt.Errorf("token not valid until %s (needed by %s)",
			nbf.Format(time.RFC3339), usableBy.Format(time.RFC3339))
	}
	return nil
}

// LongevityConfig controls connection lifetime enforcement. MaxDuration and
// ImplementsExpiry are orthogonal; both may be active simultaneously, in which
// case the connection ends at whichever limit is reached first.
type LongevityConfig struct {
	// MaxDuration is a hard ceiling on tunnel lifetime. Zero means unlimited.
	MaxDuration time.Duration
	// ImplementsExpiry ties the tunnel lifetime to the access token's exp
	// claim. When enabled, the server sends an expiry warning before the
	// token expires and disconnects if no refreshed token arrives in time.
	ImplementsExpiry bool
	// ExpiryWarning is the lead time before either deadline at which the
	// server sends an expiry_warning control message to the client.
	ExpiryWarning time.Duration
	// ExpiryGrace extends the connection deadline beyond the access token's
	// exp claim. This accommodates providers (e.g. Auth0) that cache access
	// tokens and return the same one on refresh until the original expires.
	// The grace window gives the client time to obtain a genuinely new token
	// after the old one expires at the provider. Default: 0 (no grace).
	ExpiryGrace time.Duration
}

func (lc LongevityConfig) active() bool {
	return lc.MaxDuration > 0 || lc.ImplementsExpiry
}

// HandlerOptions controls optional behavior of the HTTP handler.
type HandlerOptions struct {
	// TrustForwardedProto instructs the same-origin WebSocket check to use
	// X-Forwarded-Proto and X-Forwarded-Host as the effective scheme and host,
	// for deployments where a TLS-terminating reverse proxy forwards plain HTTP
	// to the backend. Without this flag the check infers scheme from r.TLS and
	// host from r.Host, so browser clients behind such a proxy would be
	// rejected as cross-origin: their Origin carries https://<public-host> but
	// the backend sees plain HTTP and possibly a rewritten Host header.
	// Enable only when the server is in plaintext mode and the reverse proxy is
	// known to set these headers reliably. Caddy, AWS ALB, Traefik, and HAProxy
	// forward the original Host by default; nginx requires an explicit
	// "proxy_set_header Host $host;" directive. The headers are never consulted
	// in TLS modes because r.TLS != nil short-circuits before they are reached.
	TrustForwardedProto bool

	// Longevity controls connection lifetime enforcement.
	Longevity LongevityConfig

	// Admission enforces concurrency, per-user, and rate-limit admission
	// policy before the WebSocket upgrade. A nil value disables admission
	// checks entirely.
	Admission *Admitter
}

// NewHandler installs the small HTTP surface used by the server:
//   - "/" for a simple liveness response
//   - "/protected" for token-validation smoke testing
//   - "/protected/tunnel" for the authenticated websocket-to-SOCKS bridge
//
// When Longevity is configured in the handler options, each tunnel is managed
// by a background goroutine that enforces connection lifetime limits and
// handles token refresh requests from the client over the control channel.
func NewHandler(validator TokenValidator, socks SOCKSServer, opts ...HandlerOptions) *http.ServeMux {
	var opt HandlerOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !allowMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write([]byte("OK " + time.Now().String()))
	})

	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		if !allowMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		if _, ok := validateRequestToken(w, r, validator); !ok {
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write([]byte("Protected OK " + time.Now().String()))
	})

	mux.HandleFunc("/protected/tunnel", func(w http.ResponseWriter, r *http.Request) {
		if !checkWebSocketRequest(w, r, opt.TrustForwardedProto) {
			return
		}
		claims, ok := validateRequestToken(w, r, validator)
		if !ok {
			return
		}
		decision, release, retryAfter := opt.Admission.Admit(claims.Subject)
		if decision != AdmitOK {
			writeAdmissionDenied(w, r, decision, retryAfter, claims.Subject)
			return
		}
		defer release()
		// websocket.Accept hijacks the HTTP/1.1 connection. Clear any
		// server-level deadlines first so the upgraded SOCKS tunnel can stay
		// open independently of the HTTP request timeout budget.
		c, err := websocket.Accept(clearHijackedConnDeadlines(w), r, nil)
		if err != nil {
			loggerFromContext(r.Context()).Warn("websocket_upgrade_failed",
				slog.String("error", err.Error()),
			)
			http.Error(w, err.Error(), http.StatusUpgradeRequired)
			return
		}
		defer c.CloseNow()
		tunnelLogger := loggerFromContext(r.Context()).With(
			slog.String("tunnel_id", newLogID()),
			slog.String("remote_ip", requestRemoteIP(r)),
		)
		tunnelLogger = loggerWithAccessTokenClaims(tunnelLogger, claims)
		tunnelStart := time.Now()
		tunnelLogger.Info("tunnel_open")
		defer logTunnelClose(tunnelLogger, tunnelStart)

		// tunnelCtx controls the tunnel lifetime. When longevity is active,
		// manageTunnelLongevity cancels this context to force the MultiplexConn
		// reads to fail, which terminates the SOCKS session. When longevity is
		// inactive the context is only cancelled by the deferred tunnelCancel
		// (normal cleanup) or the parent r.Context() closing.
		tunnelCtx, tunnelCancel := context.WithCancel(r.Context())
		defer tunnelCancel()

		// MultiplexConn wraps the WebSocket so binary frames carry SOCKS5 data
		// while text frames are routed to a control channel for longevity messages
		// (expiry warnings, token refresh, disconnect). The SOCKS layer sees a
		// plain net.Conn and is unaware of the control channel. It uses tunnelCtx
		// so that longevity enforcement can terminate reads.
		muxConn := wsconn.New(tunnelCtx, c)
		defer muxConn.Close()

		if opt.Longevity.active() {
			go manageTunnelLongevity(tunnelCtx, tunnelCancel, muxConn, validator, claims, opt.Longevity, tunnelStart, tunnelLogger)
		}

		if err := socks.ServeConn(newObservedTunnelConn(muxConn, tunnelLogger)); err != nil {
			tunnelLogger.Warn("socks_session_failed",
				slog.String("error", err.Error()),
			)
		}
	})
	return mux
}

func logTunnelClose(logger *slog.Logger, started time.Time) {
	logger.Info("tunnel_close",
		slog.Int64("duration_ms", time.Since(started).Milliseconds()),
	)
}

// manageTunnelLongevity enforces connection lifetime limits. It manages up to
// two independent deadlines (max-duration and token-expiry), sends warnings
// before each, and handles token refresh requests from the client.
func manageTunnelLongevity(
	ctx context.Context,
	cancel context.CancelFunc,
	conn *wsconn.MultiplexConn,
	validator TokenValidator,
	claims *oidc.AccessTokenClaims,
	cfg LongevityConfig,
	tunnelStart time.Time,
	logger *slog.Logger,
) {
	originalSubject := claims.Subject

	// All peer-visible control frames go through a buffered channel drained
	// by a dedicated writer goroutine. This keeps the deadline-critical
	// select below independent of peer reads: even if the writer parks on a
	// blocked write or contended writeMu, the select still observes its
	// expiry and max-duration timers and cancels the tunnel on time.
	// SendControlTimeout uses an independent context, so the courtesy
	// disconnect frame queued after cancel() can still reach the peer rather
	// than failing against the already-cancelled tunnel context. Note that
	// the timeout bounds the underlying ws.Write, not writeMu acquisition,
	// so a stuck binary writer can still delay individual control frames —
	// enforcement is unaffected because cancellation has already happened.
	// Drop-on-full is safe — every frame is best-effort by design.
	out := make(chan wsconn.ControlMessage, 16)
	defer close(out)
	go func() {
		for msg := range out {
			_ = conn.SendControlTimeout(2*time.Second, msg)
		}
	}()
	enqueue := func(msg wsconn.ControlMessage) {
		select {
		case out <- msg:
		default:
			logger.Warn("control_send_dropped", slog.String("type", msg.Type))
		}
	}

	// Token-expiry deadline (resettable via refresh). The connection deadline
	// is token exp + grace, giving clients time to obtain a new token from
	// providers that cache access tokens (e.g. Auth0).
	var tokenExpiry time.Time    // raw exp claim from the current token
	var connDeadline time.Time   // tokenExpiry + grace — the actual enforcement point
	var tokenWarnTimer, tokenDeadlineTimer *time.Timer
	if cfg.ImplementsExpiry {
		tokenExpiry = claims.GetExpiration()
		connDeadline = tokenExpiry.Add(cfg.ExpiryGrace)
		tokenWarnTimer = newTimerUntil(connDeadline, cfg.ExpiryWarning)
		tokenDeadlineTimer = time.NewTimer(time.Until(connDeadline))
	} else {
		// Inert timers that never fire.
		tokenWarnTimer = stoppedTimer()
		tokenDeadlineTimer = stoppedTimer()
	}
	// Stop the current timers on exit. These closures capture the pointer
	// variables, so they stop whichever timer is active at return time —
	// including replacements created by token refresh.
	defer func() { tokenWarnTimer.Stop() }()
	defer func() { tokenDeadlineTimer.Stop() }()

	// Max-duration deadline (immovable, never replaced).
	var maxWarnTimer, maxDeadlineTimer *time.Timer
	if cfg.MaxDuration > 0 {
		maxDeadline := tunnelStart.Add(cfg.MaxDuration)
		maxWarnTimer = newTimerUntil(maxDeadline, cfg.ExpiryWarning)
		maxDeadlineTimer = time.NewTimer(time.Until(maxDeadline))
		defer maxWarnTimer.Stop()
		defer maxDeadlineTimer.Stop()
	} else {
		maxWarnTimer = stoppedTimer()
		maxDeadlineTimer = stoppedTimer()
	}

	for {
		select {
		case <-ctx.Done():
			return

		case <-tokenWarnTimer.C:
			logger.Info("token_expiry_warning_sent", slog.Time("expires_at", connDeadline))
			enqueue(wsconn.ControlMessage{
				Type: "expiry_warning",
				Data: mustMarshal(map[string]string{
					"reason":     "token",
					"expires_at": connDeadline.Format(time.RFC3339),
				}),
			})

		case <-tokenDeadlineTimer.C:
			logger.Info("tunnel_closing_token_expired")
			cancel()
			enqueue(wsconn.ControlMessage{
				Type: "disconnect",
				Data: mustMarshal(map[string]string{"reason": "token_expired"}),
			})
			return

		case <-maxWarnTimer.C:
			maxDeadline := tunnelStart.Add(cfg.MaxDuration)
			logger.Info("max_duration_warning_sent", slog.Time("expires_at", maxDeadline))
			enqueue(wsconn.ControlMessage{
				Type: "expiry_warning",
				Data: mustMarshal(map[string]string{
					"reason":     "max_duration",
					"expires_at": maxDeadline.Format(time.RFC3339),
				}),
			})

		case <-maxDeadlineTimer.C:
			logger.Info("tunnel_closing_max_duration")
			cancel()
			enqueue(wsconn.ControlMessage{
				Type: "disconnect",
				Data: mustMarshal(map[string]string{"reason": "max_duration_reached"}),
			})
			return

		case msg, ok := <-conn.ControlChan():
			if !ok {
				return
			}
			if msg.Type != "token_refresh" {
				continue
			}
			var payload struct {
				AccessToken string `json:"access_token"`
			}
			if err := json.Unmarshal(msg.Data, &payload); err != nil || payload.AccessToken == "" {
				enqueue(wsconn.ControlMessage{
					Type: "token_rejected",
					Data: mustMarshal(map[string]string{"reason": "invalid_payload"}),
				})
				continue
			}
			if !cfg.ImplementsExpiry {
				enqueue(wsconn.ControlMessage{
					Type: "token_rejected",
					Data: mustMarshal(map[string]string{"reason": "token_expiry_not_enforced"}),
				})
				continue
			}
			newClaims, err := validator.ValidateAccessToken(ctx, payload.AccessToken)
			if err != nil {
				logger.Warn("token_refresh_rejected", slog.String("error", err.Error()))
				enqueue(wsconn.ControlMessage{
					Type: "token_rejected",
					Data: mustMarshal(map[string]string{"reason": "validation_failed"}),
				})
				continue
			}
			// A future-nbf token is admissible on refresh only if it
			// activates at or before the tunnel's current enforced
			// deadline (exp + ExpiryGrace). connDeadline is the
			// operator-chosen policy boundary — during ExpiryGrace the
			// underlying JWT is already past its own exp, so the
			// operator has explicitly opted into extending enforcement
			// to that point. The comparison is strict (no clock skew)
			// to make sure a refresh handover never silently stretches
			// the configured deadline beyond exp + grace.
			if err := checkTokenUsableBy(newClaims, connDeadline); err != nil {
				logger.Warn("token_refresh_rejected_not_yet_valid", slog.String("error", err.Error()))
				enqueue(wsconn.ControlMessage{
					Type: "token_rejected",
					Data: mustMarshal(map[string]string{"reason": "not_yet_valid"}),
				})
				continue
			}
			if newClaims.Subject != originalSubject {
				logger.Warn("token_refresh_rejected_subject_mismatch",
					slog.String("original", originalSubject),
					slog.String("received", newClaims.Subject),
				)
				enqueue(wsconn.ControlMessage{
					Type: "token_rejected",
					Data: mustMarshal(map[string]string{"reason": "subject_mismatch"}),
				})
				continue
			}

			newExpiry := newClaims.GetExpiration()
			if newExpiry.Before(tokenExpiry) {
				logger.Warn("token_refresh_rejected_expiry_reduced",
					slog.Time("current", tokenExpiry),
					slog.Time("received", newExpiry),
				)
				enqueue(wsconn.ControlMessage{
					Type: "token_rejected",
					Data: mustMarshal(map[string]string{"reason": "expiry_reduced"}),
				})
				continue
			}

			if newExpiry.Equal(tokenExpiry) {
				// Same expiry — common with providers like Auth0 that
				// cache access tokens and return the same one until it
				// expires. The token is valid, so accept it. The deadline
				// timer is already correct. If we are already inside the
				// warning window (the warning has fired), schedule a
				// retry at remaining/2 so the client retries once the
				// provider starts issuing genuinely new tokens. If the
				// refresh arrived proactively (before the warning window),
				// leave the existing warning timer untouched — rescheduling
				// would pull the warning earlier than the configured lead
				// time and cause unnecessary token churn.
				remaining := time.Until(connDeadline)
				if remaining > 0 && remaining <= cfg.ExpiryWarning {
					drainTimer(tokenWarnTimer)
					tokenWarnTimer = time.NewTimer(remaining / 2)
				}
				logger.Info("token_refresh_accepted_unchanged", slog.Time("expiry", connDeadline))
				enqueue(wsconn.ControlMessage{
					Type: "token_accepted",
					Data: mustMarshal(map[string]string{"expires_at": connDeadline.Format(time.RFC3339)}),
				})
				continue
			}

			// Expiry extended — update deadline and reset timers.
			tokenExpiry = newExpiry
			connDeadline = tokenExpiry.Add(cfg.ExpiryGrace)
			drainTimer(tokenWarnTimer)
			drainTimer(tokenDeadlineTimer)
			remaining := time.Until(connDeadline)
			if remaining > cfg.ExpiryWarning {
				tokenWarnTimer = newTimerUntil(connDeadline, cfg.ExpiryWarning)
			} else {
				// Connection deadline is shorter than the warning window.
				// Schedule the next warning at half the remaining time
				// to avoid an immediate-fire loop while still giving the
				// client a future refresh opportunity.
				tokenWarnTimer = time.NewTimer(remaining / 2)
			}
			tokenDeadlineTimer = time.NewTimer(remaining)
			logger.Info("token_refresh_accepted", slog.Time("new_expiry", connDeadline))
			enqueue(wsconn.ControlMessage{
				Type: "token_accepted",
				Data: mustMarshal(map[string]string{"expires_at": connDeadline.Format(time.RFC3339)}),
			})
		}
	}
}

// newTimerUntil returns a timer that fires warningBefore a deadline. If the
// warning time has already passed, the timer fires immediately.
func newTimerUntil(deadline time.Time, warningBefore time.Duration) *time.Timer {
	d := time.Until(deadline) - warningBefore
	if d < 0 {
		d = 0
	}
	return time.NewTimer(d)
}

// drainTimer stops a timer so it can safely be replaced. Since Go 1.23,
// Stop guarantees no stale values will be sent after it returns.
func drainTimer(t *time.Timer) {
	t.Stop()
}

func stoppedTimer() *time.Timer {
	t := time.NewTimer(0)
	t.Stop()
	return t
}

func mustMarshal(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// checkWebSocketRequest rejects requests that should never reach the
// authenticated upgrade path. This keeps protocol admission checks separate
// from bearer-token validation and makes browser-origin handling explicit.
// trustForwardedProto enables X-Forwarded-Proto and X-Forwarded-Host for
// scheme and host inference; see HandlerOptions.TrustForwardedProto.
func checkWebSocketRequest(w http.ResponseWriter, r *http.Request, trustForwardedProto bool) bool {
	if r.Method != http.MethodGet {
		loggerFromContext(r.Context()).Warn("websocket_rejected",
			slog.String("reason", "method_not_allowed"),
		)
		http.Error(w, "websocket upgrade requires GET", http.StatusMethodNotAllowed)
		return false
	}
	if !headerContainsToken(r.Header, "Connection", "upgrade") || !headerContainsToken(r.Header, "Upgrade", "websocket") {
		loggerFromContext(r.Context()).Warn("websocket_rejected",
			slog.String("reason", "upgrade_headers_missing"),
		)
		http.Error(w, "websocket upgrade required", http.StatusUpgradeRequired)
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	originURL, err := url.Parse(origin)
	if err != nil || originURL.Host == "" {
		loggerFromContext(r.Context()).Warn("websocket_rejected",
			slog.String("reason", "invalid_origin"),
			slog.String("origin", origin),
		)
		http.Error(w, "invalid origin", http.StatusForbidden)
		return false
	}
	scheme := requestScheme(r, trustForwardedProto)
	host := requestHost(r, trustForwardedProto)
	if !sameOrigin(originURL, scheme, host) {
		loggerFromContext(r.Context()).Warn("websocket_rejected",
			slog.String("reason", "cross_origin"),
			slog.String("origin", origin),
		)
		http.Error(w, "cross-origin websocket forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// CheckToken extracts the bearer token from the request and delegates
// verification to the configured validator. The caller decides which routes
// require protection and how to continue once validation succeeds.
func CheckToken(w http.ResponseWriter, r *http.Request, validator TokenValidator) bool {
	_, ok := validateRequestToken(w, r, validator)
	return ok
}

// validateRequestToken is the internal variant used by websocket routes that
// need the validated claims for downstream logging. The public CheckToken
// helper intentionally keeps the older bool-only contract for existing tests
// and handlers that only need admission control.
func validateRequestToken(w http.ResponseWriter, r *http.Request, validator TokenValidator) (*oidc.AccessTokenClaims, bool) {
	auth := r.Header.Get("authorization")
	if auth == "" {
		http.Error(w, "auth header missing", http.StatusUnauthorized)
		return nil, false
	}
	if !strings.HasPrefix(auth, oidc.PrefixBearer) {
		http.Error(w, "invalid header", http.StatusUnauthorized)
		return nil, false
	}
	if validator == nil {
		http.Error(w, "token validator unavailable", http.StatusInternalServerError)
		return nil, false
	}

	token := strings.TrimPrefix(auth, oidc.PrefixBearer)
	claims, err := validator.ValidateAccessToken(r.Context(), token)
	if err != nil {
		// Do not reflect verifier details (signature, issuer/audience mismatch,
		// expiry parsing errors, etc.) back to callers. Returning a fixed message
		// keeps the auth surface predictable while preserving diagnostics in logs.
		loggerFromContext(r.Context()).Warn("auth_failure",
			slog.String("error", err.Error()),
		)
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	// Admission requires the token to be usable right now. The small
	// skew allowance absorbs modest IdP/server clock drift; it applies
	// only at this wall-clock boundary, not at the refresh-vs-deadline
	// comparison, so it cannot silently stretch the configured
	// exp + grace policy on established tunnels.
	if err := checkTokenUsableBy(claims, time.Now().Add(tokenClockSkew)); err != nil {
		loggerFromContext(r.Context()).Warn("auth_failure",
			slog.String("error", err.Error()),
		)
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	return claims, true
}

func headerContainsToken(header http.Header, name, expected string) bool {
	for _, value := range header.Values(name) {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), expected) {
				return true
			}
		}
	}
	return false
}

func sameOrigin(originURL *url.URL, scheme, host string) bool {
	if !strings.EqualFold(originURL.Scheme, scheme) {
		return false
	}
	return strings.EqualFold(normalizeAuthority(originURL), normalizeAuthority(&url.URL{
		Scheme: scheme,
		Host:   host,
	}))
}

func requestHost(r *http.Request, trustForwardedProto bool) string {
	if trustForwardedProto {
		if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
			// X-Forwarded-Host is comma-separated in multi-proxy deployments;
			// the leftmost entry is the original client-facing host.
			if host := strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0]); host != "" {
				return host
			}
		}
	}
	return r.Host
}

func requestScheme(r *http.Request, trustForwardedProto bool) string {
	if r.TLS != nil {
		return "https"
	}
	if trustForwardedProto {
		if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
			// X-Forwarded-Proto is comma-separated in multi-proxy deployments;
			// the leftmost entry is the original client-facing scheme.
			if proto := strings.ToLower(strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0])); proto != "" {
				return proto
			}
		}
	}
	if r.URL != nil && r.URL.Scheme != "" {
		return strings.ToLower(r.URL.Scheme)
	}
	return "http"
}

func normalizeAuthority(u *url.URL) string {
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else {
		host = strings.ToLower(host)
	}

	port := u.Port()
	if port == "" {
		port = defaultPortForScheme(u.Scheme)
	}
	return net.JoinHostPort(host, port)
}

func defaultPortForScheme(scheme string) string {
	switch strings.ToLower(scheme) {
	case "https", "wss":
		return "443"
	case "http", "ws":
		return "80"
	default:
		return ""
	}
}

func allowMethods(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, method := range allowed {
		if r.Method == method {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func clearHijackedConnDeadlines(w http.ResponseWriter) http.ResponseWriter {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return w
	}
	return deadlineClearingResponseWriter{ResponseWriter: w, hijacker: hj}
}

type deadlineClearingResponseWriter struct {
	http.ResponseWriter
	hijacker http.Hijacker
}

func (w deadlineClearingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := w.hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("clear hijacked connection deadlines: %w", err)
	}
	return conn, rw, nil
}

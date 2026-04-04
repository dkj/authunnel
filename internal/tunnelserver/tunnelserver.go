// Package tunnelserver contains the reusable HTTP and token-validation logic
// for the Authunnel server. Keeping this separate from main makes the security-
// sensitive request flow easier to test without needing to boot the TLS server.
package tunnelserver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
)

type TokenValidator interface {
	ValidateAccessToken(ctx context.Context, token string) (*oidc.AccessTokenClaims, error)
}

// JWTTokenValidator validates bearer access tokens against issuer discovery and
// the issuer's JWKS, then applies an explicit audience check for the protected
// resource.
type JWTTokenValidator struct {
	audience string
	verifier *op.AccessTokenVerifier
}

// NewJWTTokenValidator performs provider discovery up front so configuration
// errors fail at startup rather than on the first protected request.
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

// ValidateAccessToken verifies signature, issuer, expiry and standard token
// claims via the Zitadel verifier, then enforces the configured resource
// audience separately so that resource identity stays explicit in Authunnel.
func (v *JWTTokenValidator) ValidateAccessToken(ctx context.Context, token string) (*oidc.AccessTokenClaims, error) {
	claims, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, token, v.verifier)
	if err != nil {
		return nil, err
	}
	if err := oidc.CheckAudience(claims, v.audience); err != nil {
		return nil, err
	}
	return claims, nil
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
}

// NewHandler installs the small HTTP surface used by the server:
//   - "/" for a simple liveness response
//   - "/protected" for token-validation smoke testing
//   - "/protected/socks" for the authenticated websocket-to-SOCKS bridge
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

	mux.HandleFunc("/protected/socks", func(w http.ResponseWriter, r *http.Request) {
		if !checkWebSocketRequest(w, r, opt.TrustForwardedProto) {
			return
		}
		claims, ok := validateRequestToken(w, r, validator)
		if !ok {
			return
		}
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
		// Carry token identity into the long-lived tunnel logger once, so tunnel
		// lifecycle and per-destination SOCKS logs do not need to re-parse or
		// re-validate bearer claims after the websocket upgrade succeeds.
		tunnelLogger = loggerWithAccessTokenClaims(tunnelLogger, claims)
		tunnelStart := time.Now()
		tunnelLogger.Info("tunnel_open")
		defer logTunnelClose(tunnelLogger, tunnelStart)
		// Wrap the upgraded websocket connection so the SOCKS layer can recover the
		// per-tunnel logger and emit destination logs with the same request/tunnel
		// correlation fields.
		if err := socks.ServeConn(newObservedTunnelConn(websocket.NetConn(r.Context(), c, websocket.MessageBinary), tunnelLogger)); err != nil {
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

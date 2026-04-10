package tunnelserver

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	socks5 "github.com/armon/go-socks5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const requestIDHeader = "X-Request-ID"

type requestMetadata struct {
	RequestID string
	TraceID   string
}

type contextKey string

const (
	loggerContextKey          contextKey = "logger"
	requestMetadataContextKey contextKey = "request-metadata"
	socksConnectContextKey    contextKey = "socks-connect"
)

type SOCKSServer interface {
	ServeConn(net.Conn) error
}

type observedSOCKSServer struct {
	stdLogger  *log.Logger
	allowRules Allowlist
}

type observedTunnelConn struct {
	net.Conn
	logger *slog.Logger
}

type socksConnectDetails struct {
	Command    string
	TargetHost string
	TargetPort int
}

func NewObservedSOCKSServer(stdLogger *log.Logger, rules Allowlist) SOCKSServer {
	return &observedSOCKSServer{stdLogger: stdLogger, allowRules: rules}
}

// newObservedTunnelConn preserves the concrete net.Conn behavior used by the
// websocket bridge while attaching the per-tunnel logger for the SOCKS layer.
func newObservedTunnelConn(conn net.Conn, logger *slog.Logger) net.Conn {
	return &observedTunnelConn{Conn: conn, logger: logger}
}

func (c *observedTunnelConn) TunnelLogger() *slog.Logger {
	return c.logger
}

// NewRequestLoggingMiddleware wraps an HTTP handler with structured logging and
// correlation ID management. Three IDs are used to correlate log events:
//
//   - request_id: generated fresh for every HTTP request. Scoped to a single
//     request/response cycle and returned to the client in the X-Request-ID
//     response header.
//   - trace_id: extracted from an incoming Traceparent header (W3C Trace
//     Context) when present, otherwise generated. This allows Authunnel logs
//     to correlate with upstream infrastructure such as a load balancer or
//     reverse proxy that is already assigning trace IDs.
//   - tunnel_id: generated later, when a WebSocket upgrade succeeds and a
//     SOCKS tunnel is established (see Handler). It is added to a child logger
//     that inherits request_id and trace_id, so all tunnel lifecycle events
//     (open, SOCKS CONNECT, close) carry all three IDs.
//
// For a /protected/socks request the relationship is 1:1 — one HTTP request
// produces one tunnel. The IDs serve different scopes: request_id is for HTTP
// admission, trace_id is for cross-system tracing, and tunnel_id is for the
// long-lived tunnel session and its per-destination SOCKS events.
func NewRequestLoggingMiddleware(baseLogger *slog.Logger, next http.Handler) http.Handler {
	if baseLogger == nil {
		baseLogger = slog.Default()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata := requestMetadata{
			RequestID: newLogID(),
			TraceID:   requestTraceID(r),
		}
		w.Header().Set(requestIDHeader, metadata.RequestID)

		logger := baseLogger.With(
			slog.String("request_id", metadata.RequestID),
			slog.String("trace_id", metadata.TraceID),
		)
		ctx := context.WithValue(r.Context(), loggerContextKey, logger)
		ctx = context.WithValue(ctx, requestMetadataContextKey, metadata)
		r = r.WithContext(ctx)

		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(recorder, r)

		logger.Info("http_request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", recorder.status),
			slog.Int("bytes", recorder.bytes),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			slog.String("remote_ip", requestRemoteIP(r)),
			slog.String("user_agent", r.UserAgent()),
		)
	})
}

func loggerFromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerContextKey).(*slog.Logger); ok && logger != nil {
		return logger
	}
	return slog.Default()
}

func requestMetadataFromContext(ctx context.Context) requestMetadata {
	if metadata, ok := ctx.Value(requestMetadataContextKey).(requestMetadata); ok {
		return metadata
	}
	return requestMetadata{}
}

func newLogID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return hex.EncodeToString(buf[:])
	}
	return fmt.Sprintf("%016x", time.Now().UnixNano())
}

func requestTraceID(r *http.Request) string {
	if traceID := parseTraceparentTraceID(r.Header.Get("Traceparent")); traceID != "" {
		return traceID
	}
	return newLogID()
}

func parseTraceparentTraceID(value string) string {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) != 4 {
		return ""
	}
	if len(parts[1]) != 32 || !isLowerHex(parts[1]) || parts[1] == strings.Repeat("0", 32) {
		return ""
	}
	return parts[1]
}

func isLowerHex(value string) bool {
	for _, ch := range value {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		default:
			return false
		}
	}
	return true
}

func requestRemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusRecorder) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

func (w *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}

// ServeConn builds a fresh SOCKS5 server per websocket tunnel so its Rules and
// Dial hooks can close over the tunnel-scoped logger. The upstream library only
// exposes destination details during request handling, so this wrapper is the
// narrowest place to correlate CONNECT logs with the authenticated user.
func (s *observedSOCKSServer) ServeConn(conn net.Conn) error {
	logger := slog.Default()
	if observed, ok := conn.(interface{ TunnelLogger() *slog.Logger }); ok && observed.TunnelLogger() != nil {
		logger = observed.TunnelLogger()
	}

	server, err := socks5.New(&socks5.Config{
		Logger: s.stdLogger,
		Rules:  observedSOCKSRuleSet{logger: logger, allowRules: s.allowRules},
		Dial:   observedSOCKSDial(logger),
	})
	if err != nil {
		return fmt.Errorf("create observed socks5 server: %w", err)
	}
	return server.ServeConn(conn)
}

type observedSOCKSRuleSet struct {
	logger     *slog.Logger
	allowRules Allowlist
}

func (r observedSOCKSRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	if req == nil || req.DestAddr == nil {
		return ctx, true
	}
	logger := r.logger
	if logger == nil {
		logger = slog.Default()
	}

	details := socksConnectDetails{
		Command:    socksCommandName(req.Command),
		TargetHost: socksDestinationHost(req.DestAddr),
		TargetPort: req.DestAddr.Port,
	}
	// The SOCKS library threads the returned context into its dial path. Store
	// the parsed destination once here so the later Dial hook can log both the
	// requested host/port and the concrete upstream address that was attempted.
	if req.Command == socks5.ConnectCommand {
		logger.Debug("socks_connect_requested",
			slog.String("target_host", details.TargetHost),
			slog.Int("target_port", details.TargetPort),
		)
	}
	// Security decision: apply operator-configured allowlist.
	// Empty allowlist = open mode (allow all). Non-empty = deny unless a rule matches.
	// Pass the raw FQDN and IP separately so CIDR rules and hostname-glob rules
	// are evaluated independently — details.TargetHost collapses the two.
	if !r.allowRules.Permits(req.DestAddr.FQDN, req.DestAddr.IP, req.DestAddr.Port) {
		logger.Warn("socks_connect_denied",
			slog.String("target_host", details.TargetHost),
			slog.Int("target_port", details.TargetPort),
		)
		return ctx, false
	}
	return context.WithValue(ctx, socksConnectContextKey, details), true
}

func observedSOCKSDial(logger *slog.Logger) func(context.Context, string, string) (net.Conn, error) {
	if logger == nil {
		logger = slog.Default()
	}
	dialer := net.Dialer{}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		details := socksConnectDetailsFromContext(ctx)
		logAttrs := []slog.Attr{
			slog.String("network", network),
			slog.String("upstream_addr", addr),
		}
		// Preserve the original host/port requested by the client even when the
		// SOCKS resolver has already converted it into an IP-based dial target.
		if details.TargetHost != "" {
			logAttrs = append(logAttrs,
				slog.String("target_host", details.TargetHost),
				slog.Int("target_port", details.TargetPort),
			)
		}

		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			logger.LogAttrs(ctx, slog.LevelDebug, "socks_connect_failed",
				append(logAttrs, slog.String("error", err.Error()))...,
			)
			return nil, err
		}

		logger.LogAttrs(ctx, slog.LevelDebug, "socks_connect_succeeded", logAttrs...)
		return conn, nil
	}
}

func socksConnectDetailsFromContext(ctx context.Context) socksConnectDetails {
	if details, ok := ctx.Value(socksConnectContextKey).(socksConnectDetails); ok {
		return details
	}
	return socksConnectDetails{}
}

func loggerWithAccessTokenClaims(logger *slog.Logger, claims *oidc.AccessTokenClaims) *slog.Logger {
	if logger == nil {
		logger = slog.Default()
	}
	if claims == nil {
		return logger
	}

	attrs := make([]slog.Attr, 0, 4)
	if user := accessTokenUser(claims); user != "" {
		attrs = append(attrs, slog.String("user", user))
	}
	if email := accessTokenEmail(claims); email != "" {
		attrs = append(attrs, slog.String("email", email))
	}
	if claims.Subject != "" {
		attrs = append(attrs, slog.String("subject", claims.Subject))
	}
	if claims.ClientID != "" {
		attrs = append(attrs, slog.String("client_id", claims.ClientID))
	}
	if len(attrs) == 0 {
		return logger
	}
	return logger.With(slogAttrsToArgs(attrs)...)
}

// accessTokenUser prefers a human-meaningful identifier when the provider
// includes one, but falls back to subject so logs still contain a stable
// principal identifier for providers that emit only the standard claims set.
func accessTokenUser(claims *oidc.AccessTokenClaims) string {
	if claims == nil {
		return ""
	}
	for _, key := range []string{"preferred_username", "username"} {
		if value, ok := claims.Claims[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	if email := accessTokenEmail(claims); email != "" {
		return email
	}
	return claims.Subject
}

// accessTokenEmail keeps email logging explicit instead of overloading the
// generic user field, so operators can filter for either identifier.
func accessTokenEmail(claims *oidc.AccessTokenClaims) string {
	if claims == nil {
		return ""
	}
	if value, ok := claims.Claims["email"].(string); ok && strings.TrimSpace(value) != "" {
		return value
	}
	return ""
}

func socksDestinationHost(addr *socks5.AddrSpec) string {
	if addr == nil {
		return ""
	}
	if addr.FQDN != "" {
		return addr.FQDN
	}
	return addr.IP.String()
}

func socksCommandName(command uint8) string {
	switch command {
	case socks5.ConnectCommand:
		return "connect"
	case socks5.BindCommand:
		return "bind"
	case socks5.AssociateCommand:
		return "associate"
	default:
		return "unknown"
	}
}

func slogAttrsToArgs(attrs []slog.Attr) []any {
	args := make([]any, 0, len(attrs))
	for _, attr := range attrs {
		args = append(args, attr)
	}
	return args
}

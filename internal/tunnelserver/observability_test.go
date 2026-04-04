package tunnelserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	socks5 "github.com/armon/go-socks5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestRequestLoggingMiddlewareAddsRequestIDAndLogsTraceID(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	handler := NewRequestLoggingMiddleware(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.RemoteAddr = "203.0.113.7:12345"
	req.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	req.Header.Set("User-Agent", "authunnel-test")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	requestID := rr.Header().Get(requestIDHeader)
	if requestID == "" {
		t.Fatal("expected request ID header to be set")
	}

	entry := parseLastLogEntry(t, logBuf.String())
	if got := entry["msg"]; got != "http_request" {
		t.Fatalf("unexpected log message: got %#v", got)
	}
	if got := entry["request_id"]; got != requestID {
		t.Fatalf("unexpected request_id: got %#v want %q", got, requestID)
	}
	if got := entry["trace_id"]; got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("unexpected trace_id: got %#v", got)
	}
	if got := entry["status"]; got != float64(http.StatusCreated) {
		t.Fatalf("unexpected status: got %#v", got)
	}
	if got := entry["path"]; got != "/health" {
		t.Fatalf("unexpected path: got %#v", got)
	}
}

func TestCheckTokenLogsAuthFailureWithRequestID(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	handler := NewRequestLoggingMiddleware(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		CheckToken(w, r, staticFailValidator{err: errors.New("signature mismatch")})
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("unexpected status: got %d want %d", rr.Code, http.StatusForbidden)
	}

	requestID := rr.Header().Get(requestIDHeader)
	if requestID == "" {
		t.Fatal("expected request ID header to be set")
	}

	entry := parseLogEntryByMessage(t, logBuf.String(), "auth_failure")
	if got := entry["request_id"]; got != requestID {
		t.Fatalf("unexpected request_id: got %#v want %q", got, requestID)
	}
	if got := entry["error"]; got != "signature mismatch" {
		t.Fatalf("unexpected error: got %#v", got)
	}
	if got := entry["trace_id"]; got == "" {
		t.Fatalf("expected trace_id to be present, got %#v", got)
	}
}

func TestRequestLoggingMiddlewarePreservesHijacker(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	handler := NewRequestLoggingMiddleware(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("wrapped response writer does not implement http.Hijacker")
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		_ = conn.Close()
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected/socks", nil)
	req.RemoteAddr = "203.0.113.8:23456"
	rr := fakeHijackResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             serverConn,
		rw:               bufio.NewReadWriter(bufio.NewReader(serverConn), bufio.NewWriter(serverConn)),
	}

	handler.ServeHTTP(rr, req)
}

func TestLogTunnelCloseEvaluatesDurationWhenDeferredFunctionRuns(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))

	started := time.Now()
	time.Sleep(15 * time.Millisecond)
	logTunnelClose(logger, started)

	entry := parseLogEntryByMessage(t, logBuf.String(), "tunnel_close")
	duration, ok := entry["duration_ms"].(float64)
	if !ok {
		t.Fatalf("unexpected duration_ms type: got %#v", entry["duration_ms"])
	}
	if duration < 10 {
		t.Fatalf("expected duration_ms to reflect elapsed time, got %v", duration)
	}
}

func TestLoggerWithAccessTokenClaimsAddsUserIdentity(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	logger = loggerWithAccessTokenClaims(logger, &oidc.AccessTokenClaims{
		TokenClaims: oidc.TokenClaims{
			Subject:  "user-123",
			ClientID: "authunnel-cli",
		},
		Claims: map[string]any{
			"preferred_username": "dev-user",
			"email":              "dev-user@example.com",
		},
	})

	logger.Info("tunnel_open")

	entry := parseLogEntryByMessage(t, logBuf.String(), "tunnel_open")
	if got := entry["user"]; got != "dev-user" {
		t.Fatalf("unexpected user: got %#v", got)
	}
	if got := entry["email"]; got != "dev-user@example.com" {
		t.Fatalf("unexpected email: got %#v", got)
	}
	if got := entry["subject"]; got != "user-123" {
		t.Fatalf("unexpected subject: got %#v", got)
	}
	if got := entry["client_id"]; got != "authunnel-cli" {
		t.Fatalf("unexpected client_id: got %#v", got)
	}
}

func TestObservedSOCKSRuleSetLogsRequestedDestinationAtDebug(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctx, ok := observedSOCKSRuleSet{logger: logger}.Allow(context.Background(), &socks5.Request{
		Command: socks5.ConnectCommand,
		DestAddr: &socks5.AddrSpec{
			FQDN: "db.internal",
			Port: 5432,
		},
	})
	if !ok {
		t.Fatal("expected CONNECT request to be allowed")
	}

	details := socksConnectDetailsFromContext(ctx)
	if details.TargetHost != "db.internal" {
		t.Fatalf("unexpected target host: got %q", details.TargetHost)
	}
	if details.TargetPort != 5432 {
		t.Fatalf("unexpected target port: got %d", details.TargetPort)
	}

	entry := parseLogEntryByMessage(t, logBuf.String(), "socks_connect_requested")
	if got := entry["target_host"]; got != "db.internal" {
		t.Fatalf("unexpected target_host: got %#v", got)
	}
	if got := entry["target_port"]; got != float64(5432) {
		t.Fatalf("unexpected target_port: got %#v", got)
	}
}

func TestObservedSOCKSRuleSetDeniesConnectionNotMatchingAllowlist(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	rule, err := ParseAllowRule("*.internal:22")
	if err != nil {
		t.Fatalf("ParseAllowRule: %v", err)
	}
	ruleset := observedSOCKSRuleSet{
		logger:     logger,
		allowRules: Allowlist{rule},
	}

	_, ok := ruleset.Allow(context.Background(), &socks5.Request{
		Command: socks5.ConnectCommand,
		DestAddr: &socks5.AddrSpec{
			FQDN: "evil.external",
			Port: 22,
		},
	})
	if ok {
		t.Fatal("expected connection to evil.external to be denied")
	}

	entry := parseLogEntryByMessage(t, logBuf.String(), "socks_connect_denied")
	if got := entry["target_host"]; got != "evil.external" {
		t.Fatalf("unexpected target_host in deny log: got %#v", got)
	}
	if got := entry["level"]; got != "WARN" {
		t.Fatalf("expected warn level, got %#v", got)
	}
}

func TestObservedSOCKSRuleSetAllowsConnectionMatchingAllowlist(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	rule, err := ParseAllowRule("*.internal:22")
	if err != nil {
		t.Fatalf("ParseAllowRule: %v", err)
	}
	ruleset := observedSOCKSRuleSet{
		logger:     logger,
		allowRules: Allowlist{rule},
	}

	_, ok := ruleset.Allow(context.Background(), &socks5.Request{
		Command: socks5.ConnectCommand,
		DestAddr: &socks5.AddrSpec{
			FQDN: "db.internal",
			Port: 22,
		},
	})
	if !ok {
		t.Fatal("expected connection to db.internal:22 to be allowed")
	}
}

type staticFailValidator struct {
	err error
}

func (v staticFailValidator) ValidateAccessToken(context.Context, string) (*oidc.AccessTokenClaims, error) {
	return nil, v.err
}

func parseLastLogEntry(t *testing.T, logs string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(logs), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("expected at least one log line")
	}
	return parseLogLine(t, lines[len(lines)-1])
}

func parseLogEntryByMessage(t *testing.T, logs, msg string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		entry := parseLogLine(t, line)
		if entry["msg"] == msg {
			return entry
		}
	}
	t.Fatalf("did not find log entry with msg=%q in logs %q", msg, logs)
	return nil
}

func parseLogLine(t *testing.T, line string) map[string]any {
	t.Helper()
	var entry map[string]any
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("parse log line %q: %v", line, err)
	}
	return entry
}

package tunnelserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"authunnel/internal/wsconn"
)

// mockValidator is a test double for TokenValidator that returns preconfigured
// claims keyed by token string.
type mockValidator struct {
	tokens map[string]*oidc.AccessTokenClaims
}

func (m *mockValidator) ValidateAccessToken(_ context.Context, token string) (*oidc.AccessTokenClaims, error) {
	if c, ok := m.tokens[token]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// wsPair creates a connected pair of MultiplexConns over a real WebSocket.
func wsPair(t *testing.T) (server *wsconn.MultiplexConn, client *wsconn.MultiplexConn) {
	t.Helper()
	serverReady := make(chan *wsconn.MultiplexConn, 1)
	serverCtx, serverCancel := context.WithCancel(context.Background())

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on IPv4 loopback: %v", err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("server websocket accept: %v", err)
			return
		}
		mc := wsconn.New(serverCtx, c)
		serverReady <- mc
		<-serverCtx.Done()
	}))
	ts.Listener = ln
	ts.Start()
	t.Cleanup(func() {
		serverCancel()
		ts.Close()
	})

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	c, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("client websocket dial: %v", err)
	}
	clientConn := wsconn.New(context.Background(), c)
	t.Cleanup(func() { clientConn.Close() })

	select {
	case sc := <-serverReady:
		return sc, clientConn
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server connection")
		return nil, nil
	}
}

// readControl reads from the client-side control channel, driving Read() in
// the background so text frames are dispatched.
func readControl(t *testing.T, client *wsconn.MultiplexConn, timeout time.Duration) (wsconn.ControlMessage, bool) {
	t.Helper()
	select {
	case msg := <-client.ControlChan():
		return msg, true
	case <-time.After(timeout):
		return wsconn.ControlMessage{}, false
	}
}

// drainBinary runs a background reader on conn so that text frames are
// dispatched to the control channel.
func drainBinary(t *testing.T, conn *wsconn.MultiplexConn) {
	t.Helper()
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()
}

func makeClaims(subject string, expiry time.Time) *oidc.AccessTokenClaims {
	return &oidc.AccessTokenClaims{
		TokenClaims: oidc.TokenClaims{
			Subject:    subject,
			Expiration: oidc.FromTime(expiry),
		},
	}
}

func TestTokenRefreshAccepted(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)

	originalExpiry := time.Now().Add(2 * time.Second)
	newExpiry := time.Now().Add(1 * time.Hour)
	claims := makeClaims("user-1", originalExpiry)

	validator := &mockValidator{
		tokens: map[string]*oidc.AccessTokenClaims{
			"fresh-token": makeClaims("user-1", newExpiry),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go manageTunnelLongevity(ctx, cancel, serverConn, validator, claims, LongevityConfig{
		ImplementsExpiry: true,
		ExpiryWarning:    1 * time.Second,
	}, time.Now(), slog.Default())

	// Drive server-side reads so it can receive control messages.
	drainBinary(t, serverConn)

	// Wait for the expiry warning before refreshing.
	msg, ok := readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for expiry_warning")
	}
	if msg.Type != "expiry_warning" {
		t.Fatalf("expected expiry_warning, got %s", msg.Type)
	}

	// Send a refresh.
	err := clientConn.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: mustMarshal(map[string]string{"access_token": "fresh-token"}),
	})
	if err != nil {
		t.Fatalf("send token_refresh: %v", err)
	}

	msg, ok = readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for token_accepted")
	}
	if msg.Type != "token_accepted" {
		t.Fatalf("expected token_accepted, got %s", msg.Type)
	}
	var data map[string]string
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		t.Fatalf("unmarshal token_accepted data: %v", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, data["expires_at"])
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	// The new expiry should be close to what we set (within a second of tolerance).
	if diff := newExpiry.Sub(expiresAt).Abs(); diff > time.Second {
		t.Fatalf("expires_at %v differs from expected %v by %v", expiresAt, newExpiry, diff)
	}

	// The tunnel should NOT be disconnected within 2.5s (the original expiry
	// would have fired by now without the refresh).
	time.Sleep(2500 * time.Millisecond)
	select {
	case <-ctx.Done():
		t.Fatal("tunnel was closed despite successful token refresh")
	default:
		// Good — still alive.
	}
}

func TestTokenRefreshRejectedInvalidToken(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	claims := makeClaims("user-1", time.Now().Add(10*time.Minute))
	validator := &mockValidator{tokens: map[string]*oidc.AccessTokenClaims{}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go manageTunnelLongevity(ctx, cancel, serverConn, validator, claims, LongevityConfig{
		ImplementsExpiry: true,
		ExpiryWarning:    time.Minute,
	}, time.Now(), slog.Default())

	// Send a refresh with a token the validator doesn't recognise.
	err := clientConn.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: mustMarshal(map[string]string{"access_token": "bogus-token"}),
	})
	if err != nil {
		t.Fatalf("send token_refresh: %v", err)
	}

	msg, ok := readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for token_rejected")
	}
	if msg.Type != "token_rejected" {
		t.Fatalf("expected token_rejected, got %s", msg.Type)
	}
	var data map[string]string
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if data["reason"] != "validation_failed" {
		t.Fatalf("expected reason validation_failed, got %s", data["reason"])
	}
}

func TestTokenRefreshRejectedSubjectMismatch(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	claims := makeClaims("user-1", time.Now().Add(10*time.Minute))
	validator := &mockValidator{
		tokens: map[string]*oidc.AccessTokenClaims{
			"other-user-token": makeClaims("user-2", time.Now().Add(1*time.Hour)),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go manageTunnelLongevity(ctx, cancel, serverConn, validator, claims, LongevityConfig{
		ImplementsExpiry: true,
		ExpiryWarning:    time.Minute,
	}, time.Now(), slog.Default())

	err := clientConn.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: mustMarshal(map[string]string{"access_token": "other-user-token"}),
	})
	if err != nil {
		t.Fatalf("send token_refresh: %v", err)
	}

	msg, ok := readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for token_rejected")
	}
	if msg.Type != "token_rejected" {
		t.Fatalf("expected token_rejected, got %s", msg.Type)
	}
	var data map[string]string
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if data["reason"] != "subject_mismatch" {
		t.Fatalf("expected reason subject_mismatch, got %s", data["reason"])
	}
}

func TestTokenRefreshRejectedEmptyPayload(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	claims := makeClaims("user-1", time.Now().Add(10*time.Minute))
	validator := &mockValidator{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go manageTunnelLongevity(ctx, cancel, serverConn, validator, claims, LongevityConfig{
		ImplementsExpiry: true,
		ExpiryWarning:    time.Minute,
	}, time.Now(), slog.Default())

	// Send refresh with empty access_token.
	err := clientConn.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: mustMarshal(map[string]string{"access_token": ""}),
	})
	if err != nil {
		t.Fatalf("send token_refresh: %v", err)
	}

	msg, ok := readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for token_rejected")
	}
	if msg.Type != "token_rejected" {
		t.Fatalf("expected token_rejected, got %s", msg.Type)
	}
	var data map[string]string
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if data["reason"] != "invalid_payload" {
		t.Fatalf("expected reason invalid_payload, got %s", data["reason"])
	}
}

func TestTokenRefreshRejectedWhenExpiryNotEnforced(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	claims := makeClaims("user-1", time.Now().Add(10*time.Minute))
	validator := &mockValidator{
		tokens: map[string]*oidc.AccessTokenClaims{
			"fresh-token": makeClaims("user-1", time.Now().Add(1*time.Hour)),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ImplementsExpiry is false but MaxDuration is set — refresh should be rejected.
	go manageTunnelLongevity(ctx, cancel, serverConn, validator, claims, LongevityConfig{
		MaxDuration:      10 * time.Minute,
		ImplementsExpiry: false,
		ExpiryWarning:    time.Minute,
	}, time.Now(), slog.Default())

	err := clientConn.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: mustMarshal(map[string]string{"access_token": "fresh-token"}),
	})
	if err != nil {
		t.Fatalf("send token_refresh: %v", err)
	}

	msg, ok := readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for token_rejected")
	}
	if msg.Type != "token_rejected" {
		t.Fatalf("expected token_rejected, got %s", msg.Type)
	}
	var data map[string]string
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if data["reason"] != "token_expiry_not_enforced" {
		t.Fatalf("expected reason token_expiry_not_enforced, got %s", data["reason"])
	}
}

func TestTokenRefreshRejectedExpiryNotExtended(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	sameExpiry := time.Now().Add(10 * time.Minute)
	claims := makeClaims("user-1", sameExpiry)
	validator := &mockValidator{
		tokens: map[string]*oidc.AccessTokenClaims{
			// Refreshed token has the same expiry — should be rejected.
			"same-exp-token":    makeClaims("user-1", sameExpiry),
			"earlier-exp-token": makeClaims("user-1", sameExpiry.Add(-time.Minute)),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go manageTunnelLongevity(ctx, cancel, serverConn, validator, claims, LongevityConfig{
		ImplementsExpiry: true,
		ExpiryWarning:    time.Minute,
	}, time.Now(), slog.Default())

	// Refresh with same expiry.
	err := clientConn.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: mustMarshal(map[string]string{"access_token": "same-exp-token"}),
	})
	if err != nil {
		t.Fatalf("send token_refresh: %v", err)
	}

	msg, ok := readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for token_rejected (same expiry)")
	}
	if msg.Type != "token_rejected" {
		t.Fatalf("expected token_rejected, got %s", msg.Type)
	}
	var data map[string]string
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if data["reason"] != "expiry_not_extended" {
		t.Fatalf("expected reason expiry_not_extended, got %s", data["reason"])
	}

	// Refresh with earlier expiry.
	err = clientConn.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: mustMarshal(map[string]string{"access_token": "earlier-exp-token"}),
	})
	if err != nil {
		t.Fatalf("send token_refresh: %v", err)
	}

	msg, ok = readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for token_rejected (earlier expiry)")
	}
	if msg.Type != "token_rejected" {
		t.Fatalf("expected token_rejected, got %s", msg.Type)
	}
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if data["reason"] != "expiry_not_extended" {
		t.Fatalf("expected reason expiry_not_extended, got %s", data["reason"])
	}
}

func TestTokenRefreshRejectedMalformedJSON(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	claims := makeClaims("user-1", time.Now().Add(10*time.Minute))
	validator := &mockValidator{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go manageTunnelLongevity(ctx, cancel, serverConn, validator, claims, LongevityConfig{
		ImplementsExpiry: true,
		ExpiryWarning:    time.Minute,
	}, time.Now(), slog.Default())

	// Send a token_refresh whose Data is not valid JSON for the expected
	// struct (it's a JSON string instead of an object with access_token).
	err := clientConn.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: json.RawMessage(`"not an object"`),
	})
	if err != nil {
		t.Fatalf("send token_refresh: %v", err)
	}

	msg, ok := readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for token_rejected")
	}
	if msg.Type != "token_rejected" {
		t.Fatalf("expected token_rejected, got %s", msg.Type)
	}
	var data map[string]string
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if data["reason"] != "invalid_payload" {
		t.Fatalf("expected reason invalid_payload, got %s", data["reason"])
	}
}

// TestTokenRefreshResetsDeadlineTimer verifies that after a successful refresh,
// the old token-expiry deadline does not fire. The original token expires very
// soon; a refresh extends it far into the future. The test asserts the tunnel
// survives well past the original deadline.
func TestTokenRefreshResetsDeadlineTimer(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	// Original token expires in 1.5s; refreshed token expires in 1h.
	originalExpiry := time.Now().Add(1500 * time.Millisecond)
	refreshedExpiry := time.Now().Add(1 * time.Hour)

	claims := makeClaims("user-1", originalExpiry)
	validator := &mockValidator{
		tokens: map[string]*oidc.AccessTokenClaims{
			"fresh-token": makeClaims("user-1", refreshedExpiry),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go manageTunnelLongevity(ctx, cancel, serverConn, validator, claims, LongevityConfig{
		ImplementsExpiry: true,
		ExpiryWarning:    500 * time.Millisecond,
	}, time.Now(), slog.Default())

	// Send refresh immediately — before the warning or deadline can fire.
	err := clientConn.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: mustMarshal(map[string]string{"access_token": "fresh-token"}),
	})
	if err != nil {
		t.Fatalf("send token_refresh: %v", err)
	}

	// Wait for token_accepted, skipping any expiry_warning that may arrive
	// in the race window.
	deadline := time.After(3 * time.Second)
	accepted := false
	for !accepted {
		select {
		case msg := <-clientConn.ControlChan():
			if msg.Type == "token_accepted" {
				accepted = true
			} else if msg.Type == "disconnect" {
				t.Fatal("received disconnect before token_accepted")
			}
			// Skip expiry_warning or other messages.
		case <-deadline:
			t.Fatal("timed out waiting for token_accepted")
		}
	}

	// Sleep well past the original 1.5s expiry. If drainTimer didn't work,
	// the old deadline would fire and cancel the context.
	time.Sleep(2 * time.Second)

	select {
	case <-ctx.Done():
		t.Fatal("tunnel was closed — old deadline timer was not properly replaced")
	default:
		// Good — the refresh successfully replaced the deadline timer.
	}

	// Also verify no disconnect message was sent to the client.
	select {
	case stray := <-clientConn.ControlChan():
		if stray.Type == "disconnect" {
			t.Fatal("received unexpected disconnect after successful refresh")
		}
	default:
	}
}

// TestTokenRefreshDefersWarningWhenInsideWarningWindow verifies that after
// a successful refresh where the new token's lifetime is shorter than the
// warning window, the server schedules the next warning at half the remaining
// lifetime (not immediately, which would create a tight loop) and the client
// still gets a future chance to refresh.
func TestTokenRefreshDefersWarningWhenInsideWarningWindow(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	// Token lifetime (2s) < ExpiryWarning (5s). The warning fires immediately
	// at startup.
	originalExpiry := time.Now().Add(2 * time.Second)
	// Refreshed token also has a short lifetime — still shorter than the warning.
	refreshedExpiry := time.Now().Add(4 * time.Second)

	claims := makeClaims("user-1", originalExpiry)
	validator := &mockValidator{
		tokens: map[string]*oidc.AccessTokenClaims{
			"fresh-token": makeClaims("user-1", refreshedExpiry),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go manageTunnelLongevity(ctx, cancel, serverConn, validator, claims, LongevityConfig{
		ImplementsExpiry: true,
		ExpiryWarning:    5 * time.Second,
	}, time.Now(), slog.Default())

	// The initial warning fires immediately (lifetime < warning window).
	msg, ok := readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for initial expiry_warning")
	}
	if msg.Type != "expiry_warning" {
		t.Fatalf("expected expiry_warning, got %s", msg.Type)
	}

	// Refresh the token.
	err := clientConn.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: mustMarshal(map[string]string{"access_token": "fresh-token"}),
	})
	if err != nil {
		t.Fatalf("send token_refresh: %v", err)
	}

	// Expect token_accepted.
	msg, ok = readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for token_accepted")
	}
	if msg.Type != "token_accepted" {
		t.Fatalf("expected token_accepted, got %s", msg.Type)
	}

	// The refreshed token's remaining lifetime (~2s) is less than
	// ExpiryWarning (5s). The next warning should fire at remaining/2 (~1s),
	// NOT immediately. Verify: no warning within 200ms (rules out immediate
	// fire), but a warning does arrive before the deadline.
	select {
	case stray := <-clientConn.ControlChan():
		if stray.Type == "expiry_warning" {
			t.Fatal("received immediate expiry_warning after refresh — warning loop not deferred")
		}
	case <-time.After(200 * time.Millisecond):
		// Good — no immediate warning.
	}

	// A deferred warning should still arrive, giving the client another
	// refresh opportunity.
	msg, ok = readControl(t, clientConn, 3*time.Second)
	if !ok {
		t.Fatal("timed out waiting for deferred expiry_warning — client lost future refresh opportunity")
	}
	if msg.Type != "expiry_warning" {
		// A disconnect is also acceptable if the deadline beat the warning.
		if msg.Type != "disconnect" {
			t.Fatalf("expected deferred expiry_warning or disconnect, got %s", msg.Type)
		}
	}
}

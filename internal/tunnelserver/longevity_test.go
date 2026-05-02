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

// TestTokenRefreshAcceptedFutureNbfWithinDeadline verifies that a refresh
// carrying a token whose nbf is in the future is accepted as long as the
// token activates before the current connection deadline. The old token
// keeps the tunnel authenticated until nbf arrives, so there is no
// unauthenticated interval.
func TestTokenRefreshAcceptedFutureNbfWithinDeadline(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	// Original token: the tunnel's initial authorisation window.
	originalExpiry := time.Now().Add(3 * time.Second)
	claims := makeClaims("user-1", originalExpiry)

	// Refresh token: nbf 1s in the future (still inside the original
	// deadline), exp far in the future. connDeadline after refresh should
	// jump to the new exp.
	newNbf := time.Now().Add(1 * time.Second)
	newExpiry := time.Now().Add(1 * time.Hour)
	newClaims := makeClaims("user-1", newExpiry)
	newClaims.NotBefore = oidc.FromTime(newNbf)

	validator := &mockValidator{
		tokens: map[string]*oidc.AccessTokenClaims{
			"fresh-token": newClaims,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go manageTunnelLongevity(ctx, cancel, serverConn, validator, claims, LongevityConfig{
		ImplementsExpiry: true,
		ExpiryWarning:    500 * time.Millisecond,
	}, time.Now(), slog.Default())

	err := clientConn.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: mustMarshal(map[string]string{"access_token": "fresh-token"}),
	})
	if err != nil {
		t.Fatalf("send token_refresh: %v", err)
	}

	// Drain any concurrent expiry_warning that may have raced the refresh.
	var msg wsconn.ControlMessage
	for i := 0; i < 3; i++ {
		m, ok := readControl(t, clientConn, 2*time.Second)
		if !ok {
			t.Fatal("timed out waiting for token_accepted")
		}
		if m.Type == "token_accepted" {
			msg = m
			break
		}
	}
	if msg.Type != "token_accepted" {
		t.Fatalf("expected token_accepted, got %s", msg.Type)
	}

	// The tunnel should still be alive past the original 3s expiry.
	time.Sleep(3500 * time.Millisecond)
	select {
	case <-ctx.Done():
		t.Fatal("tunnel was closed despite refresh with future-nbf token within deadline")
	default:
	}
}

// TestTokenRefreshRejectedNbfAfterDeadline verifies that a refresh carrying
// a token whose nbf is past the current connection deadline is rejected —
// accepting it would leave the tunnel unauthenticated between the old
// token's expiry and the new token's activation.
func TestTokenRefreshRejectedNbfAfterDeadline(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	claims := makeClaims("user-1", time.Now().Add(10*time.Minute))

	// Refresh token activates an hour from now — far past the current
	// connection deadline of ~10 minutes, so there would be an auth gap.
	newNbf := time.Now().Add(1 * time.Hour)
	newExpiry := time.Now().Add(2 * time.Hour)
	newClaims := makeClaims("user-1", newExpiry)
	newClaims.NotBefore = oidc.FromTime(newNbf)

	validator := &mockValidator{
		tokens: map[string]*oidc.AccessTokenClaims{
			"future-token": newClaims,
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
		Data: mustMarshal(map[string]string{"access_token": "future-token"}),
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
	if data["reason"] != "not_yet_valid" {
		t.Fatalf("expected reason not_yet_valid, got %s", data["reason"])
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

// TestTokenRefreshSameExpiryBeforeWarningKeepsTimer verifies that a proactive
// same-expiry refresh that arrives before the warning window does NOT pull the
// warning timer forward. With exp far away and warning=2s, a same-exp refresh
// at T+0 should leave the warning timer at its original schedule, not halve it.
func TestTokenRefreshSameExpiryBeforeWarningKeepsTimer(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	// Token expires in 10s, warning at 2s before deadline → warning at T+8s.
	sameExpiry := time.Now().Add(10 * time.Second)
	claims := makeClaims("user-1", sameExpiry)
	validator := &mockValidator{
		tokens: map[string]*oidc.AccessTokenClaims{
			"cached-token": makeClaims("user-1", sameExpiry),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go manageTunnelLongevity(ctx, cancel, serverConn, validator, claims, LongevityConfig{
		ImplementsExpiry: true,
		ExpiryWarning:    2 * time.Second,
	}, time.Now(), slog.Default())

	// Send a proactive same-expiry refresh immediately (well before warning window).
	err := clientConn.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: mustMarshal(map[string]string{"access_token": "cached-token"}),
	})
	if err != nil {
		t.Fatalf("send token_refresh: %v", err)
	}

	msg, ok := readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for token_accepted")
	}
	if msg.Type != "token_accepted" {
		t.Fatalf("expected token_accepted, got %s", msg.Type)
	}

	// The warning timer should still be at its original schedule (~T+8s).
	// If the bug exists, it would be rescheduled to remaining/2 (~T+5s)
	// and fire within 6s. Assert no warning arrives within 6s.
	select {
	case stray := <-clientConn.ControlChan():
		if stray.Type == "expiry_warning" {
			t.Fatal("warning timer was pulled forward by proactive same-expiry refresh")
		}
		t.Fatalf("unexpected control message: %s", stray.Type)
	case <-time.After(6 * time.Second):
		// Good — no premature warning. Original timer is intact.
	}

	// The warning should still arrive around T+8s (within 4 more seconds).
	msg, ok = readControl(t, clientConn, 4*time.Second)
	if !ok {
		t.Fatal("timed out waiting for the original expiry_warning — timer was lost")
	}
	if msg.Type != "expiry_warning" {
		t.Fatalf("expected expiry_warning, got %s", msg.Type)
	}
}

// TestTokenRefreshAcceptsSameExpiry verifies that a refreshed token with the
// same expiry is accepted (common with providers like Auth0 that cache access
// tokens) but timers are not reset.
func TestTokenRefreshAcceptsSameExpiry(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	sameExpiry := time.Now().Add(10 * time.Minute)
	claims := makeClaims("user-1", sameExpiry)
	validator := &mockValidator{
		tokens: map[string]*oidc.AccessTokenClaims{
			"same-exp-token": makeClaims("user-1", sameExpiry),
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
		Data: mustMarshal(map[string]string{"access_token": "same-exp-token"}),
	})
	if err != nil {
		t.Fatalf("send token_refresh: %v", err)
	}

	msg, ok := readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for response")
	}
	if msg.Type != "token_accepted" {
		t.Fatalf("expected token_accepted, got %s", msg.Type)
	}
}

// TestTokenRefreshRejectedExpiryReduced verifies that a refreshed token with
// an earlier expiry than the current one is rejected.
func TestTokenRefreshRejectedExpiryReduced(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	currentExpiry := time.Now().Add(10 * time.Minute)
	claims := makeClaims("user-1", currentExpiry)
	validator := &mockValidator{
		tokens: map[string]*oidc.AccessTokenClaims{
			"earlier-exp-token": makeClaims("user-1", currentExpiry.Add(-time.Minute)),
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
		Data: mustMarshal(map[string]string{"access_token": "earlier-exp-token"}),
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
	if data["reason"] != "expiry_reduced" {
		t.Fatalf("expected reason expiry_reduced, got %s", data["reason"])
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

// TestExpiryGraceWarningGTGraceRetriesUntilNewToken exercises the common case
// where --expiry-warning exceeds --expiry-grace. The first warning fires before
// the raw token expires; the client refreshes but the provider returns the same
// cached token (same exp). The server accepts it unchanged and schedules a
// retry warning at remaining/2. When the retry fires, the client refreshes
// again — this time with a genuinely new token — and the tunnel extends.
func TestExpiryGraceWarningGTGraceRetriesUntilNewToken(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	// Token expires in 3s, grace 1s → deadline at T+4s, warning 5s.
	// Warning fires at max(0, 4s-5s) = T+0 (immediately).
	tokenExpiry := time.Now().Add(3 * time.Second)
	extendedExpiry := time.Now().Add(10 * time.Second)
	claims := makeClaims("user-1", tokenExpiry)

	// The validator knows two tokens: one with the same exp (cached provider
	// response) and one with extended exp (new token after provider cache expires).
	validator := &mockValidator{
		tokens: map[string]*oidc.AccessTokenClaims{
			"cached-token": makeClaims("user-1", tokenExpiry),
			"new-token":    makeClaims("user-1", extendedExpiry),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go manageTunnelLongevity(ctx, cancel, serverConn, validator, claims, LongevityConfig{
		ImplementsExpiry: true,
		ExpiryWarning:    5 * time.Second,
		ExpiryGrace:      1 * time.Second,
	}, time.Now(), slog.Default())

	// 1. First warning fires immediately (warning > deadline).
	msg, ok := readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for initial expiry_warning")
	}
	if msg.Type != "expiry_warning" {
		t.Fatalf("expected expiry_warning, got %s", msg.Type)
	}

	// 2. Client refreshes with cached (same-exp) token.
	err := clientConn.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: mustMarshal(map[string]string{"access_token": "cached-token"}),
	})
	if err != nil {
		t.Fatalf("send cached token_refresh: %v", err)
	}

	msg, ok = readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for token_accepted (cached)")
	}
	if msg.Type != "token_accepted" {
		t.Fatalf("expected token_accepted, got %s", msg.Type)
	}

	// 3. A retry warning should fire at remaining/2 (not never).
	msg, ok = readControl(t, clientConn, 4*time.Second)
	if !ok {
		t.Fatal("timed out waiting for retry expiry_warning — server did not schedule retry after same-exp accept")
	}
	if msg.Type == "disconnect" {
		t.Fatal("tunnel disconnected without giving client a retry warning")
	}
	if msg.Type != "expiry_warning" {
		t.Fatalf("expected retry expiry_warning, got %s", msg.Type)
	}

	// 4. Client refreshes with a genuinely new token.
	err = clientConn.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: mustMarshal(map[string]string{"access_token": "new-token"}),
	})
	if err != nil {
		t.Fatalf("send new token_refresh: %v", err)
	}

	msg, ok = readControl(t, clientConn, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for token_accepted (new)")
	}
	if msg.Type != "token_accepted" {
		t.Fatalf("expected token_accepted, got %s", msg.Type)
	}

	// 5. Tunnel should survive past original deadline (T+4s).
	time.Sleep(2 * time.Second)
	select {
	case <-ctx.Done():
		t.Fatal("tunnel closed despite successful refresh with new token")
	default:
		// Good — still alive.
	}
}

// TestExpiryGraceExtendsTunnelBeyondTokenExp verifies that the grace period
// pushes the connection deadline past the token's raw exp claim. With a 1s
// token and 2s grace, the tunnel should survive for ~3s total.
func TestExpiryGraceExtendsTunnelBeyondTokenExp(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	// Token expires in 1s, but grace extends the connection deadline to 3s.
	tokenExpiry := time.Now().Add(1 * time.Second)
	claims := makeClaims("user-1", tokenExpiry)
	validator := &mockValidator{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go manageTunnelLongevity(ctx, cancel, serverConn, validator, claims, LongevityConfig{
		ImplementsExpiry: true,
		ExpiryWarning:    500 * time.Millisecond,
		ExpiryGrace:      2 * time.Second,
	}, time.Now(), slog.Default())

	// At T+1s the token has expired, but the tunnel should still be alive
	// (grace extends to T+3s).
	time.Sleep(1500 * time.Millisecond)
	select {
	case <-ctx.Done():
		t.Fatal("tunnel closed at token exp despite grace period")
	default:
		// Good — still alive.
	}

	// By T+3.5s the grace period should be exhausted and the tunnel closed.
	time.Sleep(2 * time.Second)
	select {
	case <-ctx.Done():
		// Good — tunnel closed after grace period.
	default:
		t.Fatal("tunnel still alive after grace period should have expired")
	}
}

// TestExpiryGraceWarningRelativeToDeadline verifies that the expiry_warning
// fires relative to the connection deadline (exp + grace), not the raw token
// exp. With a 3s token, 3s grace, and 1s warning, the deadline is at T+6s
// and the warning fires at T+5s — well past the raw token exp.
func TestExpiryGraceWarningRelativeToDeadline(t *testing.T) {
	serverConn, clientConn := wsPair(t)
	drainBinary(t, clientConn)
	drainBinary(t, serverConn)

	tokenExpiry := time.Now().Add(3 * time.Second)
	claims := makeClaims("user-1", tokenExpiry)
	validator := &mockValidator{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go manageTunnelLongevity(ctx, cancel, serverConn, validator, claims, LongevityConfig{
		ImplementsExpiry: true,
		ExpiryWarning:    1 * time.Second,
		ExpiryGrace:      3 * time.Second,
	}, time.Now(), slog.Default())

	// Token exp is at T+3s, grace pushes deadline to T+6s, warning at T+5s.
	// No warning should arrive before T+4s (well past raw token exp).
	select {
	case msg := <-clientConn.ControlChan():
		t.Fatalf("unexpected early control message: %s", msg.Type)
	case <-time.After(4 * time.Second):
		// Good — no warning yet, even though raw token has expired.
	}

	// Warning should arrive between T+4s and T+6s.
	msg, ok := readControl(t, clientConn, 3*time.Second)
	if !ok {
		t.Fatal("timed out waiting for expiry_warning")
	}
	if msg.Type != "expiry_warning" {
		t.Fatalf("expected expiry_warning, got %s", msg.Type)
	}
}

// TestExpiryCancellationFiresWhenPeerStopsReading proves that a peer that
// stops reading control frames cannot prevent token-expiry cancellation from
// firing. Peer-visible writes happen in a separate writer goroutine, so the
// deadline-critical select in manageTunnelLongevity must observe its
// tokenDeadlineTimer regardless of writer back-pressure.
func TestExpiryCancellationFiresWhenPeerStopsReading(t *testing.T) {
	serverConn, _ := wsPair(t)
	// Deliberately do NOT drain the client side. Any control frame the
	// writer goroutine attempts will park inside ws.Write once buffers
	// fill, which used to also park the longevity select.

	claims := makeClaims("user-1", time.Now().Add(50*time.Millisecond))
	cfg := LongevityConfig{
		ImplementsExpiry: true,
		ExpiryWarning:    100 * time.Millisecond,
		ExpiryGrace:      100 * time.Millisecond, // connDeadline ≈ now+150ms
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan struct{})
	go func() {
		defer close(done)
		manageTunnelLongevity(ctx, cancel, serverConn, &mockValidator{}, claims, cfg, time.Now(), slog.Default())
	}()

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("ctx not cancelled within 2s — peer-blocked write stalled enforcement")
	}

	// The longevity goroutine should return promptly after enqueueing the
	// disconnect frame; it no longer waits on a peer-visible write.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("manageTunnelLongevity did not return promptly after cancellation")
	}
}

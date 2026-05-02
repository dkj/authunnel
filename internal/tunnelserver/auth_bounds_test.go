package tunnelserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// rejectingValidator fails the test if invoked. Used to assert that an
// oversized header or token is rejected before the validator sees it.
type rejectingValidator struct {
	t *testing.T
}

func (r rejectingValidator) ValidateAccessToken(_ context.Context, _ string) (*oidc.AccessTokenClaims, error) {
	r.t.Fatalf("validator must not be invoked for oversized credentials")
	return nil, nil
}

func TestValidateRequestTokenRejectsOversizedAuthorizationHeader(t *testing.T) {
	mux := NewHandler(rejectingValidator{t: t}, NewObservedSOCKSServer(nil, nil, nil, 0))

	// Build a non-Bearer scheme that exceeds the header cap so the size
	// check fires before the prefix mismatch path.
	header := "Custom " + strings.Repeat("x", maxAuthorizationHeaderBytes)
	req := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	req.Header.Set("Authorization", header)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rr.Body.String(), "invalid header") {
		t.Fatalf("body = %q, want it to contain 'invalid header'", rr.Body.String())
	}
}

func TestValidateRequestTokenRejectsOversizedBearerToken(t *testing.T) {
	mux := NewHandler(rejectingValidator{t: t}, NewObservedSOCKSServer(nil, nil, nil, 0))

	token := strings.Repeat("a", maxBearerTokenBytes+1)
	req := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rr.Body.String(), "invalid header") {
		t.Fatalf("body = %q, want it to contain 'invalid header'", rr.Body.String())
	}
}

func TestValidateRequestTokenAcceptsTokenAtBoundary(t *testing.T) {
	// Token of exactly maxBearerTokenBytes must reach the validator. We use
	// a mockValidator that returns claims so the handler proceeds past the
	// size check; the WS-headers check then fails (no upgrade headers), but
	// that is expected and shows we got past the pre-validator gates.
	token := strings.Repeat("a", maxBearerTokenBytes)
	v := &mockValidator{tokens: map[string]*oidc.AccessTokenClaims{
		token: {TokenClaims: oidc.TokenClaims{Subject: "alice", Expiration: oidc.FromTime(time.Now().Add(time.Hour))}},
	}}
	mux := NewHandler(v, NewObservedSOCKSServer(nil, nil, nil, 0))

	req := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("token at the size boundary was rejected as oversized; body=%q", rr.Body.String())
	}
}

// newBlockingIssuer returns the URL of a TCP listener that accepts
// connections but never replies, simulating an OIDC issuer that completes
// the TCP handshake but never serves discovery. The accept goroutine owns
// the channel close so cleanup cannot race with a just-accepted connection.
func newBlockingIssuer(t *testing.T) (issuerURL string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepted := make(chan net.Conn, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				close(accepted)
				return
			}
			select {
			case accepted <- conn:
			default:
				// Buffer is full; drop on the floor — the test only
				// needs the listener to accept, not to retain conns.
				_ = conn.Close()
			}
		}
	}()
	cleanup = func() {
		_ = ln.Close()
		<-done
		for c := range accepted {
			_ = c.Close()
		}
	}
	return "http://" + ln.Addr().String(), cleanup
}

func TestNewJWTTokenValidatorDiscoveryTimesOut(t *testing.T) {
	issuer, cleanup := newBlockingIssuer(t)
	defer cleanup()

	// A short overall client timeout so the test stays fast. The bounded
	// transport defaults are 10s; we tighten with a per-test client.
	client := &http.Client{Timeout: 500 * time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	_, err := NewJWTTokenValidator(ctx, issuer, "test-aud", client)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected discovery against blocking issuer to fail, got nil error")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("discovery took %v, expected to abort within client timeout", elapsed)
	}
}

func TestNewJWTTokenValidatorRespectsContextDeadline(t *testing.T) {
	issuer, cleanup := newBlockingIssuer(t)
	defer cleanup()

	// No client timeout — this proves the context deadline alone is
	// sufficient to abort discovery, which is what wraps startup in
	// server.go.
	client := &http.Client{}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := NewJWTTokenValidator(ctx, issuer, "test-aud", client)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected discovery to fail when context deadline elapses")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("discovery took %v, expected to abort near context deadline", elapsed)
	}
}

func TestJWTTokenValidatorJWKSFetchTimesOut(t *testing.T) {
	jwksBaseURL, cleanup := newBlockingIssuer(t)
	defer cleanup()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	jwk := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     "blocking-jwks-key",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	var issuerURL string
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeAuthBoundsJSON(t, w, map[string]string{
				"issuer":   issuerURL,
				"jwks_uri": jwksBaseURL + "/keys",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuer.Close()
	issuerURL = issuer.URL

	client := &http.Client{Timeout: 500 * time.Millisecond}
	validator, err := NewJWTTokenValidator(context.Background(), issuerURL, "test-aud", client)
	if err != nil {
		t.Fatalf("create validator: %v", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID),
	)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	now := time.Now().UTC()
	claims := &oidc.AccessTokenClaims{
		TokenClaims: oidc.TokenClaims{
			Issuer:     issuerURL,
			Subject:    "test-user",
			Audience:   oidc.Audience{"test-aud"},
			Expiration: oidc.FromTime(now.Add(time.Hour)),
			IssuedAt:   oidc.FromTime(now),
			NotBefore:  oidc.FromTime(now),
		},
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	start := time.Now()
	_, err = validator.ValidateAccessToken(context.Background(), token)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected validation to fail when JWKS endpoint blocks")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("JWKS fetch took %v, expected to abort within client timeout", elapsed)
	}
}

func writeAuthBoundsJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode JSON: %v", err)
	}
}

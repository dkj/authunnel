package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	socks5 "github.com/armon/go-socks5"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"authunnel/internal/tunnelserver"
)

func TestCheckTokenRequiresAuthorizationHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()

	ok := tunnelserver.CheckToken(rr, req, nil)
	if ok {
		t.Fatalf("expected token check to fail when authorization header is missing")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestCheckTokenRejectsInvalidAuthorizationScheme(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Basic abc123")
	rr := httptest.NewRecorder()

	ok := tunnelserver.CheckToken(rr, req, nil)
	if ok {
		t.Fatalf("expected token check to fail for non-bearer authorization scheme")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestJWTTokenValidatorAcceptsConfiguredAudience(t *testing.T) {
	issuer, serverClient, token := newJWTTestIssuer(t, "authunnel-server")

	validator, err := tunnelserver.NewJWTTokenValidator(context.Background(), issuer, "authunnel-server", serverClient)
	if err != nil {
		t.Fatalf("expected validator construction to succeed, got error: %v", err)
	}
	if _, err := validator.ValidateAccessToken(context.Background(), token); err != nil {
		t.Fatalf("expected token validation to succeed, got error: %v", err)
	}
}

func TestJWTTokenValidatorRejectsWrongAudience(t *testing.T) {
	issuer, serverClient, token := newJWTTestIssuer(t, "wrong-audience")

	validator, err := tunnelserver.NewJWTTokenValidator(context.Background(), issuer, "authunnel-server", serverClient)
	if err != nil {
		t.Fatalf("expected validator construction to succeed, got error: %v", err)
	}
	if _, err := validator.ValidateAccessToken(context.Background(), token); err == nil {
		t.Fatalf("expected wrong audience token to be rejected")
	}
}

func TestCheckTokenDoesNotLeakValidationErrors(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rr := httptest.NewRecorder()

	ok := tunnelserver.CheckToken(rr, req, staticFailValidator{err: errors.New("signature mismatch for key kid=abc123")})
	if ok {
		t.Fatalf("expected token check to fail for invalid token")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
	if strings.Contains(rr.Body.String(), "kid=abc123") || strings.Contains(rr.Body.String(), "signature mismatch") {
		t.Fatalf("expected response body to avoid leaking verifier internals, got %q", rr.Body.String())
	}
}

func TestRootRejectsUnsupportedMethod(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	handler := tunnelserver.NewHandler(staticSuccessValidator{}, socks)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
	if rr.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("expected Allow header %q, got %q", "GET, HEAD", rr.Header().Get("Allow"))
	}
}

func TestProtectedAllowsHEAD(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	handler := tunnelserver.NewHandler(staticSuccessValidator{}, socks)

	req := httptest.NewRequest(http.MethodHead, "/protected", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if rr.Body.Len() != 0 {
		t.Fatalf("expected HEAD response body to be empty, got %q", rr.Body.String())
	}
}

func TestProtectedSocksRejectsNonWebSocketRequestsBeforeAuth(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	handler := tunnelserver.NewHandler(staticSuccessValidator{}, socks)

	req := httptest.NewRequest(http.MethodGet, "/protected/socks", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUpgradeRequired {
		t.Fatalf("expected status %d, got %d", http.StatusUpgradeRequired, rr.Code)
	}
	if strings.Contains(rr.Body.String(), "forbidden") {
		t.Fatalf("expected request admission failure before token validation, got %q", rr.Body.String())
	}
}

func TestProtectedSocksRejectsNonGETMethod(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	handler := tunnelserver.NewHandler(staticSuccessValidator{}, socks)

	req := httptest.NewRequest(http.MethodPost, "/protected/socks", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestProtectedSocksRejectsCrossOriginWebSocketRequests(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	handler := tunnelserver.NewHandler(staticSuccessValidator{}, socks)

	req := httptest.NewRequest(http.MethodGet, "https://authunnel.example/protected/socks", nil)
	req.Host = "authunnel.example"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "cross-origin websocket forbidden") {
		t.Fatalf("expected explicit cross-origin rejection, got %q", rr.Body.String())
	}
}

func TestProtectedSocksRejectsOriginWithDifferentScheme(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	handler := tunnelserver.NewHandler(staticSuccessValidator{}, socks)

	req := httptest.NewRequest(http.MethodGet, "https://authunnel.example/protected/socks", nil)
	req.Host = "authunnel.example"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "http://authunnel.example")
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}

func TestProtectedSocksRejectsOriginWithDifferentPort(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	handler := tunnelserver.NewHandler(staticSuccessValidator{}, socks)

	req := httptest.NewRequest(http.MethodGet, "https://authunnel.example:8443/protected/socks", nil)
	req.Host = "authunnel.example:8443"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://authunnel.example:444")
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}

func TestProtectedSocksAllowsSameHostOriginToReachAuth(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	handler := tunnelserver.NewHandler(staticFailValidator{err: errors.New("token rejected")}, socks)

	req := httptest.NewRequest(http.MethodGet, "https://authunnel.example/protected/socks", nil)
	req.Host = "authunnel.example"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://authunnel.example")
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "forbidden") {
		t.Fatalf("expected request to pass admission checks and fail in token validation, got %q", rr.Body.String())
	}
}

func TestProtectedSocksAllowsOriginWithImplicitDefaultHTTPSPort(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	handler := tunnelserver.NewHandler(staticFailValidator{err: errors.New("token rejected")}, socks)

	req := httptest.NewRequest(http.MethodGet, "https://authunnel.example/protected/socks", nil)
	req.Host = "authunnel.example:443"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://authunnel.example")
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "forbidden") {
		t.Fatalf("expected request to pass admission checks and fail in token validation, got %q", rr.Body.String())
	}
}

type staticFailValidator struct {
	err error
}

func (v staticFailValidator) ValidateAccessToken(context.Context, string) (*oidc.AccessTokenClaims, error) {
	return nil, v.err
}

type staticSuccessValidator struct{}

func (staticSuccessValidator) ValidateAccessToken(context.Context, string) (*oidc.AccessTokenClaims, error) {
	return &oidc.AccessTokenClaims{}, nil
}

func newJWTTestIssuer(t *testing.T, audience string) (string, *http.Client, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	jwk := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     "test-key",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	var issuerURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, w, map[string]string{
				"issuer":   issuerURL,
				"jwks_uri": issuerURL + "/keys",
			})
		case "/keys":
			writeJSON(t, w, map[string]any{
				"keys": []jose.JSONWebKey{jwk},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	issuerURL = server.URL

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	now := time.Now().UTC()
	claims := &oidc.AccessTokenClaims{
		TokenClaims: oidc.TokenClaims{
			Issuer:     issuerURL,
			Subject:    "test-user",
			Audience:   oidc.Audience{audience},
			Expiration: oidc.FromTime(now.Add(time.Hour)),
			IssuedAt:   oidc.FromTime(now),
			NotBefore:  oidc.FromTime(now),
			ClientID:   "authunnel-cli",
			JWTID:      "jwt-id",
		},
		Scopes: oidc.SpaceDelimitedArray{"openid"},
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	return issuerURL, server.Client(), token
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode JSON: %v", err)
	}
}

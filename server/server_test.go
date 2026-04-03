package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	socks5 "github.com/armon/go-socks5"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"authunnel/internal/tunnelserver"
)

func TestParseServerConfigReadsFlagsAndEnv(t *testing.T) {
	cfg, err := parseServerConfig(
		[]string{
			"--oidc-issuer", "https://flag-issuer.example",
			"--listen-addr", "127.0.0.1:9443",
			"--tls-cert", "/flags/server.crt",
			"--tls-key", "/flags/server.key",
		},
		func(key string) string {
			switch key {
			case "TOKEN_AUDIENCE":
				return "authunnel-server"
			case "LISTEN_ADDR":
				return ":8443"
			default:
				return ""
			}
		},
	)
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}

	want := serverConfig{
		Issuer:        "https://flag-issuer.example",
		TokenAudience: "authunnel-server",
		ListenAddr:    "127.0.0.1:9443",
		TLSCertPath:   "/flags/server.crt",
		TLSKeyPath:    "/flags/server.key",
		LogLevel:      slog.LevelInfo,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("unexpected config: got %#v want %#v", cfg, want)
	}
}

func TestParseServerConfigAcceptsTLSPathsFromEnv(t *testing.T) {
	cfg, err := parseServerConfig(nil, func(key string) string {
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		case "TLS_CERT_FILE":
			return "/env/server.crt"
		case "TLS_KEY_FILE":
			return "/env/server.key"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}

	if cfg.ListenAddr != ":8443" {
		t.Fatalf("unexpected default listen addr: got %q want %q", cfg.ListenAddr, ":8443")
	}
	if cfg.TLSCertPath != "/env/server.crt" {
		t.Fatalf("unexpected TLS cert path: got %q", cfg.TLSCertPath)
	}
	if cfg.TLSKeyPath != "/env/server.key" {
		t.Fatalf("unexpected TLS key path: got %q", cfg.TLSKeyPath)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Fatalf("unexpected default log level: got %v want %v", cfg.LogLevel, slog.LevelInfo)
	}
}

func TestParseServerConfigAcceptsLogLevelFromFlagAndEnv(t *testing.T) {
	cfg, err := parseServerConfig([]string{
		"--log-level", "debug",
		"--tls-cert", "/flags/server.crt",
		"--tls-key", "/flags/server.key",
	}, func(key string) string {
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		case "LOG_LEVEL":
			return "warn"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Fatalf("unexpected log level: got %v want %v", cfg.LogLevel, slog.LevelDebug)
	}
}

func TestParseServerConfigAllowsValidFlagWhenEnvLogLevelIsInvalid(t *testing.T) {
	cfg, err := parseServerConfig([]string{
		"--log-level", "debug",
		"--tls-cert", "/flags/server.crt",
		"--tls-key", "/flags/server.key",
	}, func(key string) string {
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		case "LOG_LEVEL":
			return "verbose"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Fatalf("unexpected log level: got %v want %v", cfg.LogLevel, slog.LevelDebug)
	}
}

func TestParseServerConfigRejectsInvalidLogLevel(t *testing.T) {
	_, err := parseServerConfig([]string{
		"--log-level", "verbose",
		"--tls-cert", "/flags/server.crt",
		"--tls-key", "/flags/server.key",
	}, func(key string) string {
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		default:
			return ""
		}
	})
	if err == nil {
		t.Fatal("expected invalid log level to fail")
	}
	if !strings.Contains(err.Error(), "invalid log level") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseServerConfigRejectsMissingTLSPaths(t *testing.T) {
	_, err := parseServerConfig(nil, func(key string) string {
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		default:
			return ""
		}
	})
	if err == nil {
		t.Fatalf("expected missing TLS path configuration to fail")
	}
	if !strings.Contains(err.Error(), "TLS_CERT_FILE") {
		t.Fatalf("expected error to mention missing TLS cert path, got %q", err.Error())
	}
}

func TestParseServerConfigHelpFlag(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		_, err := parseServerConfig([]string{arg}, func(string) string { return "" })
		if !errors.Is(err, flag.ErrHelp) {
			t.Errorf("parseServerConfig(%q) error = %v, want flag.ErrHelp", arg, err)
		}
	}
}

func TestParseServerConfigHelpPositional(t *testing.T) {
	_, err := parseServerConfig([]string{"help"}, func(string) string { return "" })
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("parseServerConfig(\"help\") error = %v, want flag.ErrHelp", err)
	}
}

func TestParseServerConfigRejectsLegacyIssuerFlag(t *testing.T) {
	_, err := parseServerConfig(
		[]string{
			"--issuer", "https://issuer.example",
			"--token-audience", "authunnel-server",
			"--tls-cert", "/flags/server.crt",
			"--tls-key", "/flags/server.key",
		},
		func(string) string { return "" },
	)
	if err == nil {
		t.Fatalf("expected legacy --issuer flag to be rejected")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined: -issuer") {
		t.Fatalf("unexpected error for legacy issuer flag: %q", err.Error())
	}
}

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
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func newIPv4TestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on IPv4 loopback: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	return server
}

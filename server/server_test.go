package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	socks5 "github.com/armon/go-socks5"
	"github.com/coder/websocket"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"authunnel/internal/tunnelserver"
	"authunnel/internal/wsconn"
)

func TestParseServerConfigReadsFlagsAndEnv(t *testing.T) {
	cfg, err := parseServerConfig(
		[]string{
			"--oidc-issuer", "https://flag-issuer.example",
			"--listen-addr", "127.0.0.1:9443",
			"--tls-cert", "/flags/server.crt",
			"--tls-key", "/flags/server.key",
			"--allow-open-egress",
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
		Issuer:          "https://flag-issuer.example",
		TokenAudience:   "authunnel-server",
		ListenAddr:      "127.0.0.1:9443",
		TLSCertPath:     "/flags/server.crt",
		TLSKeyPath:      "/flags/server.key",
		ACMECacheDir:    "/var/cache/authunnel/acme",
		LogLevel:        slog.LevelInfo,
		AllowOpenEgress: true,
		IPBlockRanges:   tunnelserver.DefaultIPBlocklist(),
		ExpiryWarning:   3 * time.Minute,
		DialTimeout:     10 * time.Second,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("unexpected config: got %#v want %#v", cfg, want)
	}
}

func TestParseServerConfigRejectsHTTPIssuer(t *testing.T) {
	_, err := parseServerConfig(
		[]string{
			"--oidc-issuer", "http://issuer.example",
			"--token-audience", "authunnel-server",
			"--tls-cert", "/srv/server.crt",
			"--tls-key", "/srv/server.key",
		},
		func(string) string { return "" },
	)
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("expected https rejection for http issuer, got: %v", err)
	}
}

func TestParseServerConfigAcceptsHTTPIssuerWithFlag(t *testing.T) {
	_, err := parseServerConfig(
		[]string{
			"--oidc-issuer", "http://issuer.example",
			"--token-audience", "authunnel-server",
			"--tls-cert", "/srv/server.crt",
			"--tls-key", "/srv/server.key",
			"--insecure-oidc-issuer",
		},
		func(string) string { return "" },
	)
	// May fail for other reasons (TLS files don't exist at runtime) but must NOT reject the http scheme.
	if err != nil && strings.Contains(err.Error(), "https://") {
		t.Fatalf("insecure-oidc-issuer flag should suppress scheme error, got: %v", err)
	}
}

func TestParseServerConfigAcceptsHTTPIssuerViaEnv(t *testing.T) {
	_, err := parseServerConfig(
		[]string{
			"--oidc-issuer", "http://issuer.example",
			"--token-audience", "authunnel-server",
			"--tls-cert", "/srv/server.crt",
			"--tls-key", "/srv/server.key",
		},
		func(key string) string {
			if key == "INSECURE_OIDC_ISSUER" {
				return "true"
			}
			return ""
		},
	)
	if err != nil && strings.Contains(err.Error(), "https://") {
		t.Fatalf("INSECURE_OIDC_ISSUER=true should suppress scheme error, got: %v", err)
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
		case "ALLOW_OPEN_EGRESS":
			return "true"
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
		case "ALLOW_OPEN_EGRESS":
			return "true"
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
		case "ALLOW_OPEN_EGRESS":
			return "true"
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
	if !strings.Contains(err.Error(), "--tls-cert") && !strings.Contains(err.Error(), "--acme-domain") && !strings.Contains(err.Error(), "--plaintext-behind-reverse-proxy") {
		t.Fatalf("expected error to mention TLS mode options, got %q", err.Error())
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

func TestParseServerConfigVersionFlag(t *testing.T) {
	for _, arg := range []string{"--version", "version"} {
		_, err := parseServerConfig([]string{arg}, func(string) string { return "" })
		if !errors.Is(err, flag.ErrHelp) {
			t.Errorf("parseServerConfig(%q) error = %v, want flag.ErrHelp", arg, err)
		}
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

	req := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
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

	req := httptest.NewRequest(http.MethodPost, "/protected/tunnel", nil)
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

	req := httptest.NewRequest(http.MethodGet, "https://authunnel.example/protected/tunnel", nil)
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

	req := httptest.NewRequest(http.MethodGet, "https://authunnel.example/protected/tunnel", nil)
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

	req := httptest.NewRequest(http.MethodGet, "https://authunnel.example:8443/protected/tunnel", nil)
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

	req := httptest.NewRequest(http.MethodGet, "https://authunnel.example/protected/tunnel", nil)
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

	req := httptest.NewRequest(http.MethodGet, "https://authunnel.example/protected/tunnel", nil)
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
	issuer, client, token, _ := newJWTTestIssuerFull(t, audience, time.Hour)
	return issuer, client, token
}

func newJWTTestIssuerWithExpiry(t *testing.T, audience string, expiry time.Duration) (string, *http.Client, string) {
	issuer, client, token, _ := newJWTTestIssuerFull(t, audience, expiry)
	return issuer, client, token
}

// tokenMinter creates signed JWTs with a given expiry from the test issuer.
type tokenMinter func(expiry time.Duration) string

func newJWTTestIssuerFull(t *testing.T, audience string, initialExpiry time.Duration) (string, *http.Client, string, tokenMinter) {
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

	mintToken := func(expiry time.Duration) string {
		now := time.Now().UTC()
		claims := &oidc.AccessTokenClaims{
			TokenClaims: oidc.TokenClaims{
				Issuer:     issuerURL,
				Subject:    "test-user",
				Audience:   oidc.Audience{audience},
				Expiration: oidc.FromTime(now.Add(expiry)),
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
		return token
	}

	return issuerURL, server.Client(), mintToken(initialExpiry), mintToken
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

// minimalServerEnvWithRules is the companion to minimalServerEnv for tests
// that supply their own --allow rules and therefore must NOT inherit the
// ALLOW_OPEN_EGRESS shortcut, which would now conflict with the rules and be
// rejected as an ambiguous posture.
func minimalServerEnvWithRules(key string) string {
	if key == "ALLOW_OPEN_EGRESS" {
		return ""
	}
	return minimalServerEnv(key)
}

func minimalServerEnv(key string) string {
	switch key {
	case "OIDC_ISSUER":
		return "https://issuer.example"
	case "TOKEN_AUDIENCE":
		return "authunnel-server"
	case "TLS_CERT_FILE":
		return "/env/server.crt"
	case "TLS_KEY_FILE":
		return "/env/server.key"
	case "ALLOW_OPEN_EGRESS":
		// Tests that do not exercise the egress-posture gate rely on this
		// helper to satisfy the default-deny allowlist check introduced in
		// Task D. Tests that specifically cover that gate construct their
		// own env function and leave ALLOW_OPEN_EGRESS unset.
		return "true"
	default:
		return ""
	}
}

func TestParseServerConfigAllowFlag(t *testing.T) {
	cfg, err := parseServerConfig([]string{
		"--allow", "*.internal:22",
		"--allow", "10.0.0.0/8:443",
	}, minimalServerEnvWithRules)
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if len(cfg.AllowRules) != 2 {
		t.Fatalf("expected 2 allow rules, got %d", len(cfg.AllowRules))
	}
}

func TestParseServerConfigAllowRulesEnv(t *testing.T) {
	cfg, err := parseServerConfig(nil, func(key string) string {
		if key == "ALLOW_RULES" {
			return "*.internal:22,10.0.0.0/8:443"
		}
		return minimalServerEnvWithRules(key)
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if len(cfg.AllowRules) != 2 {
		t.Fatalf("expected 2 allow rules from env, got %d", len(cfg.AllowRules))
	}
}

// TestParseServerConfigRejectsEmptyAllowlistByDefault verifies the Task D
// default-deny posture: absent both --allow rules and --allow-open-egress,
// startup must fail so a misconfigured deployment cannot silently become a
// general-purpose authenticated TCP pivot.
func TestParseServerConfigRejectsEmptyAllowlistByDefault(t *testing.T) {
	_, err := parseServerConfig(nil, func(key string) string {
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
	if err == nil {
		t.Fatal("expected startup to fail with no allow rules and no --allow-open-egress")
	}
	if !strings.Contains(err.Error(), "--allow") || !strings.Contains(err.Error(), "--allow-open-egress") {
		t.Fatalf("error should mention both --allow and --allow-open-egress so operators can pick a posture, got: %v", err)
	}
}

// TestParseServerConfigAcceptsAllowOpenEgressFlag verifies the explicit escape
// hatch: --allow-open-egress alone is enough to start the server with no
// allowlist, preserving today's open-mode behaviour for operators who opt in.
func TestParseServerConfigAcceptsAllowOpenEgressFlag(t *testing.T) {
	cfg, err := parseServerConfig([]string{"--allow-open-egress"}, func(key string) string {
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
	if !cfg.AllowOpenEgress {
		t.Fatal("AllowOpenEgress should be true when --allow-open-egress is set")
	}
	if len(cfg.AllowRules) != 0 {
		t.Fatalf("expected 0 allow rules in open-egress mode, got %d", len(cfg.AllowRules))
	}
}

// TestParseServerConfigAcceptsAllowOpenEgressEnv mirrors the flag test for
// the ALLOW_OPEN_EGRESS environment variable, so containerised deployments can
// opt in through env without shell flags.
func TestParseServerConfigAcceptsAllowOpenEgressEnv(t *testing.T) {
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
		case "ALLOW_OPEN_EGRESS":
			return "true"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if !cfg.AllowOpenEgress {
		t.Fatal("AllowOpenEgress should be true when ALLOW_OPEN_EGRESS=true")
	}
}

// TestParseServerConfigAcceptsAllowRulesWithoutOpenEgress is the positive path
// for restrictive mode: a non-empty allowlist is sufficient and does not
// require the open-egress escape hatch.
func TestParseServerConfigAcceptsAllowRulesWithoutOpenEgress(t *testing.T) {
	cfg, err := parseServerConfig([]string{"--allow", "*.internal:22"}, func(key string) string {
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
	if cfg.AllowOpenEgress {
		t.Fatal("AllowOpenEgress should remain false when only --allow rules are set")
	}
	if len(cfg.AllowRules) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(cfg.AllowRules))
	}
}

// TestParseServerConfigRejectsAllowRulesWithOpenEgress forbids the ambiguous
// combination of allowlist rules and the open-egress escape hatch. Accepting
// both would obscure the active posture — operators should pick one.
func TestParseServerConfigRejectsAllowRulesWithOpenEgress(t *testing.T) {
	_, err := parseServerConfig([]string{
		"--allow", "*.internal:22",
		"--allow-open-egress",
	}, func(key string) string {
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
	if err == nil {
		t.Fatal("expected --allow and --allow-open-egress together to be rejected")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected 'mutually exclusive' error, got: %v", err)
	}
}

// commonAllowGetenv satisfies the mandatory issuer/audience/TLS env vars so
// the new --ip-block tests can focus on ip-block-specific behaviour without
// re-stating the same boilerplate per case.
func commonAllowGetenv(extra map[string]string) func(string) string {
	return func(key string) string {
		if v, ok := extra[key]; ok {
			return v
		}
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		case "TLS_CERT_FILE":
			return "/env/server.crt"
		case "TLS_KEY_FILE":
			return "/env/server.key"
		}
		return ""
	}
}

// TestParseServerConfigDefaultsIPBlock asserts that when neither --ip-block
// nor --no-ip-block is set, the configured blocklist is the documented
// default protected set. This is the safe-by-default posture.
func TestParseServerConfigDefaultsIPBlock(t *testing.T) {
	cfg, err := parseServerConfig(
		[]string{"--allow-open-egress"},
		commonAllowGetenv(nil),
	)
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}
	want := tunnelserver.DefaultIPBlocklist()
	if !reflect.DeepEqual(cfg.IPBlockRanges, want) {
		t.Fatalf("expected default ip-block (len %d), got len %d (%v)", len(want), len(cfg.IPBlockRanges), cfg.IPBlockRanges)
	}
	if cfg.NoIPBlock {
		t.Fatal("NoIPBlock should be false by default")
	}
}

func TestParseServerConfigAcceptsIPBlockFlagReplacesDefault(t *testing.T) {
	cfg, err := parseServerConfig(
		[]string{"--allow-open-egress", "--ip-block", "169.254.0.0/16"},
		commonAllowGetenv(nil),
	)
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}
	if len(cfg.IPBlockRanges) != 1 {
		t.Fatalf("expected 1 ip-block entry (custom replaces default), got %d", len(cfg.IPBlockRanges))
	}
	// Custom range only covers 169.254/16, so loopback must NOT match.
	if blocked, _ := cfg.IPBlockRanges.Blocks(net.ParseIP("127.0.0.1")); blocked {
		t.Errorf("custom --ip-block 169.254.0.0/16 should not block loopback")
	}
	if blocked, reason := cfg.IPBlockRanges.Blocks(net.ParseIP("169.254.169.254")); !blocked {
		t.Errorf("custom --ip-block 169.254.0.0/16 should block IMDS, blocked=%v reason=%q", blocked, reason)
	}
}

func TestParseServerConfigAcceptsIPBlockFromEnv(t *testing.T) {
	cfg, err := parseServerConfig(
		[]string{"--allow-open-egress"},
		commonAllowGetenv(map[string]string{"IP_BLOCK": "127.0.0.0/8, 169.254.0.0/16"}),
	)
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}
	if len(cfg.IPBlockRanges) != 2 {
		t.Fatalf("expected 2 ip-block entries from env, got %d", len(cfg.IPBlockRanges))
	}
}

func TestParseServerConfigCombinesIPBlockFlagAndEnv(t *testing.T) {
	cfg, err := parseServerConfig(
		[]string{"--allow-open-egress", "--ip-block", "224.0.0.0/4"},
		commonAllowGetenv(map[string]string{"IP_BLOCK": "127.0.0.0/8"}),
	)
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}
	if len(cfg.IPBlockRanges) != 2 {
		t.Fatalf("expected 2 ip-block entries (env + flag combined), got %d: %v", len(cfg.IPBlockRanges), cfg.IPBlockRanges)
	}
}

func TestParseServerConfigAcceptsNoIPBlockFlag(t *testing.T) {
	cfg, err := parseServerConfig(
		[]string{"--allow-open-egress", "--no-ip-block"},
		commonAllowGetenv(nil),
	)
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}
	if !cfg.NoIPBlock {
		t.Fatal("NoIPBlock should be true when --no-ip-block is set")
	}
	if len(cfg.IPBlockRanges) != 0 {
		t.Fatalf("expected empty ip-block when --no-ip-block is set, got %d entries", len(cfg.IPBlockRanges))
	}
}

func TestParseServerConfigAcceptsNoIPBlockEnv(t *testing.T) {
	cfg, err := parseServerConfig(
		[]string{"--allow-open-egress"},
		commonAllowGetenv(map[string]string{"NO_IP_BLOCK": "true"}),
	)
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}
	if !cfg.NoIPBlock {
		t.Fatal("NoIPBlock should be true when NO_IP_BLOCK=true")
	}
	if len(cfg.IPBlockRanges) != 0 {
		t.Fatalf("expected empty ip-block, got %d entries", len(cfg.IPBlockRanges))
	}
}

// TestParseServerConfigRejectsIPBlockWithNoIPBlock keeps the operator's
// intent unambiguous on startup: passing both is a configuration error
// rather than a silent precedence rule.
func TestParseServerConfigRejectsIPBlockWithNoIPBlock(t *testing.T) {
	_, err := parseServerConfig(
		[]string{"--allow-open-egress", "--ip-block", "127.0.0.0/8", "--no-ip-block"},
		commonAllowGetenv(nil),
	)
	if err == nil {
		t.Fatal("expected --ip-block with --no-ip-block to be rejected")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected 'mutually exclusive' error, got: %v", err)
	}
}

func TestParseServerConfigRejectsIPBlockEnvWithNoIPBlockFlag(t *testing.T) {
	_, err := parseServerConfig(
		[]string{"--allow-open-egress", "--no-ip-block"},
		commonAllowGetenv(map[string]string{"IP_BLOCK": "127.0.0.0/8"}),
	)
	if err == nil {
		t.Fatal("expected IP_BLOCK with --no-ip-block to be rejected")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected 'mutually exclusive' error, got: %v", err)
	}
}

func TestParseServerConfigRejectsInvalidIPBlock(t *testing.T) {
	_, err := parseServerConfig(
		[]string{"--allow-open-egress", "--ip-block", "not-an-ip"},
		commonAllowGetenv(nil),
	)
	if err == nil {
		t.Fatal("expected invalid --ip-block value to be rejected")
	}
}

func TestParseServerConfigRejectsInvalidIPBlockEnv(t *testing.T) {
	_, err := parseServerConfig(
		[]string{"--allow-open-egress"},
		commonAllowGetenv(map[string]string{"IP_BLOCK": "127.0.0.0/8,not-an-ip"}),
	)
	if err == nil {
		t.Fatal("expected invalid IP_BLOCK value to be rejected")
	}
	if !strings.Contains(err.Error(), "IP_BLOCK") {
		t.Fatalf("expected error to mention IP_BLOCK, got: %v", err)
	}
}

func TestParseServerConfigAllowFlagAndEnvAreCombined(t *testing.T) {
	cfg, err := parseServerConfig([]string{
		"--allow", "10.0.0.0/8:443",
	}, func(key string) string {
		if key == "ALLOW_RULES" {
			return "*.internal:22"
		}
		return minimalServerEnvWithRules(key)
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if len(cfg.AllowRules) != 2 {
		t.Fatalf("expected 2 allow rules (env + flag), got %d", len(cfg.AllowRules))
	}
}

func TestParseServerConfigAdmissionFlags(t *testing.T) {
	cfg, err := parseServerConfig([]string{
		"--max-concurrent-tunnels", "100",
		"--max-tunnels-per-user", "3",
		"--tunnel-open-rate", "2.5",
		"--tunnel-open-burst", "5",
		"--dial-timeout", "5s",
	}, minimalServerEnv)
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.MaxConcurrentTunnels != 100 {
		t.Errorf("MaxConcurrentTunnels: got %d want 100", cfg.MaxConcurrentTunnels)
	}
	if cfg.MaxTunnelsPerUser != 3 {
		t.Errorf("MaxTunnelsPerUser: got %d want 3", cfg.MaxTunnelsPerUser)
	}
	if cfg.TunnelOpenRate != 2.5 {
		t.Errorf("TunnelOpenRate: got %v want 2.5", cfg.TunnelOpenRate)
	}
	if cfg.TunnelOpenBurst != 5 {
		t.Errorf("TunnelOpenBurst: got %d want 5", cfg.TunnelOpenBurst)
	}
	if cfg.DialTimeout != 5*time.Second {
		t.Errorf("DialTimeout: got %v want 5s", cfg.DialTimeout)
	}
}

func TestParseServerConfigAdmissionFromEnv(t *testing.T) {
	cfg, err := parseServerConfig(nil, func(key string) string {
		switch key {
		case "MAX_CONCURRENT_TUNNELS":
			return "50"
		case "MAX_TUNNELS_PER_USER":
			return "2"
		case "TUNNEL_OPEN_RATE":
			return "1"
		case "DIAL_TIMEOUT":
			return "3s"
		default:
			return minimalServerEnv(key)
		}
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.MaxConcurrentTunnels != 50 {
		t.Errorf("MaxConcurrentTunnels: got %d want 50", cfg.MaxConcurrentTunnels)
	}
	if cfg.MaxTunnelsPerUser != 2 {
		t.Errorf("MaxTunnelsPerUser: got %d want 2", cfg.MaxTunnelsPerUser)
	}
	if cfg.TunnelOpenRate != 1 {
		t.Errorf("TunnelOpenRate: got %v want 1", cfg.TunnelOpenRate)
	}
	// Burst is derived from rate when unset.
	if cfg.TunnelOpenBurst != 1 {
		t.Errorf("TunnelOpenBurst (derived): got %d want 1", cfg.TunnelOpenBurst)
	}
	if cfg.DialTimeout != 3*time.Second {
		t.Errorf("DialTimeout: got %v want 3s", cfg.DialTimeout)
	}
}

func TestParseServerConfigBurstDerivedFromRate(t *testing.T) {
	cfg, err := parseServerConfig([]string{
		"--tunnel-open-rate", "4.2",
	}, minimalServerEnv)
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	// ceil(4.2) = 5
	if cfg.TunnelOpenBurst != 5 {
		t.Errorf("TunnelOpenBurst (derived): got %d want 5", cfg.TunnelOpenBurst)
	}
}

func TestParseServerConfigAcceptsMaxTunnelOpenRate(t *testing.T) {
	cfg, err := parseServerConfig([]string{
		"--tunnel-open-rate", "10000",
	}, minimalServerEnv)
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.TunnelOpenRate != maxTunnelOpenRate {
		t.Errorf("TunnelOpenRate: got %v want %d", cfg.TunnelOpenRate, maxTunnelOpenRate)
	}
	if cfg.TunnelOpenBurst != maxTunnelOpenRate {
		t.Errorf("TunnelOpenBurst (derived): got %d want %d", cfg.TunnelOpenBurst, maxTunnelOpenRate)
	}
}

func TestParseServerConfigAcceptsMaxExpiryGrace(t *testing.T) {
	cfg, err := parseServerConfig([]string{
		"--expiry-grace", "1h",
	}, minimalServerEnv)
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.ExpiryGrace != maxExpiryGrace {
		t.Errorf("ExpiryGrace: got %v want %v", cfg.ExpiryGrace, maxExpiryGrace)
	}
}

func TestParseServerConfigRejectsBurstWithoutRate(t *testing.T) {
	_, err := parseServerConfig([]string{
		"--tunnel-open-burst", "5",
	}, minimalServerEnv)
	if err == nil {
		t.Fatalf("expected error when --tunnel-open-burst set without --tunnel-open-rate")
	}
}

func TestParseServerConfigRejectsNegativeAdmissionValues(t *testing.T) {
	cases := []struct {
		name  string
		flags []string
		env   string
	}{
		{"max-concurrent-tunnels", []string{"--max-concurrent-tunnels", "-1"}, ""},
		{"max-tunnels-per-user", []string{"--max-tunnels-per-user", "-1"}, ""},
		{"tunnel-open-rate", []string{"--tunnel-open-rate", "-0.5"}, ""},
		{"dial-timeout", []string{"--dial-timeout", "-1s"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseServerConfig(tc.flags, minimalServerEnv)
			if err == nil {
				t.Fatalf("expected error for negative %s", tc.name)
			}
		})
	}
}

// TestParseServerConfigRejectsNonFiniteTunnelOpenRate ensures NaN and ±Inf
// are rejected on both the flag and env paths. strconv.ParseFloat accepts
// those spellings, and they are not meaningful operator policies here.
func TestParseServerConfigRejectsNonFiniteTunnelOpenRate(t *testing.T) {
	cases := []string{"NaN", "nan", "+Inf", "-Inf", "Inf"}
	for _, v := range cases {
		t.Run("flag/"+v, func(t *testing.T) {
			_, err := parseServerConfig([]string{"--tunnel-open-rate", v}, minimalServerEnv)
			if err == nil {
				t.Fatalf("expected rejection of --tunnel-open-rate=%q", v)
			}
		})
		t.Run("env/"+v, func(t *testing.T) {
			_, err := parseServerConfig(nil, func(key string) string {
				if key == "TUNNEL_OPEN_RATE" {
					return v
				}
				return minimalServerEnv(key)
			})
			if err == nil {
				t.Fatalf("expected rejection of TUNNEL_OPEN_RATE=%q", v)
			}
		})
	}
}

func TestParseServerConfigRejectsTooLargeTunnelOpenRate(t *testing.T) {
	cases := []string{"10000.1", "10001"}
	for _, v := range cases {
		t.Run("flag/"+v, func(t *testing.T) {
			_, err := parseServerConfig([]string{"--tunnel-open-rate", v}, minimalServerEnv)
			if err == nil {
				t.Fatalf("expected rejection of --tunnel-open-rate=%q", v)
			}
			if !strings.Contains(err.Error(), "must be a non-negative finite number not exceeding 10000") {
				t.Fatalf("unexpected error for --tunnel-open-rate=%q: %v", v, err)
			}
		})
		t.Run("env/"+v, func(t *testing.T) {
			_, err := parseServerConfig(nil, func(key string) string {
				if key == "TUNNEL_OPEN_RATE" {
					return v
				}
				return minimalServerEnv(key)
			})
			if err == nil {
				t.Fatalf("expected rejection of TUNNEL_OPEN_RATE=%q", v)
			}
			if !strings.Contains(err.Error(), "must be a non-negative finite number not exceeding 10000") {
				t.Fatalf("unexpected error for TUNNEL_OPEN_RATE=%q: %v", v, err)
			}
		})
	}
}

func TestParseServerConfigRejectsTooLargeTunnelOpenBurst(t *testing.T) {
	cases := []string{"10001"}
	for _, v := range cases {
		t.Run("flag/"+v, func(t *testing.T) {
			_, err := parseServerConfig([]string{
				"--tunnel-open-rate", "1",
				"--tunnel-open-burst", v,
			}, minimalServerEnv)
			if err == nil {
				t.Fatalf("expected rejection of --tunnel-open-burst=%q", v)
			}
			if !strings.Contains(err.Error(), "must be between 0 and 10000") {
				t.Fatalf("unexpected error for --tunnel-open-burst=%q: %v", v, err)
			}
		})
		t.Run("env/"+v, func(t *testing.T) {
			_, err := parseServerConfig(nil, func(key string) string {
				switch key {
				case "TUNNEL_OPEN_RATE":
					return "1"
				case "TUNNEL_OPEN_BURST":
					return v
				default:
					return minimalServerEnv(key)
				}
			})
			if err == nil {
				t.Fatalf("expected rejection of TUNNEL_OPEN_BURST=%q", v)
			}
			if !strings.Contains(err.Error(), "must be between 0 and 10000") {
				t.Fatalf("unexpected error for TUNNEL_OPEN_BURST=%q: %v", v, err)
			}
		})
	}
}

func TestParseServerConfigRejectsTooLargeExpiryGrace(t *testing.T) {
	cases := []string{"1h1s", "2h"}
	for _, v := range cases {
		t.Run("flag/"+v, func(t *testing.T) {
			_, err := parseServerConfig([]string{"--expiry-grace", v}, minimalServerEnv)
			if err == nil {
				t.Fatalf("expected rejection of --expiry-grace=%q", v)
			}
			if !strings.Contains(err.Error(), "must be between 0 and 1h0m0s") {
				t.Fatalf("unexpected error for --expiry-grace=%q: %v", v, err)
			}
		})
		t.Run("env/"+v, func(t *testing.T) {
			_, err := parseServerConfig(nil, func(key string) string {
				if key == "EXPIRY_GRACE" {
					return v
				}
				return minimalServerEnv(key)
			})
			if err == nil {
				t.Fatalf("expected rejection of EXPIRY_GRACE=%q", v)
			}
			if !strings.Contains(err.Error(), "must be between 0 and 1h0m0s") {
				t.Fatalf("unexpected error for EXPIRY_GRACE=%q: %v", v, err)
			}
		})
	}
}

func TestParseServerConfigRejectsInvalidAllowRule(t *testing.T) {
	_, err := parseServerConfig([]string{
		"--allow", "notarule",
	}, minimalServerEnv)
	if err == nil {
		t.Fatal("expected error for invalid allow rule, got nil")
	}
}

func TestParseServerConfigACMEDomainFromFlag(t *testing.T) {
	cfg, err := parseServerConfig([]string{
		"--acme-domain", "authunnel.example.com",
		"--acme-domain", "www.example.com",
	}, func(key string) string {
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		case "ALLOW_OPEN_EGRESS":
			return "true"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if len(cfg.ACMEDomains) != 2 || cfg.ACMEDomains[0] != "authunnel.example.com" || cfg.ACMEDomains[1] != "www.example.com" {
		t.Fatalf("unexpected ACME domains: %v", cfg.ACMEDomains)
	}
	if cfg.ListenAddr != ":443" {
		t.Fatalf("expected ACME mode to default listen addr to :443, got %q", cfg.ListenAddr)
	}
	if cfg.ACMECacheDir != "/var/cache/authunnel/acme" {
		t.Fatalf("expected default ACME cache dir, got %q", cfg.ACMECacheDir)
	}
}

func TestParseServerConfigACMEDomainFromEnv(t *testing.T) {
	cfg, err := parseServerConfig(nil, func(key string) string {
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		case "ACME_DOMAINS":
			return "authunnel.example.com, www.example.com"
		case "ALLOW_OPEN_EGRESS":
			return "true"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if len(cfg.ACMEDomains) != 2 || cfg.ACMEDomains[0] != "authunnel.example.com" || cfg.ACMEDomains[1] != "www.example.com" {
		t.Fatalf("unexpected ACME domains: %v", cfg.ACMEDomains)
	}
}

func TestParseServerConfigACMEFlagAndEnvCombined(t *testing.T) {
	cfg, err := parseServerConfig([]string{
		"--acme-domain", "flag.example.com",
	}, func(key string) string {
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		case "ACME_DOMAINS":
			return "env.example.com"
		case "ALLOW_OPEN_EGRESS":
			return "true"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	// env domains come first, flag domains are additive
	if len(cfg.ACMEDomains) != 2 || cfg.ACMEDomains[0] != "env.example.com" || cfg.ACMEDomains[1] != "flag.example.com" {
		t.Fatalf("unexpected ACME domains: %v", cfg.ACMEDomains)
	}
}

func TestParseServerConfigACMECacheDirOverride(t *testing.T) {
	cfg, err := parseServerConfig([]string{
		"--acme-domain", "authunnel.example.com",
		"--acme-cache-dir", "/tmp/acme-cache",
	}, func(key string) string {
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		case "ALLOW_OPEN_EGRESS":
			return "true"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.ACMECacheDir != "/tmp/acme-cache" {
		t.Fatalf("expected overridden ACME cache dir, got %q", cfg.ACMECacheDir)
	}
}

func TestParseServerConfigPlaintextMode(t *testing.T) {
	cfg, err := parseServerConfig([]string{
		"--plaintext-behind-reverse-proxy",
	}, func(key string) string {
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		case "ALLOW_OPEN_EGRESS":
			return "true"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if !cfg.PlaintextBehindProxy {
		t.Fatal("expected PlaintextHTTP to be true")
	}
	if cfg.ListenAddr != ":8080" {
		t.Fatalf("expected plaintext mode to default listen addr to :8080, got %q", cfg.ListenAddr)
	}
}

func TestParseServerConfigPlaintextModeFromEnv(t *testing.T) {
	cfg, err := parseServerConfig(nil, func(key string) string {
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		case "PLAINTEXT_BEHIND_REVERSE_PROXY":
			return "true"
		case "ALLOW_OPEN_EGRESS":
			return "true"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if !cfg.PlaintextBehindProxy {
		t.Fatal("expected PlaintextHTTP to be true from env")
	}
}

func TestParseServerConfigACMEDomainsEnvFiltersEmptyEntries(t *testing.T) {
	// Trailing comma and whitespace-only entries must not be appended as empty
	// strings; they should be silently dropped so the effective domain list
	// only contains real hostnames.
	cfg, err := parseServerConfig(nil, func(key string) string {
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		case "ACME_DOMAINS":
			return "authunnel.example.com, , ,other.example.com,"
		case "ALLOW_OPEN_EGRESS":
			return "true"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if len(cfg.ACMEDomains) != 2 {
		t.Fatalf("expected 2 domains after filtering, got %v", cfg.ACMEDomains)
	}
}

func TestParseServerConfigACMEDomainsOnlyEmptyEntriesSelectsNoMode(t *testing.T) {
	// ACME_DOMAINS containing only commas/whitespace should not trigger ACME
	// mode — the server must fail at startup rather than starting with an
	// empty host whitelist.
	_, err := parseServerConfig(nil, func(key string) string {
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		case "ACME_DOMAINS":
			return ", ,"
		default:
			return ""
		}
	})
	if err == nil {
		t.Fatal("expected error when ACME_DOMAINS contains only empty entries")
	}
	if !strings.Contains(err.Error(), "--acme-domain") && !strings.Contains(err.Error(), "--tls-cert") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseServerConfigListenAddrOverridesACMEDefault(t *testing.T) {
	cfg, err := parseServerConfig([]string{
		"--acme-domain", "authunnel.example.com",
		"--listen-addr", ":8443",
	}, func(key string) string {
		switch key {
		case "OIDC_ISSUER":
			return "https://issuer.example"
		case "TOKEN_AUDIENCE":
			return "authunnel-server"
		case "ALLOW_OPEN_EGRESS":
			return "true"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.ListenAddr != ":8443" {
		t.Fatalf("expected explicit --listen-addr to override ACME default, got %q", cfg.ListenAddr)
	}
}

func TestParseServerConfigRejectsMultipleTLSModes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  func(string) string
	}{
		{
			name: "tls-files and plaintext",
			args: []string{"--tls-cert", "/c.pem", "--tls-key", "/k.pem", "--plaintext-behind-reverse-proxy"},
			env:  minimalACMElessEnv,
		},
		{
			name: "tls-files and acme",
			args: []string{"--tls-cert", "/c.pem", "--tls-key", "/k.pem", "--acme-domain", "x.example.com"},
			env:  minimalACMElessEnv,
		},
		{
			name: "acme and plaintext",
			args: []string{"--acme-domain", "x.example.com", "--plaintext-behind-reverse-proxy"},
			env:  minimalACMElessEnv,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseServerConfig(tc.args, tc.env)
			if err == nil {
				t.Fatal("expected error for multiple TLS modes, got nil")
			}
			if !strings.Contains(err.Error(), "only one of") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPlaintextModeAcceptsBrowserOriginViaForwardedProto(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	handler := tunnelserver.NewHandler(
		staticFailValidator{err: errors.New("token rejected")},
		socks,
		tunnelserver.HandlerOptions{TrustForwardedProto: true},
	)

	// Simulate a browser WebSocket request forwarded by a TLS-terminating
	// reverse proxy: Origin is https:// but the backend sees plain HTTP.
	req := httptest.NewRequest(http.MethodGet, "http://authunnel.example/protected/tunnel", nil)
	req.Host = "authunnel.example"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://authunnel.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should pass origin check and reach token validation (not be rejected as cross-origin).
	if rr.Code == http.StatusForbidden && strings.Contains(rr.Body.String(), "cross-origin") {
		t.Fatal("expected request to pass origin check in plaintext+TrustForwardedProto mode, but was rejected as cross-origin")
	}
}

func TestPlaintextModeAcceptsBrowserOriginViaForwardedHost(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	handler := tunnelserver.NewHandler(
		staticFailValidator{err: errors.New("token rejected")},
		socks,
		tunnelserver.HandlerOptions{TrustForwardedProto: true},
	)

	// Proxy rewrites Host to the backend address but sets X-Forwarded-Host
	// and X-Forwarded-Proto to the external values.
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/protected/tunnel", nil)
	req.Host = "localhost:8080"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://authunnel.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "authunnel.example.com")
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden && strings.Contains(rr.Body.String(), "cross-origin") {
		t.Fatal("expected request to pass origin check with X-Forwarded-Host set, but was rejected as cross-origin")
	}
}

func TestPlaintextModeAcceptsBrowserOriginViaForwardedProtoMultiProxy(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	handler := tunnelserver.NewHandler(
		staticFailValidator{err: errors.New("token rejected")},
		socks,
		tunnelserver.HandlerOptions{TrustForwardedProto: true},
	)

	// Multi-proxy deployment: X-Forwarded-Proto is comma-separated; the
	// leftmost entry is the original client-facing scheme.
	req := httptest.NewRequest(http.MethodGet, "http://authunnel.example.com/protected/tunnel", nil)
	req.Host = "authunnel.example.com"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://authunnel.example.com")
	req.Header.Set("X-Forwarded-Proto", "https, http")
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden && strings.Contains(rr.Body.String(), "cross-origin") {
		t.Fatal("expected leftmost X-Forwarded-Proto entry to be used for origin check, but was rejected as cross-origin")
	}
}

func TestPlaintextModeAcceptsBrowserOriginViaForwardedHostMultiProxy(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	handler := tunnelserver.NewHandler(
		staticFailValidator{err: errors.New("token rejected")},
		socks,
		tunnelserver.HandlerOptions{TrustForwardedProto: true},
	)

	// Multi-proxy deployment: X-Forwarded-Host is comma-separated; the
	// leftmost entry is the original client-facing host.
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/protected/tunnel", nil)
	req.Host = "localhost:8080"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://authunnel.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "authunnel.example.com, proxy.internal")
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden && strings.Contains(rr.Body.String(), "cross-origin") {
		t.Fatal("expected leftmost X-Forwarded-Host entry to be used for origin check, but was rejected as cross-origin")
	}
}

func TestPlaintextModeIgnoresForwardedHostWhenNotEnabled(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	handler := tunnelserver.NewHandler(staticSuccessValidator{}, socks)

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/protected/tunnel", nil)
	req.Host = "localhost:8080"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://authunnel.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "authunnel.example.com")
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected cross-origin rejection without TrustForwardedProto, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "cross-origin") {
		t.Fatalf("expected cross-origin error, got %q", rr.Body.String())
	}
}

func TestPlaintextModeIgnoresForwardedProtoWhenNotEnabled(t *testing.T) {
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}
	// Default handler: TrustForwardedProto not set.
	handler := tunnelserver.NewHandler(staticSuccessValidator{}, socks)

	req := httptest.NewRequest(http.MethodGet, "http://authunnel.example/protected/tunnel", nil)
	req.Host = "authunnel.example"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://authunnel.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected cross-origin rejection without TrustForwardedProto, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "cross-origin") {
		t.Fatalf("expected cross-origin error, got %q", rr.Body.String())
	}
}

func minimalACMElessEnv(key string) string {
	switch key {
	case "OIDC_ISSUER":
		return "https://issuer.example"
	case "TOKEN_AUDIENCE":
		return "authunnel-server"
	case "ALLOW_OPEN_EGRESS":
		return "true"
	default:
		return ""
	}
}

func TestParseServerConfigRejectsInvalidAllowRulesEnv(t *testing.T) {
	_, err := parseServerConfig(nil, func(key string) string {
		if key == "ALLOW_RULES" {
			return "*.internal:notaport"
		}
		return minimalServerEnv(key)
	})
	if err == nil {
		t.Fatal("expected error for invalid ALLOW_RULES env, got nil")
	}
}

func TestParseServerConfigRejectsNegativeDurations(t *testing.T) {
	tests := []struct {
		name   string
		envKey string
		flag   string
	}{
		{"negative MAX_CONNECTION_DURATION env", "MAX_CONNECTION_DURATION", ""},
		{"negative EXPIRY_WARNING env", "EXPIRY_WARNING", ""},
		{"negative EXPIRY_GRACE env", "EXPIRY_GRACE", ""},
		{"negative --max-connection-duration flag", "", "--max-connection-duration"},
		{"negative --expiry-warning flag", "", "--expiry-warning"},
		{"negative --expiry-grace flag", "", "--expiry-grace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args []string
			env := func(key string) string {
				if key == tt.envKey {
					return "-5m"
				}
				return minimalServerEnv(key)
			}
			if tt.flag != "" {
				args = []string{tt.flag, "-5m"}
			}
			_, err := parseServerConfig(args, env)
			if err == nil {
				t.Fatal("expected error for negative duration, got nil")
			}
			if tt.envKey == "EXPIRY_GRACE" || tt.flag == "--expiry-grace" {
				if !strings.Contains(err.Error(), "must be between 0 and 1h0m0s") {
					t.Fatalf("expected expiry-grace bounds error, got: %v", err)
				}
				return
			}
			if !strings.Contains(err.Error(), "negative") {
				t.Fatalf("expected error mentioning 'negative', got: %v", err)
			}
		})
	}
}

// TestMaxDurationActuallyClosesConnection verifies that the server-side
// longevity enforcement actually terminates the tunnel when the max-duration
// deadline is reached. This is an integration test that sets up a real JWT
// issuer, WebSocket tunnel, and SOCKS5 echo destination.
func TestMaxDurationActuallyClosesConnection(t *testing.T) {
	const audience = "authunnel-server"
	issuer, issuerClient, token := newJWTTestIssuer(t, audience)

	validator, err := tunnelserver.NewJWTTokenValidator(context.Background(), issuer, audience, issuerClient)
	if err != nil {
		t.Fatalf("create validator: %v", err)
	}

	// Start a TCP echo server as the SOCKS destination.
	echoLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	socksServer, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create socks server: %v", err)
	}

	handler := tunnelserver.NewHandler(validator, tunnelserver.NewObservedSOCKSServer(nil, nil, nil, 0),
		tunnelserver.HandlerOptions{
			Longevity: tunnelserver.LongevityConfig{
				MaxDuration:      200 * time.Millisecond,
				ImplementsExpiry: false,
				ExpiryWarning:    50 * time.Millisecond,
			},
		})
	_ = socksServer // We use the observed wrapper above.

	ts := newIPv4TestServer(t, tunnelserver.NewRequestLoggingMiddleware(
		slog.New(slog.NewTextHandler(io.Discard, nil)), handler))

	// Dial the WebSocket tunnel.
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/protected/tunnel"
	ctx := context.Background()
	wsConn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	})
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	defer wsConn.CloseNow()

	mux := wsconn.New(ctx, wsConn)
	defer mux.Close()

	// Perform SOCKS5 CONNECT to the echo server.
	echoHost, echoPortStr, _ := net.SplitHostPort(echoLn.Addr().String())
	var echoPort int
	fmt.Sscanf(echoPortStr, "%d", &echoPort)

	// SOCKS5 greeting: version 5, 1 method, no-auth
	if _, err := mux.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("socks greeting write: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(mux, greeting); err != nil {
		t.Fatalf("socks greeting read: %v", err)
	}

	// SOCKS5 CONNECT to the echo server.
	connectReq := []byte{0x05, 0x01, 0x00, 0x01} // ver, connect, rsv, IPv4
	connectReq = append(connectReq, net.ParseIP(echoHost).To4()...)
	connectReq = append(connectReq, byte(echoPort>>8), byte(echoPort))
	if _, err := mux.Write(connectReq); err != nil {
		t.Fatalf("socks connect write: %v", err)
	}
	connectReply := make([]byte, 10) // 4 header + 4 IPv4 + 2 port
	if _, err := io.ReadFull(mux, connectReply); err != nil {
		t.Fatalf("socks connect read: %v", err)
	}
	if connectReply[1] != 0x00 {
		t.Fatalf("socks connect failed with reply code %d", connectReply[1])
	}

	// Verify the tunnel works: echo a byte.
	if _, err := mux.Write([]byte{0x42}); err != nil {
		t.Fatalf("echo write: %v", err)
	}
	echoBuf := make([]byte, 1)
	if _, err := io.ReadFull(mux, echoBuf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if echoBuf[0] != 0x42 {
		t.Fatalf("echo got %x, want 0x42", echoBuf[0])
	}

	// Now wait for the max-duration to expire. The tunnel MUST be closed by
	// the server after ~200ms. If longevity enforcement is broken, Read will
	// block indefinitely and the test times out.
	deadline := time.After(5 * time.Second)
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := mux.Read(buf)
		readDone <- err
	}()

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("expected read to fail after max-duration, but it succeeded")
		}
		// Any error is acceptable — the connection was closed by the server.
	case <-deadline:
		t.Fatal("tunnel was NOT closed after max-duration expired — longevity enforcement is broken")
	}
}

// TestMaxDurationSendsWarningBeforeDisconnect verifies that the server sends
// an expiry_warning with reason "max_duration" before the tunnel is closed.
func TestMaxDurationSendsWarningBeforeDisconnect(t *testing.T) {
	const audience = "authunnel-server"
	issuer, issuerClient, token := newJWTTestIssuer(t, audience)

	validator, err := tunnelserver.NewJWTTokenValidator(context.Background(), issuer, audience, issuerClient)
	if err != nil {
		t.Fatalf("create validator: %v", err)
	}

	echoLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	handler := tunnelserver.NewHandler(validator, tunnelserver.NewObservedSOCKSServer(nil, nil, nil, 0),
		tunnelserver.HandlerOptions{
			Longevity: tunnelserver.LongevityConfig{
				MaxDuration:      2 * time.Second,
				ImplementsExpiry: false,
				ExpiryWarning:    1 * time.Second,
			},
		})

	ts := newIPv4TestServer(t, tunnelserver.NewRequestLoggingMiddleware(
		slog.New(slog.NewTextHandler(io.Discard, nil)), handler))

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/protected/tunnel"
	ctx := context.Background()
	wsConn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	})
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	defer wsConn.CloseNow()

	mux := wsconn.New(ctx, wsConn)
	defer mux.Close()

	// Complete SOCKS5 handshake to establish the tunnel.
	echoHost, echoPortStr, _ := net.SplitHostPort(echoLn.Addr().String())
	var echoPort int
	fmt.Sscanf(echoPortStr, "%d", &echoPort)

	if _, err := mux.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("socks greeting write: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(mux, greeting); err != nil {
		t.Fatalf("socks greeting read: %v", err)
	}

	connectReq := []byte{0x05, 0x01, 0x00, 0x01}
	connectReq = append(connectReq, net.ParseIP(echoHost).To4()...)
	connectReq = append(connectReq, byte(echoPort>>8), byte(echoPort))
	if _, err := mux.Write(connectReq); err != nil {
		t.Fatalf("socks connect write: %v", err)
	}
	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(mux, connectReply); err != nil {
		t.Fatalf("socks connect read: %v", err)
	}

	// Start draining binary data so control messages are dispatched.
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := mux.Read(buf); err != nil {
				return
			}
		}
	}()

	// Expect expiry_warning with reason "max_duration" before disconnect.
	timer := time.After(10 * time.Second)
	gotWarning := false
	gotDisconnect := false

	for !gotDisconnect {
		select {
		case msg, ok := <-mux.ControlChan():
			if !ok {
				if !gotWarning {
					t.Fatal("control channel closed without receiving expiry_warning")
				}
				// Channel closed after disconnect — acceptable.
				gotDisconnect = true
				continue
			}
			switch msg.Type {
			case "expiry_warning":
				var payload map[string]string
				if err := json.Unmarshal(msg.Data, &payload); err != nil {
					t.Fatalf("unmarshal warning: %v", err)
				}
				if payload["reason"] != "max_duration" {
					t.Fatalf("expected warning reason max_duration, got %s", payload["reason"])
				}
				gotWarning = true
			case "disconnect":
				gotDisconnect = true
			}
		case <-timer:
			t.Fatal("timed out waiting for warning + disconnect")
		}
	}

	if !gotWarning {
		t.Fatal("received disconnect without prior expiry_warning")
	}
}

// TestTokenExpiryActuallyClosesConnection is the token-expiry counterpart of
// TestMaxDurationActuallyClosesConnection. It verifies that when
// ImplementsExpiry is true and the JWT expires, the tunnel is terminated.
func TestTokenExpiryActuallyClosesConnection(t *testing.T) {
	const audience = "authunnel-server"
	// Token expires in 2s — long enough for the WebSocket dial and SOCKS
	// handshake to complete, short enough to verify enforcement.
	issuer, issuerClient, token := newJWTTestIssuerWithExpiry(t, audience, 2*time.Second)

	validator, err := tunnelserver.NewJWTTokenValidator(context.Background(), issuer, audience, issuerClient)
	if err != nil {
		t.Fatalf("create validator: %v", err)
	}

	echoLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	handler := tunnelserver.NewHandler(validator, tunnelserver.NewObservedSOCKSServer(nil, nil, nil, 0),
		tunnelserver.HandlerOptions{
			Longevity: tunnelserver.LongevityConfig{
				ImplementsExpiry: true,
				ExpiryWarning:    500 * time.Millisecond,
			},
		})

	ts := newIPv4TestServer(t, tunnelserver.NewRequestLoggingMiddleware(
		slog.New(slog.NewTextHandler(io.Discard, nil)), handler))

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/protected/tunnel"
	ctx := context.Background()
	wsConn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	})
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	defer wsConn.CloseNow()

	mux := wsconn.New(ctx, wsConn)
	defer mux.Close()

	// Complete SOCKS5 handshake.
	echoHost, echoPortStr, _ := net.SplitHostPort(echoLn.Addr().String())
	var echoPort int
	fmt.Sscanf(echoPortStr, "%d", &echoPort)

	if _, err := mux.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("socks greeting write: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(mux, greeting); err != nil {
		t.Fatalf("socks greeting read: %v", err)
	}

	connectReq := []byte{0x05, 0x01, 0x00, 0x01}
	connectReq = append(connectReq, net.ParseIP(echoHost).To4()...)
	connectReq = append(connectReq, byte(echoPort>>8), byte(echoPort))
	if _, err := mux.Write(connectReq); err != nil {
		t.Fatalf("socks connect write: %v", err)
	}
	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(mux, connectReply); err != nil {
		t.Fatalf("socks connect read: %v", err)
	}
	if connectReply[1] != 0x00 {
		t.Fatalf("socks connect failed with reply code %d", connectReply[1])
	}

	// Verify tunnel works before expiry.
	if _, err := mux.Write([]byte{0x42}); err != nil {
		t.Fatalf("echo write: %v", err)
	}
	echoBuf := make([]byte, 1)
	if _, err := io.ReadFull(mux, echoBuf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if echoBuf[0] != 0x42 {
		t.Fatalf("echo got %x, want 0x42", echoBuf[0])
	}

	// Wait for the token to expire. The tunnel MUST close.
	deadline := time.After(10 * time.Second)
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := mux.Read(buf)
		readDone <- err
	}()

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("expected read to fail after token expiry, but it succeeded")
		}
	case <-deadline:
		t.Fatal("tunnel was NOT closed after token expired — token-expiry enforcement is broken")
	}
}

// TestTokenRefreshExtendsTunnelBeyondOriginalExpiry is a full integration test
// that verifies a tunnel can be extended past the original access token's expiry
// by refreshing with a new JWT. It uses a real JWT issuer, WebSocket tunnel,
// and SOCKS5 echo server.
func TestTokenRefreshExtendsTunnelBeyondOriginalExpiry(t *testing.T) {
	const audience = "authunnel-server"
	// Initial token expires in 2s.
	issuer, issuerClient, initialToken, mint := newJWTTestIssuerFull(t, audience, 2*time.Second)

	validator, err := tunnelserver.NewJWTTokenValidator(context.Background(), issuer, audience, issuerClient)
	if err != nil {
		t.Fatalf("create validator: %v", err)
	}

	// TCP echo server.
	echoLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	handler := tunnelserver.NewHandler(validator, tunnelserver.NewObservedSOCKSServer(nil, nil, nil, 0),
		tunnelserver.HandlerOptions{
			Longevity: tunnelserver.LongevityConfig{
				ImplementsExpiry: true,
				ExpiryWarning:    1 * time.Second,
			},
		})

	ts := newIPv4TestServer(t, tunnelserver.NewRequestLoggingMiddleware(
		slog.New(slog.NewTextHandler(io.Discard, nil)), handler))

	// Dial the WebSocket tunnel with the short-lived initial token.
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/protected/tunnel"
	ctx := context.Background()
	wsConn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + initialToken}},
	})
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	defer wsConn.CloseNow()

	mux := wsconn.New(ctx, wsConn)
	defer mux.Close()

	// Complete SOCKS5 handshake.
	echoHost, echoPortStr, _ := net.SplitHostPort(echoLn.Addr().String())
	var echoPort int
	fmt.Sscanf(echoPortStr, "%d", &echoPort)

	if _, err := mux.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("socks greeting write: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(mux, greeting); err != nil {
		t.Fatalf("socks greeting read: %v", err)
	}

	connectReq := []byte{0x05, 0x01, 0x00, 0x01}
	connectReq = append(connectReq, net.ParseIP(echoHost).To4()...)
	connectReq = append(connectReq, byte(echoPort>>8), byte(echoPort))
	if _, err := mux.Write(connectReq); err != nil {
		t.Fatalf("socks connect write: %v", err)
	}
	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(mux, connectReply); err != nil {
		t.Fatalf("socks connect read: %v", err)
	}
	if connectReply[1] != 0x00 {
		t.Fatalf("socks connect failed with reply code %d", connectReply[1])
	}

	// Start a background reader so control messages are dispatched.
	binaryData := make(chan []byte, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := mux.Read(buf)
			if err != nil {
				close(binaryData)
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			binaryData <- data
		}
	}()

	// Wait for the expiry_warning (fires ~1s before the 2s expiry).
	timer := time.After(5 * time.Second)
	select {
	case msg := <-mux.ControlChan():
		if msg.Type != "expiry_warning" {
			t.Fatalf("expected expiry_warning, got %s", msg.Type)
		}
	case <-timer:
		t.Fatal("timed out waiting for expiry_warning")
	}

	// Mint a fresh token (expires 1 hour from now) and send it as a refresh.
	freshToken := mint(1 * time.Hour)
	tokenData, _ := json.Marshal(map[string]string{"access_token": freshToken})
	if err := mux.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: tokenData,
	}); err != nil {
		t.Fatalf("send token_refresh: %v", err)
	}

	// Wait for token_accepted.
	select {
	case msg := <-mux.ControlChan():
		if msg.Type != "token_accepted" {
			t.Fatalf("expected token_accepted, got %s", msg.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for token_accepted")
	}

	// Sleep past the original token's expiry. Without the refresh, the tunnel
	// would have been closed by now.
	time.Sleep(2 * time.Second)

	// Verify the tunnel is still alive by echoing data through it.
	if _, err := mux.Write([]byte{0xAB}); err != nil {
		t.Fatalf("echo write after refresh: %v", err)
	}

	select {
	case data := <-binaryData:
		if len(data) != 1 || data[0] != 0xAB {
			t.Fatalf("echo after refresh got %x, want 0xAB", data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("echo read timed out after refresh — tunnel did not survive past original expiry")
	}
}

// TestExpiryGraceKeepsTunnelAliveForCachedTokenRefresh is a full integration
// test that verifies the --expiry-grace flag wires through config parsing into
// an actual server instance. A short-lived token (2s) with a 2s grace period
// gives a connection deadline of T+4s. The warning fires, the client refreshes
// with the same cached token (same exp), and the server schedules a retry
// warning. On the retry the client sends a genuinely new token, extending the
// tunnel past the original deadline. The echo server confirms data still flows.
func TestExpiryGraceKeepsTunnelAliveForCachedTokenRefresh(t *testing.T) {
	const audience = "authunnel-server"
	// Initial token expires in 2s.
	issuer, issuerClient, initialToken, mint := newJWTTestIssuerFull(t, audience, 2*time.Second)

	validator, err := tunnelserver.NewJWTTokenValidator(context.Background(), issuer, audience, issuerClient)
	if err != nil {
		t.Fatalf("create validator: %v", err)
	}

	// TCP echo server.
	echoLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// Key: ExpiryGrace is set, and ExpiryWarning > ExpiryGrace (the
	// scenario that triggered the reviewer concern).
	handler := tunnelserver.NewHandler(validator, tunnelserver.NewObservedSOCKSServer(nil, nil, nil, 0),
		tunnelserver.HandlerOptions{
			Longevity: tunnelserver.LongevityConfig{
				ImplementsExpiry: true,
				ExpiryWarning:    3 * time.Second,
				ExpiryGrace:      2 * time.Second,
			},
		})

	ts := newIPv4TestServer(t, tunnelserver.NewRequestLoggingMiddleware(
		slog.New(slog.NewTextHandler(io.Discard, nil)), handler))

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/protected/tunnel"
	ctx := context.Background()
	wsConn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + initialToken}},
	})
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	defer wsConn.CloseNow()

	mux := wsconn.New(ctx, wsConn)
	defer mux.Close()

	// Complete SOCKS5 handshake.
	echoHost, echoPortStr, _ := net.SplitHostPort(echoLn.Addr().String())
	var echoPort int
	fmt.Sscanf(echoPortStr, "%d", &echoPort)

	if _, err := mux.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("socks greeting write: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(mux, greeting); err != nil {
		t.Fatalf("socks greeting read: %v", err)
	}

	connectReq := []byte{0x05, 0x01, 0x00, 0x01}
	connectReq = append(connectReq, net.ParseIP(echoHost).To4()...)
	connectReq = append(connectReq, byte(echoPort>>8), byte(echoPort))
	if _, err := mux.Write(connectReq); err != nil {
		t.Fatalf("socks connect write: %v", err)
	}
	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(mux, connectReply); err != nil {
		t.Fatalf("socks connect read: %v", err)
	}
	if connectReply[1] != 0x00 {
		t.Fatalf("socks connect failed with reply code %d", connectReply[1])
	}

	// Background reader so control messages are dispatched.
	binaryData := make(chan []byte, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := mux.Read(buf)
			if err != nil {
				close(binaryData)
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			binaryData <- data
		}
	}()

	// Token exp=2s, grace=2s → deadline at T+4s, warning=3s → fires at T+1s.
	// 1. Wait for first expiry_warning.
	select {
	case msg := <-mux.ControlChan():
		if msg.Type != "expiry_warning" {
			t.Fatalf("expected expiry_warning, got %s", msg.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for expiry_warning")
	}

	// 2. Refresh with the SAME token (simulating a cached-token provider).
	//    Mint a token with the same 2s lifetime as the original — by the time
	//    this runs ~1s has elapsed, so the new token's exp is ~1s in the future,
	//    which is close to (or equal to) the original exp. The server should
	//    accept it (same or slightly different exp) and schedule a retry warning.
	cachedToken := mint(2 * time.Second)
	tokenData, _ := json.Marshal(map[string]string{"access_token": cachedToken})
	if err := mux.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: tokenData,
	}); err != nil {
		t.Fatalf("send cached token_refresh: %v", err)
	}

	// Wait for token_accepted.
	select {
	case msg := <-mux.ControlChan():
		if msg.Type != "token_accepted" {
			t.Fatalf("expected token_accepted for cached token, got %s", msg.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for token_accepted (cached)")
	}

	// 3. Wait for the retry warning (remaining/2 of the remaining deadline).
	select {
	case msg := <-mux.ControlChan():
		if msg.Type == "disconnect" {
			t.Fatal("tunnel disconnected without giving a retry warning")
		}
		if msg.Type != "expiry_warning" {
			t.Fatalf("expected retry expiry_warning, got %s", msg.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for retry expiry_warning")
	}

	// 4. Refresh with a genuinely new, long-lived token.
	freshToken := mint(1 * time.Hour)
	tokenData, _ = json.Marshal(map[string]string{"access_token": freshToken})
	if err := mux.SendControl(wsconn.ControlMessage{
		Type: "token_refresh",
		Data: tokenData,
	}); err != nil {
		t.Fatalf("send fresh token_refresh: %v", err)
	}

	select {
	case msg := <-mux.ControlChan():
		if msg.Type != "token_accepted" {
			t.Fatalf("expected token_accepted for fresh token, got %s", msg.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for token_accepted (fresh)")
	}

	// 5. Sleep past the original deadline (T+4s). Without the grace+retry
	//    logic the tunnel would be dead by now.
	time.Sleep(2 * time.Second)

	// 6. Verify the tunnel is still alive by echoing data.
	if _, err := mux.Write([]byte{0xCD}); err != nil {
		t.Fatalf("echo write after refresh: %v", err)
	}
	select {
	case data := <-binaryData:
		if len(data) != 1 || data[0] != 0xCD {
			t.Fatalf("echo after refresh got %x, want 0xCD", data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("echo read timed out — tunnel did not survive past original deadline with grace+refresh")
	}
}

func TestCheckACMECacheDirCreatesMissingDirectoryWithOwnerOnlyMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acme")
	if err := checkACMECacheDir(dir); err != nil {
		t.Fatalf("checkACMECacheDir failed: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("ACME dir created with %#o, want 0o700", got)
	}
}

func TestCheckACMECacheDirRejectsExistingGroupWritableDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acme")
	if err := os.MkdirAll(dir, 0o770); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	err := checkACMECacheDir(dir)
	if err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("expected group/world writable rejection, got %v", err)
	}
}

func TestCheckACMECacheDirAcceptsExistingSafeDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acme")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := checkACMECacheDir(dir); err != nil {
		t.Fatalf("0o700 ACME dir should be accepted: %v", err)
	}
}

func TestCheckACMECacheDirRejectsSafeButUnwritableDirectory(t *testing.T) {
	// A 0o500 dir is current-user-owned and not group/world writable, so the
	// safety check accepts it. autocert would later fail to persist
	// certificates; surface that at startup with the temp-file write probe.
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX permission checks; cannot exercise unwritable rejection")
	}
	dir := filepath.Join(t.TempDir(), "acme")
	if err := os.MkdirAll(dir, 0o500); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	err := checkACMECacheDir(dir)
	if err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("expected writability rejection, got %v", err)
	}
}

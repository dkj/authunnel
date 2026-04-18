package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	socks5 "github.com/armon/go-socks5"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"authunnel/internal/tunnelserver"
)

func TestManagedOIDCProxyCommandE2EWithAudienceAndRedirectPort(t *testing.T) {
	provider := newJWTBackedOIDCProvider(t, "default-audience")
	server, wsHTTPClient := newJWTValidatedTunnelServer(t, provider.issuer(), "authunnel-server", provider.server.Client())

	targetListener, targetDone, payload := newEchoTarget(t)
	defer targetListener.Close()

	var stderr bytes.Buffer
	redirectPort := freeLoopbackPortForTest(t)
	cfg := clientConfig{
		AuthMode:         authModeOIDC,
		OIDCIssuer:       provider.issuer(),
		OIDCClientID:     "authunnel-cli",
		OIDCAudience:     "authunnel-server",
		OIDCScopes:       normalizeScopes("openid"),
		OIDCCache:        filepathForTest(t, "tokens.json"),
		OIDCRedirectPort: redirectPort,
		TunnelURL:        server.URL + "/protected/tunnel",
		ProxyCommandMode: true,
		TargetHost:       "127.0.0.1",
		TargetPort:       targetListener.Addr().(*net.TCPAddr).Port,
		Stderr:           &stderr,
		HTTPClient:       wsHTTPClient,
		AuthHTTPClient:   provider.server.Client(),
	}

	browserCalls := 0
	cfg.BrowserOpener = func(ctx context.Context, authURL string) error {
		browserCalls++
		parsed, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		if got := parsed.Query().Get("audience"); got != "authunnel-server" {
			return fmt.Errorf("unexpected authorize audience %q", got)
		}
		redirectURI, err := url.Parse(parsed.Query().Get("redirect_uri"))
		if err != nil {
			return err
		}
		if got := redirectURI.Port(); got != fmt.Sprintf("%d", redirectPort) {
			return fmt.Errorf("unexpected redirect port %q", got)
		}
		return provider.completeBrowserAuth(authURL)
	}

	firstStdout, firstInput := stdioPair(payload)
	cfg.Stdout = firstStdout
	cfg.Stdin = firstInput
	source, err := newAuthTokenSource(cfg)
	if err != nil {
		t.Fatalf("create auth source: %v", err)
	}

	runCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := runProxyCommandMode(runCtx, cfg, source); err != nil {
		t.Fatalf("proxycommand e2e failed: %v\nstderr:\n%s", err, stderr.String())
	}
	if got := firstStdout.String(); got != string(payload) {
		t.Fatalf("unexpected stdout payload: got %q want %q", got, string(payload))
	}
	if browserCalls != 1 {
		t.Fatalf("expected one browser-driven login, got %d", browserCalls)
	}
	if err := waitForTargetResult(targetDone); err != nil {
		t.Fatalf("target echo server failed: %v", err)
	}

	secondTarget, secondDone, payload := newEchoTarget(t)
	defer secondTarget.Close()
	cfg.TargetPort = secondTarget.Addr().(*net.TCPAddr).Port
	secondStdout, secondInput := stdioPair(payload)
	cfg.Stdout = secondStdout
	cfg.Stdin = secondInput
	cfg.BrowserOpener = func(context.Context, string) error {
		t.Fatalf("cached token should avoid a second interactive login")
		return nil
	}

	source, err = newAuthTokenSource(cfg)
	if err != nil {
		t.Fatalf("create second auth source: %v", err)
	}
	secondCtx, cancelSecond := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelSecond()
	if err := runProxyCommandMode(secondCtx, cfg, source); err != nil {
		t.Fatalf("second proxycommand e2e failed: %v", err)
	}
	if got := secondStdout.String(); got != string(payload) {
		t.Fatalf("unexpected second stdout payload: got %q want %q", got, string(payload))
	}
	if err := waitForTargetResult(secondDone); err != nil {
		t.Fatalf("second target echo server failed: %v", err)
	}
}

func TestManagedOIDCProxyCommandE2ERejectsWrongAudience(t *testing.T) {
	provider := newJWTBackedOIDCProvider(t, "default-audience")
	server, wsHTTPClient := newJWTValidatedTunnelServer(t, provider.issuer(), "authunnel-server", provider.server.Client())

	targetListener, acceptedConn, payload := newSilentEchoTarget(t)
	defer targetListener.Close()

	var stderr bytes.Buffer
	cfg := clientConfig{
		AuthMode:         authModeOIDC,
		OIDCIssuer:       provider.issuer(),
		OIDCClientID:     "authunnel-cli",
		OIDCAudience:     "wrong-audience",
		OIDCScopes:       normalizeScopes("openid"),
		OIDCCache:        filepathForTest(t, "tokens.json"),
		OIDCRedirectPort: freeLoopbackPortForTest(t),
		TunnelURL:        server.URL + "/protected/tunnel",
		ProxyCommandMode: true,
		TargetHost:       "127.0.0.1",
		TargetPort:       targetListener.Addr().(*net.TCPAddr).Port,
		Stderr:           &stderr,
		HTTPClient:       wsHTTPClient,
		AuthHTTPClient:   provider.server.Client(),
		BrowserOpener: func(ctx context.Context, authURL string) error {
			return provider.completeBrowserAuth(authURL)
		},
	}

	stdout, input := stdioPair(payload)
	cfg.Stdout = stdout
	cfg.Stdin = input
	source, err := newAuthTokenSource(cfg)
	if err != nil {
		t.Fatalf("create auth source: %v", err)
	}

	runCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = runProxyCommandMode(runCtx, cfg, source)
	if err == nil {
		t.Fatalf("expected wrong-audience token to be rejected")
	}
	if !strings.Contains(err.Error(), "websocket dial failed") {
		t.Fatalf("expected websocket dial failure, got %v", err)
	}

	select {
	case conn := <-acceptedConn:
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("target should not receive a connection when audience validation fails")
	case <-time.After(200 * time.Millisecond):
	}
}

type jwtBackedOIDCProvider struct {
	t *testing.T

	server *httptest.Server

	privateKey *rsa.PrivateKey
	jwk        jose.JSONWebKey

	defaultAudience string

	mu    sync.Mutex
	codes map[string]jwtAuthRequest
}

type jwtAuthRequest struct {
	codeChallenge string
	audience      string
}

func newJWTBackedOIDCProvider(t *testing.T, defaultAudience string) *jwtBackedOIDCProvider {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	provider := &jwtBackedOIDCProvider{
		t:               t,
		privateKey:      privateKey,
		defaultAudience: defaultAudience,
		codes:           map[string]jwtAuthRequest{},
		jwk: jose.JSONWebKey{
			Key:       &privateKey.PublicKey,
			KeyID:     "test-key",
			Algorithm: string(jose.RS256),
			Use:       "sig",
		},
	}

	var issuer string
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/issuer/.well-known/openid-configuration":
			writeJSONForTest(t, w, map[string]string{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/auth",
				"token_endpoint":         issuer + "/token",
				"jwks_uri":               issuer + "/keys",
			})
		case "/issuer/keys", "/keys":
			writeJSONForTest(t, w, map[string]any{
				"keys": []jose.JSONWebKey{provider.jwk},
			})
		case "/issuer/auth", "/auth":
			provider.handleAuthorize(w, r)
		case "/issuer/token", "/token":
			provider.handleToken(w, r, issuer)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	provider.server = server
	issuer = server.URL + "/issuer"
	return provider
}

func (p *jwtBackedOIDCProvider) issuer() string {
	return p.server.URL + "/issuer"
}

func (p *jwtBackedOIDCProvider) completeBrowserAuth(authURL string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(authURL)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return fmt.Errorf("unexpected browser callback status %d: %s", response.StatusCode, string(body))
	}
	return nil
}

func (p *jwtBackedOIDCProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	redirectURI := query.Get("redirect_uri")
	callbackURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audience := query.Get("audience")
	if audience == "" {
		audience = p.defaultAudience
	}
	code := "auth-code-1"

	p.mu.Lock()
	p.codes[code] = jwtAuthRequest{
		codeChallenge: query.Get("code_challenge"),
		audience:      audience,
	}
	p.mu.Unlock()

	values := callbackURL.Query()
	values.Set("code", code)
	values.Set("state", query.Get("state"))
	callbackURL.RawQuery = values.Encode()
	http.Redirect(w, r, callbackURL.String(), http.StatusFound)
}

func (p *jwtBackedOIDCProvider) handleToken(w http.ResponseWriter, r *http.Request, issuer string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		http.Error(w, "unsupported grant type", http.StatusBadRequest)
		return
	}

	p.mu.Lock()
	request, ok := p.codes[r.Form.Get("code")]
	p.mu.Unlock()
	if !ok {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}

	verifier := r.Form.Get("code_verifier")
	hashed := sha256.Sum256([]byte(verifier))
	if got := base64.RawURLEncoding.EncodeToString(hashed[:]); got != request.codeChallenge {
		http.Error(w, "invalid code verifier", http.StatusBadRequest)
		return
	}

	token, err := p.signAccessToken(issuer, request.audience)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONForTest(p.t, w, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func (p *jwtBackedOIDCProvider) signAccessToken(issuer, audience string) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: p.privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", p.jwk.KeyID),
	)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	claims := &oidc.AccessTokenClaims{
		TokenClaims: oidc.TokenClaims{
			Issuer:     issuer,
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
	return jwt.Signed(signer).Claims(claims).Serialize()
}

func newJWTValidatedTunnelServer(t *testing.T, issuer, audience string, validatorHTTPClient *http.Client) (*httptest.Server, *http.Client) {
	t.Helper()

	validator, err := tunnelserver.NewJWTTokenValidator(context.Background(), issuer, audience, validatorHTTPClient)
	if err != nil {
		t.Fatalf("create JWT validator: %v", err)
	}
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create SOCKS5 server: %v", err)
	}
	server := newIPv4TLSTestServer(t, tunnelserver.NewHandler(validator, socks))
	client := server.Client()
	client.Timeout = 5 * time.Second
	return server, client
}

func newEchoTarget(t *testing.T) (net.Listener, <-chan error, []byte) {
	t.Helper()

	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start echo target: %v", err)
	}
	payload := []byte("hello-over-authunnel")
	targetDone := make(chan error, 1)
	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			targetDone <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			targetDone <- err
			return
		}
		if !bytes.Equal(buf, payload) {
			targetDone <- fmt.Errorf("unexpected payload %q", string(buf))
			return
		}
		_, err = conn.Write(buf)
		targetDone <- err
	}()
	return targetListener, targetDone, payload
}

func newSilentEchoTarget(t *testing.T) (net.Listener, <-chan net.Conn, []byte) {
	t.Helper()

	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start target listener: %v", err)
	}
	acceptedConn := make(chan net.Conn, 1)
	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		acceptedConn <- conn
	}()
	return targetListener, acceptedConn, []byte("hello-over-authunnel")
}

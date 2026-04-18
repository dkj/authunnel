package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseClientConfigHelpFlag(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		_, err := parseClientConfig([]string{arg}, func(string) string { return "" })
		if !errors.Is(err, flag.ErrHelp) {
			t.Errorf("parseClientConfig(%q) error = %v, want flag.ErrHelp", arg, err)
		}
	}
}

func TestParseClientConfigHelpPositional(t *testing.T) {
	_, err := parseClientConfig([]string{"help"}, func(string) string { return "" })
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("parseClientConfig(\"help\") error = %v, want flag.ErrHelp", err)
	}
}

func TestParseClientConfigVersionFlag(t *testing.T) {
	for _, arg := range []string{"--version", "version"} {
		_, err := parseClientConfig([]string{arg}, func(string) string { return "" })
		if !errors.Is(err, flag.ErrHelp) {
			t.Errorf("parseClientConfig(%q) error = %v, want flag.ErrHelp", arg, err)
		}
	}
}

func TestParseClientConfigAccessTokenFlag(t *testing.T) {
	cfg, err := parseClientConfig([]string{"--access-token", "tok123"}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseClientConfig failed: %v", err)
	}
	if cfg.AccessToken != "tok123" {
		t.Fatalf("unexpected AccessToken: got %q want %q", cfg.AccessToken, "tok123")
	}
	if cfg.AuthMode != authModeManual {
		t.Fatalf("unexpected AuthMode: got %q want %q", cfg.AuthMode, authModeManual)
	}
}

func TestParseClientConfigAcceptsTunnelURLFlag(t *testing.T) {
	cfg, err := parseClientConfig([]string{
		"--access-token", "tok123",
		"--tunnel-url", "https://example.com/protected/tunnel",
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseClientConfig failed: %v", err)
	}
	if cfg.TunnelURL != "https://example.com/protected/tunnel" {
		t.Fatalf("unexpected TunnelURL: got %q", cfg.TunnelURL)
	}
}

func TestParseClientConfigRejectsMixedManualAndOIDCAuth(t *testing.T) {
	_, err := parseClientConfig([]string{"--oidc-issuer", "http://issuer", "--oidc-client-id", "client"}, func(key string) string {
		if key == "ACCESS_TOKEN" {
			return "token"
		}
		return ""
	})
	if err == nil {
		t.Fatalf("expected mutual exclusivity validation error")
	}
}

func TestParseClientConfigAcceptsOIDCAudienceAndRedirectPort(t *testing.T) {
	cfg, err := parseClientConfig([]string{
		"--oidc-issuer", "https://issuer.example",
		"--oidc-client-id", "client",
		"--oidc-audience", "authunnel-server",
		"--oidc-redirect-port", "38081",
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseClientConfig failed: %v", err)
	}
	if cfg.OIDCAudience != "authunnel-server" {
		t.Fatalf("unexpected OIDC audience: got %q", cfg.OIDCAudience)
	}
	if cfg.OIDCRedirectPort != 38081 {
		t.Fatalf("unexpected OIDC redirect port: got %d", cfg.OIDCRedirectPort)
	}
}

func TestParseClientConfigRejectsInvalidOIDCRedirectPort(t *testing.T) {
	_, err := parseClientConfig([]string{
		"--oidc-issuer", "http://issuer",
		"--oidc-client-id", "client",
		"--oidc-redirect-port", "70000",
	}, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "between 0 and 65535") {
		t.Fatalf("expected redirect-port validation error, got %v", err)
	}
}

func TestParseClientConfigRejectsManualAuthWithManagedOIDCFlags(t *testing.T) {
	_, err := parseClientConfig([]string{"--oidc-audience", "authunnel-server"}, func(key string) string {
		if key == "ACCESS_TOKEN" {
			return "token"
		}
		return ""
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("expected manual/OIDC validation error, got %v", err)
	}
}

func TestParseClientConfigRejectsAccessTokenWithOIDCCacheOrNoBrowser(t *testing.T) {
	for _, extra := range [][]string{
		{"--oidc-cache", "/tmp/tokens.json"},
		{"--oidc-no-browser"},
		{"--oidc-scopes", "openid"},
	} {
		args := append([]string{"--access-token", "tok"}, extra...)
		_, err := parseClientConfig(args, func(string) string { return "" })
		if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
			t.Errorf("parseClientConfig(%v) expected conflict error, got %v", args, err)
		}
	}
}

func TestParseClientConfigRejectsHTTPTunnelURL(t *testing.T) {
	_, err := parseClientConfig([]string{
		"--tunnel-url", "http://tunnel.example/protected/tunnel",
		"--oidc-issuer", "https://issuer.example",
		"--oidc-client-id", "client",
	}, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("expected https tunnel-url rejection, got: %v", err)
	}
}

func TestParseClientConfigAcceptsHTTPTunnelURLWithInsecureFlag(t *testing.T) {
	cfg, err := parseClientConfig([]string{
		"--tunnel-url", "http://tunnel.example/protected/tunnel",
		"--oidc-issuer", "https://issuer.example",
		"--oidc-client-id", "client",
		"--insecure-tunnel-url",
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("insecure-tunnel-url flag should allow http tunnel URL: %v", err)
	}
	if !cfg.InsecureTunnelURL {
		t.Fatal("InsecureTunnelURL should be true")
	}
}

func TestParseClientConfigRejectsHTTPOIDCIssuer(t *testing.T) {
	_, err := parseClientConfig([]string{
		"--oidc-issuer", "http://issuer.example",
		"--oidc-client-id", "client",
	}, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("expected https oidc-issuer rejection, got: %v", err)
	}
}

func TestParseClientConfigAcceptsHTTPOIDCIssuerWithInsecureFlag(t *testing.T) {
	cfg, err := parseClientConfig([]string{
		"--oidc-issuer", "http://issuer.example",
		"--oidc-client-id", "client",
		"--insecure-oidc-issuer",
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("insecure-oidc-issuer flag should allow http issuer: %v", err)
	}
	if !cfg.InsecureOIDCIssuer {
		t.Fatal("InsecureOIDCIssuer should be true")
	}
}

func TestParseClientConfigAcceptsHTTPSIssuerAndTunnelURL(t *testing.T) {
	cfg, err := parseClientConfig([]string{
		"--oidc-issuer", "https://issuer.example",
		"--oidc-client-id", "client",
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("valid https:// URLs should be accepted: %v", err)
	}
	if cfg.InsecureTunnelURL || cfg.InsecureOIDCIssuer {
		t.Fatal("insecure flags should default to false")
	}
}

func TestManagedOIDCTokenSourceUsesCachedValidTokenWithoutBrowser(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	cachePath := filepathForTest(t, "tokens.json")
	cache := tokenCache{
		Issuer:      provider.issuer(),
		ClientID:    "authunnel-cli",
		Scopes:      normalizeScopes("openid offline_access"),
		AccessToken: "cached-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(5 * time.Minute),
	}
	writeTokenCacheForTest(t, cachePath, cache)

	var browserCalls int
	source := &managedOIDCTokenSource{
		issuer:      provider.issuer(),
		clientID:    "authunnel-cli",
		scopes:      normalizeScopes("openid offline_access"),
		cachePath:   cachePath,
		httpClient:  provider.server.Client(),
		output:      io.Discard,
		openBrowser: func(context.Context, string) error { browserCalls++; return nil },
		now:         time.Now,
	}

	token, err := source.AccessToken(context.Background(), true)
	if err != nil {
		t.Fatalf("expected cached token lookup to succeed, got error: %v", err)
	}
	if token != "cached-access-token" {
		t.Fatalf("unexpected token: got %q", token)
	}
	if browserCalls != 0 {
		t.Fatalf("expected browser not to be opened, got %d calls", browserCalls)
	}
	if provider.tokenRequests() != 0 {
		t.Fatalf("expected token endpoint to remain unused, got %d requests", provider.tokenRequests())
	}
}

func TestManagedOIDCTokenSourceRefreshesExpiredTokenBeforeBrowser(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	cachePath := filepathForTest(t, "tokens.json")
	cache := tokenCache{
		Issuer:       provider.issuer(),
		ClientID:     "authunnel-cli",
		Scopes:       normalizeScopes("openid offline_access"),
		AccessToken:  "expired-token",
		RefreshToken: provider.validRefreshToken,
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Minute),
	}
	writeTokenCacheForTest(t, cachePath, cache)

	var browserCalls int
	source := &managedOIDCTokenSource{
		issuer:      provider.issuer(),
		clientID:    "authunnel-cli",
		scopes:      normalizeScopes("openid offline_access"),
		cachePath:   cachePath,
		httpClient:  provider.server.Client(),
		output:      io.Discard,
		openBrowser: func(context.Context, string) error { browserCalls++; return nil },
		now:         time.Now,
	}

	token, err := source.AccessToken(context.Background(), true)
	if err != nil {
		t.Fatalf("expected refresh flow to succeed, got error: %v", err)
	}
	if token != provider.refreshedAccessToken {
		t.Fatalf("unexpected token: got %q want %q", token, provider.refreshedAccessToken)
	}
	if browserCalls != 0 {
		t.Fatalf("expected browser not to be opened, got %d calls", browserCalls)
	}
	if provider.refreshRequests() == 0 {
		t.Fatalf("expected refresh token flow to be exercised")
	}
}

func TestManagedOIDCTokenSourceFallsBackToInteractiveLoginWhenRefreshFails(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	provider.rejectRefresh = true

	cachePath := filepathForTest(t, "tokens.json")
	cache := tokenCache{
		Issuer:       provider.issuer(),
		ClientID:     "authunnel-cli",
		Scopes:       normalizeScopes("openid offline_access"),
		AccessToken:  "expired-token",
		RefreshToken: provider.validRefreshToken,
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Minute),
	}
	writeTokenCacheForTest(t, cachePath, cache)

	var output bytes.Buffer
	var browserCalls int
	source := &managedOIDCTokenSource{
		issuer:     provider.issuer(),
		clientID:   "authunnel-cli",
		scopes:     normalizeScopes("openid offline_access"),
		cachePath:  cachePath,
		httpClient: provider.server.Client(),
		output:     &output,
		openBrowser: func(ctx context.Context, authURL string) error {
			browserCalls++
			return provider.completeBrowserAuth(authURL)
		},
		now: time.Now,
	}

	token, err := source.AccessToken(context.Background(), true)
	if err != nil {
		t.Fatalf("expected interactive fallback to succeed, got error: %v", err)
	}
	if token != provider.codeAccessToken {
		t.Fatalf("unexpected token: got %q want %q", token, provider.codeAccessToken)
	}
	if browserCalls != 1 {
		t.Fatalf("expected browser opener to be called once, got %d", browserCalls)
	}
	if provider.codeRequests() == 0 {
		t.Fatalf("expected authorization code exchange to be exercised")
	}
	if !strings.Contains(output.String(), "Open this URL to authenticate:") {
		t.Fatalf("expected auth URL message on configured stderr output, got %q", output.String())
	}
}

func TestManagedOIDCTokenSourceRejectsCallbackStateMismatch(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	provider.redirectState = "wrong-state"

	source := &managedOIDCTokenSource{
		issuer:     provider.issuer(),
		clientID:   "authunnel-cli",
		scopes:     normalizeScopes("openid offline_access"),
		cachePath:  filepathForTest(t, "tokens.json"),
		httpClient: provider.server.Client(),
		output:     io.Discard,
		openBrowser: func(ctx context.Context, authURL string) error {
			return provider.completeBrowserAuth(authURL)
		},
		now: time.Now,
	}

	if _, err := source.AccessToken(context.Background(), true); err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("expected state mismatch error, got %v", err)
	}
}

func TestManagedOIDCTokenSourceIncludesAudienceAndConfiguredRedirectPortInAuthURL(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	redirectPort := freeLoopbackPortForTest(t)

	source := &managedOIDCTokenSource{
		issuer:       provider.issuer(),
		clientID:     "authunnel-cli",
		audience:     "authunnel-server",
		scopes:       normalizeScopes("openid offline_access"),
		cachePath:    filepathForTest(t, "tokens.json"),
		redirectPort: redirectPort,
		httpClient:   provider.server.Client(),
		output:       io.Discard,
		openBrowser: func(ctx context.Context, authURL string) error {
			parsed, err := url.Parse(authURL)
			if err != nil {
				return err
			}
			if got := parsed.Query().Get("audience"); got != "authunnel-server" {
				t.Fatalf("unexpected audience query parameter: got %q", got)
			}
			redirectURI, err := url.Parse(parsed.Query().Get("redirect_uri"))
			if err != nil {
				return err
			}
			if got := redirectURI.Port(); got != strconv.Itoa(redirectPort) {
				t.Fatalf("unexpected redirect port: got %q want %q", got, strconv.Itoa(redirectPort))
			}
			return provider.completeBrowserAuth(authURL)
		},
		now: time.Now,
	}

	token, err := source.AccessToken(context.Background(), true)
	if err != nil {
		t.Fatalf("expected interactive flow to succeed, got error: %v", err)
	}
	if token != provider.codeAccessToken {
		t.Fatalf("unexpected token: got %q want %q", token, provider.codeAccessToken)
	}
}

func TestManagedOIDCTokenSourceFailsClosedWhenRedirectPortInUse(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	defer listener.Close()

	redirectPort := listener.Addr().(*net.TCPAddr).Port
	browserCalls := 0
	source := &managedOIDCTokenSource{
		issuer:       provider.issuer(),
		clientID:     "authunnel-cli",
		audience:     "authunnel-server",
		scopes:       normalizeScopes("openid offline_access"),
		cachePath:    filepathForTest(t, "tokens.json"),
		redirectPort: redirectPort,
		httpClient:   provider.server.Client(),
		output:       io.Discard,
		openBrowser: func(context.Context, string) error {
			browserCalls++
			return nil
		},
		now: time.Now,
	}

	_, err = source.AccessToken(context.Background(), true)
	if err == nil || !strings.Contains(err.Error(), "listen for OIDC callback") {
		t.Fatalf("expected callback-listener failure, got %v", err)
	}
	if browserCalls != 0 {
		t.Fatalf("expected browser opener not to be called when the redirect port is unavailable")
	}
}

func TestManagedOIDCTokenSourceIgnoresMismatchedCacheAndRunsInteractiveFlow(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		Issuer:      "http://other-issuer",
		ClientID:    "other-client",
		Audience:    "other-audience",
		Scopes:      "openid",
		AccessToken: "stale",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(5 * time.Minute),
	})

	source := &managedOIDCTokenSource{
		issuer:     provider.issuer(),
		clientID:   "authunnel-cli",
		audience:   "authunnel-server",
		scopes:     normalizeScopes("openid offline_access"),
		cachePath:  cachePath,
		httpClient: provider.server.Client(),
		output:     io.Discard,
		openBrowser: func(ctx context.Context, authURL string) error {
			return provider.completeBrowserAuth(authURL)
		},
		now: time.Now,
	}

	token, err := source.AccessToken(context.Background(), true)
	if err != nil {
		t.Fatalf("expected interactive flow to succeed, got error: %v", err)
	}
	if token != provider.codeAccessToken {
		t.Fatalf("unexpected token: got %q want %q", token, provider.codeAccessToken)
	}
}

func TestManagedOIDCTokenSourceIgnoresCacheWhenAudienceChanges(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	cachePath := filepathForTest(t, "tokens.json")
	writeTokenCacheForTest(t, cachePath, tokenCache{
		Issuer:      provider.issuer(),
		ClientID:    "authunnel-cli",
		Audience:    "old-audience",
		Scopes:      normalizeScopes("openid offline_access"),
		AccessToken: "stale",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(5 * time.Minute),
	})

	source := &managedOIDCTokenSource{
		issuer:     provider.issuer(),
		clientID:   "authunnel-cli",
		audience:   "authunnel-server",
		scopes:     normalizeScopes("openid offline_access"),
		cachePath:  cachePath,
		httpClient: provider.server.Client(),
		output:     io.Discard,
		openBrowser: func(ctx context.Context, authURL string) error {
			return provider.completeBrowserAuth(authURL)
		},
		now: time.Now,
	}

	token, err := source.AccessToken(context.Background(), true)
	if err != nil {
		t.Fatalf("expected interactive flow to succeed, got error: %v", err)
	}
	if token != provider.codeAccessToken {
		t.Fatalf("unexpected token: got %q want %q", token, provider.codeAccessToken)
	}
}

func TestAcquireFileLockAllowsReuseOfExistingLockFile(t *testing.T) {
	lockPath := filepathForTest(t, "tokens.lock")
	if err := os.WriteFile(lockPath, []byte("leftover-data"), 0o600); err != nil {
		t.Fatalf("seed lock file: %v", err)
	}
	release, err := acquireFileLock(context.Background(), lockPath)
	if err != nil {
		t.Fatalf("acquire lock: %v", err)
	}
	defer release()
}

func TestAcquireFileLockCanBeReacquiredAfterHolderProcessExits(t *testing.T) {
	lockPath := filepathForTest(t, "tokens.lock")
	cmd := exec.Command(os.Args[0], "-test.run=TestAcquireFileLockHelperProcess$")
	cmd.Env = append(os.Environ(),
		"AUTHUNNEL_LOCK_HELPER=1",
		"AUTHUNNEL_LOCK_PATH="+lockPath,
		"AUTHUNNEL_LOCK_HOLD_MS=100",
	)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper process: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(stdout.String(), "locked\n") {
		if time.Now().After(deadline) {
			t.Fatalf("helper did not report lock acquisition: %s", stdout.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait for helper process: %v\noutput:\n%s", err, stdout.String())
	}

	release, err := acquireFileLock(context.Background(), lockPath)
	if err != nil {
		t.Fatalf("acquire lock after helper exit: %v", err)
	}
	release()
}

func TestAcquireFileLockHelperProcess(t *testing.T) {
	if os.Getenv("AUTHUNNEL_LOCK_HELPER") != "1" {
		return
	}
	lockPath := os.Getenv("AUTHUNNEL_LOCK_PATH")
	if lockPath == "" {
		t.Fatal("AUTHUNNEL_LOCK_PATH is required")
	}
	release, err := acquireFileLock(context.Background(), lockPath)
	if err != nil {
		t.Fatalf("helper acquire lock: %v", err)
	}
	defer release()
	_, _ = os.Stdout.WriteString("locked\n")
	holdDuration, err := time.ParseDuration(os.Getenv("AUTHUNNEL_LOCK_HOLD_MS") + "ms")
	if err != nil {
		t.Fatalf("parse AUTHUNNEL_LOCK_HOLD_MS: %v", err)
	}
	time.Sleep(holdDuration)
}

type fakeOIDCProvider struct {
	t *testing.T

	server *httptest.Server

	mu sync.Mutex

	lastCodeChallenge string
	redirectState     string
	rejectRefresh     bool

	validRefreshToken    string
	refreshedAccessToken string
	codeAccessToken      string

	tokenRequestCount   int
	refreshRequestCount int
	codeRequestCount    int
}

func newFakeOIDCProvider(t *testing.T) *fakeOIDCProvider {
	t.Helper()
	provider := &fakeOIDCProvider{
		t:                    t,
		validRefreshToken:    "refresh-token-1",
		refreshedAccessToken: "refreshed-access-token",
		codeAccessToken:      "interactive-access-token",
	}

	var issuer string
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/issuer/.well-known/openid-configuration":
			writeJSONForTest(t, w, map[string]string{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/auth",
				"token_endpoint":         issuer + "/token",
			})
		case "/auth", "/issuer/auth":
			provider.handleAuthorize(w, r)
		case "/token", "/issuer/token":
			provider.handleToken(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	provider.server = server
	issuer = server.URL + "/issuer"
	return provider
}

func (p *fakeOIDCProvider) issuer() string {
	return p.server.URL + "/issuer"
}

func (p *fakeOIDCProvider) tokenRequests() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tokenRequestCount
}

func (p *fakeOIDCProvider) refreshRequests() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshRequestCount
}

func (p *fakeOIDCProvider) codeRequests() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.codeRequestCount
}

func (p *fakeOIDCProvider) completeBrowserAuth(authURL string) error {
	parsed, err := url.Parse(authURL)
	if err != nil {
		return err
	}
	query := parsed.Query()

	p.mu.Lock()
	p.lastCodeChallenge = query.Get("code_challenge")
	state := query.Get("state")
	if p.redirectState != "" {
		state = p.redirectState
	}
	p.mu.Unlock()

	callbackURL, err := url.Parse(query.Get("redirect_uri"))
	if err != nil {
		return err
	}
	values := callbackURL.Query()
	values.Set("code", "auth-code-1")
	values.Set("state", state)
	callbackURL.RawQuery = values.Encode()

	client := p.server.Client()
	deadline := time.Now().Add(2 * time.Second)
	for {
		callbackResp, err := client.Get(callbackURL.String())
		if err == nil {
			defer callbackResp.Body.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (p *fakeOIDCProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	p.mu.Lock()
	p.lastCodeChallenge = query.Get("code_challenge")
	redirectState := query.Get("state")
	if p.redirectState != "" {
		redirectState = p.redirectState
	}
	p.mu.Unlock()

	redirectURI := query.Get("redirect_uri")
	callbackURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	values := callbackURL.Query()
	values.Set("code", "auth-code-1")
	values.Set("state", redirectState)
	callbackURL.RawQuery = values.Encode()
	http.Redirect(w, r, callbackURL.String(), http.StatusFound)
}

func (p *fakeOIDCProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	p.mu.Lock()
	p.tokenRequestCount++
	defer p.mu.Unlock()

	switch r.Form.Get("grant_type") {
	case "authorization_code":
		p.codeRequestCount++
		if r.Form.Get("code") != "auth-code-1" {
			http.Error(w, "invalid code", http.StatusBadRequest)
			return
		}
		verifier := r.Form.Get("code_verifier")
		hashed := sha256.Sum256([]byte(verifier))
		if got := base64.RawURLEncoding.EncodeToString(hashed[:]); got != p.lastCodeChallenge {
			http.Error(w, "invalid code verifier", http.StatusBadRequest)
			return
		}
		writeJSONForTest(p.t, w, map[string]any{
			"access_token":  p.codeAccessToken,
			"refresh_token": p.validRefreshToken,
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	case "refresh_token":
		p.refreshRequestCount++
		if p.rejectRefresh {
			http.Error(w, "refresh rejected", http.StatusBadRequest)
			return
		}
		if r.Form.Get("refresh_token") != p.validRefreshToken {
			http.Error(w, "invalid refresh token", http.StatusBadRequest)
			return
		}
		writeJSONForTest(p.t, w, map[string]any{
			"access_token":  p.refreshedAccessToken,
			"refresh_token": p.validRefreshToken,
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	default:
		http.Error(w, "unsupported grant type", http.StatusBadRequest)
	}
}

func writeTokenCacheForTest(t *testing.T, path string, cache tokenCache) {
	t.Helper()
	data, err := json.Marshal(cache)
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}
}

func writeJSONForTest(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode JSON: %v", err)
	}
}

func filepathForTest(t *testing.T, name string) string {
	t.Helper()
	return path.Join(t.TempDir(), name)
}

func freeLoopbackPortForTest(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
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

func newIPv4TLSTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on IPv4 loopback: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

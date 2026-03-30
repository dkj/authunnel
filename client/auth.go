package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	oidcclient "github.com/zitadel/oidc/v3/pkg/client"
	"golang.org/x/oauth2"
)

const tokenReuseWindow = time.Minute

// authTokenSource hides how the client obtains an access token so tunnel setup
// can stay identical for manual tokens and managed OIDC login.
type authTokenSource interface {
	AccessToken(ctx context.Context) (string, error)
}

type staticTokenSource struct {
	token string
}

func (s staticTokenSource) AccessToken(context.Context) (string, error) {
	return s.token, nil
}

type browserOpener func(context.Context, string) error

// managedOIDCTokenSource implements the native-app flow used by ProxyCommand
// mode. It serializes cache access across concurrent ssh invocations, reuses
// cached tokens when they are still safely valid, refreshes when possible, and
// only falls back to interactive PKCE when needed.
type managedOIDCTokenSource struct {
	issuer       string
	clientID     string
	audience     string
	scopes       string
	cachePath    string
	noBrowser    bool
	redirectPort int
	httpClient   *http.Client
	output       io.Writer
	openBrowser  browserOpener
	now          func() time.Time

	mu        sync.Mutex
	discovery oauth2.Endpoint
}

// tokenCache is intentionally a single JSON document so developers can inspect
// and delete it easily during debugging. Cache entries are scoped to issuer,
// client ID, audience, and scopes to avoid cross-provider token reuse.
type tokenCache struct {
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"client_id"`
	Audience     string    `json:"audience,omitempty"`
	Scopes       string    `json:"scopes"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	Expiry       time.Time `json:"expiry"`
}

func newAuthTokenSource(cfg clientConfig) (authTokenSource, error) {
	switch cfg.AuthMode {
	case authModeManual:
		return staticTokenSource{token: cfg.AccessToken}, nil
	case authModeOIDC:
		client := cfg.AuthHTTPClient
		if client == nil {
			client = http.DefaultClient
		}
		output := cfg.Stderr
		if output == nil {
			output = io.Discard
		}
		opener := cfg.BrowserOpener
		if opener == nil {
			opener = defaultBrowserOpener
		}
		return &managedOIDCTokenSource{
			issuer:       cfg.OIDCIssuer,
			clientID:     cfg.OIDCClientID,
			audience:     cfg.OIDCAudience,
			scopes:       normalizeScopes(cfg.OIDCScopes),
			cachePath:    cfg.OIDCCache,
			noBrowser:    cfg.OIDCNoBrowser,
			redirectPort: cfg.OIDCRedirectPort,
			httpClient:   client,
			output:       output,
			openBrowser:  opener,
			now:          time.Now,
		}, nil
	default:
		return nil, errors.New("unknown authentication mode")
	}
}

func defaultOIDCCachePath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}
	return filepath.Join(configDir, "authunnel", "tokens.json"), nil
}

func normalizeScopes(scopes string) string {
	return strings.Join(strings.Fields(scopes), " ")
}

// AccessToken is the single entry point for managed authentication. The order
// is deliberate: cache first, then refresh, then browser-based login. That
// keeps repeat ssh invocations fast while still recovering automatically when
// the cached access token has expired.
func (s *managedOIDCTokenSource) AccessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.cachePath), 0o755); err != nil {
		return "", fmt.Errorf("create cache directory: %w", err)
	}

	release, err := acquireFileLock(ctx, s.cachePath+".lock")
	if err != nil {
		return "", err
	}
	defer release()

	cache, err := s.loadCache()
	if err != nil {
		return "", err
	}
	if tokenUsable(cache.asOAuth2Token(), s.now()) {
		return cache.AccessToken, nil
	}
	if cache.RefreshToken != "" {
		refreshed, err := s.refreshToken(ctx, cache)
		if err == nil {
			nextCache := tokenCacheFromOAuth2Token(s.issuer, s.clientID, s.audience, s.scopes, refreshed)
			if err := s.saveCache(nextCache); err != nil {
				return "", err
			}
			return refreshed.AccessToken, nil
		}
	}

	token, err := s.interactiveToken(ctx)
	if err != nil {
		return "", err
	}
	nextCache := tokenCacheFromOAuth2Token(s.issuer, s.clientID, s.audience, s.scopes, token)
	if err := s.saveCache(nextCache); err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

// oauthConfig resolves the provider metadata once and reuses it for both
// refresh and interactive code exchange. AuthStyleInParams is used because the
// test Keycloak public client rejects the default client-auth style negotiation.
func (s *managedOIDCTokenSource) oauthConfig(ctx context.Context, redirectURL string) (*oauth2.Config, error) {
	if s.discovery.AuthURL == "" || s.discovery.TokenURL == "" {
		discovery, err := oidcclient.Discover(context.WithValue(ctx, oauth2.HTTPClient, s.httpClient), s.issuer, s.httpClient)
		if err != nil {
			return nil, fmt.Errorf("discover issuer %q: %w", s.issuer, err)
		}
		s.discovery = oauth2.Endpoint{
			AuthURL:   discovery.AuthorizationEndpoint,
			TokenURL:  discovery.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInParams,
		}
	}
	return &oauth2.Config{
		ClientID:    s.clientID,
		RedirectURL: redirectURL,
		Scopes:      strings.Fields(s.scopes),
		Endpoint:    s.discovery,
	}, nil
}

func (s *managedOIDCTokenSource) loadCache() (tokenCache, error) {
	cache := tokenCache{}
	data, err := os.ReadFile(s.cachePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cache, nil
		}
		return cache, fmt.Errorf("read OIDC token cache: %w", err)
	}
	if err := json.Unmarshal(data, &cache); err != nil {
		return tokenCache{}, fmt.Errorf("parse OIDC token cache: %w", err)
	}
	if cache.Issuer != s.issuer || cache.ClientID != s.clientID || cache.Audience != s.audience || normalizeScopes(cache.Scopes) != s.scopes {
		return tokenCache{}, nil
	}
	return cache, nil
}

func (s *managedOIDCTokenSource) saveCache(cache tokenCache) error {
	if err := os.MkdirAll(filepath.Dir(s.cachePath), 0o755); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal OIDC token cache: %w", err)
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(s.cachePath), "tokens-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp cache file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if err := tmpFile.Chmod(0o600); err != nil {
		tmpFile.Close()
		return fmt.Errorf("chmod temp cache file: %w", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write temp cache file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp cache file: %w", err)
	}
	if err := os.Rename(tmpPath, s.cachePath); err != nil {
		return fmt.Errorf("replace OIDC token cache: %w", err)
	}
	return nil
}

func (s *managedOIDCTokenSource) refreshToken(ctx context.Context, cache tokenCache) (*oauth2.Token, error) {
	config, err := s.oauthConfig(ctx, "")
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.httpClient)
	token := cache.asOAuth2Token()
	refreshed, err := config.TokenSource(ctx, token).Token()
	if err != nil {
		return nil, fmt.Errorf("refresh OIDC token: %w", err)
	}
	return refreshed, nil
}

func (s *managedOIDCTokenSource) interactiveToken(ctx context.Context) (*oauth2.Token, error) {
	listenAddr := "127.0.0.1:0"
	if s.redirectPort != 0 {
		listenAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(s.redirectPort))
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen for OIDC callback: %w", err)
	}
	defer listener.Close()

	redirectURL := "http://" + listener.Addr().String() + "/callback"
	config, err := s.oauthConfig(ctx, redirectURL)
	if err != nil {
		return nil, err
	}

	state, err := randomToken()
	if err != nil {
		return nil, fmt.Errorf("generate OIDC state: %w", err)
	}
	verifier, err := randomToken()
	if err != nil {
		return nil, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	challenge := sha256.Sum256([]byte(verifier))
	challengeValue := base64.RawURLEncoding.EncodeToString(challenge[:])

	resultCh := make(chan callbackResult, 1)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result := callbackResult{}
			query := r.URL.Query()
			if oauthErr := query.Get("error"); oauthErr != "" {
				result.err = fmt.Errorf("OIDC authorization failed: %s", oauthErr)
				http.Error(w, "Authentication failed. Return to the terminal.", http.StatusBadRequest)
			} else if query.Get("state") != state {
				result.err = errors.New("OIDC callback state mismatch")
				http.Error(w, "Authentication failed. Return to the terminal.", http.StatusBadRequest)
			} else if code := query.Get("code"); code == "" {
				result.err = errors.New("OIDC callback missing authorization code")
				http.Error(w, "Authentication failed. Return to the terminal.", http.StatusBadRequest)
			} else {
				result.code = code
				_, _ = io.WriteString(w, "Authentication complete. Return to your terminal.\n")
			}
			select {
			case resultCh <- result:
			default:
			}
		}),
	}

	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case resultCh <- callbackResult{err: fmt.Errorf("OIDC callback server failed: %w", err)}:
			default:
			}
		}
	}()

	authCodeOptions := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", challengeValue),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	if s.audience != "" {
		authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam("audience", s.audience))
	}
	authURL := config.AuthCodeURL(state, authCodeOptions...)
	fmt.Fprintf(s.output, "Open this URL to authenticate:\n%s\n", authURL)
	if !s.noBrowser {
		if err := s.openBrowser(ctx, authURL); err != nil {
			fmt.Fprintf(s.output, "Browser launch failed, open the URL manually: %v\n", err)
		}
	}

	var callback callbackResult
	select {
	case <-ctx.Done():
		callback.err = ctx.Err()
	case callback = <-resultCh:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)

	if callback.err != nil {
		return nil, callback.err
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.httpClient)
	token, err := config.Exchange(ctx, callback.code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	return token, nil
}

// acquireFileLock coordinates concurrent client processes that share the same
// token cache using an OS-backed advisory lock. The lock file is never deleted;
// the kernel releases the lock when the owning process exits, which avoids both
// age-based lock stealing and stale lock files after crashes.
func acquireFileLock(ctx context.Context, lockPath string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open cache lock %q: %w", lockPath, err)
	}
	for {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return func() {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
			}, nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("lock cache lock %q: %w", lockPath, err)
		}

		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// tokenUsable keeps a small reuse window so the client does not start a tunnel
// with a token that is about to expire mid-handshake.
func tokenUsable(token *oauth2.Token, now time.Time) bool {
	if token == nil || token.AccessToken == "" {
		return false
	}
	if token.Expiry.IsZero() {
		return false
	}
	return token.Expiry.After(now.Add(tokenReuseWindow))
}

func tokenCacheFromOAuth2Token(issuer, clientID, audience, scopes string, token *oauth2.Token) tokenCache {
	cache := tokenCache{
		Issuer:       issuer,
		ClientID:     clientID,
		Audience:     audience,
		Scopes:       scopes,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry,
	}
	if cache.TokenType == "" {
		cache.TokenType = "Bearer"
	}
	return cache
}

func (c tokenCache) asOAuth2Token() *oauth2.Token {
	if c.AccessToken == "" && c.RefreshToken == "" {
		return nil
	}
	return &oauth2.Token{
		AccessToken:  c.AccessToken,
		RefreshToken: c.RefreshToken,
		TokenType:    c.TokenType,
		Expiry:       c.Expiry,
	}
}

type callbackResult struct {
	code string
	err  error
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func defaultBrowserOpener(ctx context.Context, url string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name = "open"
		args = []string{url}
	default:
		// Linux and most Unix desktops use xdg-open. Unsupported platforms still
		// get the URL printed to stderr, so browser launch remains best-effort.
		name = "xdg-open"
		args = []string{url}
	}

	commandCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(commandCtx, name, args...)
	if err := command.Run(); err != nil {
		return fmt.Errorf("launch %s: %w", name, err)
	}
	return nil
}

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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"authunnel/internal/authhttp"
	"authunnel/internal/safefs"

	oidcclient "github.com/zitadel/oidc/v3/pkg/client"
	"golang.org/x/oauth2"
)

const tokenReuseWindow = time.Minute

// authTokenSource hides how the client obtains an access token so tunnel setup
// can stay identical for manual tokens and managed OIDC login.
type authTokenSource interface {
	// AccessToken returns a usable access token. When useCache is true, a
	// cached token that passes the reuse window is returned immediately.
	// When false, the cache-reuse check is skipped, forcing a refresh-token
	// grant — used when the server warns that the current token is expiring.
	AccessToken(ctx context.Context, useCache bool) (string, error)
}

type staticTokenSource struct {
	token string
}

func (s staticTokenSource) AccessToken(_ context.Context, _ bool) (string, error) {
	return s.token, nil
}

type browserOpener func(context.Context, string) error

// managedOIDCTokenSource implements the native-app flow used by ProxyCommand
// mode. It serializes cache access across concurrent ssh invocations, reuses
// cached tokens when they are still safely valid, refreshes when possible, and
// only falls back to interactive PKCE when needed.
type managedOIDCTokenSource struct {
	issuer string
	// metadataURL, when set, replaces the well-known path derived from
	// issuer.
	//
	// Discovery compares the document's `issuer` field against issuer, but
	// that field is supplied by the document about itself and proves nothing
	// about the host serving it. Treat the check as catching an honest wrong
	// URL — staging for production, one tenant for another, which a
	// legitimate AS reveals by declaring its own issuer — not as a boundary.
	// A hostile or mistyped URL can echo the expected issuer and name any
	// endpoints it likes; only trusting this value prevents that.
	metadataURL  string
	clientID     string
	audience     string
	resource     string
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
// metadata URL, client ID, audience, resource, and scopes to avoid reusing a
// credential in a context it was not obtained for.
//
// The metadata URL belongs in that identity, and an earlier version of this
// comment argued the opposite — that the override only relocates the document,
// so a token obtained through it is "the same token". That reasoning asks
// whether the credential is still *valid*, which is the wrong question. The
// question is who receives it. The metadata document names the token endpoint
// the refresh token is posted to, and the only check on that document is that
// its `issuer` field equals the configured issuer — a plain string comparison
// against a value the document supplies about itself. Nothing binds the
// metadata host to the issuer it claims, so a mistyped or hostile metadata URL
// can echo the right issuer and name any token endpoint it likes.
//
// Left out of the identity, adding or changing --oidc-metadata-url would keep an
// existing refresh token valid and post it to whatever that new document
// advertises, with no user interaction. Including it means the cache is
// discarded instead and the user re-authenticates.
//
// What that does and does not buy, precisely: it prevents the **silent reuse of
// an already-issued refresh token**. It is not a general defence against a
// hostile metadata URL. If the user goes on to complete the fallback login, the
// authorization code and its PKCE verifier are still sent to the token endpoint
// that document names — and a document can pair the *real* authorization
// endpoint with an attacker's token endpoint, so the user sees a genuine IdP
// page and the code that comes back is a real, redeemable one. Nothing here
// stops that; only trusting the metadata URL does.
//
// The cost is one interactive login the first time an operator sets the flag,
// and again if they change it. That is the correct trade. Caches written before
// this field existed unmarshal with an empty MetadataURL and still match a
// source that uses the derived path, so no one is logged out by the upgrade.
type tokenCache struct {
	Issuer string `json:"issuer"`
	// MetadataURL records which metadata document produced the endpoints these
	// tokens were obtained through. Omitted when discovery used the derived
	// well-known path, so caches written before this field existed still match.
	MetadataURL  string    `json:"metadata_url,omitempty"`
	ClientID     string    `json:"client_id"`
	Audience     string    `json:"audience,omitempty"`
	Resource     string    `json:"resource,omitempty"`
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
			// Bounded default mirrors the server-side validator HTTP
			// client: discovery, refresh, and code exchange all serve
			// small static responses, so a stalled IdP is the only thing
			// these long timeouts would protect. Tests inject their own
			// client through cfg.AuthHTTPClient.
			client = authhttp.NewBoundedClient()
		}
		// Applied here rather than relying on NewBoundedClient, which sets
		// the same policy: an injected client must not be able to opt out of
		// it. This path carries the refresh token and the authorization code,
		// so a redirect off https would disclose a credential rather than
		// merely weaken a fetch of public material.
		client = authhttp.RefuseTransportDowngrade(client)
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
			metadataURL:  cfg.OIDCMetadataURL,
			clientID:     cfg.OIDCClientID,
			audience:     cfg.OIDCAudience,
			resource:     cfg.OIDCResource,
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

// AccessToken is the single entry point for managed authentication. When
// useCache is true the order is: cache first, then refresh, then browser-based
// login — keeping repeat ssh invocations fast. When useCache is false (e.g.
// responding to a server expiry_warning), the cache-reuse check is skipped so
// the refresh-token grant produces a token with a later expiry.
func (s *managedOIDCTokenSource) AccessToken(ctx context.Context, useCache bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := safefs.EnsurePrivateDir(filepath.Dir(s.cachePath)); err != nil {
		return "", fmt.Errorf("prepare cache directory: %w", err)
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
	if useCache && tokenUsable(cache.asOAuth2Token(), s.now()) {
		return cache.AccessToken, nil
	}
	if cache.RefreshToken != "" {
		refreshed, err := s.refreshToken(ctx, cache)
		if err == nil {
			nextCache := s.cacheFor(refreshed)
			if err := s.saveCache(nextCache); err != nil {
				return "", err
			}
			return refreshed.AccessToken, nil
		}
		// Falling through to interactive login is right for an expired or
		// revoked refresh token: a fresh login fixes it. It is wrong for a
		// refusal to use the endpoint at all — the interactive flow ends at
		// the same token endpoint, so it would open a browser, walk the user
		// through authenticating, and then fail identically. Surface the
		// real reason instead.
		if errors.Is(err, authhttp.ErrUnsafeTransport) {
			return "", err
		}
	}

	token, err := s.interactiveToken(ctx)
	if err != nil {
		return "", err
	}
	nextCache := s.cacheFor(token)
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
		// Discover ignores an empty wellKnownUrl, so the derived path needs
		// no branch. On both paths it compares the document's issuer against
		// s.issuer — a consistency check against an honest wrong URL, not a
		// defence against a hostile one, since the document asserts that
		// field about itself. See the metadataURL field comment.
		discovery, err := oidcclient.Discover(context.WithValue(ctx, oauth2.HTTPClient, s.httpClient), s.issuer, s.httpClient, s.metadataURL)
		if err != nil {
			return nil, fmt.Errorf("discover issuer %q: %w", s.issuer, err)
		}
		// Downgrade is judged against wherever the metadata actually came
		// from, not against the issuer: with --oidc-metadata-url those differ,
		// and it is the document's own transport that determines whether a
		// plaintext endpoint is a downgrade.
		metadataSource := s.issuer
		if s.metadataURL != "" {
			metadataSource = s.metadataURL
		}
		// Validate both endpoints before either is used. token_endpoint
		// receives the refresh token and the authorization code;
		// authorization_endpoint is handed to the OS URL dispatcher, which
		// will launch whatever application claims the scheme, so
		// CheckEndpointURL is the whole of the protection there — the
		// redirect guard on s.httpClient never sees that leg.
		for _, endpoint := range []struct{ label, value string }{
			{"authorization_endpoint", discovery.AuthorizationEndpoint},
			{"token_endpoint", discovery.TokenEndpoint},
		} {
			if err := authhttp.CheckEndpointURL(endpoint.label, endpoint.value); err != nil {
				return nil, fmt.Errorf("discover issuer %q: %w", s.issuer, err)
			}
			if err := authhttp.CheckNoSchemeDowngrade(endpoint.label, metadataSource, endpoint.value); err != nil {
				return nil, fmt.Errorf("discover issuer %q: %w", s.issuer, err)
			}
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
	if err := safefs.EnsurePrivateFile(s.cachePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cache, nil
		}
		return cache, fmt.Errorf("validate OIDC token cache: %w", err)
	}
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
	// MetadataURL is part of the identity, not an incidental detail: it
	// determines the token endpoint these credentials get posted to. See the
	// tokenCache doc comment.
	if cache.Issuer != s.issuer || cache.MetadataURL != s.metadataURL || cache.ClientID != s.clientID || cache.Audience != s.audience || cache.Resource != s.resource || normalizeScopes(cache.Scopes) != s.scopes {
		return tokenCache{}, nil
	}
	return cache, nil
}

func (s *managedOIDCTokenSource) saveCache(cache tokenCache) error {
	if err := safefs.EnsurePrivateDir(filepath.Dir(s.cachePath)); err != nil {
		return fmt.Errorf("prepare cache directory: %w", err)
	}
	// #nosec G117 -- this is an accepted tradeoff, not a false positive.
	// authunnel persists access and refresh tokens as plaintext JSON so that
	// subsequent client invocations can reuse them without a fresh browser
	// login. Confidentiality relies entirely on POSIX filesystem permissions:
	// the file is written 0o600 via atomic rename into a directory that
	// ensurePrivateDir has validated as 0o700, owned by the current user,
	// with every ancestor safe against peer rename(2). This does NOT defend
	// against root on the host, offline access to an unencrypted disk image,
	// or a backup of the config directory. See the "Token cache at rest"
	// section of the README for the explicit threat model.
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
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp cache file: %w", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
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
		// Defence in depth: even though this server is only bound to a
		// 127.0.0.1 loopback listener during an interactive OIDC login, a
		// ReadHeaderTimeout defeats a local attacker who could otherwise keep
		// the listener occupied by dribbling headers forever.
		ReadHeaderTimeout: 10 * time.Second,
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
	// RFC 8707 resource indicator. Providers that bind the access-token `aud`
	// claim to a requested resource (e.g. AWS Cognito) require this parameter;
	// the Auth0-style `audience` parameter above is ignored by them.
	if s.resource != "" {
		authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam("resource", s.resource))
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

// cacheFor builds a cache entry stamped with this source's full identity.
// A method rather than a function taking each field: the identity is what
// loadCache compares against, and enumerating it at every call site is how a
// new field gets added to the struct and missed at one of them.
func (s *managedOIDCTokenSource) cacheFor(token *oauth2.Token) tokenCache {
	cache := tokenCache{
		Issuer:       s.issuer,
		MetadataURL:  s.metadataURL,
		ClientID:     s.clientID,
		Audience:     s.audience,
		Resource:     s.resource,
		Scopes:       s.scopes,
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

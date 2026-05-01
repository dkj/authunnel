package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"authunnel/internal/authhttp"

	"golang.org/x/oauth2"
)

// TestNewAuthTokenSourceDefaultsToBoundedClient verifies that callers who do
// not inject an AuthHTTPClient still get the bounded transport rather than
// http.DefaultClient. This protects production callers from an unbounded
// OIDC HTTP client even when they do not customise auth.
func TestNewAuthTokenSourceDefaultsToBoundedClient(t *testing.T) {
	src, err := newAuthTokenSource(clientConfig{
		AuthMode:     authModeOIDC,
		OIDCIssuer:   "https://issuer.example",
		OIDCClientID: "authunnel-cli",
	})
	if err != nil {
		t.Fatalf("newAuthTokenSource: %v", err)
	}
	managed, ok := src.(*managedOIDCTokenSource)
	if !ok {
		t.Fatalf("expected managed OIDC token source, got %T", src)
	}
	if managed.httpClient == nil {
		t.Fatal("managed token source missing http client")
	}
	if managed.httpClient == http.DefaultClient {
		t.Fatal("managed token source must not default to http.DefaultClient")
	}
	if managed.httpClient.Timeout == 0 {
		t.Fatal("default managed http client must carry a non-zero Timeout")
	}
}

// blockingTCP listens for TCP connections and holds them open without
// writing. It models an OIDC issuer that completes the TCP handshake but
// never replies to discovery. The accept goroutine owns the channel close
// so cleanup cannot race with a just-accepted connection.
func blockingTCP(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	conns := make(chan net.Conn, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				close(conns)
				return
			}
			select {
			case conns <- conn:
			default:
				// Buffer is full; drop on the floor — the test only
				// needs the listener to accept, not to retain conns.
				_ = conn.Close()
			}
		}
	}()
	cleanup := func() {
		_ = ln.Close()
		<-done
		for c := range conns {
			_ = c.Close()
		}
	}
	return "http://" + ln.Addr().String(), cleanup
}

// TestManagedOIDCTokenSourceDiscoveryTimesOut points the managed client at a
// blocking issuer and confirms that AccessToken returns within the bounded
// client's timeout instead of hanging on discovery.
func TestManagedOIDCTokenSourceDiscoveryTimesOut(t *testing.T) {
	issuer, cleanup := blockingTCP(t)
	defer cleanup()

	// Inject a tighter client than the production default to keep the
	// test fast; the production client uses authhttp.NewBoundedClient,
	// which carries the same kind of overall Timeout but at 10s.
	client := &http.Client{Timeout: 750 * time.Millisecond}

	cachePath := filepathForTest(t, "tokens.json")
	source := &managedOIDCTokenSource{
		issuer:      issuer,
		clientID:    "authunnel-cli",
		scopes:      normalizeScopes("openid offline_access"),
		cachePath:   cachePath,
		httpClient:  client,
		output:      io.Discard,
		openBrowser: func(context.Context, string) error { return nil },
		now:         time.Now,
	}

	start := time.Now()
	_, err := source.AccessToken(context.Background(), false)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected discovery against blocking issuer to fail, got nil")
	}
	if !strings.Contains(err.Error(), "discover issuer") {
		t.Fatalf("expected error to mention discovery, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("AccessToken took %v, expected to abort within client timeout", elapsed)
	}
}

// TestManagedOIDCTokenSourceCodeExchangeTimesOut skips discovery by seeding
// provider metadata, then completes the local browser callback and points the
// authorization-code exchange at a token endpoint that accepts but never
// replies. This covers the post-discovery token endpoint path.
func TestManagedOIDCTokenSourceCodeExchangeTimesOut(t *testing.T) {
	tokenEndpoint, cleanup := blockingTCP(t)
	defer cleanup()

	client := &http.Client{Timeout: 750 * time.Millisecond}
	source := &managedOIDCTokenSource{
		issuer:     "https://issuer.example",
		clientID:   "authunnel-cli",
		scopes:     normalizeScopes("openid offline_access"),
		cachePath:  filepathForTest(t, "tokens.json"),
		httpClient: client,
		output:     io.Discard,
		discovery: oauth2.Endpoint{
			AuthURL:   "https://issuer.example/auth",
			TokenURL:  tokenEndpoint + "/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		openBrowser: completeTimeoutTestCallback,
		now:         time.Now,
	}

	start := time.Now()
	_, err := source.interactiveToken(context.Background())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected code exchange against blocking token endpoint to fail")
	}
	if !strings.Contains(err.Error(), "exchange authorization code") {
		t.Fatalf("expected exchange error, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("interactiveToken took %v, expected to abort within client timeout", elapsed)
	}
}

// TestBoundedClientCarriesTimeout sanity-checks the production constructor.
// Operators rely on the constructor delivering a non-zero overall timeout;
// regressing this constant would silently disable the protection.
func TestBoundedClientCarriesTimeout(t *testing.T) {
	c := authhttp.NewBoundedClient()
	if c.Timeout <= 0 {
		t.Fatalf("bounded client must carry a positive Timeout, got %v", c.Timeout)
	}
	if c.Transport == nil {
		t.Fatal("bounded client must carry a non-nil Transport")
	}
}

func completeTimeoutTestCallback(ctx context.Context, authURL string) error {
	parsed, err := url.Parse(authURL)
	if err != nil {
		return err
	}
	query := parsed.Query()
	callbackURL, err := url.Parse(query.Get("redirect_uri"))
	if err != nil {
		return err
	}
	values := callbackURL.Query()
	values.Set("code", "auth-code-1")
	values.Set("state", query.Get("state"))
	callbackURL.RawQuery = values.Encode()

	client := &http.Client{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, callbackURL.String(), nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

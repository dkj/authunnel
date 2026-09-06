package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	socks5 "github.com/armon/go-socks5"

	"authunnel/internal/authmeta"
	"authunnel/internal/tunnelserver"
)

// newDiscoverableTunnelServer is newJWTValidatedTunnelServer's plaintext sibling,
// publishing protected-resource metadata.
//
// Plaintext deliberately: the JWT-backed provider fixture serves over http, and a
// discovered issuer is held to the same rule a configured one is, so an https
// tunnel naming an http issuer is refused — correctly. Running both over http with
// --insecure-oidc-issuer is the local-development configuration
// docs/DEVELOPMENT.md describes, which makes this the shape worth covering end to
// end.
func newDiscoverableTunnelServer(t *testing.T, issuer, audience string, validatorHTTPClient *http.Client, metadata *tunnelserver.ResourceMetadataConfig) (*httptest.Server, *http.Client) {
	t.Helper()

	validator, _, err := tunnelserver.NewJWTTokenValidator(context.Background(), tunnelserver.JWTValidatorConfig{
		Issuer:     issuer,
		Audience:   audience,
		HTTPClient: validatorHTTPClient,
	})
	if err != nil {
		t.Fatalf("create JWT validator: %v", err)
	}
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create SOCKS5 server: %v", err)
	}
	server := newIPv4TestServer(t, tunnelserver.NewHandler(validator, socks, tunnelserver.HandlerOptions{
		ResourceMetadata: metadata,
	}))
	client := server.Client()
	client.Timeout = 5 * time.Second
	return server, client
}

// TestZeroConfigProxyCommandE2E is the whole point of this work, exercised against
// the real handler rather than a stub: a client given nothing but --tunnel-url
// discovers the issuer, client ID, audience and scopes from the server, completes
// a browser login, opens a tunnel, and moves bytes.
//
// It goes through parseClientConfig so the ssh_config line under test is the real
// one, and it asserts the second invocation reuses the cache without contacting
// either server — which is what makes this usable as a ProxyCommand at all.
func TestZeroConfigProxyCommandE2E(t *testing.T) {
	provider := newJWTBackedOIDCProvider(t, "authunnel-server")
	metadataRequests := 0
	server, wsHTTPClient := newDiscoverableTunnelServer(t, provider.issuer(), "authunnel-server", provider.server.Client(),
		&tunnelserver.ResourceMetadataConfig{
			Issuer:        provider.issuer(),
			ClientID:      "authunnel-cli",
			Audience:      "authunnel-server",
			DefaultScopes: []string{"openid", "offline_access"},
		})

	// The auth client has to reach both the tunnel server (for the document) and
	// the provider; both are plaintext, so one client covers it. Counting through
	// a RoundTripper keeps the assertion about *the client's* requests rather than
	// about handler bookkeeping.
	authHTTPClient := &http.Client{Transport: countingTransport(http.DefaultTransport, server.URL, &metadataRequests)}

	targetListener, targetDone, payload := newEchoTarget(t)
	defer targetListener.Close()

	cachePath := filepathForTest(t, "tokens.json")
	cfg, err := parseClientConfig([]string{
		"--proxycommand",
		"--tunnel-url", server.URL + "/protected/tunnel",
		"--insecure-tunnel-url",
		"--insecure-oidc-issuer",
		"--oidc-cache", cachePath,
		"--oidc-redirect-port", "0",
		"127.0.0.1", strconv.Itoa(targetListener.Addr().(*net.TCPAddr).Port),
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseClientConfig: %v", err)
	}
	if cfg.OIDCClientID != "" || cfg.OIDCIssuer != "" {
		t.Fatalf("nothing OIDC should be configured; got issuer %q client %q", cfg.OIDCIssuer, cfg.OIDCClientID)
	}

	var stderr bytes.Buffer
	stdout, input := stdioPair(payload)
	browserCalls := 0
	cfg.Stderr = &stderr
	cfg.Stdout = stdout
	cfg.Stdin = input
	cfg.HTTPClient = wsHTTPClient
	cfg.AuthHTTPClient = authHTTPClient
	cfg.BrowserOpener = func(_ context.Context, authURL string) error {
		browserCalls++
		return provider.completeBrowserAuth(authURL)
	}

	source, err := newAuthTokenSource(cfg)
	if err != nil {
		t.Fatalf("create auth source: %v", err)
	}
	runCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := runProxyCommandMode(runCtx, cfg, source); err != nil {
		t.Fatalf("zero-config proxycommand failed: %v\nstderr:\n%s", err, stderr.String())
	}
	if got := stdout.String(); got != string(payload) {
		t.Fatalf("stdout = %q, want %q", got, string(payload))
	}
	if browserCalls != 1 {
		t.Fatalf("browser logins = %d, want exactly one", browserCalls)
	}
	if metadataRequests != 1 {
		t.Fatalf("protected-resource metadata fetched %d times, want one", metadataRequests)
	}
	if err := waitForTargetResult(targetDone); err != nil {
		t.Fatalf("target echo server failed: %v", err)
	}

	// The entry written back has to carry the resolved identity, or the next
	// invocation cannot match it.
	written := readTokenCacheForTest(t, cachePath)
	if written.ResourceURL != server.URL+"/protected/tunnel" || written.ClientID != "authunnel-cli" || written.Issuer != provider.issuer() {
		t.Fatalf("cache = %+v, want it stamped with the discovered identity", written)
	}

	// Second invocation: same config, valid cached token. It must reach neither
	// the tunnel server's metadata endpoint nor the browser.
	secondTarget, secondDone, payload := newEchoTarget(t)
	defer secondTarget.Close()
	cfg.TargetPort = secondTarget.Addr().(*net.TCPAddr).Port
	secondStdout, secondInput := stdioPair(payload)
	cfg.Stdout = secondStdout
	cfg.Stdin = secondInput
	cfg.BrowserOpener = failingOpener(t)

	source, err = newAuthTokenSource(cfg)
	if err != nil {
		t.Fatalf("create second auth source: %v", err)
	}
	secondCtx, cancelSecond := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelSecond()
	if err := runProxyCommandMode(secondCtx, cfg, source); err != nil {
		t.Fatalf("second zero-config proxycommand failed: %v", err)
	}
	if got := secondStdout.String(); got != string(payload) {
		t.Fatalf("second stdout = %q, want %q", got, string(payload))
	}
	if metadataRequests != 1 {
		t.Fatalf("metadata fetched %d times in total; the cached-token path must make no request", metadataRequests)
	}
	if err := waitForTargetResult(secondDone); err != nil {
		t.Fatalf("second target echo server failed: %v", err)
	}
}

// TestZeroConfigFailsClearlyWhenServerPublishesNothing pairs with the above: with
// --no-resource-metadata on the server there is nothing to discover, and the
// client's error has to name the flags that fix it rather than only the 404.
func TestZeroConfigFailsClearlyWhenServerPublishesNothing(t *testing.T) {
	provider := newJWTBackedOIDCProvider(t, "authunnel-server")
	server, wsHTTPClient := newDiscoverableTunnelServer(t, provider.issuer(), "authunnel-server", provider.server.Client(), nil)

	cfg, err := parseClientConfig([]string{
		"--proxycommand",
		"--tunnel-url", server.URL + "/protected/tunnel",
		"--insecure-tunnel-url",
		"--insecure-oidc-issuer",
		"--oidc-cache", filepathForTest(t, "tokens.json"),
		"127.0.0.1", "22",
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseClientConfig: %v", err)
	}
	cfg.HTTPClient = wsHTTPClient
	cfg.AuthHTTPClient = provider.server.Client()
	cfg.BrowserOpener = failingOpener(t)
	cfg.Stderr = &bytes.Buffer{}

	source, err := newAuthTokenSource(cfg)
	if err != nil {
		t.Fatalf("create auth source: %v", err)
	}
	_, err = source.AccessToken(context.Background(), true)
	if err == nil {
		t.Fatal("expected discovery against a server publishing nothing to fail")
	}
	for _, want := range []string{"--oidc-client-id", "--oidc-issuer", "--oidc-metadata-url"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want it to name %q", err, want)
		}
	}
}

// countingTransport counts requests to prefix, so a test can assert on what the
// client fetched rather than on what a handler happened to record.
func countingTransport(base http.RoundTripper, prefix string, count *int) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasPrefix(r.URL.String(), prefix+authmeta.ProtectedResourcePath) {
			*count++
		}
		return base.RoundTrip(r)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

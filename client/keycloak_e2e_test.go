package main

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	socks5 "github.com/armon/go-socks5"

	"authunnel/internal/tunnelserver"
)

func TestKeycloakProxyCommandManagedOIDCE2E(t *testing.T) {
	if os.Getenv("AUTHUNNEL_E2E") != "1" {
		t.Skip("set AUTHUNNEL_E2E=1 to run Keycloak-backed end-to-end tests")
	}

	issuer := getenvDefault("KEYCLOAK_ISSUER", "http://127.0.0.1:18080/realms/authunnel")
	clientID := getenvDefault("KEYCLOAK_CLIENT_ID", "authunnel-cli")
	username := getenvDefault("KEYCLOAK_USERNAME", "dev-user")
	password := getenvDefault("KEYCLOAK_PASSWORD", "dev-password")
	audience := getenvDefault("AUTHUNNEL_TOKEN_AUDIENCE", "authunnel-server")

	validator, err := tunnelserver.NewJWTTokenValidator(context.Background(), issuer, audience, http.DefaultClient)
	if err != nil {
		t.Fatalf("create JWT validator: %v", err)
	}
	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("create SOCKS5 server: %v", err)
	}
	server := httptest.NewTLSServer(tunnelserver.NewHandler(validator, socks))
	defer server.Close()

	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start echo target: %v", err)
	}
	defer targetListener.Close()

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

	var stderr bytes.Buffer
	cachePath := filepathForTest(t, "tokens.json")
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	browserClient := &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
	}

	browserCalls := 0
	cfg := clientConfig{
		AuthMode:         authModeOIDC,
		OIDCIssuer:       issuer,
		OIDCClientID:     clientID,
		OIDCScopes:       normalizeScopes("openid"),
		OIDCCache:        cachePath,
		WebSocketURL:     server.URL + "/protected/socks",
		ProxyCommandMode: true,
		TargetHost:       "127.0.0.1",
		TargetPort:       targetListener.Addr().(*net.TCPAddr).Port,
		Stderr:           &stderr,
		HTTPClient:       server.Client(),
		AuthHTTPClient:   browserClient,
		BrowserOpener: func(ctx context.Context, authURL string) error {
			browserCalls++
			return completeKeycloakLogin(browserClient, authURL, username, password)
		},
	}

	firstStdout, firstInput := stdioPair(payload)
	cfg.Stdout = firstStdout
	cfg.Stdin = firstInput
	source, err := newAuthTokenSource(cfg)
	if err != nil {
		t.Fatalf("create auth source: %v", err)
	}
	if err := runProxyCommandMode(context.Background(), cfg, source); err != nil {
		t.Fatalf("first proxycommand run failed: %v\nstderr:\n%s", err, stderr.String())
	}
	if got := firstStdout.String(); got != string(payload) {
		t.Fatalf("unexpected first run stdout: got %q want %q", got, string(payload))
	}
	if browserCalls != 1 {
		t.Fatalf("expected first run to trigger one browser login, got %d", browserCalls)
	}
	if err := <-targetDone; err != nil {
		t.Fatalf("target echo server failed: %v", err)
	}

	secondTarget, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start second echo target: %v", err)
	}
	defer secondTarget.Close()
	secondDone := make(chan error, 1)
	go func() {
		conn, err := secondTarget.Accept()
		if err != nil {
			secondDone <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			secondDone <- err
			return
		}
		_, err = conn.Write(buf)
		secondDone <- err
	}()

	cfg.TargetPort = secondTarget.Addr().(*net.TCPAddr).Port
	secondStdout, secondInput := stdioPair(payload)
	cfg.Stdout = secondStdout
	cfg.Stdin = secondInput
	cfg.BrowserOpener = func(context.Context, string) error {
		t.Fatalf("second run should not need interactive login when cache is valid")
		return nil
	}
	source, err = newAuthTokenSource(cfg)
	if err != nil {
		t.Fatalf("create second auth source: %v", err)
	}
	if err := runProxyCommandMode(context.Background(), cfg, source); err != nil {
		t.Fatalf("second proxycommand run failed: %v", err)
	}
	if got := secondStdout.String(); got != string(payload) {
		t.Fatalf("unexpected second run stdout: got %q want %q", got, string(payload))
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second target echo server failed: %v", err)
	}
}

func completeKeycloakLogin(client *http.Client, authURL, username, password string) error {
	loginResp, err := client.Get(authURL)
	if err != nil {
		return err
	}
	defer loginResp.Body.Close()

	body, err := io.ReadAll(loginResp.Body)
	if err != nil {
		return err
	}
	if loginResp.Request != nil && loginResp.Request.URL != nil && strings.Contains(loginResp.Request.URL.String(), "code=") {
		return nil
	}

	loginAction, err := keycloakLoginAction(authURL, string(body))
	if err != nil {
		return err
	}

	form := url.Values{
		"username":     {username},
		"password":     {password},
		"credentialId": {""},
	}
	postResp, err := client.PostForm(loginAction, form)
	if err != nil {
		return err
	}
	defer postResp.Body.Close()
	if postResp.Request == nil || postResp.Request.URL == nil || !strings.Contains(postResp.Request.URL.String(), "code=") {
		postBody, _ := io.ReadAll(postResp.Body)
		return fmt.Errorf("unexpected Keycloak login result: final_url=%q status=%d body=%q", postResp.Request.URL.String(), postResp.StatusCode, string(postBody))
	}
	return nil
}

var keycloakLoginFormPattern = regexp.MustCompile(`(?s)<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)

func keycloakLoginAction(authURL, body string) (string, error) {
	match := keycloakLoginFormPattern.FindStringSubmatch(body)
	if len(match) != 2 {
		return "", fmt.Errorf("could not find Keycloak login form action")
	}
	action := html.UnescapeString(match[1])
	baseURL, err := url.Parse(authURL)
	if err != nil {
		return "", err
	}
	actionURL, err := baseURL.Parse(action)
	if err != nil {
		return "", err
	}
	return actionURL.String(), nil
}

func stdioPair(payload []byte) (*bytes.Buffer, io.ReadCloser) {
	reader, writer := io.Pipe()
	go func() {
		_, _ = writer.Write(payload)
		time.Sleep(200 * time.Millisecond)
		_ = writer.Close()
	}()
	return &bytes.Buffer{}, reader
}

func getenvDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

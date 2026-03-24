package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestProxyForwardsBidirectionalTraffic validates that proxy copies bytes
// in both directions between the two tunnel endpoints.
func TestProxyForwardsBidirectionalTraffic(t *testing.T) {
	leftApp, leftProxy := net.Pipe()
	rightProxy, rightApp := net.Pipe()

	done := make(chan struct{})
	go func() {
		proxy(leftProxy, rightProxy)
		close(done)
	}()

	// Forward left->right.
	leftToRight := []byte("hello-through-tunnel")
	if _, err := leftApp.Write(leftToRight); err != nil {
		t.Fatalf("write left->right failed: %v", err)
	}
	receivedRight := make([]byte, len(leftToRight))
	if err := rightApp.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline right failed: %v", err)
	}
	if _, err := io.ReadFull(rightApp, receivedRight); err != nil {
		t.Fatalf("read left->right failed: %v", err)
	}
	if string(receivedRight) != string(leftToRight) {
		t.Fatalf("left->right payload mismatch: got %q want %q", string(receivedRight), string(leftToRight))
	}

	// Forward right->left.
	rightToLeft := []byte("reply-through-tunnel")
	if _, err := rightApp.Write(rightToLeft); err != nil {
		t.Fatalf("write right->left failed: %v", err)
	}
	receivedLeft := make([]byte, len(rightToLeft))
	if err := leftApp.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline left failed: %v", err)
	}
	if _, err := io.ReadFull(leftApp, receivedLeft); err != nil {
		t.Fatalf("read right->left failed: %v", err)
	}
	if string(receivedLeft) != string(rightToLeft) {
		t.Fatalf("right->left payload mismatch: got %q want %q", string(receivedLeft), string(rightToLeft))
	}

	// Close application ends to let proxy goroutines exit.
	_ = leftApp.Close()
	_ = rightApp.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("proxy did not exit after closing both application endpoints")
	}
}

// TestBuildSOCKS5ConnectRequestDomain ensures hostname-based CONNECT requests
// are encoded with the expected domain ATYP and destination port bytes.
func TestBuildSOCKS5ConnectRequestDomain(t *testing.T) {
	request, err := buildSOCKS5ConnectRequest("example.com", 22)
	if err != nil {
		t.Fatalf("build request failed: %v", err)
	}

	expectedPrefix := []byte{socksVersion5, socksCmdConnect, 0x00, socksAtypDomain, byte(len("example.com"))}
	if !bytes.Equal(request[:len(expectedPrefix)], expectedPrefix) {
		t.Fatalf("unexpected request prefix: got %v want %v", request[:len(expectedPrefix)], expectedPrefix)
	}

	hostBytes := []byte("example.com")
	hostStart := len(expectedPrefix)
	hostEnd := hostStart + len(hostBytes)
	if !bytes.Equal(request[hostStart:hostEnd], hostBytes) {
		t.Fatalf("unexpected hostname encoding: got %v want %v", request[hostStart:hostEnd], hostBytes)
	}

	if gotHi, gotLo := request[len(request)-2], request[len(request)-1]; gotHi != 0x00 || gotLo != 0x16 {
		t.Fatalf("unexpected port encoding for 22: got [%d %d]", gotHi, gotLo)
	}
}

// TestPerformSOCKS5ConnectSuccess validates the end-to-end greeting + CONNECT
// exchange against a mock SOCKS5 server running over net.Pipe.
func TestPerformSOCKS5ConnectSuccess(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- runMockSOCKS5ServerSuccess(serverConn, t)
	}()

	if err := performSOCKS5Connect(clientConn, "example.com", 22); err != nil {
		t.Fatalf("performSOCKS5Connect failed: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("mock server failed: %v", err)
	}
}

// TestPerformSOCKS5ConnectRejectsUnsupportedAuthMethod verifies that we fail fast
// when the SOCKS5 server does not accept no-authentication.
func TestPerformSOCKS5ConnectRejectsUnsupportedAuthMethod(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 3)
		_, _ = io.ReadFull(serverConn, buf)
		_, _ = serverConn.Write([]byte{socksVersion5, 0x02})
	}()

	err := performSOCKS5Connect(clientConn, "example.com", 22)
	if err == nil {
		t.Fatalf("expected unsupported auth method error")
	}
}

func runMockSOCKS5ServerSuccess(conn net.Conn, t *testing.T) error {
	greeting := make([]byte, 3)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return err
	}
	expectedGreeting := []byte{socksVersion5, 0x01, 0x00}
	if !bytes.Equal(greeting, expectedGreeting) {
		t.Fatalf("unexpected greeting: got %v want %v", greeting, expectedGreeting)
	}
	if _, err := conn.Write([]byte{socksVersion5, 0x00}); err != nil {
		return err
	}

	requestHeader := make([]byte, 5)
	if _, err := io.ReadFull(conn, requestHeader); err != nil {
		return err
	}
	if requestHeader[0] != socksVersion5 || requestHeader[1] != socksCmdConnect || requestHeader[3] != socksAtypDomain {
		t.Fatalf("unexpected request header: %v", requestHeader)
	}

	hostLen := int(requestHeader[4])
	hostBytes := make([]byte, hostLen)
	if _, err := io.ReadFull(conn, hostBytes); err != nil {
		return err
	}
	if string(hostBytes) != "example.com" {
		t.Fatalf("unexpected host: got %q", string(hostBytes))
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return err
	}
	if !bytes.Equal(portBytes, []byte{0x00, 0x16}) {
		t.Fatalf("unexpected port bytes for 22: %v", portBytes)
	}

	// SOCKS5 success reply with IPv4 bind addr 0.0.0.0:0.
	_, err := conn.Write([]byte{socksVersion5, socksReplySucceeded, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// TestDiscoverOIDCEndpointsSuccess verifies we can read auth/token endpoints
// from a well-formed OpenID discovery document.
func TestDiscoverOIDCEndpointsSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/default/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"authorization_endpoint":"https://idp.example/auth","token_endpoint":"https://idp.example/token"}`))
	}))
	defer server.Close()

	authURL, tokenURL, err := discoverOIDCEndpoints(context.Background(), server.URL+"/oauth2/default")
	if err != nil {
		t.Fatalf("discoverOIDCEndpoints failed: %v", err)
	}
	if authURL != "https://idp.example/auth" {
		t.Fatalf("unexpected authURL: got %q", authURL)
	}
	if tokenURL != "https://idp.example/token" {
		t.Fatalf("unexpected tokenURL: got %q", tokenURL)
	}
}

// TestDiscoverOIDCEndpointsMissingFields validates discovery failures are
// surfaced when required fields are absent.
func TestDiscoverOIDCEndpointsMissingFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"authorization_endpoint":"https://idp.example/auth"}`))
	}))
	defer server.Close()

	_, _, err := discoverOIDCEndpoints(context.Background(), server.URL)
	if err == nil {
		t.Fatalf("expected missing-field discovery error")
	}
}

// TestPKCES256Challenge checks deterministic challenge calculation for auditing.
func TestPKCES256Challenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expected := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	challenge := pkceS256Challenge(verifier)
	if challenge != expected {
		t.Fatalf("unexpected challenge: got %q want %q", challenge, expected)
	}

	// Ensure output is URL-safe base64 without padding.
	if _, err := base64.RawURLEncoding.DecodeString(challenge); err != nil {
		t.Fatalf("challenge should be url-safe base64: %v", err)
	}
}

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestParseServerConfigAcceptsPreAuthRateAndBurstFlags(t *testing.T) {
	cfg, err := parseServerConfig(
		[]string{
			"--oidc-issuer", "https://issuer.example",
			"--token-audience", "authunnel-server",
			"--tls-cert", "/flags/server.crt",
			"--tls-key", "/flags/server.key",
			"--allow-open-egress",
			"--preauth-rate", "5",
			"--preauth-burst", "20",
		},
		func(string) string { return "" },
	)
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.PreAuthRate != 5 {
		t.Fatalf("PreAuthRate = %v, want 5", cfg.PreAuthRate)
	}
	if cfg.PreAuthBurst != 20 {
		t.Fatalf("PreAuthBurst = %v, want 20", cfg.PreAuthBurst)
	}
}

func TestParseServerConfigDefaultsPreAuthBurstToCeilRate(t *testing.T) {
	cfg, err := parseServerConfig(
		[]string{
			"--oidc-issuer", "https://issuer.example",
			"--token-audience", "authunnel-server",
			"--tls-cert", "/flags/server.crt",
			"--tls-key", "/flags/server.key",
			"--allow-open-egress",
			"--preauth-rate", "2.3",
		},
		func(string) string { return "" },
	)
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.PreAuthBurst != 3 {
		t.Fatalf("PreAuthBurst defaulting expected ceil(2.3)=3, got %d", cfg.PreAuthBurst)
	}
}

func TestParseServerConfigRejectsPreAuthBurstWithoutRate(t *testing.T) {
	_, err := parseServerConfig(
		[]string{
			"--oidc-issuer", "https://issuer.example",
			"--token-audience", "authunnel-server",
			"--tls-cert", "/flags/server.crt",
			"--tls-key", "/flags/server.key",
			"--allow-open-egress",
			"--preauth-burst", "10",
		},
		func(string) string { return "" },
	)
	if err == nil {
		t.Fatalf("expected error when --preauth-burst is set without --preauth-rate")
	}
	if !strings.Contains(err.Error(), "preauth-rate") {
		t.Fatalf("error %q does not mention --preauth-rate", err.Error())
	}
}

func TestParseServerConfigReadsPreAuthEnvVars(t *testing.T) {
	cfg, err := parseServerConfig(
		[]string{
			"--oidc-issuer", "https://issuer.example",
			"--token-audience", "authunnel-server",
			"--tls-cert", "/flags/server.crt",
			"--tls-key", "/flags/server.key",
			"--allow-open-egress",
		},
		func(key string) string {
			switch key {
			case "PREAUTH_RATE":
				return "4"
			case "PREAUTH_BURST":
				return "12"
			}
			return ""
		},
	)
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.PreAuthRate != 4 {
		t.Fatalf("PreAuthRate via env = %v, want 4", cfg.PreAuthRate)
	}
	if cfg.PreAuthBurst != 12 {
		t.Fatalf("PreAuthBurst via env = %v, want 12", cfg.PreAuthBurst)
	}
}

func TestParseServerConfigRejectsNegativePreAuthRate(t *testing.T) {
	_, err := parseServerConfig(
		[]string{
			"--oidc-issuer", "https://issuer.example",
			"--token-audience", "authunnel-server",
			"--tls-cert", "/flags/server.crt",
			"--tls-key", "/flags/server.key",
			"--allow-open-egress",
			"--preauth-rate", "-1",
		},
		func(string) string { return "" },
	)
	if err == nil {
		t.Fatal("expected negative --preauth-rate to be rejected")
	}
}

// TestHTTPServerMaxHeaderBytesEnforced builds an http.Server with the
// production MaxHeaderBytes setting and confirms requests with headers above
// the cap are rejected with 431, before reaching the handler. This guards the
// pre-validator memory bound the lowered cap is meant to provide.
func TestHTTPServerMaxHeaderBytesEnforced(t *testing.T) {
	handlerHit := false
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerHit = true
			w.WriteHeader(http.StatusOK)
		}),
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    httpServerMaxHeaderBytes,
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() { _ = server.Serve(ln) }()
	defer server.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Go's net/http allows MaxHeaderBytes + 4096 bytes of slack on the wire
	// before rejecting; send a header that exceeds the cap by a safe margin
	// so the rejection is unambiguous.
	bigValue := strings.Repeat("x", httpServerMaxHeaderBytes+8192)
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: localhost\r\nX-Big: %s\r\n\r\n", bigValue)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		t.Fatalf("read response: %v", err)
	}
	got := string(buf[:n])
	if !strings.HasPrefix(got, "HTTP/1.1 431 ") {
		t.Fatalf("expected 431 status line, got: %q", strings.SplitN(got, "\r\n", 2)[0])
	}
	if handlerHit {
		t.Fatal("handler must not be invoked when headers exceed MaxHeaderBytes")
	}
}

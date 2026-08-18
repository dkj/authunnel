package authhttp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckDiscoveredEndpoint(t *testing.T) {
	tests := []struct {
		name           string
		metadataSource string
		endpoint       string
		wantErr        string
	}{
		{name: "https to https", metadataSource: "https://as.example/meta", endpoint: "https://as.example/token"},
		{name: "https to http", metadataSource: "https://as.example/meta", endpoint: "http://as.example/token", wantErr: "non-https token_endpoint"},
		{name: "http to http", metadataSource: "http://127.0.0.1/meta", endpoint: "http://127.0.0.1/token"},
		{name: "http to https", metadataSource: "http://127.0.0.1/meta", endpoint: "https://as.example/token"},
		{name: "opaque no host", metadataSource: "https://as.example/meta", endpoint: "https:relative-path", wantErr: "absolute URL with a host"},
		{name: "scheme only", metadataSource: "https://as.example/meta", endpoint: "https:", wantErr: "absolute URL with a host"},
		{name: "empty host", metadataSource: "https://as.example/meta", endpoint: "https:///path", wantErr: "absolute URL with a host"},
		{name: "file scheme over http", metadataSource: "http://127.0.0.1/meta", endpoint: "file:///etc/passwd", wantErr: `unsupported scheme "file"`},
		{name: "custom scheme", metadataSource: "https://as.example/meta", endpoint: "myapp://do-something", wantErr: `unsupported scheme "myapp"`},
		{name: "empty", metadataSource: "https://as.example/meta", wantErr: "did not advertise"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckDiscoveredEndpoint("token_endpoint", tt.metadataSource, tt.endpoint)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckDiscoveredEndpoint(%q, %q) = %v, want nil", tt.metadataSource, tt.endpoint, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("CheckDiscoveredEndpoint(%q, %q) = nil, want error containing %q", tt.metadataSource, tt.endpoint, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("CheckDiscoveredEndpoint(%q, %q) = %v, want error containing %q", tt.metadataSource, tt.endpoint, err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), "token_endpoint") {
				t.Fatalf("error should name the endpoint being checked, got %v", err)
			}
		})
	}
}

func TestCheckConfiguredURL(t *testing.T) {
	tests := []struct {
		name           string
		raw            string
		allowPlaintext bool
		wantErr        string
	}{
		{name: "https", raw: "https://issuer.example"},
		{name: "http rejected by default", raw: "http://issuer.example", wantErr: "must use an https:// URL"},
		{name: "http with override", raw: "http://issuer.example", allowPlaintext: true},

		// The override relaxes the transport, not the scheme allowlist.
		{name: "file rejected", raw: "file:///etc/jwks.json", wantErr: `unsupported scheme "file"`},
		{name: "file rejected under override", raw: "file:///etc/jwks.json", allowPlaintext: true, wantErr: `unsupported scheme "file"`},

		{name: "host-less", raw: "https:relative", wantErr: "absolute URL with a host"},
		{name: "host-less under override", raw: "https:relative", allowPlaintext: true, wantErr: "absolute URL with a host"},
		{name: "empty", raw: "", wantErr: "is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckConfiguredURL("--oidc-issuer", tt.raw, tt.allowPlaintext)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckConfiguredURL(%q, %v) = %v, want nil", tt.raw, tt.allowPlaintext, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("CheckConfiguredURL(%q, %v) = %v, want error containing %q", tt.raw, tt.allowPlaintext, err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), "--oidc-issuer") {
				t.Fatalf("error should name the flag to fix, got %v", err)
			}
		})
	}
}

func TestCheckHTTPURL(t *testing.T) {
	for _, tt := range []struct {
		name, raw, wantErr string
	}{
		{name: "https", raw: "https://keys.example/jwks"},
		{name: "http", raw: "http://127.0.0.1/jwks"},
		{name: "unsupported scheme", raw: "file:///tmp/jwks.json", wantErr: `unsupported scheme "file"`},
		{name: "host-less", raw: "https:relative", wantErr: "absolute URL with a host"},
		{name: "empty", wantErr: "is required"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckHTTPURL("JWKS URI", tt.raw)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("CheckHTTPURL(%q) = %v, want nil", tt.raw, err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("CheckHTTPURL(%q) = %v, want error containing %q", tt.raw, err, tt.wantErr)
			}
		})
	}
}

// Refusals match the sentinel without exposing its generic text to operators.
func TestRefusalMessagesAreOperatorReadable(t *testing.T) {
	for _, err := range []error{
		CheckConfiguredURL("--oidc-issuer", "http://issuer.example", false),
		CheckHTTPURL("JWKS URI", "file:///etc/jwks.json"),
		CheckDiscoveredEndpoint("token_endpoint", "https://as.example", "file:///tmp/token"),
		CheckDiscoveredEndpoint("jwks_uri", "https://as.example", "http://as.example/keys"),
	} {
		if strings.Contains(err.Error(), ErrUnsafeTransport.Error()) {
			t.Fatalf("message leaks the sentinel text: %v", err)
		}
		if !errors.Is(err, ErrUnsafeTransport) {
			t.Fatalf("error %v no longer matches the sentinel", err)
		}
	}
}

func TestNewBoundedClientRefusesDowngradeRedirect(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer plain.Close()

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/next", http.StatusFound)
	}))
	defer tlsSrv.Close()

	client := NewBoundedClient()
	// Trust the fixture while retaining the bounded client's redirect policy.
	client.Transport = tlsSrv.Client().Transport

	resp, err := client.Get(tlsSrv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected the bounded client to refuse an https->http redirect")
	}
	if !strings.Contains(err.Error(), "transport downgrade") {
		t.Fatalf("error = %v, want the downgrade guard", err)
	}
}

// Callers use the sentinel to distinguish policy refusal from transient errors.
func TestRefusalsWrapErrUnsafeTransport(t *testing.T) {
	t.Run("endpoint checks", func(t *testing.T) {
		const unparseable = "http://[::1" // missing ']' in host

		for name, err := range map[string]error{
			"missing endpoint":      CheckDiscoveredEndpoint("token_endpoint", "https://as.example", ""),
			"bad scheme":            CheckDiscoveredEndpoint("token_endpoint", "https://as.example", "file:///x"),
			"host-less":             CheckDiscoveredEndpoint("token_endpoint", "https://as.example", "https:relative"),
			"unparseable endpoint":  CheckDiscoveredEndpoint("token_endpoint", "https://as.example", unparseable),
			"downgraded":            CheckDiscoveredEndpoint("jwks_uri", "https://as.example", "http://as.example/keys"),
			"unparseable source":    CheckDiscoveredEndpoint("jwks_uri", unparseable, "https://as.example/keys"),
			"configured missing":    CheckConfiguredURL("--oidc-issuer", "", false),
			"configured plaintext":  CheckConfiguredURL("--oidc-issuer", "http://issuer.example", false),
			"configured bad scheme": CheckConfiguredURL("--oidc-issuer", "file:///x", true),
			"configured host-less":  CheckConfiguredURL("--oidc-issuer", "https:relative", false),
			"HTTP URL missing":      CheckHTTPURL("JWKS URI", ""),
			"HTTP URL bad scheme":   CheckHTTPURL("JWKS URI", "file:///x"),
		} {
			if err == nil {
				t.Fatalf("%s: expected an error", name)
			}
			if !errors.Is(err, ErrUnsafeTransport) {
				t.Fatalf("%s: error %v does not wrap ErrUnsafeTransport", name, err)
			}
		}
	})

	t.Run("redirect limit", func(t *testing.T) {
		// Redirect exhaustion is also a policy refusal.
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, srv.URL+"/next", http.StatusFound)
		}))
		defer srv.Close()

		resp, err := NewBoundedClient().Get(srv.URL)
		if err == nil {
			resp.Body.Close()
			t.Fatal("expected the redirect cap to stop the chain")
		}
		if !strings.Contains(err.Error(), "stopped after") {
			t.Fatalf("error = %v, want the redirect cap", err)
		}
		if !errors.Is(err, ErrUnsafeTransport) {
			t.Fatalf("redirect-cap error %v does not wrap ErrUnsafeTransport", err)
		}
	})
}

// Preserve a caller-supplied redirect error without relabelling it as ours.
func TestInheritedPolicyErrorIsNotRelabelled(t *testing.T) {
	callerPolicy := errors.New("caller policy: no cross-host redirects")

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/next" {
			http.Redirect(w, r, srv.URL+"/next", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	base := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return callerPolicy
	}}

	resp, err := RefuseTransportDowngrade(base).Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected the caller's redirect policy to reject the redirect")
	}
	if !errors.Is(err, callerPolicy) {
		t.Fatalf("error = %v, want the caller's own error identity preserved", err)
	}
	if errors.Is(err, ErrUnsafeTransport) {
		t.Fatalf("error = %v, must not be relabelled as this package's refusal", err)
	}
}

// TestNewBoundedClientAllowsSameSchemeRedirect is the control: the guard must
// not turn into "no redirects at all".
func TestNewBoundedClientAllowsSameSchemeRedirect(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/final" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	resp, err := NewBoundedClient().Get(srv.URL)
	if err != nil {
		t.Fatalf("same-scheme redirect should be followed, got %v", err)
	}
	defer resp.Body.Close()
	if hits != 2 {
		t.Fatalf("expected the redirect to be followed (2 requests), got %d", hits)
	}
}

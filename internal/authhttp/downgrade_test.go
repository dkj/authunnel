package authhttp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckEndpointURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{name: "https with host", raw: "https://as.example/token"},
		{name: "http with host", raw: "http://127.0.0.1:8080/token"},

		// These are the cases a scheme-only check admits. "https:relative"
		// parses with Scheme "https" and IsAbs() true, so neither a scheme
		// test nor an IsAbs test rejects it — only requiring a host and an
		// empty Opaque does.
		{name: "opaque, no host", raw: "https:relative-path", wantErr: "absolute URL with a host"},
		{name: "scheme only", raw: "https:", wantErr: "absolute URL with a host"},
		{name: "empty host", raw: "https:///path", wantErr: "absolute URL with a host"},

		{name: "file scheme", raw: "file:///etc/passwd", wantErr: `unsupported scheme "file"`},
		{name: "custom scheme", raw: "myapp://do-something", wantErr: `unsupported scheme "myapp"`},
		{name: "empty", raw: "", wantErr: "did not advertise"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckEndpointURL("token_endpoint", tt.raw)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckEndpointURL(%q) = %v, want nil", tt.raw, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("CheckEndpointURL(%q) = nil, want error containing %q", tt.raw, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("CheckEndpointURL(%q) = %v, want error containing %q", tt.raw, err, tt.wantErr)
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

// TestRefusalMessagesAreOperatorReadable pins the refusef design. Wrapping the
// sentinel with %w would append ": unsafe auth transport" to every message an
// operator sees at startup, which says nothing they can act on.
func TestRefusalMessagesAreOperatorReadable(t *testing.T) {
	for _, err := range []error{
		CheckConfiguredURL("--oidc-issuer", "http://issuer.example", false),
		CheckConfiguredURL("--oidc-jwks-uri", "file:///etc/jwks.json", true),
		CheckEndpointURL("token_endpoint", "file:///tmp/token"),
		CheckNoSchemeDowngrade("jwks_uri", "https://as.example", "http://as.example/keys"),
	} {
		if strings.Contains(err.Error(), ErrUnsafeTransport.Error()) {
			t.Fatalf("message leaks the sentinel text: %v", err)
		}
		if !errors.Is(err, ErrUnsafeTransport) {
			t.Fatalf("error %v no longer matches the sentinel", err)
		}
	}
}

func TestCheckNoSchemeDowngrade(t *testing.T) {
	tests := []struct {
		name           string
		source, target string
		wantErr        bool
	}{
		{name: "https to https", source: "https://as.example", target: "https://as.example/keys"},
		{name: "https to http", source: "https://as.example", target: "http://as.example/keys", wantErr: true},

		// An http metadata source has no downgrade left to prevent — the
		// development path. CheckEndpointURL, not this function, is what
		// keeps other schemes out here.
		{name: "http to http", source: "http://127.0.0.1:8080", target: "http://127.0.0.1:8080/keys"},
		{name: "http to https", source: "http://127.0.0.1:8080", target: "https://as.example/keys"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckNoSchemeDowngrade("jwks_uri", tt.source, tt.target)
			if tt.wantErr && err == nil {
				t.Fatalf("CheckNoSchemeDowngrade(%q, %q) = nil, want error", tt.source, tt.target)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("CheckNoSchemeDowngrade(%q, %q) = %v, want nil", tt.source, tt.target, err)
			}
		})
	}
}

// TestNewBoundedClientRefusesDowngradeRedirect covers the constructor default
// independently of either caller, so the guarantee does not rest on every call
// site remembering to opt in.
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
	// Trust the test server's certificate without disturbing the redirect
	// policy under test.
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

// TestRefusalsWrapErrUnsafeTransport pins the sentinel's contract. Callers use
// it to decide that retrying cannot help, so a refusal that fails to wrap it
// gets treated as an ordinary failure — on the client that means falling
// through to an interactive login which then fails the same way.
func TestRefusalsWrapErrUnsafeTransport(t *testing.T) {
	// Every error this package's own policy generates, including the
	// malformed-URL ones. Those are unreachable through the current call
	// sites, since CheckEndpointURL parses first — but they are exported, and
	// an unwrapped error here would read to a caller as "transient" and send
	// a user through a login that cannot succeed.
	t.Run("endpoint checks", func(t *testing.T) {
		const unparseable = "http://[::1" // missing ']' in host

		for name, err := range map[string]error{
			"missing endpoint":      CheckEndpointURL("token_endpoint", ""),
			"bad scheme":            CheckEndpointURL("token_endpoint", "file:///x"),
			"host-less":             CheckEndpointURL("token_endpoint", "https:relative"),
			"unparseable endpoint":  CheckEndpointURL("token_endpoint", unparseable),
			"downgraded":            CheckNoSchemeDowngrade("jwks_uri", "https://as.example", "http://as.example/keys"),
			"unparseable source":    CheckNoSchemeDowngrade("jwks_uri", unparseable, "https://as.example/keys"),
			"unparseable resolved":  CheckNoSchemeDowngrade("jwks_uri", "https://as.example", unparseable),
			"configured missing":    CheckConfiguredURL("--oidc-issuer", "", false),
			"configured plaintext":  CheckConfiguredURL("--oidc-issuer", "http://issuer.example", false),
			"configured bad scheme": CheckConfiguredURL("--oidc-issuer", "file:///x", true),
			"configured host-less":  CheckConfiguredURL("--oidc-issuer", "https:relative", false),
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
		// A redirect loop is us declining to continue, not the issuer being
		// unreachable, so it belongs under the same sentinel as the
		// downgrade refusal.
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

// TestInheritedPolicyErrorIsNotRelabelled pins the other side of the sentinel's
// contract. A caller's own CheckRedirect verdict is delegated to and returned
// unchanged: its identity must survive so the caller can still recognise it,
// and it must *not* acquire our sentinel, which would report the caller's
// policy as ours and assert a retry semantic we cannot know.
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

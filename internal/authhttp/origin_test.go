package authhttp

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
)

// TestSameOriginAgreesOnEquivalentSpellings is the regression guard for a drift
// between two implementations of one rule. SameOrigin kept its own authority
// normalisation, which omitted the IP canonicalisation the resource-identifier
// comparison applied, so these pairs were "different origins" here and "the same
// identifier" there — and a published metadata URL on a pinned issuer's own origin,
// spelled with a non-canonical IPv6 literal, was disregarded.
func TestSameOriginAgreesOnEquivalentSpellings(t *testing.T) {
	for _, tt := range []struct{ a, b string }{
		{"https://[0:0:0:0:0:0:0:1]/x", "https://[::1]/y"},
		{"https://[::FFFF:127.0.0.1]/x", "https://127.0.0.1/y"},
		{"https://TUNNEL.example:443/x", "https://tunnel.example/y"},
		{"HTTP://tunnel.example:80/x", "http://tunnel.example/y"},
	} {
		same, err := SameOrigin(tt.a, tt.b)
		if err != nil {
			t.Fatalf("SameOrigin(%q, %q): %v", tt.a, tt.b, err)
		}
		if !same {
			t.Fatalf("SameOrigin(%q, %q) = false; these are one origin spelled two ways", tt.a, tt.b)
		}
	}
	// And origins that genuinely differ must stay different, including on port.
	for _, tt := range []struct{ a, b string }{
		{"https://tunnel.example/x", "https://tunnel.example:8443/x"},
		{"https://tunnel.example/x", "http://tunnel.example/x"},
		{"https://[::1]/x", "https://[::2]/x"},
	} {
		if same, _ := SameOrigin(tt.a, tt.b); same {
			t.Fatalf("SameOrigin(%q, %q) = true", tt.a, tt.b)
		}
	}
	for _, tt := range []struct{ a, b string }{
		{"not-a-url", "https://tunnel.example"},
		{"https://tunnel.example", "/relative"},
	} {
		if _, err := SameOrigin(tt.a, tt.b); err == nil {
			t.Fatalf("SameOrigin(%q, %q): expected an error", tt.a, tt.b)
		}
	}
}

// TestPinRedirectOriginLayersOnTheCallersPolicy pins the contract in its own
// package. RefuseTransportDowngrade has the identical contract and a test for it;
// this one did not, so dropping the delegation to an inherited CheckRedirect went
// unnoticed — a caller's own policy could be silently discarded.
func TestPinRedirectOriginLayersOnTheCallersPolicy(t *testing.T) {
	inheritedCalled := false
	sentinel := errors.New("the caller's own refusal")
	base := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		inheritedCalled = true
		return sentinel
	}}

	pinned := PinRedirectOrigin(base)
	from, err := http.NewRequest(http.MethodGet, "https://issuer.example/meta", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	// Same origin: our rule passes, so the caller's must be consulted and its
	// verdict returned unchanged.
	sameOrigin, err := http.NewRequest(http.MethodGet, "https://issuer.example/elsewhere", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := pinned.CheckRedirect(sameOrigin, []*http.Request{from}); !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the caller's own %v", err, sentinel)
	}
	if !inheritedCalled {
		t.Fatal("the caller's CheckRedirect was not consulted")
	}
	// An inherited verdict must not acquire our sentinel: it is the caller's
	// policy, and we do not know whether retrying it could help.
	if errors.Is(pinned.CheckRedirect(sameOrigin, []*http.Request{from}), ErrUnsafeTransport) {
		t.Fatal("an inherited error must keep its own identity")
	}

	crossOrigin, err := http.NewRequest(http.MethodGet, "https://elsewhere.example/meta", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// The caller's verdict is reported ahead of ours, so a redirect that is both a
	// downgrade and an origin change is named as the downgrade — the more specific
	// fault. The composed answer is still refusal either way.
	if err := pinned.CheckRedirect(crossOrigin, []*http.Request{from}); !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the caller's more specific %v", err, sentinel)
	}
	// With a permissive caller, ours is what refuses a cross-origin hop.
	permissive := PinRedirectOrigin(&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }})
	if err := permissive.CheckRedirect(crossOrigin, []*http.Request{from}); !errors.Is(err, ErrUnsafeTransport) {
		t.Fatalf("error = %v, want %v", err, ErrUnsafeTransport)
	}
	if err := permissive.CheckRedirect(sameOrigin, []*http.Request{from}); err != nil {
		t.Fatalf("a same-origin hop with a permissive caller should be allowed, got: %v", err)
	}

	// And the caller's own client is untouched.
	if base.CheckRedirect == nil {
		t.Fatal("the base client lost its policy")
	}
	if err := base.CheckRedirect(crossOrigin, []*http.Request{from}); !errors.Is(err, sentinel) {
		t.Fatalf("the base client's policy changed: %v", err)
	}
}

// TestPinRedirectOriginToleratesAnEmptyChain covers the defensive branch: net/http
// always supplies a non-empty via, but a nil-safe policy is cheaper than a panic in
// a redirect handler.
func TestPinRedirectOriginToleratesAnEmptyChain(t *testing.T) {
	pinned := PinRedirectOrigin(&http.Client{})
	req, err := http.NewRequest(http.MethodGet, "https://issuer.example/meta", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := pinned.CheckRedirect(req, nil); err != nil {
		t.Fatalf("empty via chain should be permitted, got %v", err)
	}
}

// TestNormalizeAuthorityCanonicalises documents the shared helper directly, since
// two callers now depend on it agreeing with itself.
func TestNormalizeAuthorityCanonicalises(t *testing.T) {
	for _, tt := range []struct{ scheme, rawURL, want string }{
		{"https", "https://TUNNEL.example", "tunnel.example"},
		{"https", "https://tunnel.example:443", "tunnel.example"},
		{"http", "http://tunnel.example:80", "tunnel.example"},
		{"https", "https://tunnel.example:8443", "tunnel.example:8443"},
		{"https", "https://[0:0:0:0:0:0:0:1]", "[::1]"},
		{"https", "https://[::1]:8443", "[::1]:8443"},
		{"https", "https://[::FFFF:127.0.0.1]", "127.0.0.1"},
	} {
		u, err := url.Parse(tt.rawURL)
		if err != nil {
			t.Fatalf("parse %q: %v", tt.rawURL, err)
		}
		if got := NormalizeAuthority(tt.scheme, u); got != tt.want {
			t.Fatalf("NormalizeAuthority(%q) = %q, want %q", tt.rawURL, got, tt.want)
		}
	}
}

package authmeta

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"authunnel/internal/authhttp"
)

func TestProtectedResourceURLDerivation(t *testing.T) {
	for _, tt := range []struct{ resource, want string }{
		// §3.1 inserts the well-known segment between authority and path.
		{"https://tunnel.example/protected/tunnel", "https://tunnel.example/.well-known/oauth-protected-resource/protected/tunnel"},
		{"https://tunnel.example", "https://tunnel.example/.well-known/oauth-protected-resource"},
		{"https://tunnel.example/", "https://tunnel.example/.well-known/oauth-protected-resource"},
		{"https://tunnel.example:8443/protected/tunnel", "https://tunnel.example:8443/.well-known/oauth-protected-resource/protected/tunnel"},
		{"http://127.0.0.1:8080/protected/tunnel", "http://127.0.0.1:8080/.well-known/oauth-protected-resource/protected/tunnel"},
		// The query is part of the identifier and rides along.
		{"https://tunnel.example/protected/tunnel?tenant=a", "https://tunnel.example/.well-known/oauth-protected-resource/protected/tunnel?tenant=a"},
		// Including an empty one. A bare "?" is recorded in ForceQuery rather than
		// RawQuery, so carrying only RawQuery drops the delimiter — and the dial does
		// send it, which the "?tenant=a" case above cannot detect. Contrast the bare
		// "#" in the rejection list below: a fragment is not part of an identifier,
		// while an empty query is.
		{"https://tunnel.example/protected/tunnel?", "https://tunnel.example/.well-known/oauth-protected-resource/protected/tunnel?"},
		// Syntax normalisation is shared with the comparison, so a redundant
		// default port and an upper-case host derive the same location as their
		// canonical spellings.
		{"HTTPS://TUNNEL.example:443/protected/tunnel", "https://tunnel.example/.well-known/oauth-protected-resource/protected/tunnel"},
		// An encoded separator survives: %2F is not a path separator, and
		// decoding it would ask for the document of a different resource.
		{"https://tunnel.example/tenant%2Fone/tunnel", "https://tunnel.example/.well-known/oauth-protected-resource/tenant%2Fone/tunnel"},
	} {
		got, err := ProtectedResourceURL(tt.resource)
		if err != nil {
			t.Fatalf("ProtectedResourceURL(%q): %v", tt.resource, err)
		}
		if got != tt.want {
			t.Fatalf("ProtectedResourceURL(%q) = %q, want %q", tt.resource, got, tt.want)
		}
	}
}

func TestProtectedResourceURLRejectsUnusableResource(t *testing.T) {
	for _, resource := range []string{
		"",
		"tunnel.example/protected/tunnel",
		"wss://tunnel.example/protected/tunnel",
		"ftp://tunnel.example/protected/tunnel",
		"file:///etc/authunnel",
		"https:relative",
		"https://",
		// Refused rather than stripped: a fragment is not part of an identifier,
		// and quietly deriving a location for a *different* value than the one
		// handed in is how the derived URL and the compared URL drift apart.
		"https://tunnel.example/protected/tunnel#frag",
		// A *bare* delimiter, which parses with an empty Fragment and no other
		// trace — so a check on the parsed field alone accepts it and normalisation
		// then drops the "#". The "#frag" case above cannot detect that.
		"https://tunnel.example/protected/tunnel#",
		"https://tunnel.example/protected/tunnel?tenant=a#",
	} {
		if _, err := ProtectedResourceURL(resource); err == nil {
			t.Fatalf("ProtectedResourceURL(%q): expected an error", resource)
		}
	}
}

// protectedResourceServer serves a document at the derived well-known path for
// its own origin, with the declared `resource` under the test's control.
func protectedResourceServer(t *testing.T, declaredResource func(base string) string, useTLS bool) (*httptest.Server, string) {
	t.Helper()
	var server *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, ProtectedResourcePath) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		document := ProtectedResource{
			Resource:               declaredResource(server.URL),
			AuthorizationServers:   []string{"https://idp.example/realms/main"},
			BearerMethodsSupported: []string{"header"},
			ClientID:               "authunnel-cli",
			ScopesSupported:        []string{"openid", "offline_access"},
		}
		writeJSON(t, w, document)
	})
	if useTLS {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(server.Close)
	return server, server.URL + "/protected/tunnel"
}

func TestFetchProtectedResource(t *testing.T) {
	server, resourceURL := protectedResourceServer(t, func(base string) string { return base + "/protected/tunnel" }, false)

	document, err := FetchProtectedResource(context.Background(), server.Client(), resourceURL)
	if err != nil {
		t.Fatalf("FetchProtectedResource: %v", err)
	}
	if document.AuthorizationServer() != "https://idp.example/realms/main" {
		t.Fatalf("authorization server = %q", document.AuthorizationServer())
	}
	if document.ClientID != "authunnel-cli" {
		t.Fatalf("client ID hint = %q", document.ClientID)
	}
}

// TestFetchProtectedResourceRejectsForeignResource is the check that makes this
// document trustworthy enough to take an authorization server's identity from.
// Without it, a resource server could point a client's login anywhere by
// describing someone else's resource.
func TestFetchProtectedResourceRejectsForeignResource(t *testing.T) {
	server, resourceURL := protectedResourceServer(t, func(string) string { return "https://attacker.example/protected/tunnel" }, false)

	_, err := FetchProtectedResource(context.Background(), server.Client(), resourceURL)
	if err == nil {
		t.Fatal("expected a document describing another resource to be refused")
	}
	for _, want := range []string{"attacker.example", resourceURL} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should name both resources, got: %v", err)
		}
	}
}

// TestFetchProtectedResourceRejectsDifferentPath is the case that makes the
// comparison exact rather than origin-only: one host can serve several protected
// resources, and a document about a neighbouring path would otherwise hand this
// client that neighbour's authorization server and client ID.
func TestFetchProtectedResourceRejectsDifferentPath(t *testing.T) {
	server, resourceURL := protectedResourceServer(t, func(base string) string { return base + "/different/path" }, false)

	_, err := FetchProtectedResource(context.Background(), server.Client(), resourceURL)
	if err == nil {
		t.Fatal("expected a document describing a different path on the same host to be refused")
	}
	if !strings.Contains(err.Error(), "/different/path") {
		t.Fatalf("error should quote the declared identifier, got: %v", err)
	}

	// An https control, so the rejection above is attributable to the declared
	// identifier rather than to TLS handling in the fixture.
	secure, secureResource := protectedResourceServer(t, func(base string) string { return base + "/protected/tunnel" }, true)
	if _, err := FetchProtectedResource(context.Background(), secure.Client(), secureResource); err != nil {
		t.Fatalf("https control should succeed: %v", err)
	}
}

// TestFetchProtectedResourceMatchesOnQuery pins that the query is part of the
// identifier on both sides. Two tunnel URLs differing only in their query are two
// resources; treating them as one is how a token minted for one tenant reaches
// another.
func TestFetchProtectedResourceMatchesOnQuery(t *testing.T) {
	server, resourceURL := protectedResourceServer(t, func(base string) string { return base + "/protected/tunnel?tenant=a" }, false)

	if _, err := FetchProtectedResource(context.Background(), server.Client(), resourceURL+"?tenant=a"); err != nil {
		t.Fatalf("a matching query must be accepted: %v", err)
	}
	if _, err := FetchProtectedResource(context.Background(), server.Client(), resourceURL+"?tenant=b"); err == nil {
		t.Fatal("expected a document describing another tenant's query to be refused")
	}
	if _, err := FetchProtectedResource(context.Background(), server.Client(), resourceURL); err == nil {
		t.Fatal("expected a query-bearing document to be refused for a query-less identifier")
	}
}

// TestProtectedResourceURLCarriesTheQuery covers the §3.1 derivation half of the
// same point: the lookup for a query-bearing identifier has to reach the document
// for *that* identifier.
func TestProtectedResourceURLCarriesTheQuery(t *testing.T) {
	got, err := ProtectedResourceURL("https://tunnel.example/protected/tunnel?tenant=a")
	if err != nil {
		t.Fatalf("ProtectedResourceURL: %v", err)
	}
	const want = "https://tunnel.example/.well-known/oauth-protected-resource/protected/tunnel?tenant=a"
	if got != want {
		t.Fatalf("derived %q, want %q", got, want)
	}
}

// TestNormalizeResourceIdentifier pins exactly how much normalisation the
// comparison applies: RFC 3986 syntax-based only. Anything more would make an
// "exact" comparison quietly inexact.
func TestNormalizeResourceIdentifier(t *testing.T) {
	// Same identifier, different spelling: must compare equal.
	for _, tt := range []struct{ a, b string }{
		{"https://tunnel.example/x", "https://tunnel.example:443/x"},
		{"http://tunnel.example/x", "http://TUNNEL.example:80/x"},
		{"https://TUNNEL.Example", "https://tunnel.example"},
		{"HTTPS://tunnel.example/x?q=1", "https://tunnel.example/x?q=1"},
	} {
		first, err := NormalizeResourceIdentifier(tt.a)
		if err != nil {
			t.Fatalf("NormalizeResourceIdentifier(%q): %v", tt.a, err)
		}
		second, err := NormalizeResourceIdentifier(tt.b)
		if err != nil {
			t.Fatalf("NormalizeResourceIdentifier(%q): %v", tt.b, err)
		}
		if first != second {
			t.Fatalf("%q normalised to %q but %q to %q; these are one identifier", tt.a, first, tt.b, second)
		}
	}
	// Genuinely different identifiers must stay different — including the pairs
	// an origin-only comparison used to collapse.
	for _, tt := range []struct{ a, b string }{
		{"https://tunnel.example", "http://tunnel.example"},
		{"https://tunnel.example", "https://tunnel.example:8443"},
		{"https://tunnel.example", "https://other.example"},
		{"https://tunnel.example/a/tunnel", "https://tunnel.example/b/tunnel"},
		{"https://tunnel.example/tunnel", "https://tunnel.example/tunnel/"},
		{"https://tunnel.example/t?tenant=a", "https://tunnel.example/t?tenant=b"},
		{"https://tunnel.example/t?tenant=a", "https://tunnel.example/t"},
		// An empty query is still a query: `/t?` and `/t` are two request targets a
		// proxy may route apart, and collapsing them here would put discovery and the
		// token cache on a different resource from the one the dial requests.
		{"https://tunnel.example/t?", "https://tunnel.example/t"},
		// The finding this pins: an encoded separator is not a separator, so
		// these are two resources and must not normalise to one.
		{"https://tunnel.example/tenant%2Fone/tunnel", "https://tunnel.example/tenant/one/tunnel"},
		{"https://tunnel.example/a%2Fb", "https://tunnel.example/a/b"},
	} {
		first, _ := NormalizeResourceIdentifier(tt.a)
		second, _ := NormalizeResourceIdentifier(tt.b)
		if first == second {
			t.Fatalf("normalisation collapsed %q and %q to %q", tt.a, tt.b, first)
		}
	}
	// IPv6 and non-canonical literals. These were absent, and the branch that
	// handles them is load-bearing rather than cosmetic: without the bracketing, a
	// port-less IPv6 identifier fails to normalise at all, so every such tunnel URL
	// would fail discovery outright.
	for _, tt := range []struct{ in, want string }{
		{"https://[::1]/x", "https://[::1]/x"},
		{"https://[0:0:0:0:0:0:0:1]/x", "https://[::1]/x"},
		{"https://[::1]:8443/x", "https://[::1]:8443/x"},
		{"https://[::FFFF:127.0.0.1]/x", "https://127.0.0.1/x"},
		// Left alone rather than canonicalised: net.ParseIP rejects leading zeros
		// (they invite octal ambiguity), so this is not recognised as an address
		// and stays verbatim — which keeps it *unequal* to 127.0.0.1, the
		// conservative direction for an equality check.
		{"https://127.000.000.1/x", "https://127.000.000.1/x"},
	} {
		got, err := NormalizeResourceIdentifier(tt.in)
		if err != nil {
			t.Fatalf("NormalizeResourceIdentifier(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("NormalizeResourceIdentifier(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	// And the derivation must survive them too.
	if got, err := ProtectedResourceURL("https://[::1]/protected/tunnel"); err != nil || got != "https://[::1]/.well-known/oauth-protected-resource/protected/tunnel" {
		t.Fatalf("ProtectedResourceURL for an IPv6 identifier = (%q, %v)", got, err)
	}

	for _, invalid := range []string{
		"https://tunnel.example/t#frag",
		"https://tunnel.example/t#",
		"https://tunnel.example/t?q=1#",
		"/relative",
		"tunnel.example",
		// Not merely un-idiomatic: a client derives the metadata location from
		// this value and fetches it over HTTP, so any other scheme names a
		// document nothing can retrieve.
		"ftp://tunnel.example/t",
		"wss://tunnel.example/t",
	} {
		if _, err := NormalizeResourceIdentifier(invalid); err == nil {
			t.Fatalf("NormalizeResourceIdentifier(%q): expected rejection", invalid)
		}
	}
}

func TestFetchProtectedResourceRejectsDocumentWithoutResource(t *testing.T) {
	server, resourceURL := protectedResourceServer(t, func(string) string { return "" }, false)

	_, err := FetchProtectedResource(context.Background(), server.Client(), resourceURL)
	if err == nil || !strings.Contains(err.Error(), "names no resource") {
		t.Fatalf("error = %v, want a refusal naming the missing field", err)
	}
}

func TestFetchProtectedResourceRefusesRedirectOffHTTPS(t *testing.T) {
	plaintext, _ := protectedResourceServer(t, func(base string) string { return base + "/protected/tunnel" }, false)
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plaintext.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer secure.Close()

	_, err := FetchProtectedResource(context.Background(), secure.Client(), secure.URL+"/protected/tunnel")
	if err == nil || !errors.Is(err, authhttp.ErrUnsafeTransport) {
		t.Fatalf("error = %v, want the https-to-http redirect refused as %v", err, authhttp.ErrUnsafeTransport)
	}
}

func TestValidateClientID(t *testing.T) {
	for _, valid := range []string{"authunnel-cli", "0oa1b2c3", "client_id.with~chars", "spaces are legal per *VSCHAR"} {
		if err := ValidateClientID(valid); err != nil {
			t.Fatalf("ValidateClientID(%q) = %v, want accepted", valid, err)
		}
	}
	for _, invalid := range []string{"", "tab\there", "newline\n", "café", strings.Repeat("a", maxHintBytes+1)} {
		if err := ValidateClientID(invalid); err == nil {
			t.Fatalf("ValidateClientID(%q): expected rejection", invalid)
		}
	}
}

func TestValidateScopes(t *testing.T) {
	if err := ValidateScopes([]string{"openid", "offline_access", "api:read"}); err != nil {
		t.Fatalf("ValidateScopes: %v", err)
	}
	for _, invalid := range [][]string{
		{""},
		{"openid profile"},
		{`openid"`},
		{`openid\`},
		{"open\tid"},
		{strings.Repeat("a", maxScopeBytes+1)},
	} {
		if err := ValidateScopes(invalid); err == nil {
			t.Fatalf("ValidateScopes(%q): expected rejection", invalid)
		}
	}
}

func TestValidateResourceIndicator(t *testing.T) {
	if err := ValidateResourceIndicator("https://api.example/v1"); err != nil {
		t.Fatalf("ValidateResourceIndicator: %v", err)
	}
	for _, invalid := range []string{
		"https://api.example#frag",
		// This check was always raw-string based and so never had the
		// empty-fragment hole that NormalizeResourceIdentifier briefly acquired.
		// Pinned here so the two stay consistent.
		"https://api.example#",
		"/api",
		"api.example",
	} {
		if err := ValidateResourceIndicator(invalid); err == nil {
			t.Fatalf("ValidateResourceIndicator(%q): expected rejection", invalid)
		}
	}
}

func TestCheckDiscoveredURLHoldsRemoteInputToTheConfiguredRule(t *testing.T) {
	// https required by default, exactly as for a flag.
	if err := CheckDiscoveredURL("authorization_servers[0]", "https://tunnel.example", "http://idp.example", false); err == nil {
		t.Fatal("expected a plaintext discovered issuer to be refused without the insecure override")
	}
	// The override relaxes transport only, and only when the source is itself
	// plaintext — otherwise the downgrade rule still applies.
	if err := CheckDiscoveredURL("authorization_servers[0]", "http://tunnel.example", "http://idp.example", true); err != nil {
		t.Fatalf("a plaintext issuer from a plaintext resource should be permitted with the override: %v", err)
	}
	if err := CheckDiscoveredURL("authorization_servers[0]", "https://tunnel.example", "http://idp.example", true); err == nil {
		t.Fatal("expected an https resource naming a plaintext issuer to be refused even with the override")
	}
	// file:// stays refused with the override set: it relaxes transport, not
	// the scheme allowlist.
	if err := CheckDiscoveredURL("authorization_servers[0]", "http://tunnel.example", "file:///etc/issuer", true); err == nil {
		t.Fatal("expected file:// to be refused with the insecure override set")
	}
}

// TestFetchProtectedResourceMatchesOnEscapedPath is the end-to-end half of the
// escaped-path finding: a document about /tenant/one/tunnel must not satisfy a
// client using /tenant%2Fone/tunnel, however similar the two look once decoded.
func TestFetchProtectedResourceMatchesOnEscapedPath(t *testing.T) {
	encoded, decoded := "/tenant%2Fone/tunnel", "/tenant/one/tunnel"

	server, _ := protectedResourceServer(t, func(base string) string { return base + decoded }, false)
	if _, err := FetchProtectedResource(context.Background(), server.Client(), server.URL+encoded); err == nil {
		t.Fatal("expected a document about the decoded path to be refused for the encoded identifier")
	}

	// The control: the same fixture declaring the encoded form is accepted, so
	// the rejection above is about the comparison and not about %2F breaking the
	// fetch.
	matching, _ := protectedResourceServer(t, func(base string) string { return base + encoded }, false)
	if _, err := FetchProtectedResource(context.Background(), matching.Client(), matching.URL+encoded); err != nil {
		t.Fatalf("an encoded identifier matching itself should be accepted: %v", err)
	}
}

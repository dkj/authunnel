package tunnelserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"authunnel/internal/authmeta"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func resourceMetadataHandler(t *testing.T, opts HandlerOptions) *http.ServeMux {
	t.Helper()
	validator := &mockValidator{tokens: map[string]*oidc.AccessTokenClaims{
		"good": {TokenClaims: oidc.TokenClaims{Subject: "alice"}},
	}}
	return NewHandler(validator, NewObservedSOCKSServer(nil, nil, nil, 0), opts)
}

func fetchDocumentForTest(t *testing.T, mux *http.ServeMux, path string, headers map[string]string) (*httptest.ResponseRecorder, authmeta.ProtectedResource) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)

	document := authmeta.ProtectedResource{}
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
			t.Fatalf("response is not valid JSON: %v (body %q)", err, recorder.Body.String())
		}
	}
	return recorder, document
}

// TestResourceMetadataServedAtBothWellKnownShapes covers the RFC 9728 §3.1
// derivation from both ends: a client whose resource identifier has a path
// derives the subtree form, one whose identifier has none derives the exact form,
// and a path-rewriting proxy can present either.
func TestResourceMetadataServedAtBothWellKnownShapes(t *testing.T) {
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example/realms/main"},
	})

	for _, path := range []string{
		authmeta.ProtectedResourcePath,
		authmeta.ProtectedResourcePath + "/protected/tunnel",
		authmeta.ProtectedResourcePath + "/authunnel/protected/tunnel",
	} {
		recorder, document := fetchDocumentForTest(t, mux, path, nil)
		if recorder.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, recorder.Code)
		}
		if got := document.AuthorizationServer(); got != "https://idp.example/realms/main" {
			t.Fatalf("GET %s: authorization server = %q, want the configured issuer", path, got)
		}
		// Whatever path the caller appended, the document describes this
		// server's own tunnel endpoint: the reply is not steerable.
		if !strings.HasSuffix(document.Resource, "/protected/tunnel") {
			t.Fatalf("GET %s: resource = %q, want the canonical tunnel path", path, document.Resource)
		}
		if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json" {
			t.Fatalf("GET %s: Content-Type = %q, want application/json", path, contentType)
		}
	}
}

// TestResourceMetadataIsUnauthenticated pins the point of the endpoint: it is
// what a client reads when it cannot yet authenticate.
func TestResourceMetadataIsUnauthenticated(t *testing.T) {
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example"},
	})

	recorder, _ := fetchDocumentForTest(t, mux, authmeta.ProtectedResourcePath, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want the document served without a token", recorder.Code)
	}
}

// TestResourceMetadataNotCoveredByPreAuthLimiter asserts a decision rather than
// an accident. The limiter exists to bound work done *before* token validation on
// the authenticated routes; this route has no validation to protect and serves a
// small constant document, so it is deliberately outside the gate. If that is ever
// wrong, this test is where the change is visible.
func TestResourceMetadataNotCoveredByPreAuthLimiter(t *testing.T) {
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example"},
		// A limiter with no budget at all: any gated route would 429 on the
		// first request.
		PreAuth: NewPreAuthLimiter(PreAuthConfig{Rate: 0.0001, Burst: 1}),
	})

	for attempt := range 3 {
		recorder, _ := fetchDocumentForTest(t, mux, authmeta.ProtectedResourcePath, nil)
		if recorder.Code != http.StatusOK {
			t.Fatalf("attempt %d: status = %d, want 200; the well-known route is not rate limited", attempt, recorder.Code)
		}
	}
}

func TestResourceMetadataPublishesHintsOnlyWhenSet(t *testing.T) {
	bare := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example"},
	})
	_, document := fetchDocumentForTest(t, bare, authmeta.ProtectedResourcePath, nil)
	if document.ClientID != "" || document.Audience != "" || document.ResourceIndicator != "" ||
		document.AuthorizationServerMetadataURL != "" || len(document.ScopesSupported) != 0 {
		t.Fatalf("unset hints should be absent, got %+v", document)
	}
	if len(document.BearerMethodsSupported) != 1 || document.BearerMethodsSupported[0] != "header" {
		t.Fatalf("bearer_methods_supported = %v, want [header]", document.BearerMethodsSupported)
	}

	full := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{
			Issuer:                         "https://idp.example",
			AuthorizationServerMetadataURL: "https://idp.example/.well-known/oauth-authorization-server/tenant1",
			ClientID:                       "authunnel-cli",
			Audience:                       "https://api.example",
			ResourceIndicator:              "https://tunnel.example",
			Scopes:                         []string{"openid", "offline_access"},
		},
	})
	_, document = fetchDocumentForTest(t, full, authmeta.ProtectedResourcePath, nil)
	if document.ClientID != "authunnel-cli" {
		t.Fatalf("client ID hint = %q", document.ClientID)
	}
	if document.AuthorizationServerMetadataURL != "https://idp.example/.well-known/oauth-authorization-server/tenant1" {
		t.Fatalf("metadata URL hint = %q", document.AuthorizationServerMetadataURL)
	}
	if document.Audience != "https://api.example" || document.ResourceIndicator != "https://tunnel.example" {
		t.Fatalf("audience hints = %q / %q", document.Audience, document.ResourceIndicator)
	}
	if strings.Join(document.ScopesSupported, " ") != "openid offline_access" {
		t.Fatalf("scopes = %v", document.ScopesSupported)
	}
}

// TestResourceIdentifierFollowsForwardedHeadersOnlyWhenTrusted mirrors the matrix
// the WebSocket origin check already has: X-Forwarded-* are honoured only in the
// mode that trusts them, so a client-supplied header cannot change what the
// document says on a directly-exposed server.
func TestResourceIdentifierFollowsForwardedHeadersOnlyWhenTrusted(t *testing.T) {
	headers := map[string]string{
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "tunnel.example",
	}

	trusting := resourceMetadataHandler(t, HandlerOptions{
		TrustForwardedProto: true,
		ResourceMetadata:    &ResourceMetadataConfig{Issuer: "https://idp.example"},
	})
	_, document := fetchDocumentForTest(t, trusting, authmeta.ProtectedResourcePath, headers)
	if document.Resource != "https://tunnel.example/protected/tunnel" {
		t.Fatalf("resource = %q, want the forwarded scheme and host behind a trusted proxy", document.Resource)
	}

	direct := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example"},
	})
	_, document = fetchDocumentForTest(t, direct, authmeta.ProtectedResourcePath, headers)
	if strings.Contains(document.Resource, "tunnel.example") {
		t.Fatalf("resource = %q, want the forwarded headers ignored without --plaintext-behind-reverse-proxy", document.Resource)
	}
}

func TestResourceMetadataDisabled(t *testing.T) {
	mux := resourceMetadataHandler(t, HandlerOptions{})

	for _, path := range []string{
		authmeta.ProtectedResourcePath,
		authmeta.ProtectedResourcePath + "/protected/tunnel",
	} {
		recorder, _ := fetchDocumentForTest(t, mux, path, nil)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404 with metadata disabled", path, recorder.Code)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if challenge := recorder.Header().Get("WWW-Authenticate"); challenge != "" {
		t.Fatalf("WWW-Authenticate = %q, want no challenge pointing at a document that is not published", challenge)
	}
}

// TestChallengePointsAtAServedDocument checks the header on each 401 path *and*
// that the URL it advertises actually resolves — a challenge naming a 404 is
// worse than none, because it sends a standards-compliant client somewhere
// useless.
func TestChallengePointsAtAServedDocument(t *testing.T) {
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example"},
	})

	oversized := "Bearer " + strings.Repeat("a", maxBearerTokenBytes+1)
	for _, tt := range []struct{ name, path, auth string }{
		{"missing header", "/protected", ""},
		{"wrong scheme", "/protected", "Basic dXNlcjpwYXNz"},
		{"oversized token", "/protected", oversized},
		{"tunnel missing header", "/protected/tunnel", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.auth != "" {
				request.Header.Set("Authorization", tt.auth)
			}
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", recorder.Code)
			}
			challenge := recorder.Header().Get("WWW-Authenticate")
			if !strings.HasPrefix(challenge, "Bearer resource_metadata=") {
				t.Fatalf("WWW-Authenticate = %q, want a Bearer challenge with resource_metadata", challenge)
			}
			advertised := strings.Trim(strings.TrimPrefix(challenge, "Bearer resource_metadata="), `"`)
			if advertised == "" {
				t.Fatalf("challenge %q carries no URL", challenge)
			}
			served, document := fetchDocumentForTest(t, mux, advertised, nil)
			if served.Code != http.StatusOK {
				t.Fatalf("the advertised URL %s returned %d, want a served document", advertised, served.Code)
			}
			if document.AuthorizationServer() != "https://idp.example" {
				t.Fatalf("document at the advertised URL names %q", document.AuthorizationServer())
			}
		})
	}
}

// TestChallengeAbsentOnSuccessAndOnForbidden keeps the header where RFC 7235
// defines it. A 403 from a validated-but-rejected token is authorization, not a
// missing credential, and this server's 403 is deliberately uninformative.
func TestChallengeAbsentOnSuccessAndOnForbidden(t *testing.T) {
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example"},
	})

	for _, tt := range []struct {
		name       string
		auth       string
		wantStatus int
	}{
		{"authenticated", "Bearer good", http.StatusOK},
		{"rejected token", "Bearer nope", http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/protected", nil)
			request.Header.Set("Authorization", tt.auth)
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if challenge := recorder.Header().Get("WWW-Authenticate"); challenge != "" {
				t.Fatalf("WWW-Authenticate = %q, want it absent on a %d", challenge, recorder.Code)
			}
		})
	}
}

func TestResourceMetadataConfigValidate(t *testing.T) {
	for name, cfg := range map[string]*ResourceMetadataConfig{
		"no issuer":          {},
		"client ID with tab": {Issuer: "https://idp.example", ClientID: "authunnel\tcli"},
		"client ID too long": {Issuer: "https://idp.example", ClientID: strings.Repeat("a", 300)},
		"scope with space":   {Issuer: "https://idp.example", Scopes: []string{"openid profile"}},
		"empty scope":        {Issuer: "https://idp.example", Scopes: []string{""}},
		"resource fragment":  {Issuer: "https://idp.example", ResourceIndicator: "https://api.example#frag"},
		"resource relative":  {Issuer: "https://idp.example", ResourceIndicator: "/api"},
		"audience control":   {Issuer: "https://idp.example", Audience: "api\nexample"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected %s to be rejected", name)
			}
		})
	}

	valid := &ResourceMetadataConfig{
		Issuer:            "https://idp.example",
		ClientID:          "authunnel-cli",
		Scopes:            []string{"openid", "offline_access"},
		Audience:          "https://api.example",
		ResourceIndicator: "https://tunnel.example",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	var disabled *ResourceMetadataConfig
	if err := disabled.Validate(); err != nil {
		t.Fatalf("a nil config means publishing is off, not invalid: %v", err)
	}
}

// TestChallengeCarriesTheQueryOfTheRequestedResource follows the challenge the way
// a standards-following client would, and checks it lands somewhere
// self-consistent.
//
// That is the whole requirement: the document at the advertised location must
// describe the identifier the client was using, query included. Omit the query
// from the challenge and the client fetches the query-less document, whose
// `resource` then fails its own equality check — a challenge pointing somewhere
// self-defeating, which is worse than sending none.
func TestChallengeCarriesTheQueryOfTheRequestedResource(t *testing.T) {
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example"},
	})

	request := httptest.NewRequest(http.MethodGet, "/protected/tunnel?tenant=a", nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}

	advertised := strings.Trim(strings.TrimPrefix(recorder.Header().Get("WWW-Authenticate"), "Bearer resource_metadata="), `"`)
	if !strings.Contains(advertised, "tenant=a") {
		t.Fatalf("challenge advertised %q, want the query of the resource it is about", advertised)
	}

	served, document := fetchDocumentForTest(t, mux, advertised, nil)
	if served.Code != http.StatusOK {
		t.Fatalf("the advertised URL %s returned %d", advertised, served.Code)
	}
	// The identifier the client would have compared against: same origin, the
	// tunnel path, and the query it used.
	if !strings.HasSuffix(document.Resource, "/protected/tunnel?tenant=a") {
		t.Fatalf("document at the advertised URL describes %q, which is not the resource that was requested", document.Resource)
	}
}

// TestPublishedIdentifierKeepsAnEmptyQuery is the degenerate case of the test above,
// and it needs its own: a bare "?" reaches the handler in url.URL.ForceQuery rather
// than RawQuery, so a reconstruction that carries only RawQuery drops it. The client
// compares this identifier byte for byte against the URL it dialled, and that dial
// does send the delimiter — Go's own client puts `/protected/tunnel?` on the wire.
func TestPublishedIdentifierKeepsAnEmptyQuery(t *testing.T) {
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example"},
	})

	served, document := fetchDocumentForTest(t, mux, "/.well-known/oauth-protected-resource/protected/tunnel?", nil)
	if served.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", served.Code)
	}
	if !strings.HasSuffix(document.Resource, "/protected/tunnel?") {
		t.Fatalf("published resource = %q, want the empty query preserved", document.Resource)
	}
}

// TestResourceURLValidatedAsFetchable covers the other half of "published" — a
// value no client could retrieve is not a usable identifier, however well-formed.
func TestResourceURLValidatedAsFetchable(t *testing.T) {
	for name, resourceURL := range map[string]string{
		"ftp":              "ftp://tunnel.example/protected/tunnel",
		"websocket scheme": "wss://tunnel.example/protected/tunnel",
		"file":             "file:///etc/authunnel",
		"no host":          "https:///protected/tunnel",
		"relative":         "/protected/tunnel",
		"fragment":         "https://tunnel.example/protected/tunnel#frag",
		"bare delimiter":   "https://tunnel.example/protected/tunnel#",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &ResourceMetadataConfig{Issuer: "https://idp.example", ResourceURL: resourceURL}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("--resource-url %q: expected rejection", resourceURL)
			}
			if !strings.Contains(err.Error(), "--resource-url") {
				t.Fatalf("error should name the flag to fix, got: %v", err)
			}
		})
	}

	for _, resourceURL := range []string{
		"https://tunnel.example/protected/tunnel",
		"https://tunnel.example/authunnel/protected/tunnel",
		"http://127.0.0.1:8443/protected/tunnel",
	} {
		cfg := &ResourceMetadataConfig{Issuer: "https://idp.example", ResourceURL: resourceURL}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("--resource-url %q should be accepted: %v", resourceURL, err)
		}
	}
}

// TestResourceURLIsPublishedVerbatim is the point of the flag: a deployment whose
// externally visible path differs from the one this server sees declares it, and
// what a client compares against is that declaration.
func TestResourceURLIsPublishedVerbatim(t *testing.T) {
	const declared = "https://tunnel.example/authunnel/protected/tunnel"
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example", ResourceURL: declared},
	})

	_, document := fetchDocumentForTest(t, mux, authmeta.ProtectedResourcePath+"/protected/tunnel", nil)
	if document.Resource != declared {
		t.Fatalf("resource = %q, want the declared identifier verbatim", document.Resource)
	}

	request := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	challenge := recorder.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, "/authunnel/protected/tunnel") {
		t.Fatalf("challenge = %q, want it to point at the document for the declared identifier", challenge)
	}
}

// TestMetadataIsNotServedUnderTheProtectedPrefix pins a property of the RFC 9728
// derivation that is easy to invert by accident.
//
// §3.1 *inserts* the well-known segment between the authority and the resource's
// path, so the document for https://host/protected/tunnel lives at
// https://host/.well-known/oauth-protected-resource/protected/tunnel — outside the
// /protected/ subtree. Appending the segment instead, which is the natural mistake,
// would put an unauthenticated document *under* the prefix this server uses to mean
// "a token is required", and the prefix would no longer mean that.
//
// Asserted from both directions: the derived location is unauthenticated, and the
// appended shapes stay behind the token check.
func TestMetadataIsNotServedUnderTheProtectedPrefix(t *testing.T) {
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example"},
	})

	recorder, document := fetchDocumentForTest(t, mux, authmeta.ProtectedResourcePath+tunnelResourcePath, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("the derived location returned %d, want the document", recorder.Code)
	}
	if document.Resource == "" {
		t.Fatal("the derived location served no document")
	}
	if strings.HasPrefix(authmeta.ProtectedResourcePath, "/protected") {
		t.Fatalf("the well-known path %q is under the authenticated prefix", authmeta.ProtectedResourcePath)
	}

	for _, path := range []string{
		"/protected" + authmeta.ProtectedResourcePath,
		"/protected/tunnel" + authmeta.ProtectedResourcePath,
		"/protected/tunnel/.well-known/oauth-protected-resource/protected/tunnel",
	} {
		unauthenticated, _ := fetchDocumentForTest(t, mux, path, nil)
		if unauthenticated.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s = %d without a token, want 401: nothing under /protected/ may be readable unauthenticated", path, unauthenticated.Code)
		}

		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer good")
		authenticated := httptest.NewRecorder()
		mux.ServeHTTP(authenticated, request)
		if authenticated.Code != http.StatusNotFound {
			t.Fatalf("GET %s = %d with a valid token, want 404: the document does not live here", path, authenticated.Code)
		}
	}

	// A doubled slash is path-cleaned by the mux into the protected form above
	// rather than matching the well-known route, so the redirect is the answer and
	// no document comes back with it.
	redirected, document := fetchDocumentForTest(t, mux, "/protected//.well-known/oauth-protected-resource", nil)
	if redirected.Code != http.StatusTemporaryRedirect && redirected.Code != http.StatusMovedPermanently {
		t.Fatalf("doubled-slash path = %d, want a path-cleaning redirect", redirected.Code)
	}
	if document.Resource != "" {
		t.Fatalf("a path-cleaning redirect served a document: %+v", document)
	}
	if location := redirected.Header().Get("Location"); !strings.HasPrefix(location, "/protected/") {
		t.Fatalf("Location = %q, want the cleaned path to stay under the authenticated prefix", location)
	}
}

// TestDocumentAndChallengeAgreeOnAnUnvalidatedConfig pins the invariant that
// replaced a divergence: whatever identifier the document declares, the challenge
// points at the document for *that* identifier.
//
// NewHandler does not call Validate — only the server binary does — so a config with
// an unusable ResourceURL reaches the handler. It used to publish that value verbatim
// while the challenge fell back to the request-derived URL, so a client following the
// challenge landed on a document about a resource it was not using and refused it.
func TestDocumentAndChallengeAgreeOnAnUnvalidatedConfig(t *testing.T) {
	for name, resourceURL := range map[string]string{
		"valid and declared": "https://tunnel.example/authunnel/protected/tunnel",
		"unusable scheme":    "ftp://tunnel.example/protected/tunnel",
		"no host":            "https://",
		"fragment":           "https://tunnel.example/protected/tunnel#frag",
		"unset":              "",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &ResourceMetadataConfig{Issuer: "https://idp.example", ResourceURL: resourceURL}
			mux := resourceMetadataHandler(t, HandlerOptions{ResourceMetadata: cfg})

			request := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)
			challenge := recorder.Header().Get("WWW-Authenticate")
			advertised := strings.Trim(strings.TrimPrefix(challenge, "Bearer resource_metadata="), `"`)
			if advertised == "" {
				t.Fatalf("challenge %q carries no URL", challenge)
			}

			// Follow it, exactly as an RFC 9728 client would, and check the
			// document it reaches describes the identifier it would compare.
			served, document := fetchDocumentForTest(t, mux, advertised, nil)
			if served.Code != http.StatusOK {
				t.Fatalf("the advertised URL %s returned %d", advertised, served.Code)
			}
			derived, err := authmeta.ProtectedResourceURL(document.Resource)
			if err != nil {
				t.Fatalf("the published resource %q is not one a client could derive a location from: %v", document.Resource, err)
			}
			if derived != advertised {
				t.Fatalf("document declares %q (metadata at %q) but the challenge advertises %q",
					document.Resource, derived, advertised)
			}
		})
	}
}

// TestResourceMetadataServesHeadAndForbidsCaching covers two lines that were live
// but unasserted: Go's mux routes HEAD to a GET pattern, and the document must not be
// cached, since an operator changing a hint expects clients to see it.
func TestResourceMetadataServesHeadAndForbidsCaching(t *testing.T) {
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example"},
	})

	recorder, _ := fetchDocumentForTest(t, mux, authmeta.ProtectedResourcePath, nil)
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}

	request := httptest.NewRequest(http.MethodHead, authmeta.ProtectedResourcePath, nil)
	head := httptest.NewRecorder()
	mux.ServeHTTP(head, request)
	if head.Code != http.StatusOK {
		t.Fatalf("HEAD = %d, want 200", head.Code)
	}
	if head.Body.Len() != 0 {
		t.Fatalf("HEAD returned %d body bytes, want none", head.Body.Len())
	}
	if got := head.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("HEAD Content-Type = %q, want the same as GET", got)
	}
}

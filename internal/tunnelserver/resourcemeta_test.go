package tunnelserver

import (
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
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
		document.AuthorizationServerMetadataURL != "" || len(document.DefaultScopes) != 0 {
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
			DefaultScopes:                  []string{"openid", "offline_access"},
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
	if strings.Join(document.DefaultScopes, " ") != "openid offline_access" {
		t.Fatalf("scopes = %v", document.DefaultScopes)
	}
}

// TestBearerChallengeAlwaysCarriesAParameter pins the invariant across every
// combination the two optional parameters produce: never a bare scheme. See
// bearerChallenge for the grammar that requires it.
func TestBearerChallengeAlwaysCarriesAParameter(t *testing.T) {
	for name, tt := range map[string]struct {
		errorCode, metadataURL, want string
	}{
		"neither":    {"", "", `Bearer realm="authunnel"`},
		"error only": {"invalid_token", "", `Bearer error="invalid_token"`},
		"hint only":  {"", "https://tunnel.example/.well-known/x", `Bearer resource_metadata="https://tunnel.example/.well-known/x"`},
		"both":       {"invalid_token", "https://tunnel.example/.well-known/x", `Bearer error="invalid_token", resource_metadata="https://tunnel.example/.well-known/x"`},
	} {
		t.Run(name, func(t *testing.T) {
			got := bearerChallenge(tt.errorCode, tt.metadataURL)
			if got != tt.want {
				t.Fatalf("challenge = %q, want %q", got, tt.want)
			}
			// The property, independent of the exact strings above.
			scheme, params, found := strings.Cut(got, " ")
			if scheme != "Bearer" {
				t.Fatalf("challenge = %q, want the Bearer scheme", got)
			}
			if !found || strings.TrimSpace(params) == "" {
				t.Fatalf("challenge = %q carries no auth-param; RFC 6750 §3 requires at least one", got)
			}
		})
	}
}

// TestCheckTokenChallengesEvenWithoutMetadata covers the exported helper, which has no
// access to the handler options and so cannot name a document — but a 401 must carry a
// challenge regardless, and the client reads the error code from it.
func TestCheckTokenChallengesEvenWithoutMetadata(t *testing.T) {
	for name, tt := range map[string]struct {
		auth      string
		validator TokenValidator
		want      string
	}{
		"no credential": {"", nil, `Bearer realm="authunnel"`},
		"rejected token": {
			"Bearer nope",
			staticFailValidator{err: errors.New("signature mismatch")},
			`Bearer error="invalid_token"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
			if tt.auth != "" {
				request.Header.Set("Authorization", tt.auth)
			}
			recorder := httptest.NewRecorder()
			if ok := CheckToken(recorder, request, tt.validator); ok {
				t.Fatal("expected the check to fail")
			}
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", recorder.Code)
			}
			if got := recorder.Header().Get("WWW-Authenticate"); got != tt.want {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestPublishedWireKeysAreTheAgreedOnes asserts the JSON keys rather than the Go
// fields, which is the only way this side can pin a wire contract: every other test
// here decodes into authmeta.ProtectedResource, so it would follow a renamed tag
// wherever it went and still pass.
//
// The scope key is the one that matters, and `scopes_supported` must be *absent* — see
// authmeta.ProtectedResource.DefaultScopes for why this server has nothing to disclose
// under that name.
func TestPublishedWireKeysAreTheAgreedOnes(t *testing.T) {
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{
			Issuer:                         "https://idp.example",
			AuthorizationServerMetadataURL: "https://idp.example/.well-known/oauth-authorization-server/tenant1",
			ClientID:                       "authunnel-cli",
			Audience:                       "https://api.example",
			ResourceIndicator:              "https://tunnel.example",
			DefaultScopes:                  []string{"openid", "offline_access"},
		},
	})
	recorder, _ := fetchDocumentForTest(t, mux, authmeta.ProtectedResourcePath, nil)

	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &raw); err != nil {
		t.Fatalf("response is not a JSON object: %v", err)
	}
	for _, key := range []string{
		"resource", "authorization_servers", "bearer_methods_supported",
		"authunnel_client_id", "authunnel_authorization_server_metadata_url",
		"authunnel_audience", "authunnel_resource", "authunnel_default_scopes",
	} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("published document is missing %q; keys were %v", key, slices.Sorted(maps.Keys(raw)))
		}
	}
	if _, ok := raw["scopes_supported"]; ok {
		t.Fatal("scopes_supported must not be published: this server enforces no scope requirement, so it has no supported set to disclose; what it publishes is a recommendation for the request")
	}
}

// TestDeclaredResourceURLIsPublishedNormalised is the publication half of RFC 9728
// §3.3's identity requirement, and the two halves only work together.
//
// A client compares `resource` against its own identifier by code-point equality, and
// normalises what it derives from its tunnel URL because that value is also a cache
// key. So an operator writing --resource-url with an upper-case host or a redundant
// :443 must not produce a document that fails that comparison for what is one
// resource. Publishing the normalised form is what prevents it; the alternative would
// be a client lenient about a remote value, inside the very check that decides whether
// the document can be trusted.
//
// The path is untouched, which is the part the flag exists for: normalisation is
// syntax-based, so a prefix a reverse proxy strips reaches the document unchanged.
func TestDeclaredResourceURLIsPublishedNormalised(t *testing.T) {
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{
			Issuer:      "https://idp.example",
			ResourceURL: "HTTPS://TUNNEL.Example:443/authunnel/protected/tunnel",
		},
	})

	recorder, document := fetchDocumentForTest(t, mux, authmeta.ProtectedResourcePath, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	const want = "https://tunnel.example/authunnel/protected/tunnel"
	if document.Resource != want {
		t.Fatalf("published resource = %q, want %q: a client compares this byte for byte", document.Resource, want)
	}

	// The challenge must point at the document *for that same identifier*, or a client
	// following it lands on a document describing something else and refuses it.
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	challengeRecorder := httptest.NewRecorder()
	mux.ServeHTTP(challengeRecorder, request)
	challenge := challengeRecorder.Header().Get("WWW-Authenticate")
	const wantMetadata = "https://tunnel.example/.well-known/oauth-protected-resource/authunnel/protected/tunnel"
	if !strings.Contains(challenge, wantMetadata) {
		t.Fatalf("challenge = %q, want it to name %q", challenge, wantMetadata)
	}
}

// TestDeclaredResourceCarriesTheRequestQuery covers the combination a path-rewriting
// deployment actually needs: --resource-url declares the external base, and the client
// still distinguishes resources by query.
//
// The declared branch used to return before the query was attached, so `?tenant=a`
// vanished from both the document and the challenge. The client derives a
// query-bearing identifier from its own tunnel URL and compares by code-point equality,
// so nothing matched and zero-configuration login could not proceed at all — for the
// one deployment shape the flag exists to serve.
func TestDeclaredResourceCarriesTheRequestQuery(t *testing.T) {
	const declared = "https://tunnel.example/authunnel/protected/tunnel"
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example", ResourceURL: declared},
	})

	for name, tt := range map[string]struct{ query, want string }{
		"a query":        {"?tenant=a", declared + "?tenant=a"},
		"another":        {"?tenant=b", declared + "?tenant=b"},
		"none":           {"", declared},
		"bare delimiter": {"?", declared + "?"},
	} {
		t.Run(name, func(t *testing.T) {
			// The document, as the client fetches it.
			_, document := fetchDocumentForTest(t, mux, authmeta.ProtectedResourcePath+tunnelResourcePath+tt.query, nil)
			if document.Resource != tt.want {
				t.Fatalf("resource = %q, want %q", document.Resource, tt.want)
			}

			// And the challenge, which must point at the document describing *that*
			// identifier — a client following it lands there and compares.
			request := httptest.NewRequest(http.MethodGet, tunnelResourcePath+tt.query, nil)
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)
			challenge := recorder.Header().Get("WWW-Authenticate")
			wantMetadata, err := authmeta.ProtectedResourceURL(tt.want)
			if err != nil {
				t.Fatalf("derive expected metadata URL: %v", err)
			}
			if !strings.Contains(challenge, `resource_metadata="`+wantMetadata+`"`) {
				t.Fatalf("challenge = %q, want it to point at %q", challenge, wantMetadata)
			}
		})
	}
}

// TestResourceURLRejectsAQuery pins the other half: the flag declares a base, so a
// query in it would compete with the request's for the same slot.
func TestResourceURLRejectsAQuery(t *testing.T) {
	for name, resourceURL := range map[string]string{
		"query":          "https://tunnel.example/protected/tunnel?tenant=a",
		"bare delimiter": "https://tunnel.example/protected/tunnel?",
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
}

// TestRequestDerivedIdentifierIsNormalised covers the branch --resource-url does not
// take. A Host header spelling — case, or a redundant default port — must not decide
// whether the client's exact §3.3 comparison succeeds, since the client normalises the
// identifier it compares.
//
// The second assertion is the one that shows the shape of the bug: the metadata URL was
// already normalised, because the §3.1 derivation normalises internally, so the
// published `resource` and the location the challenge names described the same resource
// with different spellings. A client following the challenge landed on a document it
// then had to refuse.
func TestRequestDerivedIdentifierIsNormalised(t *testing.T) {
	const canonical = "https://tunnel.example/protected/tunnel"
	mux := resourceMetadataHandler(t, HandlerOptions{
		TrustForwardedProto: true,
		ResourceMetadata:    &ResourceMetadataConfig{Issuer: "https://idp.example"},
	})

	for _, host := range []string{
		"tunnel.example",
		"TUNNEL.Example",
		"tunnel.example:443",
		"TUNNEL.example:443",
	} {
		t.Run(host, func(t *testing.T) {
			headers := map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": host}
			_, document := fetchDocumentForTest(t, mux, authmeta.ProtectedResourcePath+tunnelResourcePath, headers)
			if document.Resource != canonical {
				t.Fatalf("Host %q published resource %q, want the canonical %q", host, document.Resource, canonical)
			}

			// And the challenge points at the document for exactly that identifier.
			request := httptest.NewRequest(http.MethodGet, tunnelResourcePath, nil)
			for name, value := range headers {
				request.Header.Set(name, value)
			}
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)
			want, err := authmeta.ProtectedResourceURL(document.Resource)
			if err != nil {
				t.Fatalf("derive expected metadata URL: %v", err)
			}
			if got := recorder.Header().Get("WWW-Authenticate"); !strings.Contains(got, `resource_metadata="`+want+`"`) {
				t.Fatalf("challenge = %q, want it to name %q — the location for the identifier just published", got, want)
			}
		})
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

	// The challenge survives --no-resource-metadata; only the RFC 9728 parameter goes.
	// See setChallenge for why the header is not optional.
	for name, tt := range map[string]struct {
		auth string
		want string
	}{
		"no credential":  {"", `Bearer realm="authunnel"`},
		"rejected token": {"Bearer nope", `Bearer error="invalid_token"`},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tt.auth != "" {
				request.Header.Set("Authorization", tt.auth)
			}
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", recorder.Code)
			}
			if got := recorder.Header().Get("WWW-Authenticate"); got != tt.want {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, tt.want)
			}
			if strings.Contains(recorder.Header().Get("WWW-Authenticate"), "resource_metadata") {
				t.Fatal("the challenge must not point at a document this server does not publish")
			}
		})
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

// TestChallengeMatchesTheReasonForTheRejection pins the three shapes a caller can
// get, because the client keys its recovery on the challenge rather than on a status
// code. RFC 6750 §3.1: no credential means no error code, a credential that failed
// means invalid_token, and success means no challenge at all.
//
// The middle case is the one that carries weight. It used to be a 403 with no
// challenge, on the reasoning that a validated-but-rejected token is an authorization
// decision — but the token had not validated, so `invalid_token` is exactly what §3.1
// defines, and 403 belongs to a *valid* token with insufficient scope, which this
// server never decides. Without the error code a client cannot tell a bad token from
// an origin-check failure, and had to treat both as a possible configuration change.
func TestChallengeMatchesTheReasonForTheRejection(t *testing.T) {
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example"},
	})

	for _, tt := range []struct {
		name          string
		auth          string
		wantStatus    int
		wantChallenge string
	}{
		{"authenticated", "Bearer good", http.StatusOK, ""},
		{
			"no credential", "", http.StatusUnauthorized,
			`Bearer resource_metadata="http://example.com/.well-known/oauth-protected-resource/protected/tunnel"`,
		},
		{
			"rejected token", "Bearer nope", http.StatusUnauthorized,
			`Bearer error="invalid_token", resource_metadata="http://example.com/.well-known/oauth-protected-resource/protected/tunnel"`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tt.auth != "" {
				request.Header.Set("Authorization", tt.auth)
			}
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if got := recorder.Header().Get("WWW-Authenticate"); got != tt.wantChallenge {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, tt.wantChallenge)
			}
		})
	}
}

// TestChallengeAbsentOnAnOriginRefusal is the distinction the client depends on: an
// origin-check refusal is not about the token, so it stays a 403 and carries no
// challenge. A client seeing it must not re-read metadata.
func TestChallengeAbsentOnAnOriginRefusal(t *testing.T) {
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example"},
	})

	request := httptest.NewRequest(http.MethodGet, "/protected/tunnel", nil)
	request.Header.Set("Authorization", "Bearer good")
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d for a cross-origin upgrade", recorder.Code, http.StatusForbidden)
	}
	if challenge := recorder.Header().Get("WWW-Authenticate"); challenge != "" {
		t.Fatalf("WWW-Authenticate = %q, want none: this refusal is not about the token", challenge)
	}
}

func TestResourceMetadataConfigValidate(t *testing.T) {
	for name, cfg := range map[string]*ResourceMetadataConfig{
		"no issuer":          {},
		"client ID with tab": {Issuer: "https://idp.example", ClientID: "authunnel\tcli"},
		"client ID too long": {Issuer: "https://idp.example", ClientID: strings.Repeat("a", 300)},
		"scope with space":   {Issuer: "https://idp.example", DefaultScopes: []string{"openid profile"}},
		"empty scope":        {Issuer: "https://idp.example", DefaultScopes: []string{""}},
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
		DefaultScopes:     []string{"openid", "offline_access"},
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

// TestDeclaredResourceURLIsWhatClientsCompareAgainst is the point of the flag: a
// deployment whose externally visible path differs from the one this server sees
// declares it, and that declaration is what a client compares against. The declared
// value reaches the document normalised and with the request's query appended; this
// case has neither to apply, so it arrives unchanged.
func TestDeclaredResourceURLIsWhatClientsCompareAgainst(t *testing.T) {
	const declared = "https://tunnel.example/authunnel/protected/tunnel"
	mux := resourceMetadataHandler(t, HandlerOptions{
		ResourceMetadata: &ResourceMetadataConfig{Issuer: "https://idp.example", ResourceURL: declared},
	})

	_, document := fetchDocumentForTest(t, mux, authmeta.ProtectedResourcePath+"/protected/tunnel", nil)
	if document.Resource != declared {
		t.Fatalf("resource = %q, want the declared identifier %q", document.Resource, declared)
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

package authmeta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"authunnel/internal/authhttp"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// asDocument serves an authorization server metadata document at the derived
// well-known path and at /meta, so a single fixture covers both the derived and
// the overridden location.
func asDocument(t *testing.T, issuerOverride string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	handler := func(w http.ResponseWriter, _ *http.Request) {
		issuer := issuerOverride
		if issuer == "" {
			issuer = server.URL
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"issuer": %q,
			"authorization_endpoint": %q,
			"token_endpoint": %q
		}`, issuer, server.URL+"/auth", server.URL+"/token")
	}
	mux.HandleFunc("/.well-known/openid-configuration", handler)
	mux.HandleFunc("/meta", handler)
	return server
}

func TestFetchAuthorizationServerDerivesWellKnownPath(t *testing.T) {
	server := asDocument(t, "")

	document, err := FetchAuthorizationServer(context.Background(), server.Client(), server.URL, "")
	if err != nil {
		t.Fatalf("FetchAuthorizationServer returned error: %v", err)
	}
	if document.TokenEndpoint != server.URL+"/token" {
		t.Fatalf("token_endpoint = %q, want the document's value", document.TokenEndpoint)
	}
}

// TestFetchAuthorizationServerDerivesFromIssuerWithTrailingSlash pins that the
// derivation matches zitadel's: one slash, not two.
func TestFetchAuthorizationServerDerivesFromIssuerWithTrailingSlash(t *testing.T) {
	server := asDocument(t, "")

	// The document declares the slash-less issuer, so this also covers the
	// comparison being made against the configured value verbatim.
	_, err := FetchAuthorizationServer(context.Background(), server.Client(), server.URL+"/", "")
	if err == nil || !errors.Is(err, oidc.ErrIssuerInvalid) {
		t.Fatalf("error = %v, want %v: the trailing slash must survive into the comparison", err, oidc.ErrIssuerInvalid)
	}
	if !strings.Contains(err.Error(), server.URL+"/") {
		t.Fatalf("error should quote the configured issuer, got: %v", err)
	}
}

func TestFetchAuthorizationServerUsesMetadataURL(t *testing.T) {
	server := asDocument(t, "")

	document, err := FetchAuthorizationServer(context.Background(), server.Client(), server.URL, server.URL+"/meta")
	if err != nil {
		t.Fatalf("FetchAuthorizationServer returned error: %v", err)
	}
	if document.Issuer != server.URL {
		t.Fatalf("issuer = %q, want %q", document.Issuer, server.URL)
	}
}

// TestFetchAuthorizationServerAdoptsIssuerWhenUnset is the behaviour that lets
// --oidc-metadata-url stand alone. Note what is given up along with the
// comparison: nothing here can tell a correct document from one belonging to the
// wrong tenant.
func TestFetchAuthorizationServerAdoptsIssuerWhenUnset(t *testing.T) {
	server := asDocument(t, "https://declared.example/realms/main")

	document, err := FetchAuthorizationServer(context.Background(), server.Client(), "", server.URL+"/meta")
	if err != nil {
		t.Fatalf("FetchAuthorizationServer returned error: %v", err)
	}
	if document.Issuer != "https://declared.example/realms/main" {
		t.Fatalf("issuer = %q, want the declared value to be adopted verbatim", document.Issuer)
	}
}

func TestFetchAuthorizationServerRejectsIssuerMismatch(t *testing.T) {
	server := asDocument(t, "https://declared.example/realms/main")

	_, err := FetchAuthorizationServer(context.Background(), server.Client(), "https://configured.example", server.URL+"/meta")
	if !errors.Is(err, oidc.ErrIssuerInvalid) {
		t.Fatalf("error = %v, want it to be %v", err, oidc.ErrIssuerInvalid)
	}
}

// TestFetchAuthorizationServerRejectsDocumentWithoutIssuer covers the reason the
// adopt-when-unset path can trust document.Issuer without checking it again:
// an absent or null document is refused here rather than yielding an empty
// issuer that a caller would adopt and then use as a cache key.
func TestFetchAuthorizationServerRejectsDocumentWithoutIssuer(t *testing.T) {
	for name, body := range map[string]string{
		"empty object": `{}`,
		"null":         `null`,
		"issuer empty": `{"issuer": ""}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()

			_, err := FetchAuthorizationServer(context.Background(), server.Client(), "", server.URL+"/meta")
			if err == nil || !strings.Contains(err.Error(), "declares no issuer") {
				t.Fatalf("error = %v, want a refusal naming the missing issuer", err)
			}
			if !errors.Is(err, oidc.ErrDiscoveryFailed) {
				t.Fatalf("error = %v, want it to be %v", err, oidc.ErrDiscoveryFailed)
			}
		})
	}
}

func TestFetchAuthorizationServerRequiresIssuerOrMetadataURL(t *testing.T) {
	_, err := FetchAuthorizationServer(context.Background(), http.DefaultClient, "", "")
	if err == nil || !strings.Contains(err.Error(), "issuer or a metadata URL") {
		t.Fatalf("error = %v, want a refusal naming both ways of locating the document", err)
	}
}

func TestFetchAuthorizationServerRejectsNonHTTPURL(t *testing.T) {
	for _, metadataURL := range []string{
		"file:///etc/authunnel/meta.json",
		"https:relative",
		"https://",
	} {
		_, err := FetchAuthorizationServer(context.Background(), http.DefaultClient, "", metadataURL)
		if err == nil {
			t.Fatalf("metadata URL %q: expected refusal, got nil", metadataURL)
		}
		if !errors.Is(err, authhttp.ErrUnsafeTransport) {
			t.Fatalf("metadata URL %q: error = %v, want it to be %v so callers do not retry it",
				metadataURL, err, authhttp.ErrUnsafeTransport)
		}
		// A refusal must not be reported as a discovery failure: the two mean
		// opposite things to a caller deciding whether to fall through to an
		// interactive login.
		if errors.Is(err, oidc.ErrDiscoveryFailed) {
			t.Fatalf("metadata URL %q: refusal should not also be %v", metadataURL, oidc.ErrDiscoveryFailed)
		}
	}
}

// TestFetchAuthorizationServerRefusesRedirectOffHTTPS proves the package applies
// the redirect guard itself rather than relying on the caller having wrapped its
// client — the fixture deliberately passes an unwrapped one.
func TestFetchAuthorizationServerRefusesRedirectOffHTTPS(t *testing.T) {
	plaintext := asDocument(t, "")
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plaintext.URL+"/meta", http.StatusTemporaryRedirect)
	}))
	defer secure.Close()

	_, err := FetchAuthorizationServer(context.Background(), secure.Client(), "", secure.URL+"/meta")
	if err == nil || !strings.Contains(err.Error(), "transport downgrade") {
		t.Fatalf("error = %v, want the https-to-http redirect refused", err)
	}
	if !errors.Is(err, authhttp.ErrUnsafeTransport) {
		t.Fatalf("error = %v, want it to be %v", err, authhttp.ErrUnsafeTransport)
	}
}

func TestFetchAuthorizationServerRejectsNonJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>login page</html>"))
	}))
	defer server.Close()

	_, err := FetchAuthorizationServer(context.Background(), server.Client(), "", server.URL+"/meta")
	if err == nil || !strings.Contains(err.Error(), "parse metadata document") {
		t.Fatalf("error = %v, want a parse failure naming the document", err)
	}
}

func TestFetchAuthorizationServerReportsHTTPStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
	}))
	defer server.Close()

	_, err := FetchAuthorizationServer(context.Background(), server.Client(), "", server.URL+"/meta")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("error = %v, want the HTTP status reported", err)
	}
	if !strings.Contains(err.Error(), "not_found") {
		t.Fatalf("error = %v, want the provider's own error body included", err)
	}
}

// TestFetchAuthorizationServerCapsDocumentSize uses a body that is valid JSON
// well past the cap, so a missing bound would succeed rather than fail for an
// unrelated reason.
func TestFetchAuthorizationServerCapsDocumentSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		padding := strings.Repeat("x", maxDocumentBytes)
		fmt.Fprintf(w, `{"issuer": "https://issuer.example", "padding": %q}`, padding)
	}))
	defer server.Close()

	_, err := FetchAuthorizationServer(context.Background(), server.Client(), "", server.URL+"/meta")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want the oversized document refused", err)
	}
}

func TestFetchAuthorizationServerAcceptsDocumentAtExactlyTheCap(t *testing.T) {
	const prefix = `{"issuer":"https://issuer.example","padding":"`
	const suffix = `"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, prefix+strings.Repeat("x", maxDocumentBytes-len(prefix)-len(suffix))+suffix)
	}))
	defer server.Close()

	document, err := FetchAuthorizationServer(context.Background(), server.Client(), "", server.URL+"/meta")
	if err != nil {
		t.Fatalf("a document of exactly maxDocumentBytes should be accepted, got: %v", err)
	}
	if document.Issuer != "https://issuer.example" {
		t.Fatalf("issuer = %q, want the document parsed rather than truncated", document.Issuer)
	}
}

// writeJSON keeps the fixtures honest about content type and encoding; a test
// that hand-rolls JSON eventually hand-rolls invalid JSON.
func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode fixture response: %v", err)
	}
}

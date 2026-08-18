package authmeta

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// injectedControlBytes is what a metadata document may legally carry: JSON encodes
// any control character as a \u escape, and encoding/json decodes it into the Go
// string, so nothing upstream of display rejects it.
const injectedControlBytes = "\x1b[2K\rall is well"

// assertNoRawControlBytes checks that attacker-chosen bytes were escaped rather than
// passed through.
//
// The hazard is concrete rather than theoretical: an escape sequence reaching a
// terminal can erase or rewrite the line that is reporting it, and a carriage return
// can overwrite it, so a refusal can be made to read as a success. The same bytes in
// a log aggregator forge a neighbouring record.
func assertNoRawControlBytes(t *testing.T, what, text string) {
	t.Helper()
	if strings.ContainsAny(text, "\x1b\r\x00") {
		t.Fatalf("%s contains raw control bytes: %q", what, text)
	}
	if !strings.Contains(text, `\x1b`) {
		t.Fatalf("%s should render the escape in quoted form, got: %s", what, text)
	}
}

func TestHTTPErrorBodyIsEscaped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied "+injectedControlBytes, http.StatusForbidden)
	}))
	defer server.Close()

	_, err := FetchAuthorizationServer(context.Background(), server.Client(), "", server.URL+"/meta")
	if err == nil {
		t.Fatal("expected the 403 to be reported")
	}
	assertNoRawControlBytes(t, "the HTTP error", err.Error())
}

func TestDeclaredIssuerIsEscapedInTheMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A document is free to put anything in this field: it is compared as a
		// string and never parsed as a URL, so no other check would reject it.
		writeJSON(t, w, map[string]string{"issuer": "https://evil.example" + injectedControlBytes})
	}))
	defer server.Close()

	_, err := FetchAuthorizationServer(context.Background(), server.Client(), "https://configured.example", server.URL+"/meta")
	if !errors.Is(err, oidc.ErrIssuerInvalid) {
		t.Fatalf("error = %v, want the issuer mismatch", err)
	}
	assertNoRawControlBytes(t, "the mismatch error", err.Error())
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestOpenIDConfigurationEndpoint(t *testing.T) {
	cfg := config{Issuer: "http://localhost:18080/oauth2/default"}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	newMux(cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}
	if body["issuer"] != cfg.Issuer {
		t.Fatalf("unexpected issuer: got %q want %q", body["issuer"], cfg.Issuer)
	}
	if body["introspection_endpoint"] != "http://localhost:18080/oauth2/default/v1/introspect" {
		t.Fatalf("unexpected introspection endpoint: got %q", body["introspection_endpoint"])
	}
}

func TestOpenIDConfigurationEndpointNormalizesTrailingSlashIssuer(t *testing.T) {
	cfg := config{Issuer: "http://localhost:18080/oauth2/custom/"}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	newMux(cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}
	if body["introspection_endpoint"] != "http://localhost:18080/oauth2/custom/v1/introspect" {
		t.Fatalf("unexpected introspection endpoint: got %q", body["introspection_endpoint"])
	}
}

func TestIntrospectionActiveTokenWithBasicAuth(t *testing.T) {
	cfg := config{Issuer: "http://localhost:18080/oauth2/default", ClientID: "dev-client", ClientSecret: "dev-secret", ActiveToken: "dev-token"}
	form := url.Values{"token": {"dev-token"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/default/v1/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("dev-client:dev-secret")))
	rr := httptest.NewRecorder()

	handleIntrospect(rr, req, cfg)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}
	if body["active"] != true {
		t.Fatalf("expected active=true for matching token")
	}
}

func TestIntrospectionRejectsUnauthorizedRequest(t *testing.T) {
	cfg := config{ClientID: "dev-client", ClientSecret: "dev-secret", ActiveToken: "dev-token"}
	form := url.Values{"token": {"dev-token"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/default/v1/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handleIntrospect(rr, req, cfg)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestNewMuxRegistersIntrospectionRouteFromIssuer verifies that changing the
// issuer path also changes the served introspection endpoint path.
func TestNewMuxRegistersIntrospectionRouteFromIssuer(t *testing.T) {
	cfg := config{
		Issuer:       "http://localhost:18080/oauth2/custom",
		ClientID:     "dev-client",
		ClientSecret: "dev-secret",
		ActiveToken:  "dev-token",
	}
	form := url.Values{"token": {"dev-token"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/custom/v1/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("dev-client:dev-secret")))
	rr := httptest.NewRecorder()

	newMux(cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}
	if body["active"] != true {
		t.Fatalf("expected active=true for matching token")
	}
}

func TestIntrospectionPathFromIssuer(t *testing.T) {
	testCases := []struct {
		name   string
		issuer string
		want   string
	}{
		{name: "default issuer path", issuer: "http://localhost:18080/oauth2/default", want: "/oauth2/default/v1/introspect"},
		{name: "custom issuer path", issuer: "http://localhost:18080/my/issuer", want: "/my/issuer/v1/introspect"},
		{name: "issuer with trailing slash", issuer: "http://localhost:18080/oauth2/custom/", want: "/oauth2/custom/v1/introspect"},
		{name: "issuer without path", issuer: "http://localhost:18080", want: "/v1/introspect"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := introspectionPathFromIssuer(tc.issuer)
			if got != tc.want {
				t.Fatalf("unexpected path: got %q want %q", got, tc.want)
			}
		})
	}
}

func TestIntrospectionEndpointFromIssuer(t *testing.T) {
	testCases := []struct {
		name   string
		issuer string
		want   string
	}{
		{name: "default issuer path", issuer: "http://localhost:18080/oauth2/default", want: "http://localhost:18080/oauth2/default/v1/introspect"},
		{name: "issuer with trailing slash", issuer: "http://localhost:18080/oauth2/custom/", want: "http://localhost:18080/oauth2/custom/v1/introspect"},
		{name: "issuer without path", issuer: "http://localhost:18080", want: "http://localhost:18080/v1/introspect"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := introspectionEndpointFromIssuer(tc.issuer)
			if got != tc.want {
				t.Fatalf("unexpected endpoint: got %q want %q", got, tc.want)
			}
		})
	}
}

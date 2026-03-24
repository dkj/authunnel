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

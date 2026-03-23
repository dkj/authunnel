package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCheckTokenRequiresAuthorizationHeader verifies that requests
// without an Authorization header are rejected before any provider call.
func TestCheckTokenRequiresAuthorizationHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()

	ok := checkToken(rr, req, nil)
	if ok {
		t.Fatalf("expected token check to fail when authorization header is missing")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

// TestCheckTokenRejectsInvalidAuthorizationScheme verifies that
// non-Bearer Authorization headers are rejected.
func TestCheckTokenRejectsInvalidAuthorizationScheme(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Basic abc123")
	rr := httptest.NewRecorder()

	ok := checkToken(rr, req, nil)
	if ok {
		t.Fatalf("expected token check to fail for non-bearer authorization scheme")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

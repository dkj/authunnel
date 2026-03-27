package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

// config contains runtime options for the local development mock OIDC server.
type config struct {
	Addr         string
	Issuer       string
	ClientID     string
	ClientSecret string
	ActiveToken  string
}

func main() {
	cfg := loadConfig()
	mux := newMux(cfg)
	log.Printf("mock OIDC server listening on %s (issuer=%s)", cfg.Addr, cfg.Issuer)
	if err := http.ListenAndServe(cfg.Addr, mux); err != nil {
		log.Fatalf("mock OIDC server failed: %v", err)
	}
}

func loadConfig() config {
	addr := getenvDefault("MOCK_OIDC_ADDR", ":18080")
	issuer := getenvDefault("MOCK_OIDC_ISSUER", "http://localhost:18080/oauth2/default")
	return config{
		Addr:         addr,
		Issuer:       issuer,
		ClientID:     getenvDefault("MOCK_OIDC_CLIENT_ID", "dev-client"),
		ClientSecret: getenvDefault("MOCK_OIDC_CLIENT_SECRET", "dev-secret"),
		ActiveToken:  getenvDefault("MOCK_OIDC_ACTIVE_TOKEN", "dev-access-token"),
	}
}

func getenvDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func newMux(cfg config) *http.ServeMux {
	mux := http.NewServeMux()
	discoveryPath := discoveryPathFromIssuer(cfg.Issuer)
	tokenPath := tokenPathFromIssuer(cfg.Issuer)
	introspectionPath := introspectionPathFromIssuer(cfg.Issuer)
	mux.HandleFunc(discoveryPath, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"issuer":                 cfg.Issuer,
			"token_endpoint":         endpointURLFromIssuer(cfg.Issuer, "v1/token"),
			"introspection_endpoint": endpointURLFromIssuer(cfg.Issuer, "v1/introspect"),
		})
	})
	// Register the token endpoint even though Authunnel only uses introspection;
	// the OIDC client validates discovery output and requires token_endpoint.
	mux.HandleFunc(tokenPath, func(w http.ResponseWriter, r *http.Request) {
		handleToken(w, r, cfg)
	})
	// Register introspection on the exact issuer-derived path so discovery metadata
	// and served routes stay consistent even when MOCK_OIDC_ISSUER changes.
	mux.HandleFunc(introspectionPath, func(w http.ResponseWriter, r *http.Request) {
		handleIntrospect(w, r, cfg)
	})
	return mux
}

// discoveryPathFromIssuer converts issuer URL into the HTTP path used for
// /.well-known/openid-configuration. If parsing fails, it falls back to the
// historical root discovery path.
func discoveryPathFromIssuer(issuer string) string {
	return pathFromIssuer(issuer, "/.well-known/openid-configuration")
}

// tokenPathFromIssuer converts issuer URL into the HTTP path used for
// /v1/token. If parsing fails, it falls back to the historical default path.
func tokenPathFromIssuer(issuer string) string {
	return pathFromIssuer(issuer, "/v1/token")
}

// introspectionPathFromIssuer converts issuer URL into the HTTP path used for
// /v1/introspect. If parsing fails, it falls back to the historical default path.
func introspectionPathFromIssuer(issuer string) string {
	return pathFromIssuer(issuer, "/v1/introspect")
}

func pathFromIssuer(issuer string, endpointSuffix string) string {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return "/oauth2/default" + endpointSuffix
	}
	basePath := strings.TrimSuffix(parsed.EscapedPath(), "/")
	if basePath == "" {
		basePath = "/"
	}
	return path.Join(basePath, endpointSuffix)
}

func endpointURLFromIssuer(issuer string, endpointSuffix string) string {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return strings.TrimSuffix(issuer, "/") + "/" + strings.TrimPrefix(endpointSuffix, "/")
	}
	basePath := strings.TrimSuffix(parsed.EscapedPath(), "/")
	if basePath == "" {
		basePath = "/"
	}
	parsed.Path = path.Join(basePath, endpointSuffix)
	parsed.RawPath = ""
	return parsed.String()
}

func handleToken(w http.ResponseWriter, r *http.Request, cfg config) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isAuthorized(r, cfg) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if grantType := r.Form.Get("grant_type"); grantType != "" && grantType != "client_credentials" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "unsupported_grant_type",
			"error_description": "only client_credentials is supported",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": cfg.ActiveToken,
		"token_type":   "Bearer",
		"expires_in":   int(time.Hour.Seconds()),
		"scope":        "openid email profile",
	})
}

func handleIntrospect(w http.ResponseWriter, r *http.Request, cfg config) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isAuthorized(r, cfg) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	token := r.Form.Get("token")
	active := token == cfg.ActiveToken
	response := map[string]any{
		"active":     active,
		"token_type": "Bearer",
		"exp":        time.Now().Add(time.Hour).Unix(),
	}
	if active {
		response["scope"] = "openid email profile"
		response["sub"] = "dev-user"
		response["iss"] = cfg.Issuer
		response["client_id"] = cfg.ClientID
	}
	writeJSON(w, http.StatusOK, response)
}

func isAuthorized(r *http.Request, cfg config) bool {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			return false
		}
		return string(decoded) == cfg.ClientID+":"+cfg.ClientSecret
	}

	// Allow form-based client credentials for manual curl workflows.
	if err := r.ParseForm(); err == nil {
		return r.Form.Get("client_id") == cfg.ClientID && r.Form.Get("client_secret") == cfg.ClientSecret
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

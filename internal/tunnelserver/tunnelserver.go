// Package tunnelserver contains the reusable HTTP and token-validation logic
// for the Authunnel server. Keeping this separate from main makes the security-
// sensitive request flow easier to test without needing to boot the TLS server.
package tunnelserver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	socks5 "github.com/armon/go-socks5"
	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/coder/websocket"
)

type TokenValidator interface {
	ValidateAccessToken(ctx context.Context, token string) (*oidc.AccessTokenClaims, error)
}

// JWTTokenValidator validates bearer access tokens against issuer discovery and
// the issuer's JWKS, then applies an explicit audience check for the protected
// resource.
type JWTTokenValidator struct {
	audience string
	verifier *op.AccessTokenVerifier
}

// NewJWTTokenValidator performs provider discovery up front so configuration
// errors fail at startup rather than on the first protected request.
func NewJWTTokenValidator(ctx context.Context, issuer, audience string, httpClient *http.Client) (*JWTTokenValidator, error) {
	if issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if audience == "" {
		return nil, errors.New("token audience is required")
	}
	discovery, err := client.Discover(ctx, issuer, httpClient)
	if err != nil {
		return nil, fmt.Errorf("discover issuer metadata: %w", err)
	}
	if discovery.JwksURI == "" {
		return nil, errors.New("issuer discovery did not advertise jwks_uri")
	}
	keySet := rp.NewRemoteKeySet(httpClient, discovery.JwksURI)
	return &JWTTokenValidator{
		audience: audience,
		verifier: op.NewAccessTokenVerifier(issuer, keySet),
	}, nil
}

// ValidateAccessToken verifies signature, issuer, expiry and standard token
// claims via the Zitadel verifier, then enforces the configured resource
// audience separately so that resource identity stays explicit in Authunnel.
func (v *JWTTokenValidator) ValidateAccessToken(ctx context.Context, token string) (*oidc.AccessTokenClaims, error) {
	claims, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, token, v.verifier)
	if err != nil {
		return nil, err
	}
	if err := oidc.CheckAudience(claims, v.audience); err != nil {
		return nil, err
	}
	return claims, nil
}

// NewHandler installs the small HTTP surface used by the server:
//   - "/" for a simple liveness response
//   - "/protected" for token-validation smoke testing
//   - "/protected/socks" for the authenticated websocket-to-SOCKS bridge
func NewHandler(validator TokenValidator, socks *socks5.Server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !allowMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write([]byte("OK " + time.Now().String()))
	})

	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		if !allowMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		ok := CheckToken(w, r, validator)
		if !ok {
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write([]byte("Protected OK " + time.Now().String()))
	})

	mux.HandleFunc("/protected/socks", func(w http.ResponseWriter, r *http.Request) {
		if !checkWebSocketRequest(w, r) {
			return
		}
		ok := CheckToken(w, r, validator)
		if !ok {
			return
		}
		// websocket.Accept hijacks the HTTP/1.1 connection. Clear any
		// server-level deadlines first so the upgraded SOCKS tunnel can stay
		// open independently of the HTTP request timeout budget.
		c, err := websocket.Accept(clearHijackedConnDeadlines(w), r, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUpgradeRequired)
			return
		}
		defer c.CloseNow()
		socks.ServeConn(websocket.NetConn(r.Context(), c, websocket.MessageBinary))
	})
	return mux
}

// checkWebSocketRequest rejects requests that should never reach the
// authenticated upgrade path. This keeps protocol admission checks separate
// from bearer-token validation and makes browser-origin handling explicit.
func checkWebSocketRequest(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		http.Error(w, "websocket upgrade requires GET", http.StatusMethodNotAllowed)
		return false
	}
	if !headerContainsToken(r.Header, "Connection", "upgrade") || !headerContainsToken(r.Header, "Upgrade", "websocket") {
		http.Error(w, "websocket upgrade required", http.StatusUpgradeRequired)
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	originURL, err := url.Parse(origin)
	if err != nil || originURL.Host == "" {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return false
	}
	// TODO: Make the allowed origin/host comparison configurable if a reverse
	// proxy rewrites Host instead of forwarding the original external hostname.
	if !sameHost(originURL.Host, r.Host) {
		http.Error(w, "cross-origin websocket forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// CheckToken extracts the bearer token from the request and delegates
// verification to the configured validator. The caller decides which routes
// require protection and how to continue once validation succeeds.
func CheckToken(w http.ResponseWriter, r *http.Request, validator TokenValidator) bool {
	auth := r.Header.Get("authorization")
	if auth == "" {
		http.Error(w, "auth header missing", http.StatusUnauthorized)
		return false
	}
	if !strings.HasPrefix(auth, oidc.PrefixBearer) {
		http.Error(w, "invalid header", http.StatusUnauthorized)
		return false
	}
	if validator == nil {
		http.Error(w, "token validator unavailable", http.StatusInternalServerError)
		return false
	}

	token := strings.TrimPrefix(auth, oidc.PrefixBearer)
	if _, err := validator.ValidateAccessToken(r.Context(), token); err != nil {
		// Do not reflect verifier details (signature, issuer/audience mismatch,
		// expiry parsing errors, etc.) back to callers. Returning a fixed message
		// keeps the auth surface predictable while preserving diagnostics in logs.
		log.Printf("access token validation failed: %v", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func headerContainsToken(header http.Header, name, expected string) bool {
	for _, value := range header.Values(name) {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), expected) {
				return true
			}
		}
	}
	return false
}

func sameHost(a, b string) bool {
	return strings.EqualFold(normalizeHost(a), normalizeHost(b))
}

func normalizeHost(hostport string) string {
	host := hostport
	if parsedHost, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsedHost
	} else if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(hostport, "]"), "[")
	}
	return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
}

func allowMethods(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, method := range allowed {
		if r.Method == method {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func clearHijackedConnDeadlines(w http.ResponseWriter) http.ResponseWriter {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return w
	}
	return deadlineClearingResponseWriter{ResponseWriter: w, hijacker: hj}
}

type deadlineClearingResponseWriter struct {
	http.ResponseWriter
	hijacker http.Hijacker
}

func (w deadlineClearingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := w.hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("clear hijacked connection deadlines: %w", err)
	}
	return conn, rw, nil
}

// Package authhttp provides the shared transport policy for OIDC discovery,
// JWKS, and token endpoint traffic: a small bounded *http.Client, plus the
// guards that keep that traffic on https.
//
// Both the server-side validator and the managed client share the same
// transport defaults so a stalled or attacker-controlled issuer cannot hold
// either side's auth path open indefinitely. Tests still inject custom clients
// through the existing constructor seams.
//
// NewBoundedClient applies the redirect guard from downgrade.go by default.
// Callers apply it explicitly as well, so the guarantee survives a caller
// injecting its own client — the double wrap is harmless, since the outer
// policy delegates to the inner one.
package authhttp

import (
	"net"
	"net/http"
	"time"
)

// Bounded auth-HTTP defaults. Discovery and JWKS endpoints serve small static
// documents, so any latency above these bounds points at a misconfigured or
// attacker-controlled issuer rather than a legitimate slow path. The values
// are deliberately compile-time constants: operators with unusual IdP latency
// can inject a custom *http.Client through the existing constructor seams.
const (
	defaultDialTimeout         = 5 * time.Second
	defaultTLSHandshakeTimeout = 5 * time.Second
	defaultResponseHeaders     = 5 * time.Second
	defaultIdleConnTimeout     = 30 * time.Second
	defaultClientTimeout       = 10 * time.Second
)

// NewBoundedClient returns an *http.Client suitable for OIDC discovery, JWKS
// fetches, and token endpoint exchanges. The total round-trip budget is
// intentionally short. The transport is reusable so connection pooling still
// applies across repeated key-set fetches and refresh calls.
func NewBoundedClient() *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   defaultDialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: defaultResponseHeaders,
		ExpectContinueTimeout: time.Second,
	}
	return RefuseTransportDowngrade(&http.Client{
		Transport: transport,
		Timeout:   defaultClientTimeout,
	})
}

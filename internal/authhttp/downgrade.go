package authhttp

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ErrUnsafeTransport marks a local refusal, rather than a failure to reach or
// authenticate with an endpoint. The client treats it as terminal because an
// interactive retry would use the same unsafe endpoint. Errors from a caller's
// own redirect policy retain their original identity and do not match it.
var ErrUnsafeTransport = errors.New("unsafe auth transport")

// refusef preserves a concise operator message while supporting errors.Is.
func refusef(format string, args ...any) error {
	return &refusal{msg: fmt.Sprintf(format, args...)}
}

type refusal struct{ msg string }

func (r *refusal) Error() string { return r.msg }

func (r *refusal) Is(target error) bool { return target == ErrUnsafeTransport }

// maxAuthRedirects mirrors the cap Go's default CheckRedirect applies. Setting
// our own CheckRedirect replaces that default, so the bound has to be restated
// here or the chain would be unbounded.
const maxAuthRedirects = 10

// RefuseTransportDowngrade returns a shallow copy that refuses redirects from
// HTTPS to weaker schemes and then delegates to the caller's existing policy.
// This covers metadata, JWKS, refresh, and code exchanges; 307/308 redirects
// can otherwise carry credential-bearing request bodies into plaintext.
func RefuseTransportDowngrade(base *http.Client) *http.Client {
	guarded := *base
	inherited := base.CheckRedirect
	guarded.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxAuthRedirects {
			return refusef("stopped after %d redirects", maxAuthRedirects)
		}
		if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return refusef("refusing redirect from https to %s://%s: transport downgrade on the auth path",
				req.URL.Scheme, req.URL.Host)
		}
		if inherited != nil {
			return inherited(req, via)
		}
		return nil
	}
	return &guarded
}

// CheckDiscoveredEndpoint validates an endpoint supplied by issuer metadata.
// It must be an absolute http(s) URL with a host and must not downgrade from an
// HTTPS metadata source. Keeping both rules in one call prevents a caller from
// accepting custom schemes when development metadata is served over HTTP.
func CheckDiscoveredEndpoint(label, metadataSource, endpoint string) error {
	if endpoint == "" {
		return refusef("issuer metadata did not advertise %s", label)
	}
	resolved, err := parseAuthURL(label, endpoint)
	if err != nil {
		return err
	}
	source, err := url.Parse(metadataSource)
	if err != nil {
		return refusef("parse metadata source %q: %v", metadataSource, err)
	}
	if source.Scheme == "https" && resolved.Scheme != "https" {
		return refusef("issuer metadata fetched over https advertised a non-https %s %q; refusing to use a downgraded endpoint",
			label, endpoint)
	}
	return nil
}

// CheckHTTPURL validates only that rawURL is an absolute http(s) URL with a
// host. It does not decide whether plaintext is allowed. Metadata-advertised
// endpoints must use CheckDiscoveredEndpoint so their downgrade policy is not
// omitted.
func CheckHTTPURL(label, rawURL string) error {
	if rawURL == "" {
		return refusef("%s is required", label)
	}
	_, err := parseAuthURL(label, rawURL)
	return err
}

// CheckConfiguredURL validates an operator-supplied auth URL.
// Configured URLs require https unless allowPlaintext. Discovered endpoints use
// CheckDiscoveredEndpoint because their transport is judged relative to the
// metadata source.
//
// allowPlaintext relaxes transport only; it does not permit other schemes.
func CheckConfiguredURL(label, rawURL string, allowPlaintext bool) error {
	if rawURL == "" {
		return refusef("%s is required", label)
	}
	u, err := parseAuthURL(label, rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && !allowPlaintext {
		return refusef("%s must use an https:// URL; use --insecure-oidc-issuer to allow plaintext (development only)", label)
	}
	return nil
}

// parseAuthURL holds the shared definition of a usable auth URL: absolute
// http(s), with a host and no opaque component.
func parseAuthURL(label, rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, refusef("%s %q is not a valid URL: %v", label, rawURL, err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, refusef("%s %q uses unsupported scheme %q; only http and https are accepted",
			label, rawURL, u.Scheme)
	}
	if u.Opaque != "" || u.Host == "" {
		return nil, refusef("%s %q is not an absolute URL with a host", label, rawURL)
	}
	return u, nil
}

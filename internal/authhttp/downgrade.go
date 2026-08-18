package authhttp

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
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

// SameOrigin reports whether two auth URLs share a scheme and authority, after the
// syntax normalisation RFC 3986 §6.2.2 permits.
//
// Used where one configured value bounds another discovered one: a published metadata
// URL may only relocate a pinned issuer's document within that issuer's own origin.
func SameOrigin(a, b string) (bool, error) {
	first, err := url.Parse(a)
	if err != nil {
		return false, fmt.Errorf("%q is not a valid URL: %w", a, err)
	}
	second, err := url.Parse(b)
	if err != nil {
		return false, fmt.Errorf("%q is not a valid URL: %w", b, err)
	}
	for _, u := range []*url.URL{first, second} {
		if u.Scheme == "" || u.Host == "" {
			return false, fmt.Errorf("%q is not an absolute URL with a host", u.String())
		}
	}
	return originOf(first) == originOf(second), nil
}

func originOf(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	return scheme + "://" + NormalizeAuthority(scheme, u)
}

// NormalizeAuthority reduces a URL's authority to the form comparisons run on: host
// case-folded, IP literal canonicalised, redundant default port dropped, IPv6
// re-bracketed. Shared with internal/authmeta so resource identifiers and origins are
// judged by one rule.
func NormalizeAuthority(scheme string, u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	port := u.Port()
	if (strings.EqualFold(scheme, "https") && port == "443") || (strings.EqualFold(scheme, "http") && port == "80") {
		port = ""
	}
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// PinRedirectOrigin refuses a redirect that leaves the origin the request started on.
//
// Narrow by design. HTTPS-to-HTTPS delegation is permitted generally (see the
// discovery simplification plan's non-goals), but that concerns where a *document*
// may come from. This is applied to the two cases the reasoning does not reach:
//
//   - a metadata URL published by a tunnel server and adopted under a pinned
//     --oidc-issuer, where the same-origin check on the published value is the whole
//     of the pin and an open redirect on the issuer's host would defeat it;
//   - the token requests, whose bodies carry a refresh token or an authorization
//     code. A 307 preserves method and body, so without this the credential is
//     posted to whatever origin the token endpoint's host names.
//
// Layers on any policy the caller already set, so the composed verdict is the
// caller's AND ours.
func PinRedirectOrigin(base *http.Client) *http.Client {
	pinned := *base
	inherited := base.CheckRedirect
	pinned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// The inherited policy is consulted first so its verdict is the one reported:
		// a redirect onto plaintext is both a downgrade and an origin change, and
		// "downgrade" is the more specific fault to hand an operator.
		if inherited != nil {
			if err := inherited(req, via); err != nil {
				return err
			}
		}
		if len(via) == 0 {
			return nil
		}
		same, err := SameOrigin(via[0].URL.String(), req.URL.String())
		if err != nil {
			return refusef("refusing redirect to %s: %v", req.URL.Redacted(), err)
		}
		if !same {
			return refusef("refusing redirect from %s to %s: this request is pinned to the origin it started on",
				originOf(via[0].URL), originOf(req.URL))
		}
		return nil
	}
	return &pinned
}

// CheckDiscoveredEndpoint validates an endpoint supplied by issuer metadata.
// It must be an absolute http(s) URL with a host and must not downgrade from an
// HTTPS metadata source. Keeping both rules in one call prevents a caller from
// accepting custom schemes when development metadata is served over HTTP.
func CheckDiscoveredEndpoint(label, metadataSource, endpoint string) error {
	if endpoint == "" {
		return refusef("issuer metadata did not advertise %s", label)
	}
	resolved, err := ParseAuthURL(label, endpoint)
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
	_, err := ParseAuthURL(label, rawURL)
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
	u, err := ParseAuthURL(label, rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && !allowPlaintext {
		return refusef("%s must use an https:// URL; use --insecure-oidc-issuer to allow plaintext (development only)", label)
	}
	return nil
}

// ParseAuthURL holds the shared definition of a usable auth URL: absolute
// http(s), with a host and no opaque component.
func ParseAuthURL(label, rawURL string) (*url.URL, error) {
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

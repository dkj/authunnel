package authhttp

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ErrUnsafeTransport marks a refusal to use an endpoint or transport, as
// opposed to a failure to reach one.
//
// Callers key on it to decide whether a retry could help: it never can. A
// credential that could not be refreshed because the token endpoint was
// downgraded will not be obtained by authenticating again — the endpoint is
// still downgraded. Distinguishing this from an ordinary network or
// expired-credential failure keeps a client from escalating a configuration
// problem into a login prompt that is guaranteed to fail.
//
// Every refusal this package generates matches it under errors.Is, via refusef;
// malformed-URL errors included, since an endpoint that will not parse is a
// refusal in the same sense. Keep that property when adding errors here — one
// that does not match silently reads to callers as "transient", the opposite of
// what it means.
//
// Deliberately excluded: an error from a caller's own CheckRedirect, which
// RefuseTransportDowngrade delegates to and returns unchanged. That verdict
// belongs to the caller — we do not know whether retrying it could help, and
// stamping our sentinel on it would report someone else's policy as ours.
// Callers keying on the sentinel therefore see their own errors unchanged,
// which is what lets them tell the two apart.
//
// It survives net/http wrapping: a CheckRedirect error is returned inside a
// *url.Error, which unwraps, so errors.Is reaches this through the client.
var ErrUnsafeTransport = errors.New("unsafe auth transport")

// refusef builds a refusal that matches ErrUnsafeTransport under errors.Is
// without appending the sentinel's text to the message.
//
// Wrapping with %w would put ": unsafe auth transport" on the end of every
// message an operator sees, which is noise on a startup error that already says
// exactly what is wrong. The identity is for code; the text is for people.
func refusef(format string, args ...any) error {
	return &refusal{msg: fmt.Sprintf(format, args...)}
}

type refusal struct{ msg string }

func (r *refusal) Error() string { return r.msg }

// Is reports a match for ErrUnsafeTransport so callers can key on it through
// net/http's *url.Error wrapping.
func (r *refusal) Is(target error) bool { return target == ErrUnsafeTransport }

// maxAuthRedirects mirrors the cap Go's default CheckRedirect applies. Setting
// our own CheckRedirect replaces that default, so the bound has to be restated
// here or the chain would be unbounded.
const maxAuthRedirects = 10

// RefuseTransportDowngrade returns a shallow copy of base whose redirect policy
// refuses to leave https. The copy matters: the caller's client is shared with
// other auth traffic and must not acquire this policy as a side effect.
//
// It guards every auth fetch, not only metadata: JWKS on the server, and the
// refresh grant and code exchange on the client. The latter two carry
// credentials in the request body, and a 307 or 308 preserves that body across
// a redirect, so a downgrade there discloses a refresh token or authorization
// code rather than merely weakening a fetch of public material.
//
// The guard *layers on top of* any policy the caller already set rather than
// replacing it — a caller that rejects cross-host redirects, or all redirects,
// must not start following them just because it was passed here. The composed
// policy is therefore the caller's AND ours, which can only ever be more
// restrictive than either alone. The redirect cap is applied unconditionally
// for the same reason: auth metadata fetching stays bounded even if the
// caller's own policy has no ceiling.
func RefuseTransportDowngrade(base *http.Client) *http.Client {
	guarded := *base
	inherited := base.CheckRedirect
	guarded.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxAuthRedirects {
			// A refusal like every other here: hitting the cap is us
			// declining to continue, not the issuer being unreachable, and
			// re-authenticating would walk the same chain.
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

// CheckEndpointURL validates an endpoint named by a metadata document before it
// is used. label identifies the field for the error message ("jwks_uri",
// "token_endpoint", "authorization_endpoint").
//
// This is an absolute requirement, unlike CheckNoSchemeDowngrade, which is
// relative to how the metadata itself arrived. The two are not
// interchangeable: over an http metadata source the downgrade check passes
// *everything*, so without this a document could name a file:// or custom-scheme
// endpoint. That matters most for authorization_endpoint, which is handed to the
// OS URL dispatcher — see the comment in client/browser_other.go.
//
// A scheme test alone is not enough, and neither is url.URL.IsAbs: "https:x"
// parses with Scheme "https" and IsAbs true, but has no host and carries its
// content in Opaque. Requiring a host and an empty Opaque is what actually
// pins this to a real network endpoint.
func CheckEndpointURL(label, rawURL string) error {
	if rawURL == "" {
		return refusef("issuer metadata did not advertise %s", label)
	}
	_, err := parseAuthURL(label, rawURL)
	return err
}

// CheckConfiguredURL validates an operator-supplied auth URL — an issuer, a
// metadata document, a pinned JWKS endpoint. label is the flag name, used in the
// error so an operator knows which value to fix.
//
// Same shape rules as CheckEndpointURL, plus an https requirement unless
// allowPlaintext. The two differ only there, deliberately: a discovered endpoint
// is judged relative to the transport its metadata arrived over (see
// CheckNoSchemeDowngrade), while a configured one has no such context and is
// held to https unless the operator has said otherwise.
//
// allowPlaintext relaxes the transport only. It does not widen the scheme
// allowlist, so file:// stays refused with it set — an operator reaching for
// that wants a JWKS from disk, which needs its own flag and its own code path
// rather than a URL that would otherwise be fetched through the shared auth
// HTTP client.
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

// parseAuthURL holds the one definition of what a usable auth URL looks like:
// http or https, absolute, with a host. Both exported checks build on it so the
// rule cannot drift between configured and discovered URLs.
func parseAuthURL(label, rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, refusef("%s %q is not a valid URL: %v", label, rawURL, err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		// No mention of an override here. Whether http is acceptable depends
		// on the caller — a configured URL needs --insecure-oidc-issuer, a
		// discovered one only needs its metadata to have arrived over http —
		// and naming one of those in the shared message would be wrong for
		// the other. CheckConfiguredURL supplies the flag hint itself.
		return nil, refusef("%s %q uses unsupported scheme %q; only http and https are accepted",
			label, rawURL, u.Scheme)
	}
	if u.Opaque != "" || u.Host == "" {
		return nil, refusef("%s %q is not an absolute URL with a host", label, rawURL)
	}
	return u, nil
}

// CheckNoSchemeDowngrade rejects a resolved endpoint that is less protected
// than the document that named it. label identifies the field for the error
// message.
//
// Judged against the scheme the metadata itself arrived over rather than an
// absolute https requirement: if the document already travelled in clear text
// there is no downgrade left to prevent, and that case is the local development
// setup the config layer gates behind --insecure-oidc-issuer. Pair it with
// CheckEndpointURL, which does not have that escape.
func CheckNoSchemeDowngrade(label, sourceURL, resolvedURL string) error {
	source, err := url.Parse(sourceURL)
	if err != nil {
		return refusef("parse metadata source %q: %v", sourceURL, err)
	}
	resolved, err := url.Parse(resolvedURL)
	if err != nil {
		return refusef("parse %s %q: %v", label, resolvedURL, err)
	}
	if source.Scheme == "https" && resolved.Scheme != "https" {
		return refusef("issuer metadata fetched over https advertised a non-https %s %q; refusing to use a downgraded endpoint",
			label, resolvedURL)
	}
	return nil
}

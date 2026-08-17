package authhttp

import (
	"fmt"
	"net/http"
	"net/url"
)

// maxAuthRedirects mirrors the cap Go's default CheckRedirect applies. Setting
// our own CheckRedirect replaces that default, so the bound has to be restated
// here or the chain would be unbounded.
const maxAuthRedirects = 10

// RefuseTransportDowngrade returns a shallow copy of base whose redirect policy
// refuses to leave https. The copy matters: the caller's client is shared with
// other auth traffic and must not acquire this policy as a side effect.
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
			return fmt.Errorf("stopped after %d redirects", maxAuthRedirects)
		}
		if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect from https to %s://%s: transport downgrade during auth metadata fetch",
				req.URL.Scheme, req.URL.Host)
		}
		if inherited != nil {
			return inherited(req, via)
		}
		return nil
	}
	return &guarded
}

// CheckNoSchemeDowngrade rejects a resolved endpoint that is less protected
// than the document that named it.
//
// The error text names jwks_uri because the server-side validator is currently
// the only caller. When the managed client adopts this for its token and
// authorization endpoints, the message needs to name the endpoint being checked
// instead — deliberately left alone here so that promoting this function stays a
// pure move, verifiable by the existing suite passing unchanged.
func CheckNoSchemeDowngrade(sourceURL, resolvedURL string) error {
	source, err := url.Parse(sourceURL)
	if err != nil {
		return fmt.Errorf("parse metadata source %q: %w", sourceURL, err)
	}
	resolved, err := url.Parse(resolvedURL)
	if err != nil {
		return fmt.Errorf("parse jwks_uri %q: %w", resolvedURL, err)
	}
	if source.Scheme == "https" && resolved.Scheme != "https" {
		return fmt.Errorf("issuer metadata fetched over https advertised a non-https jwks_uri %q; refusing to fetch signing keys over %s",
			resolvedURL, resolved.Scheme)
	}
	return nil
}

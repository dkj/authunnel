package authmeta

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"authunnel/internal/authhttp"
)

// ProtectedResourcePath is the segment RFC 9728 §3.1 inserts between a
// resource's authority and its path to form the metadata location. A resource
// identifier of https://tunnel.example/protected/tunnel therefore publishes at
// https://tunnel.example/.well-known/oauth-protected-resource/protected/tunnel,
// and one with no path publishes at the bare segment.
const ProtectedResourcePath = "/.well-known/oauth-protected-resource"

// ProtectedResource is the RFC 9728 metadata document, as authunnel publishes it
// and as authunnel reads it. One type for both directions on purpose: a server
// field and a client field that drift apart are a wire-format bug that no test on
// either side alone can see.
//
// The authunnel_-prefixed fields are extensions. RFC 9728 §3 permits additional
// parameters, and these carry the values the registry has no room for but a
// client cannot start without — chiefly the public client ID, which is not a
// secret: it travels in every authorization request and appears in the user's
// URL bar.
type ProtectedResource struct {
	// Resource is the resource identifier this document describes. A client
	// checks it against the resource it is actually using; see
	// FetchProtectedResource.
	Resource string `json:"resource"`
	// AuthorizationServers lists issuer identifiers that mint tokens for this
	// resource. authunnel publishes exactly one, the issuer it validates
	// against, and a client reading more than one uses the first.
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	// ScopesSupported are the scopes a client should request.
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// BearerMethodsSupported is ["header"]: the Authorization header is the only
	// way this server accepts a token.
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`

	// ClientID is the public client registered for this resource at the
	// authorization server above.
	ClientID string `json:"authunnel_client_id,omitempty"`
	// AuthorizationServerMetadataURL locates the authorization server's own
	// metadata document when it is not at the path derived from the issuer.
	// Present only when the resource server itself needed that override.
	AuthorizationServerMetadataURL string `json:"authunnel_authorization_server_metadata_url,omitempty"`
	// Audience is the value to send as the provider-specific `audience`
	// authorization parameter (the Auth0 style).
	Audience string `json:"authunnel_audience,omitempty"`
	// ResourceIndicator is the value to send as the RFC 8707 `resource`
	// authorization parameter, for providers that bind the access token's `aud`
	// claim to it.
	//
	// Separate from Audience rather than derived from one required audience
	// value, because a resource server knows *what* audience it requires but not
	// *how* its authorization server wants it asked for — and a provider ignores
	// the parameter it does not implement silently, producing a login that
	// succeeds and a token this server then rejects.
	ResourceIndicator string `json:"authunnel_resource,omitempty"`
}

// AuthorizationServer returns the issuer a client should use, or "" when the
// document names none.
func (p *ProtectedResource) AuthorizationServer() string {
	if len(p.AuthorizationServers) == 0 {
		return ""
	}
	return p.AuthorizationServers[0]
}

// ProtectedResourceURL applies the RFC 9728 §3.1 derivation to a resource
// identifier: the well-known segment is inserted between the authority and the
// path, and the query is carried through.
//
// The query is part of the identifier — §3.1 retains it, and a resource
// identifier is permitted to carry one — so two tunnel URLs differing only in
// their query are two resources, with their own metadata and, downstream, their
// own cached credentials. An earlier version dropped it, reasoning that it would
// "leak whatever a caller had appended". That reasoning holds for the fragment,
// which is never sent anywhere, and fails for the query, which the WebSocket dial
// already sends to this very host: dropping it disclosed nothing and instead
// collapsed distinct resources onto one identity.
func ProtectedResourceURL(resourceURL string) (string, error) {
	// Via the identifier rule rather than a private copy of it: the value being
	// derived from and the value being compared must be judged the same way, or
	// one of the two eventually accepts something the other does not.
	normalized, err := NormalizeResourceIdentifier(resourceURL)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return "", err
	}
	// Assembled from the *escaped* path, then re-parsed, so that an encoded
	// separator survives. Setting url.URL.Path alone would re-encode from the
	// decoded form and turn %2F into /, which silently merges two identifiers
	// that RFC 3986 keeps distinct — see NormalizeResourceIdentifier.
	derived, err := url.Parse(u.Scheme + "://" + u.Host + ProtectedResourcePath + strings.TrimSuffix(u.EscapedPath(), "/"))
	if err != nil {
		return "", fmt.Errorf("derive metadata URL for %q: %w", resourceURL, err)
	}
	derived.RawQuery = u.RawQuery
	return derived.String(), nil
}

// FetchProtectedResource retrieves the protected-resource metadata for
// resourceURL and checks that the document describes exactly that resource.
//
// This check is what makes the document trustworthy enough to take an
// authorization server's identity from. Two things have to hold. The document is
// fetched from the resource's own origin — so under https only a holder of a
// certificate for that host can supply it — and its `resource` value must equal
// the identifier the client is actually using.
//
// **The comparison is over the whole identifier, not just the origin**, which
// RFC 9728 §3.3 requires and an earlier version of this function got wrong. It
// compared scheme, host and port only, on the reasoning that a path-rewriting
// reverse proxy legitimately sees a different path. The consequence was that one
// host serving several protected resources could hand a client asking about
// /a/tunnel a document describing /b/tunnel, and the client would adopt /b's
// authorization server and client ID — impersonation between resources that share
// a hostname, which is the case the requirement exists for. A deployment whose
// externally visible identifier differs from the one the request implies declares
// it with the server's --resource-url instead; that is configuration, not a reason
// to weaken the check for everyone.
//
// Only syntax-based normalisation is applied before comparing (RFC 3986 §6.2.2):
// scheme and host are case-folded and a redundant default port is dropped, because
// one side is built from an HTTP Host header and the other from a command-line
// URL. Path and query are compared verbatim.
func FetchProtectedResource(ctx context.Context, httpClient *http.Client, resourceURL string) (*ProtectedResource, error) {
	documentURL, err := ProtectedResourceURL(resourceURL)
	if err != nil {
		return nil, err
	}
	document := new(ProtectedResource)
	if err := fetchDocument(ctx, httpClient, "protected resource metadata URL", documentURL, document); err != nil {
		return nil, err
	}
	if document.Resource == "" {
		return nil, fmt.Errorf("protected resource metadata at %s names no resource", documentURL)
	}
	declared, err := NormalizeResourceIdentifier(document.Resource)
	if err != nil {
		return nil, fmt.Errorf("protected resource metadata at %s: %w", documentURL, err)
	}
	using, err := NormalizeResourceIdentifier(resourceURL)
	if err != nil {
		return nil, err
	}
	if declared != using {
		return nil, fmt.Errorf("protected resource metadata at %s describes %q, not %q; refusing to take configuration from a document about another resource",
			documentURL, document.Resource, resourceURL)
	}
	return document, nil
}

// NormalizeResourceIdentifier applies RFC 3986 syntax-based normalisation to a
// resource identifier so two spellings of the same identifier compare equal:
// scheme and host case-folded, an IP host canonicalised, and a redundant default
// port removed.
//
// Nothing else is normalised. In particular the path is not — no trailing-slash
// folding, no dot-segment removal, and **no percent-decoding** — because a
// resource identifier is opaque beyond its syntax, and quietly equating /a/ with
// /a is how a comparison that looks exact stops being exact.
//
// The percent-decoding part is the subtle one, and it was wrong here at first. The
// path was carried through url.URL.Path, the *decoded* form, so String() re-encoded
// it and /tenant%2Fone/tunnel came back as /tenant/one/tunnel: two identifiers
// that RFC 3986 §2.2 keeps distinct, collapsed onto one — one discovery result and
// one cache entry for two resources a path-routing proxy would treat separately.
// The escaped form is preserved instead.
//
// One consequence of not decoding: escapings that RFC 3986 §6.2.2.2 would call
// equivalent, such as %7E and ~, compare unequal. That errs toward refusing a
// legitimate document rather than accepting a foreign one, which is the right side
// to be wrong on, and the error quotes both values so the cause is visible.
//
// A fragment is refused rather than stripped: identifiers do not carry one, and
// silently discarding part of a value that is about to be compared for equality
// is the wrong instinct here.
func NormalizeResourceIdentifier(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("resource identifier %q is not a valid URL: %w", rawURL, err)
	}
	if u.Host == "" || u.Opaque != "" {
		return "", fmt.Errorf("resource identifier %q is not an absolute URL with a host", rawURL)
	}
	// http(s) only, and not merely as a syntax preference: an authunnel client
	// derives the metadata location from this value and fetches it over HTTP, so
	// any other scheme names a document nothing can retrieve. Enforced here rather
	// than at each caller so the server cannot start advertising an identifier its
	// own clients would refuse.
	if scheme := strings.ToLower(u.Scheme); scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("resource identifier %q must use http or https, got %q", rawURL, u.Scheme)
	}
	if u.Fragment != "" || strings.Contains(rawURL, "#") {
		return "", fmt.Errorf("resource identifier %q must not contain a fragment", rawURL)
	}
	scheme := strings.ToLower(u.Scheme)
	// Re-parsed from the escaped path for the reason in the doc comment: assigning
	// Path would re-encode from the decoded form and lose an encoded separator.
	normalized, err := url.Parse(scheme + "://" + normalizeAuthority(scheme, u) + u.EscapedPath())
	if err != nil {
		return "", fmt.Errorf("resource identifier %q could not be normalised: %w", rawURL, err)
	}
	normalized.RawQuery = u.RawQuery
	return normalized.String(), nil
}

// normalizeAuthority lower-cases the host, canonicalises an IP literal, and drops
// a port that is the scheme's default.
func normalizeAuthority(scheme string, u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		// A bracket-less IPv6 literal would be ambiguous against a host:port
		// form once these are compared as strings.
		return "[" + host + "]"
	}
	return host
}

// maxClientIDBytes and maxScopeBytes bound values that arrive in a metadata
// document and leave in an authorization URL — which is handed to the OS scheme
// dispatcher, not merely fetched. Both limits are far above any real value.
const (
	maxClientIDBytes = 256
	maxScopeBytes    = 1024
)

// ValidateClientID applies RFC 6749 appendix A's *VSCHAR to a client identifier:
// printable ASCII, no controls, no whitespace, non-empty and bounded.
//
// Shared by the server, which validates the hint it is configured to publish, and
// the client, which validates the hint it receives. The server check produces the
// good error — at startup, for the operator who typed it — but it cannot be the
// only one: a client must not trust a remote document to have been produced by a
// server that ran this code.
func ValidateClientID(clientID string) error {
	if clientID == "" {
		return errors.New("client ID is empty")
	}
	if len(clientID) > maxClientIDBytes {
		return fmt.Errorf("client ID exceeds %d bytes", maxClientIDBytes)
	}
	for _, r := range clientID {
		if r < 0x20 || r > 0x7e {
			return fmt.Errorf("client ID contains a character outside printable ASCII (%q)", r)
		}
	}
	return nil
}

// ValidateScopes applies RFC 6749 §3.3's NQCHAR to each scope token: printable
// ASCII excluding space, double quote and backslash. A caller joining these with
// spaces into a query parameter depends on it.
func ValidateScopes(scopes []string) error {
	total := 0
	for _, scope := range scopes {
		if scope == "" {
			return errors.New("scope list contains an empty token")
		}
		total += len(scope) + 1
		for _, r := range scope {
			if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
				return fmt.Errorf("scope %q contains a character not permitted in a scope token (%q)", scope, r)
			}
		}
	}
	if total > maxScopeBytes {
		return fmt.Errorf("scope list exceeds %d bytes", maxScopeBytes)
	}
	return nil
}

// ValidateResourceIndicator applies the RFC 8707 rule: an absolute URI with no
// fragment. Same rule the client's --oidc-resource flag enforces, so a value that
// arrives by discovery cannot be looser than one typed by hand.
func ValidateResourceIndicator(resource string) error {
	if strings.ContainsRune(resource, '#') {
		return fmt.Errorf("resource indicator %q must not contain a fragment (RFC 8707)", resource)
	}
	u, err := url.Parse(resource)
	if err != nil || !u.IsAbs() {
		return fmt.Errorf("resource indicator %q must be an absolute URI, for example https://api.example (RFC 8707)", resource)
	}
	return nil
}

// ValidateAudience bounds the provider-specific audience parameter. There is no
// registry rule to apply — the value is whatever the provider expects — so this
// only refuses what would corrupt the authorization URL it is interpolated into.
func ValidateAudience(audience string) error {
	if len(audience) > maxClientIDBytes {
		return fmt.Errorf("audience exceeds %d bytes", maxClientIDBytes)
	}
	for _, r := range audience {
		if unicode.IsControl(r) {
			return fmt.Errorf("audience contains a control character (%q)", r)
		}
	}
	return nil
}

// CheckDiscoveredURL applies the configured-URL rules to a URL that arrived in a
// metadata document, plus the downgrade rule relative to where that document came
// from. Remote input is held to the standard a local flag is held to, not a
// weaker one.
func CheckDiscoveredURL(label, sourceURL, discoveredURL string, allowPlaintext bool) error {
	if err := authhttp.CheckConfiguredURL(label, discoveredURL, allowPlaintext); err != nil {
		return err
	}
	return authhttp.CheckNoSchemeDowngrade(label, sourceURL, discoveredURL)
}

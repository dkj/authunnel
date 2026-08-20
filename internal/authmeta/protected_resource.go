package authmeta

import (
	"context"
	"errors"
	"fmt"
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
	// BearerMethodsSupported is ["header"]: the Authorization header is the only
	// way this server accepts a token.
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`

	// ClientID is the public client registered for this resource at the
	// authorization server above.
	ClientID string `json:"authunnel_client_id,omitempty"`
	// DefaultScopes are the scopes this server recommends a client request when the
	// operator configured none — advice about the authorization request, which is why
	// it is an extension: RFC 9728 has no field for one.
	//
	// **Not the registered scopes_supported**, for two reasons. Under §7.2 that field
	// is a protected resource disclosing the scopes it supports, which is a different
	// claim from what a client should ask for; adopting such a list wholesale requests
	// more privilege than the job needs. And authunnel has nothing to disclose there —
	// it enforces no scope requirement, accepting a token on its signature, audience
	// and standard claims without reading the `scope` claim at all.
	DefaultScopes []string `json:"authunnel_default_scopes,omitempty"`
	// AuthorizationServerMetadataURL locates the authorization server's own metadata
	// document when it is not at the path derived from the issuer. Absent when the
	// derivation is enough, which is the common case.
	//
	// Not necessarily a location the publishing server fetches itself: it may be
	// configured for clients alone, since a server pinned to a JWKS endpoint reads no
	// metadata document at all. So this is "where a client should look", not evidence
	// of where anything has already been read from.
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
// The query is part of the identifier — §3.1 retains it, and a resource identifier
// may carry one — so two tunnel URLs differing only in their query are two
// resources, with their own metadata and their own cached credentials. Dropping it
// would collapse them onto one identity, and discloses nothing in exchange: the
// WebSocket dial already sends that query to this very host. That includes an
// *empty* query, which is why every reconstruction here goes through CarryQuery. The
// fragment is the opposite case and is refused outright, since it is never sent
// anywhere.
func ProtectedResourceURL(resourceURL string) (string, error) {
	// Via the identifier rule rather than a private copy of it: the value being
	// derived from and the value being compared must be judged the same way, or
	// one of the two eventually accepts something the other does not.
	normalized, err := NormalizeResourceIdentifier(resourceURL)
	if err != nil {
		return "", err
	}
	return deriveProtectedResourceURL(normalized)
}

// deriveProtectedResourceURL applies the §3.1 derivation to an identifier already
// known to satisfy NormalizeResourceIdentifier.
//
// Separate from the validation so a caller that has normalised once does not pay
// for it again — and, more to the point, so it is obvious that the second call
// cannot fail rather than leaving an unreachable error check to puzzle over.
func deriveProtectedResourceURL(normalized string) (string, error) {
	u, err := url.Parse(normalized)
	if err != nil {
		return "", err
	}
	// Only a *root* path is dropped: §3.1 removes the terminating slash following the
	// host component, which is the slash of "https://host/" and not the one in
	// "https://host/tenant/". Trimming any trailing slash would send two identifiers
	// this package's own comparison keeps distinct to one document.
	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}
	// Assembled from the *escaped* path, then re-parsed, so that an encoded
	// separator survives. Setting url.URL.Path alone would re-encode from the
	// decoded form and turn %2F into /, which silently merges two identifiers
	// that RFC 3986 keeps distinct — see NormalizeResourceIdentifier.
	derived, err := url.Parse(u.Scheme + "://" + u.Host + ProtectedResourcePath + path)
	if err != nil {
		return "", fmt.Errorf("derive metadata URL for %q: %w", normalized, err)
	}
	CarryQuery(derived, u)
	return derived.String(), nil
}

// CarryQuery copies src's query onto dst, including the case where the query is
// present but empty. A URL ending in a bare "?" records that in url.URL.ForceQuery,
// not in RawQuery, so copying RawQuery alone drops the delimiter — and `/tunnel?` and
// `/tunnel` are two request targets that a proxy or an origin server may route
// differently. Losing it would put a client's discovery and its token-cache key on a
// different resource from the one its WebSocket dial actually requests.
//
// Used by every reconstruction on this path — the client's derivation, this package's
// two, and the server's — so the rule has one definition rather than four.
func CarryQuery(dst, src *url.URL) {
	dst.RawQuery = src.RawQuery
	dst.ForceQuery = src.ForceQuery
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
// **The comparison is over the whole identifier, not just the origin**, as RFC 9728
// §3.3 requires. An origin-only comparison lets one host serving several protected
// resources hand a client asking about /a/tunnel a document describing /b/tunnel,
// whose authorization server and client ID the client would then adopt —
// impersonation between resources sharing a hostname, which is the case the
// requirement exists for. A deployment whose externally visible identifier differs
// from the one the request implies declares it with the server's --resource-url:
// that is configuration, not a reason to weaken the check for everyone.
//
// Only syntax-based normalisation is applied before comparing (RFC 3986 §6.2.2):
// scheme and host are case-folded and a redundant default port is dropped, because
// one side is built from an HTTP Host header and the other from a command-line
// URL. Path and query are compared verbatim.
func FetchProtectedResource(ctx context.Context, httpClient *http.Client, resourceURL string) (*ProtectedResource, error) {
	// Normalised once: the derivation and the comparison both need it, and doing
	// it twice left a second error check that could not fire.
	using, err := NormalizeResourceIdentifier(resourceURL)
	if err != nil {
		return nil, err
	}
	documentURL, err := deriveProtectedResourceURL(using)
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
	// The shape rule lives in authhttp: http or https, absolute, with a host. It
	// used to be re-implemented here, which is two definitions of one rule in a
	// package whose whole argument is that there should be one.
	u, err := authhttp.ParseAuthURL("resource identifier", rawURL)
	if err != nil {
		return "", err
	}
	// Refused rather than stripped: identifiers do not carry one, and silently
	// discarding part of a value that is about to be compared for equality is the
	// wrong instinct.
	//
	// **Both halves are needed, and the raw-string half is the one that is easy to
	// talk yourself out of.** url.Parse only populates Fragment from a literal "#",
	// so it is true that a non-empty Fragment implies a "#" was present — but the
	// converse is what this check is for, and it does not hold: a URL ending in a
	// bare "#" parses with Fragment == "" and leaves no other trace of the
	// delimiter. Note the asymmetry with the query, where a bare "?" does record
	// itself, in ForceQuery — CarryQuery is what preserves it, since an empty query
	// is kept where an empty fragment is refused. There is no ForceFragment, so
	// nothing here can lean on the same trick. Dropping the raw-string
	// test made "https://h/x#" normalise to "https://h/x" — the silent discarding
	// the paragraph above forbids — and made --resource-url accept it server-side.
	if u.Fragment != "" || strings.Contains(rawURL, "#") {
		return "", fmt.Errorf("resource identifier %q must not contain a fragment", rawURL)
	}
	scheme := strings.ToLower(u.Scheme)
	// Re-parsed from the escaped path so an encoded separator survives: assigning
	// Path would re-encode from the decoded form and lose it.
	normalized, err := url.Parse(scheme + "://" + authhttp.NormalizeAuthority(scheme, u) + u.EscapedPath())
	if err != nil {
		return "", fmt.Errorf("resource identifier %q could not be normalised: %w", rawURL, err)
	}
	CarryQuery(normalized, u)
	return normalized.String(), nil
}

// maxHintBytes and maxScopeBytes bound values that arrive in a metadata document
// and leave in an authorization URL — which is handed to the OS scheme dispatcher,
// not merely fetched. Both limits are far above any real value.
//
// maxHintBytes covers the client ID and the audience, which is why it is not named
// for either: it was maxHintBytes while bounding both, so the name described
// half its use.
const (
	maxHintBytes  = 256
	maxScopeBytes = 1024
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
	if len(clientID) > maxHintBytes {
		return fmt.Errorf("client ID exceeds %d bytes", maxHintBytes)
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
	if len(audience) > maxHintBytes {
		return fmt.Errorf("audience exceeds %d bytes", maxHintBytes)
	}
	for _, r := range audience {
		if unicode.IsControl(r) {
			return fmt.Errorf("audience contains a control character (%q)", r)
		}
	}
	return nil
}

// CheckDiscoveredURL holds a discovered URL to the rule a configured one gets —
// https unless the insecure override — on top of the shape and downgrade rules
// authhttp.CheckDiscoveredEndpoint already applies. Remote input is not judged more
// leniently than a flag.
func CheckDiscoveredURL(label, sourceURL, discoveredURL string, allowPlaintext bool) error {
	if err := authhttp.CheckConfiguredURL(label, discoveredURL, allowPlaintext); err != nil {
		return err
	}
	return authhttp.CheckDiscoveredEndpoint(label, sourceURL, discoveredURL)
}

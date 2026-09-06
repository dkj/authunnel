package tunnelserver

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"authunnel/internal/authmeta"
)

// tunnelResourcePath is the path of the resource this server protects, and so
// the path component of the resource identifier it publishes. The metadata
// document is about the tunnel endpoint, not about the server as a whole.
const tunnelResourcePath = "/protected/tunnel"

// challengeRealm satisfies RFC 6750 §3's requirement that a Bearer challenge carry at
// least one parameter, for the one case with nothing else to say. It is a label, not a
// scope: this server has exactly one protected resource.
const challengeRealm = "authunnel"

// ResourceMetadataConfig turns on RFC 9728 protected-resource metadata and
// carries what the document says. A nil *ResourceMetadataConfig in
// HandlerOptions disables the document and the resource_metadata parameter that points
// at it. The Bearer challenge itself is not optional — see bearerChallenge.
//
// Everything here except the hints is already required configuration: a server
// that validates tokens knows its issuer. The hints exist so a client needs no
// OIDC configuration of its own, and each maps onto exactly one client flag —
// see the field comments on authmeta.ProtectedResource, which is where the wire
// format lives.
//
// What publishing this costs: the issuer URL, and any hints set, become readable
// by unauthenticated callers. Scope that honestly — any client that can obtain a
// token already knows the issuer, and a public client ID is not a credential —
// but it is a change from a server that revealed neither, which is why the
// operator gets a switch.
type ResourceMetadataConfig struct {
	// Issuer is published as the sole entry in authorization_servers.
	Issuer string
	// ResourceURL is the externally visible *base* identifier — scheme, host and path,
	// no query — published as `resource` after syntax normalisation with the requesting
	// client's query appended. Empty means derive the base from each request too, which
	// is correct whenever the path a client uses is the path this server sees.
	//
	// It exists for the case where that is false — a reverse proxy that strips a
	// path prefix — because the client compares `resource` against the identifier
	// it used and refuses a mismatch. That comparison is exact by requirement
	// (RFC 9728 §3.3), so a rewritten path has to be declared rather than
	// tolerated; tolerating it is what would let one host's resources impersonate
	// each other.
	ResourceURL string
	// AuthorizationServerMetadataURL tells a client where the authorization server's
	// own metadata document lives, for when the OIDC derivation cannot construct that
	// path. Empty means the client derives it, which is the common case.
	//
	// Filled from --client-oidc-metadata-url, else this server's own
	// --oidc-metadata-url; the two are separate because a server pinned to a JWKS
	// endpoint reads no metadata document itself while its clients still need one. See
	// serverConfig.ClientOIDCMetadataURL.
	AuthorizationServerMetadataURL string
	// ClientID, Audience, ResourceIndicator and DefaultScopes are the optional hints.
	ClientID          string
	Audience          string
	ResourceIndicator string
	DefaultScopes     []string
}

// Validate checks the hints at startup so a malformed value fails for the
// operator who typed it, rather than for every client that later reads it.
func (c *ResourceMetadataConfig) Validate() error {
	if c == nil {
		return nil
	}
	if c.Issuer == "" {
		return fmt.Errorf("resource metadata requires an issuer")
	}
	if c.ResourceURL != "" {
		// The identifier rule, which is where http(s) is required — a client
		// derives the metadata location from this value and fetches it over
		// HTTP, so any other scheme would have this server publish a document
		// nothing can retrieve. Deliberately not routed through
		// ProtectedResourceURL to "prove the derivation runs": that function is
		// built on this same rule and adds no rejection of its own, so the
		// indirection would be a distinction no test could detect.
		normalized, err := authmeta.NormalizeResourceIdentifier(c.ResourceURL)
		if err != nil {
			return fmt.Errorf("--resource-url: %w", err)
		}
		// The flag declares the external *base*; the query belongs to each request.
		// Accepting one here would make the published identifier depend on which of
		// two sources won, and a client whose tunnel URL carries a different query
		// would be refused by a value it had no way to predict.
		if u, err := url.Parse(normalized); err == nil && (u.RawQuery != "" || u.ForceQuery) {
			return fmt.Errorf("--resource-url must not carry a query (%q): it declares the externally visible base identifier, and the query is taken from each request", c.ResourceURL)
		}
	}
	if c.ClientID != "" {
		if err := authmeta.ValidateClientID(c.ClientID); err != nil {
			return fmt.Errorf("--client-id: %w", err)
		}
	}
	if len(c.DefaultScopes) > 0 {
		if err := authmeta.ValidateScopes(c.DefaultScopes); err != nil {
			return fmt.Errorf("--client-default-scopes: %w", err)
		}
	}
	if c.Audience != "" {
		if err := authmeta.ValidateAudience(c.Audience); err != nil {
			return fmt.Errorf("--client-audience: %w", err)
		}
	}
	if c.ResourceIndicator != "" {
		if err := authmeta.ValidateResourceIndicator(c.ResourceIndicator); err != nil {
			return fmt.Errorf("--client-resource: %w", err)
		}
	}
	return nil
}

// document builds the response for one request. See resourceIdentity for the one
// field that is not simply configuration read back.
func (c *ResourceMetadataConfig) document(r *http.Request, trustForwardedProto bool) authmeta.ProtectedResource {
	identifier, _ := c.resourceIdentity(r, trustForwardedProto)
	return authmeta.ProtectedResource{
		Resource:                       identifier,
		AuthorizationServers:           []string{c.Issuer},
		BearerMethodsSupported:         []string{"header"},
		DefaultScopes:                  c.DefaultScopes,
		ClientID:                       c.ClientID,
		AuthorizationServerMetadataURL: c.AuthorizationServerMetadataURL,
		Audience:                       c.Audience,
		ResourceIndicator:              c.ResourceIndicator,
	}
}

// resourceIdentity returns what this server calls itself and where the document
// describing it lives — as a pair, from one decision, because the two must agree. A
// document saying one thing while the challenge points at the document for another
// sends a client to a location it will then refuse.
//
// The base uses the same scheme/host helpers — and so the same X-Forwarded-* trust
// rules — as the WebSocket origin check. The Host header is
// caller-controlled, so a caller can make the document name an origin of its
// choosing, which is harmless because it affects only that caller's own response and
// the client compares the result against the identifier it actually used.
//
// The path is this server's own canonical tunnel path, not the one the caller asked
// about: paths are where distinct resources live, so reflecting a caller's path back
// would make the client's check agree with anything. The query *is* reflected,
// because this server attaches no meaning to it — it routes on path alone — so a
// query is opaque routing information belonging to whatever sits in front, and a
// client whose tunnel URL carries one is still talking about this same resource.
// Echoing it is what lets such a client validate at all; it weakens nothing, since
// the only value that can match is the one the client already had.
func (c *ResourceMetadataConfig) resourceIdentity(r *http.Request, trustForwardedProto bool) (identifier, metadataURL string) {
	// The base is what this resource is called: derived per request, or declared by
	// ResourceURL when a proxy rewrites the path out from under the derivation.
	base := url.URL{
		Scheme: requestScheme(r, trustForwardedProto),
		Host:   requestHost(r, trustForwardedProto),
		Path:   tunnelResourcePath,
	}
	if c.ResourceURL != "" {
		// Normalised, because a client normalises what it derives from its own
		// tunnel URL and the §3.3 comparison is exact. Syntax-based only, so the
		// path this flag exists to declare is untouched.
		if declared, err := authmeta.NormalizeResourceIdentifier(c.ResourceURL); err == nil {
			if parsed, err := url.Parse(declared); err == nil {
				base = *parsed
			}
		}
	}
	// One place attaches the query, below both branches: *whether* to attach it must
	// not depend on which branch produced the base. A query on ResourceURL is
	// overwritten rather than merged — Validate refuses one, and this keeps an
	// unvalidated config deterministic.
	authmeta.CarryQuery(&base, r.URL)
	// Normalised at the same single point, and for the same reason: a Host header's
	// spelling — case, or a redundant default port — must not decide whether the exact
	// §3.3 comparison succeeds, since the client normalises the identifier it compares.
	// The derivation below normalises regardless, so without this the published
	// `resource` and the location the challenge names disagree about one resource.
	rawIdentifier := base.String()
	identifier, err := authmeta.NormalizeResourceIdentifier(rawIdentifier)
	if err != nil {
		// A request whose effective host is missing or invalid, which includes a
		// trusted X-Forwarded-Host this server cannot parse — not only an absent Host
		// header. Publish what there is and omit the challenge parameter: there is no
		// location to name.
		return rawIdentifier, ""
	}

	// Via the same §3.1 rule the client uses, rather than reimplemented here. It
	// re-normalises, so the only failures left are ones the check above already
	// excluded.
	derived, err := authmeta.ProtectedResourceURL(identifier)
	if err != nil {
		return identifier, ""
	}
	return identifier, derived
}

// challenge builds the RFC 6750 WWW-Authenticate value that points an
// unauthenticated caller at the document.
//
// It is not what the authunnel client uses: that client knows it is talking to an
// authunnel server and derives the well-known URL from its tunnel URL, which costs
// neither a deliberate 401 nor a hit on the pre-auth limiter. The header is here so
// the server is legible to any RFC 9728 client, and so an operator reading a failed
// request can see where the configuration was meant to come from. Do not replace the
// client's derivation with a probe for this header on the grounds that the header
// exists.
// bearerChallenge builds the RFC 6750 §3 challenge. Both parameters are optional and
// independent, which is the point: the *scheme* announcement is mandatory on every 401
// (RFC 9110 §11.6.1, and §3 requires it to name Bearer), while the two parameters
// describe circumstances that may or may not apply.
//
// errorCode is §3.1's `error`, omitted when no credential was presented — §3.1 says a
// challenge SHOULD NOT carry an error code then, since nothing was wrong with a token
// that was never sent — and set to invalid_token when one was presented and failed.
//
// metadataURL is the RFC 9728 §5.1 hint, omitted under --no-resource-metadata. Omitting
// it must not take the challenge with it: a 401 with no WWW-Authenticate at all is
// malformed, and a client keying its recovery on `error="invalid_token"` would be unable
// to tell a stale configuration from any other refusal.
func bearerChallenge(errorCode, metadataURL string) string {
	// The quoted-string form: RFC 6750 §3 auth-param values are quoted-string, and a
	// URL contains characters (":", "/") that are not valid tokens.
	var params []string
	if errorCode != "" {
		params = append(params, fmt.Sprintf("error=%q", errorCode))
	}
	if metadataURL != "" {
		params = append(params, fmt.Sprintf("resource_metadata=%q", metadataURL))
	}
	if len(params) == 0 {
		// RFC 6750 §3's ABNF is `challenge = "Bearer" RWS 1#param`, so the scheme
		// needs at least one parameter — a bare "Bearer" is legal under RFC 7235's
		// looser grammar but not under this one, and a strict client may reject it.
		// realm is the parameter §3 names for exactly this purpose, and it carries no
		// information a caller could not already infer.
		return `Bearer realm="` + challengeRealm + `"`
	}
	return "Bearer " + strings.Join(params, ", ")
}

func (c *ResourceMetadataConfig) challenge(r *http.Request, trustForwardedProto bool, errorCode string) string {
	_, metadataURL := c.resourceIdentity(r, trustForwardedProto)
	return bearerChallenge(errorCode, metadataURL)
}

// serveResourceMetadata answers the well-known request. Unauthenticated by
// design — a client needs this document precisely because it cannot yet
// authenticate.
func (c *ResourceMetadataConfig) serveResourceMetadata(w http.ResponseWriter, r *http.Request, trustForwardedProto bool) {
	document := c.document(r, trustForwardedProto)
	body, err := json.Marshal(document)
	if err != nil {
		loggerFromContext(r.Context()).Error("resource_metadata_marshal_failed", slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Small, public, and cheap to regenerate, but a client fetches it on every
	// login rather than every invocation, so a short cache lifetime saves nothing
	// worth the staleness after an operator changes a hint.
	w.Header().Set("Cache-Control", "no-store")
	// The GET patterns this is registered under also match HEAD, per Go's mux.
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(body)
}

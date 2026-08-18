package tunnelserver

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"authunnel/internal/authmeta"
)

// tunnelResourcePath is the path of the resource this server protects, and so
// the path component of the resource identifier it publishes. The metadata
// document is about the tunnel endpoint, not about the server as a whole.
const tunnelResourcePath = "/protected/tunnel"

// ResourceMetadataConfig turns on RFC 9728 protected-resource metadata and
// carries what the document says. A nil *ResourceMetadataConfig in
// HandlerOptions disables both the document and the WWW-Authenticate challenge
// that points at it.
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
	// ResourceURL is the externally visible resource identifier, published
	// verbatim as `resource`. Empty means derive it from each request, which is
	// correct whenever the path a client uses is the path this server sees.
	//
	// It exists for the case where that is false — a reverse proxy that strips a
	// path prefix — because the client compares `resource` against the identifier
	// it used and refuses a mismatch. That comparison is exact by requirement
	// (RFC 9728 §3.3), so a rewritten path has to be declared rather than
	// tolerated; tolerating it is what would let one host's resources impersonate
	// each other.
	ResourceURL string
	// AuthorizationServerMetadataURL is the server's own --oidc-metadata-url,
	// published so a client reaches the same document rather than deriving a
	// path that does not exist. Empty when the server used the derived path,
	// in which case the client derives it too.
	AuthorizationServerMetadataURL string
	// ClientID, Audience, ResourceIndicator and Scopes are the optional hints.
	ClientID          string
	Audience          string
	ResourceIndicator string
	Scopes            []string
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
		if _, err := authmeta.NormalizeResourceIdentifier(c.ResourceURL); err != nil {
			return fmt.Errorf("--resource-url: %w", err)
		}
	}
	if c.ClientID != "" {
		if err := authmeta.ValidateClientID(c.ClientID); err != nil {
			return fmt.Errorf("--client-id: %w", err)
		}
	}
	if len(c.Scopes) > 0 {
		if err := authmeta.ValidateScopes(c.Scopes); err != nil {
			return fmt.Errorf("--client-scopes: %w", err)
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
		ScopesSupported:                c.Scopes,
		ClientID:                       c.ClientID,
		AuthorizationServerMetadataURL: c.AuthorizationServerMetadataURL,
		Audience:                       c.Audience,
		ResourceIndicator:              c.ResourceIndicator,
	}
}

// resourceIdentity returns what this server calls itself and where the document
// describing it lives — as a pair, from one decision, because the two must agree.
//
// They did not. The document published ResourceURL verbatim while the challenge
// used it only if the §3.1 derivation succeeded, falling back to the
// request-derived URL otherwise. Validate() makes that unreachable for the server
// binary, but NewHandler does not call Validate, so a caller constructing this
// directly got a document saying one thing and a challenge pointing at the document
// for another — and a client following the challenge would land on a document
// describing a resource it is not using, and refuse it. Deriving both from one
// branch removes the possibility rather than documenting it.
//
// The declared identifier is used only when a metadata location can actually be
// derived from it. That is not defence in depth: it is what lets the two values
// stay consistent when the config was never validated.
//
// Derived per request otherwise, using the same scheme/host helpers — and so the
// same X-Forwarded-* trust rules — as the WebSocket origin check. The Host header is
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
	if c.ResourceURL != "" {
		if derived, err := authmeta.ProtectedResourceURL(c.ResourceURL); err == nil {
			return c.ResourceURL, derived
		}
	}
	requested := url.URL{
		Scheme:   requestScheme(r, trustForwardedProto),
		Host:     requestHost(r, trustForwardedProto),
		Path:     tunnelResourcePath,
		RawQuery: r.URL.RawQuery,
	}
	document := requested
	document.Path = authmeta.ProtectedResourcePath + tunnelResourcePath
	return requested.String(), document.String()
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
func (c *ResourceMetadataConfig) challenge(r *http.Request, trustForwardedProto bool) string {
	_, metadataURL := c.resourceIdentity(r, trustForwardedProto)
	// The quoted-string form: RFC 6750 §3 auth-param values are quoted-string, and a
	// URL contains characters (":", "/") that are not valid tokens.
	return fmt.Sprintf("Bearer resource_metadata=%q", metadataURL)
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

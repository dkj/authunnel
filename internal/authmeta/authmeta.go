// Package authmeta fetches the two metadata documents authunnel reads: the
// authorization server's own metadata (RFC 8414 / OpenID Connect Discovery) and
// the protected-resource metadata a resource server publishes about itself
// (RFC 9728).
//
// It is the caller of internal/authhttp's transport policy rather than an
// extension of it. authhttp answers "may this URL be used, and may this
// connection be followed"; this package answers "what does the document at that
// URL say". Keeping them apart is what stops authhttp becoming the package where
// everything auth-shaped lands.
package authmeta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"authunnel/internal/authhttp"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// maxDocumentBytes caps a metadata response before it is parsed. Both documents
// are small — a generous OpenID Connect discovery document is a few kilobytes —
// and neither is authenticated at the point it is read, so an unbounded
// io.ReadAll here would let any host the client is pointed at consume memory
// until it fails. The cap is far above any legitimate document and far below
// anything that matters.
const maxDocumentBytes = 512 * 1024

// errorBodyBytes bounds how much of a non-200 body appears in the error. Enough
// for a provider's JSON error object, little enough that a hostile endpoint
// cannot use our log output as a writeable buffer.
const errorBodyBytes = 512

// FetchAuthorizationServer retrieves and validates an authorization server's
// metadata document.
//
// Exactly one of issuer and metadataURL must locate the document, and both may
// be supplied:
//
//   - metadataURL empty: the well-known path is derived from issuer, the OpenID
//     Connect Discovery default. The document was then fetched from the issuer's
//     own host, which is a real binding — the origin is authenticated, not
//     merely claimed.
//   - metadataURL set: the document is fetched from there. Where issuer is also
//     set the two are compared, which catches an honest wrong URL (staging for
//     production, one tenant for another) because a legitimate authorization
//     server declares its own issuer. It is not a defence against a hostile
//     URL: the document asserts that field about itself, so anything can echo
//     the expected value.
//   - metadataURL set and issuer empty: the declared issuer is adopted. The
//     comparison above is given up along with it, so a metadata URL pointing at
//     the wrong tenant is discovered as "correct" and fails later, after a
//     browser login. That is the trade the caller makes by not configuring an
//     issuer; it is not a check this function can perform on their behalf.
//
// The returned document's Issuer is always non-empty, so a caller that supplied
// no issuer can adopt it unconditionally.
//
// A mismatch is reported as oidc.ErrIssuerInvalid and a fetch or parse failure
// as oidc.ErrDiscoveryFailed, matching the identities zitadel's own
// client.Discover returns — callers and tests key on them.
func FetchAuthorizationServer(ctx context.Context, httpClient *http.Client, issuer, metadataURL string) (*oidc.DiscoveryConfiguration, error) {
	documentURL := metadataURL
	if documentURL == "" {
		if issuer == "" {
			return nil, errors.New("authorization server metadata needs an issuer or a metadata URL")
		}
		documentURL = strings.TrimSuffix(issuer, "/") + oidc.DiscoveryEndpoint
	}

	document := new(oidc.DiscoveryConfiguration)
	if err := fetchDocument(ctx, httpClient, "authorization server metadata URL", documentURL, document); err != nil {
		if errors.Is(err, authhttp.ErrUnsafeTransport) {
			// A refusal is not a discovery failure: joining
			// ErrDiscoveryFailed onto it would tell a caller keying on
			// "retrying cannot help" that the issuer was merely
			// unreachable. Return it with its own identity intact.
			return nil, err
		}
		return nil, errors.Join(oidc.ErrDiscoveryFailed, err)
	}
	if document.Issuer == "" {
		return nil, errors.Join(oidc.ErrDiscoveryFailed,
			fmt.Errorf("metadata document at %s declares no issuer", documentURL))
	}
	if issuer != "" && document.Issuer != issuer {
		// %q on both: the second is a string this document chose, and a value that
		// reaches a terminal or a log without having been through url.Parse can
		// carry escape sequences. Quoting the first too keeps a comparison
		// message symmetrical.
		return nil, fmt.Errorf("%w: expected: %q, got: %q", oidc.ErrIssuerInvalid, issuer, document.Issuer)
	}
	return document, nil
}

// localStatus describes a response using only values this process owns: the numeric
// code, and the reason phrase Go's own table gives for it.
func localStatus(code int) string {
	if text := http.StatusText(code); text != "" {
		return fmt.Sprintf("%d %s", code, text)
	}
	return fmt.Sprintf("%d", code)
}

// fetchDocument GETs a JSON metadata document under the package's transport
// rules: a validated http(s) URL, a client that refuses to be redirected off
// https, and a bounded body.
//
// The redirect guards are applied here even though every current caller passes an
// already-guarded client. A guarantee that depends on the caller having wrapped
// its client is not a guarantee, and double-wrapping is harmless — the outer
// policy checks, then delegates to the inner one, which checks again.
func fetchDocument(ctx context.Context, httpClient *http.Client, label, documentURL string, into any) error {
	if err := authhttp.CheckEndpointURL(label, documentURL); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, documentURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")

	// Both policies: the document may not be fetched over a downgraded transport,
	// and may not come from an origin other than the one asked. The second is what
	// makes "this document came from that origin" true after redirects as well as
	// before them — a check on where a fetch begins pins nothing if the fetch may
	// end elsewhere.
	response, err := authhttp.RefuseTransportDowngrade(authhttp.PinRedirectOrigin(httpClient)).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(response.Body, errorBodyBytes))
		// Three values, three different treatments, none of them incidental.
		//
		// The status is rebuilt from the numeric code and *local* StatusText rather
		// than taken from response.Status, which carries the HTTP/1 reason phrase
		// verbatim — Go's parser passes control bytes there straight through, so a
		// custom endpoint can put an escape sequence in what looks like the least
		// attacker-influenced part of the message. The code is the only part a
		// client should act on anyway.
		//
		// The body is quoted: bounded already, which limits how *much* an
		// unauthenticated party can put in front of an operator but not *what*.
		//
		// documentURL needs neither, having come through url.Parse, which refuses
		// control characters outright.
		return fmt.Errorf("GET %s: %s: %q", documentURL, localStatus(response.StatusCode), strings.TrimSpace(string(snippet)))
	}
	// LimitReader is given one byte more than the cap so a document exactly at
	// the limit is accepted and one byte over is detectable, rather than being
	// silently truncated into a document that happens to parse.
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDocumentBytes+1))
	if err != nil {
		return fmt.Errorf("read %s: %w", documentURL, err)
	}
	if len(body) > maxDocumentBytes {
		return fmt.Errorf("metadata document at %s exceeds %d bytes", documentURL, maxDocumentBytes)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("parse metadata document at %s: %w", documentURL, err)
	}
	return nil
}

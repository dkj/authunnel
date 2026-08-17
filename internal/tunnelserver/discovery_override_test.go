package tunnelserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// oidcWellKnownPath is the path client.Discover derives from the issuer. An
// authorization server that publishes RFC 8414 metadata instead puts the
// well-known segment *before* any path component, which is why the derivation
// cannot reach it and --oidc-metadata-url exists.
const oidcWellKnownPath = "/.well-known/openid-configuration"

type fakeIssuerConfig struct {
	// metadataPaths are the paths that serve the metadata document. Any
	// other path 404s, so a test can prove the derived path is unreachable.
	metadataPaths []string
	// advertisedIssuer overrides the `issuer` claim in the document. Empty
	// means the issuer's own URL, i.e. a correctly configured server.
	advertisedIssuer string
	// metadataStatus, when non-zero, makes every metadata path fail with
	// this status instead of serving a document.
	metadataStatus int
	// rfc8414Shape emits only the fields a pure OAuth2 authorization server
	// publishes, with none of the OIDC-specific extras.
	rfc8414Shape bool
	// useTLS serves over https, so downgrade rules apply.
	useTLS bool
	// jwksURIOverride replaces the advertised jwks_uri, letting a test point
	// the key fetch at a different scheme or host.
	jwksURIOverride string
	// jwksRedirectTo, when set, makes /keys redirect there instead of
	// serving the key set.
	jwksRedirectTo string
}

type fakeIssuer struct {
	URL          string
	server       *httptest.Server
	privateKey   *rsa.PrivateKey
	keyID        string
	metadataHits atomic.Int64
}

// newFakeIssuer starts an authorization server that serves a JWKS at /keys and
// its metadata document at the configured paths.
func newFakeIssuer(t *testing.T, cfg fakeIssuerConfig) *fakeIssuer {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	fake := &fakeIssuer{privateKey: privateKey, keyID: "test-key"}

	metadataPaths := make(map[string]bool, len(cfg.metadataPaths))
	for _, p := range cfg.metadataPaths {
		metadataPaths[p] = true
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/keys":
			if cfg.jwksRedirectTo != "" {
				http.Redirect(w, r, cfg.jwksRedirectTo, http.StatusFound)
				return
			}
			writeDiscoveryTestJSON(t, w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key:       &privateKey.PublicKey,
				KeyID:     fake.keyID,
				Algorithm: string(jose.RS256),
				Use:       "sig",
			}}})
		case metadataPaths[r.URL.Path]:
			fake.metadataHits.Add(1)
			if cfg.metadataStatus != 0 {
				http.Error(w, "metadata unavailable", cfg.metadataStatus)
				return
			}
			issuer := cfg.advertisedIssuer
			if issuer == "" {
				issuer = fake.URL
			}
			jwksURI := cfg.jwksURIOverride
			if jwksURI == "" {
				jwksURI = fake.URL + "/keys"
			}
			doc := map[string]any{
				"issuer":                 issuer,
				"jwks_uri":               jwksURI,
				"authorization_endpoint": fake.URL + "/authorize",
				"token_endpoint":         fake.URL + "/token",
			}
			if !cfg.rfc8414Shape {
				doc["userinfo_endpoint"] = fake.URL + "/userinfo"
				doc["subject_types_supported"] = []string{"public"}
				doc["id_token_signing_alg_values_supported"] = []string{"RS256"}
			}
			writeDiscoveryTestJSON(t, w, doc)
		default:
			http.NotFound(w, r)
		}
	})
	if cfg.useTLS {
		fake.server = httptest.NewTLSServer(handler)
	} else {
		fake.server = httptest.NewServer(handler)
	}
	t.Cleanup(fake.server.Close)
	fake.URL = fake.server.URL
	return fake
}

func (f *fakeIssuer) jwksURI() string { return f.URL + "/keys" }

// signToken mints an access token that should pass validation against this
// issuer for the given audience.
func (f *fakeIssuer) signToken(t *testing.T, audience string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: f.privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", f.keyID),
	)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	now := time.Now().UTC()
	claims := &oidc.AccessTokenClaims{
		TokenClaims: oidc.TokenClaims{
			Issuer:     f.URL,
			Subject:    "test-user",
			Audience:   oidc.Audience{audience},
			Expiration: oidc.FromTime(now.Add(time.Hour)),
			IssuedAt:   oidc.FromTime(now),
			NotBefore:  oidc.FromTime(now),
		},
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

func writeDiscoveryTestJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode JSON: %v", err)
	}
}

// newPlaintextJWKSMirror serves src's key set over plain http. Tests use it as
// a redirect target so the *only* thing wrong with the key fetch is the
// transport — the keys themselves are correct, so a test that fails here has
// caught the downgrade rather than a missing key.
func newPlaintextJWKSMirror(t *testing.T, src *fakeIssuer) string {
	t.Helper()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeDiscoveryTestJSON(t, w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &src.privateKey.PublicKey,
			KeyID:     src.keyID,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}}})
	}))
	t.Cleanup(mirror.Close)
	return mirror.URL + "/keys"
}

// TestHTTPSMetadataRejectsPlaintextJWKS covers the downgrade an https metadata
// document can otherwise force: it names the JWKS endpoint, so without a check
// it can send the key fetch to plaintext, where a network attacker can
// substitute signing keys and mint tokens that verify.
func TestHTTPSMetadataRejectsPlaintextJWKS(t *testing.T) {
	issuer := newFakeIssuer(t, fakeIssuerConfig{useTLS: true, metadataPaths: []string{oidcWellKnownPath}})
	plaintextJWKS := newPlaintextJWKSMirror(t, issuer)
	downgraded := newFakeIssuer(t, fakeIssuerConfig{
		useTLS:          true,
		metadataPaths:   []string{oidcWellKnownPath},
		jwksURIOverride: plaintextJWKS,
	})

	_, _, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:     downgraded.URL,
		Audience:   "test-aud",
		HTTPClient: downgraded.server.Client(),
	})
	if err == nil {
		t.Fatal("expected an https metadata document advertising a plaintext jwks_uri to be rejected")
	}
	if !strings.Contains(err.Error(), "non-https jwks_uri") {
		t.Fatalf("error = %v, want the jwks_uri scheme check", err)
	}
}

// TestHTTPSMetadataAcceptsHTTPSJWKS is the control for the test above: the same
// TLS setup with an https jwks_uri must still work, so the rejection there is
// attributable to the scheme and not to TLS handling in general.
func TestHTTPSMetadataAcceptsHTTPSJWKS(t *testing.T) {
	issuer := newFakeIssuer(t, fakeIssuerConfig{useTLS: true, metadataPaths: []string{oidcWellKnownPath}})

	validator, mode, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:     issuer.URL,
		Audience:   "test-aud",
		HTTPClient: issuer.server.Client(),
	})
	if err != nil {
		t.Fatalf("create validator over https: %v", err)
	}
	if mode != DiscoveryModeDerived {
		t.Fatalf("discovery mode = %q, want %q", mode, DiscoveryModeDerived)
	}
	if _, err := validator.ValidateAccessToken(context.Background(), issuer.signToken(t, "test-aud")); err != nil {
		t.Fatalf("validate token: %v", err)
	}
}

// TestJWKSRedirectDowngradeIsRefused covers the second half of the same
// exposure: the advertised jwks_uri passes the scheme check, then redirects to
// plaintext. Go follows cross-scheme redirects silently, so this needs its own
// guard rather than falling out of the URL check.
func TestJWKSRedirectDowngradeIsRefused(t *testing.T) {
	issuer := newFakeIssuer(t, fakeIssuerConfig{useTLS: true, metadataPaths: []string{oidcWellKnownPath}})
	mirror := newPlaintextJWKSMirror(t, issuer)

	redirecting := newFakeIssuer(t, fakeIssuerConfig{
		useTLS:         true,
		metadataPaths:  []string{oidcWellKnownPath},
		jwksRedirectTo: mirror,
	})

	// Discovery succeeds: the advertised jwks_uri is https. The downgrade
	// only appears when the key set is actually fetched.
	validator, _, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:     redirecting.URL,
		Audience:   "test-aud",
		HTTPClient: redirecting.server.Client(),
	})
	if err != nil {
		t.Fatalf("create validator: %v", err)
	}
	_, err = validator.ValidateAccessToken(context.Background(), redirecting.signToken(t, "test-aud"))
	if err == nil {
		t.Fatal("expected a jwks fetch redirected from https to http to be refused")
	}
	if !strings.Contains(err.Error(), "transport downgrade") {
		t.Fatalf("error = %v, want the redirect downgrade guard", err)
	}
}

// TestPlaintextMetadataAllowsPlaintextJWKS documents that the rule is about
// *downgrade*, not about https absolutely: an issuer already served over http
// — the local development setup the config layer gates behind
// --insecure-oidc-issuer — has no downgrade left to prevent.
func TestPlaintextMetadataAllowsPlaintextJWKS(t *testing.T) {
	issuer := newFakeIssuer(t, fakeIssuerConfig{metadataPaths: []string{oidcWellKnownPath}})

	validator, _, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:     issuer.URL,
		Audience:   "test-aud",
		HTTPClient: issuer.server.Client(),
	})
	if err != nil {
		t.Fatalf("plaintext development issuer should still work: %v", err)
	}
	if _, err := validator.ValidateAccessToken(context.Background(), issuer.signToken(t, "test-aud")); err != nil {
		t.Fatalf("validate token: %v", err)
	}
}

// TestInjectedRedirectPolicyIsPreserved covers the composition contract: the
// downgrade guard layers on top of a caller's own redirect policy instead of
// replacing it. A caller that refuses redirects must not start following them
// merely because its client was passed to the validator.
func TestInjectedRedirectPolicyIsPreserved(t *testing.T) {
	// Redirect to another https endpoint, so the downgrade guard has no
	// reason to fire — only the caller's own policy can reject this.
	sameSchemeTarget := newFakeIssuer(t, fakeIssuerConfig{useTLS: true, metadataPaths: []string{oidcWellKnownPath}})
	redirecting := newFakeIssuer(t, fakeIssuerConfig{
		useTLS:         true,
		metadataPaths:  []string{oidcWellKnownPath},
		jwksRedirectTo: sameSchemeTarget.URL + "/keys",
	})

	callerClient := redirecting.server.Client()
	callerClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("caller policy: redirects are not permitted")
	}

	validator, _, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:     redirecting.URL,
		Audience:   "test-aud",
		HTTPClient: callerClient,
	})
	if err != nil {
		t.Fatalf("create validator: %v", err)
	}
	_, err = validator.ValidateAccessToken(context.Background(), redirecting.signToken(t, "test-aud"))
	if err == nil {
		t.Fatal("expected the caller's redirect policy to still reject the jwks redirect")
	}
	if !strings.Contains(err.Error(), "caller policy") {
		t.Fatalf("error = %v, want the caller's own policy to have been consulted", err)
	}
}

// TestMetadataURLReachesNonDerivedPath covers the interop gap the flag exists
// for: an authorization server whose metadata sits at a path the OIDC
// derivation cannot construct.
func TestMetadataURLReachesNonDerivedPath(t *testing.T) {
	const tenantPath = "/.well-known/oauth-authorization-server/tenant1"
	issuer := newFakeIssuer(t, fakeIssuerConfig{metadataPaths: []string{tenantPath}})

	// Without the override the derived path 404s, so startup fails.
	if _, _, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:     issuer.URL,
		Audience:   "test-aud",
		HTTPClient: issuer.server.Client(),
	}); err == nil {
		t.Fatal("expected discovery to fail when metadata is not at the derived path")
	}

	validator, mode, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:      issuer.URL,
		Audience:    "test-aud",
		MetadataURL: issuer.URL + tenantPath,
		HTTPClient:  issuer.server.Client(),
	})
	if err != nil {
		t.Fatalf("create validator with metadata URL: %v", err)
	}
	if mode != DiscoveryModeMetadataURL {
		t.Fatalf("discovery mode = %q, want %q", mode, DiscoveryModeMetadataURL)
	}
	if _, err := validator.ValidateAccessToken(context.Background(), issuer.signToken(t, "test-aud")); err != nil {
		t.Fatalf("validate token: %v", err)
	}
}

// TestMetadataURLRejectsIssuerMismatch is the load-bearing security test for
// the override: an operator may choose where metadata is fetched from, but the
// document must still self-identify as the configured issuer. Without this, a
// metadata URL pointing at another authorization server would silently rebind
// the server to that server's keys.
func TestMetadataURLRejectsIssuerMismatch(t *testing.T) {
	const tenantPath = "/.well-known/oauth-authorization-server/tenant1"
	issuer := newFakeIssuer(t, fakeIssuerConfig{
		metadataPaths:    []string{tenantPath},
		advertisedIssuer: "https://attacker.example",
	})

	_, _, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:      issuer.URL,
		Audience:    "test-aud",
		MetadataURL: issuer.URL + tenantPath,
		HTTPClient:  issuer.server.Client(),
	})
	if err == nil {
		t.Fatal("expected a metadata document advertising a different issuer to be rejected")
	}
	// Assert the specific cause rather than any error: a network or parse
	// failure would also produce a non-nil error here and would make this
	// test pass while the binding check was gone.
	if !errors.Is(err, oidc.ErrIssuerInvalid) {
		t.Fatalf("error = %v, want it to be %v (the issuer binding check)", err, oidc.ErrIssuerInvalid)
	}
}

// TestMetadataURLAcceptsRFC8414ShapedDocument confirms a pure OAuth2 metadata
// document — no OIDC-specific fields — carries everything the server needs.
func TestMetadataURLAcceptsRFC8414ShapedDocument(t *testing.T) {
	const asPath = "/.well-known/oauth-authorization-server"
	issuer := newFakeIssuer(t, fakeIssuerConfig{
		metadataPaths: []string{asPath},
		rfc8414Shape:  true,
	})

	validator, mode, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:      issuer.URL,
		Audience:    "test-aud",
		MetadataURL: issuer.URL + asPath,
		HTTPClient:  issuer.server.Client(),
	})
	if err != nil {
		t.Fatalf("create validator from RFC 8414 document: %v", err)
	}
	if mode != DiscoveryModeMetadataURL {
		t.Fatalf("discovery mode = %q, want %q", mode, DiscoveryModeMetadataURL)
	}
	if _, err := validator.ValidateAccessToken(context.Background(), issuer.signToken(t, "test-aud")); err != nil {
		t.Fatalf("validate token: %v", err)
	}
}

// TestPinnedJWKSSkipsDiscovery asserts the pinned path never asks for metadata
// at all — that absence is the whole point of the flag, so assert on the
// request count rather than only on the happy path working.
func TestPinnedJWKSSkipsDiscovery(t *testing.T) {
	issuer := newFakeIssuer(t, fakeIssuerConfig{metadataPaths: []string{oidcWellKnownPath}})

	validator, mode, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:     issuer.URL,
		Audience:   "test-aud",
		JWKSURI:    issuer.jwksURI(),
		HTTPClient: issuer.server.Client(),
	})
	if err != nil {
		t.Fatalf("create validator with pinned JWKS: %v", err)
	}
	if mode != DiscoveryModePinnedJWKS {
		t.Fatalf("discovery mode = %q, want %q", mode, DiscoveryModePinnedJWKS)
	}
	if _, err := validator.ValidateAccessToken(context.Background(), issuer.signToken(t, "test-aud")); err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if hits := issuer.metadataHits.Load(); hits != 0 {
		t.Fatalf("metadata endpoint received %d requests, want 0", hits)
	}
}

// TestPinnedJWKSStartsWithMetadataUnavailable covers the operational reason
// for the flag: the server comes up even when the issuer cannot serve its
// metadata document.
func TestPinnedJWKSStartsWithMetadataUnavailable(t *testing.T) {
	issuer := newFakeIssuer(t, fakeIssuerConfig{
		metadataPaths:  []string{oidcWellKnownPath},
		metadataStatus: http.StatusInternalServerError,
	})

	validator, _, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:     issuer.URL,
		Audience:   "test-aud",
		JWKSURI:    issuer.jwksURI(),
		HTTPClient: issuer.server.Client(),
	})
	if err != nil {
		t.Fatalf("pinned JWKS should not depend on metadata availability: %v", err)
	}
	if _, err := validator.ValidateAccessToken(context.Background(), issuer.signToken(t, "test-aud")); err != nil {
		t.Fatalf("validate token: %v", err)
	}
}

// TestPinnedJWKSStillEnforcesIssuer pins the invariant that the overrides
// replace metadata *location* only. With no document to cross-check, the `iss`
// claim check is the only thing binding accepted tokens to an issuer.
func TestPinnedJWKSStillEnforcesIssuer(t *testing.T) {
	issuer := newFakeIssuer(t, fakeIssuerConfig{metadataPaths: []string{oidcWellKnownPath}})

	validator, _, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:     "https://expected-issuer.example",
		Audience:   "test-aud",
		JWKSURI:    issuer.jwksURI(),
		HTTPClient: issuer.server.Client(),
	})
	if err != nil {
		t.Fatalf("create validator: %v", err)
	}
	// The token is signed by a key in the pinned JWKS, but carries the fake
	// issuer's URL as `iss` rather than the configured issuer.
	if _, err := validator.ValidateAccessToken(context.Background(), issuer.signToken(t, "test-aud")); err == nil {
		t.Fatal("expected a token whose iss differs from the configured issuer to be rejected")
	}
}

func TestValidatorRejectsBothDiscoveryOverrides(t *testing.T) {
	issuer := newFakeIssuer(t, fakeIssuerConfig{metadataPaths: []string{oidcWellKnownPath}})

	_, _, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:      issuer.URL,
		Audience:    "test-aud",
		MetadataURL: issuer.URL + oidcWellKnownPath,
		JWKSURI:     issuer.jwksURI(),
		HTTPClient:  issuer.server.Client(),
	})
	if err == nil {
		t.Fatal("expected metadata URL and JWKS URI together to be rejected")
	}
}

// TestDerivedDiscoveryUnchanged guards the default path: no overrides set
// behaves exactly as before and reports the derived mode.
func TestDerivedDiscoveryUnchanged(t *testing.T) {
	issuer := newFakeIssuer(t, fakeIssuerConfig{metadataPaths: []string{oidcWellKnownPath}})

	validator, mode, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:     issuer.URL,
		Audience:   "test-aud",
		HTTPClient: issuer.server.Client(),
	})
	if err != nil {
		t.Fatalf("create validator: %v", err)
	}
	if mode != DiscoveryModeDerived {
		t.Fatalf("discovery mode = %q, want %q", mode, DiscoveryModeDerived)
	}
	if _, err := validator.ValidateAccessToken(context.Background(), issuer.signToken(t, "test-aud")); err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if hits := issuer.metadataHits.Load(); hits != 1 {
		t.Fatalf("metadata endpoint received %d requests, want 1", hits)
	}
}

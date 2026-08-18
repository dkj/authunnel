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
	"sync"
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
	// metadataRedirectTo, when set, makes the metadata paths redirect there
	// instead of serving a document.
	metadataRedirectTo string
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
			if cfg.metadataRedirectTo != "" {
				http.Redirect(w, r, cfg.metadataRedirectTo, http.StatusFound)
				return
			}
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

// plaintextMirror records requests and serves content valid for the redirecting
// issuer, proving a refusal is caused by transport rather than fixture data.
type plaintextMirror struct {
	URL string

	mu       sync.Mutex
	requests int
	body     func(http.ResponseWriter)
}

func newPlaintextMirror(t *testing.T) *plaintextMirror {
	t.Helper()
	mirror := &plaintextMirror{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mirror.mu.Lock()
		mirror.requests++
		body := mirror.body
		mirror.mu.Unlock()
		if body == nil {
			t.Errorf("plaintext mirror reached before its body was assigned")
			http.Error(w, "not configured", http.StatusInternalServerError)
			return
		}
		body(w)
	}))
	t.Cleanup(server.Close)
	mirror.URL = server.URL + "/mirrored"
	return mirror
}

func (m *plaintextMirror) received() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests
}

func (m *plaintextMirror) serveJWKSOf(t *testing.T, src *fakeIssuer) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.body = func(w http.ResponseWriter) {
		writeDiscoveryTestJSON(t, w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &src.privateKey.PublicKey,
			KeyID:     src.keyID,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}}})
	}
}

func (m *plaintextMirror) serveMetadataFor(t *testing.T, src *fakeIssuer) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.body = func(w http.ResponseWriter) {
		writeDiscoveryTestJSON(t, w, map[string]any{
			"issuer":                 src.URL,
			"jwks_uri":               src.URL + "/keys",
			"authorization_endpoint": src.URL + "/authorize",
			"token_endpoint":         src.URL + "/token",
		})
	}
}

// Metadata redirects must not leave HTTPS.
func TestMetadataRedirectDowngradeIsRefused(t *testing.T) {
	mirror := newPlaintextMirror(t)
	redirecting := newFakeIssuer(t, fakeIssuerConfig{
		useTLS:             true,
		metadataPaths:      []string{oidcWellKnownPath},
		metadataRedirectTo: mirror.URL,
	})
	mirror.serveMetadataFor(t, redirecting)

	_, _, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:     redirecting.URL,
		Audience:   "test-aud",
		HTTPClient: redirecting.server.Client(),
	})
	if err == nil {
		t.Fatal("expected a metadata fetch redirected from https to http to be refused")
	}
	if !strings.Contains(err.Error(), "transport downgrade") {
		t.Fatalf("error = %v, want the redirect downgrade guard", err)
	}
	if hits := mirror.received(); hits != 0 {
		t.Fatalf("plaintext metadata endpoint received %d request(s), want none", hits)
	}
}

// HTTPS metadata must not advertise a plaintext JWKS endpoint.
func TestHTTPSMetadataRejectsPlaintextJWKS(t *testing.T) {
	plaintextJWKS := newPlaintextMirror(t)
	downgraded := newFakeIssuer(t, fakeIssuerConfig{
		useTLS:          true,
		metadataPaths:   []string{oidcWellKnownPath},
		jwksURIOverride: plaintextJWKS.URL,
	})
	plaintextJWKS.serveJWKSOf(t, downgraded)

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

// Control: the same fixture works when JWKS remains on HTTPS.
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

// A JWKS redirect must be refused before the plaintext mirror is reached.
func TestJWKSRedirectDowngradeIsRefused(t *testing.T) {
	mirror := newPlaintextMirror(t)
	redirecting := newFakeIssuer(t, fakeIssuerConfig{
		useTLS:         true,
		metadataPaths:  []string{oidcWellKnownPath},
		jwksRedirectTo: mirror.URL,
	})
	mirror.serveJWKSOf(t, redirecting)

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
	if hits := mirror.received(); hits != 0 {
		t.Fatalf("plaintext JWKS endpoint received %d request(s), want none", hits)
	}
}

// The explicit development posture permits an all-HTTP issuer and JWKS.
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

// TestPlaintextMetadataRejectsNonHTTPJWKSURI closes the gap the downgrade check
// alone leaves: over an http metadata source nothing is a downgrade, so every
// scheme would otherwise pass. Failing here rather than inside the transport
// also turns an opaque "unsupported protocol scheme" at first-token time into a
// startup error naming the field.
func TestPlaintextMetadataRejectsNonHTTPJWKSURI(t *testing.T) {
	for _, tt := range []struct{ name, jwksURI, want string }{
		{name: "file scheme", jwksURI: "file:///etc/authunnel/jwks.json", want: `unsupported scheme "file"`},
		{name: "host-less", jwksURI: "https:relative-path", want: "absolute URL with a host"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			issuer := newFakeIssuer(t, fakeIssuerConfig{
				metadataPaths:   []string{oidcWellKnownPath},
				jwksURIOverride: tt.jwksURI,
			})

			_, _, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
				Issuer:     issuer.URL,
				Audience:   "test-aud",
				HTTPClient: issuer.server.Client(),
			})
			if err == nil {
				t.Fatalf("expected jwks_uri %q to be rejected", tt.jwksURI)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// TestPinnedJWKSURIIsValidated covers the same rule on the pinned path. The
// server's config layer checks this too, but the constructor is exported and
// must not rely on its caller having done so.
func TestPinnedJWKSURIIsValidated(t *testing.T) {
	issuer := newFakeIssuer(t, fakeIssuerConfig{metadataPaths: []string{oidcWellKnownPath}})

	_, _, err := NewJWTTokenValidator(context.Background(), JWTValidatorConfig{
		Issuer:     issuer.URL,
		Audience:   "test-aud",
		JWKSURI:    "file:///etc/authunnel/jwks.json",
		HTTPClient: issuer.server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), `unsupported scheme "file"`) {
		t.Fatalf("error = %v, want the pinned JWKS URI to be rejected by scheme", err)
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

// A legitimate but wrong metadata document is rejected by issuer comparison.
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
	if !errors.Is(err, oidc.ErrIssuerInvalid) {
		t.Fatalf("error = %v, want it to be %v (the issuer binding check)", err, oidc.ErrIssuerInvalid)
	}
}

// A pure RFC 8414 document carries everything the server needs.
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

// Pinned JWKS validates a token while the metadata endpoint is unavailable and
// without requesting it.
func TestPinnedJWKSSkipsDiscovery(t *testing.T) {
	issuer := newFakeIssuer(t, fakeIssuerConfig{
		metadataPaths:  []string{oidcWellKnownPath},
		metadataStatus: http.StatusServiceUnavailable,
	})

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

// A pinned key set does not relax the configured issuer claim.
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

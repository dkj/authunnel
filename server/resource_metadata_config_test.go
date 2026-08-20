package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"authunnel/internal/tunnelserver"
)

// metadataServerArgs reuses baseServerArgs from discovery_override_config_test.go
// but pins the issuer these tests assert on, so a change to that shared fixture
// cannot quietly invalidate them.
func metadataServerArgs(extra ...string) []string {
	return baseServerArgs(append([]string{"--oidc-issuer", testPublishedIssuer}, extra...)...)
}

const testPublishedIssuer = "https://idp.example/realms/main"

func TestResourceMetadataPublishedByDefault(t *testing.T) {
	cfg, err := parseServerConfig(metadataServerArgs(), func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}
	if cfg.NoResourceMetadata {
		t.Fatal("publishing must be the default; a feature both ends must opt into removes no configuration")
	}
	metadata := cfg.resourceMetadata()
	if metadata == nil {
		t.Fatal("resourceMetadata() = nil with publishing enabled")
	}
	if metadata.Issuer != testPublishedIssuer {
		t.Fatalf("published issuer = %q, want the configured one", metadata.Issuer)
	}
}

func TestResourceMetadataDisabledByFlag(t *testing.T) {
	cfg, err := parseServerConfig(metadataServerArgs("--no-resource-metadata"), func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}
	if cfg.resourceMetadata() != nil {
		t.Fatal("resourceMetadata() must be nil with --no-resource-metadata")
	}
}

func TestResourceMetadataDisabledByEnv(t *testing.T) {
	cfg, err := parseServerConfig(metadataServerArgs(), func(key string) string {
		if key == "NO_RESOURCE_METADATA" {
			return "true"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}
	if !cfg.NoResourceMetadata {
		t.Fatal("NO_RESOURCE_METADATA=true should disable publishing")
	}
}

func TestClientHintsReadFlagsAndEnv(t *testing.T) {
	cfg, err := parseServerConfig(metadataServerArgs(
		"--client-id", "authunnel-cli",
		"--client-default-scopes", "openid offline_access",
		"--client-audience", "https://api.example",
		"--client-resource", "https://tunnel.example",
	), func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}
	metadata := cfg.resourceMetadata()
	if metadata.ClientID != "authunnel-cli" {
		t.Fatalf("ClientID = %q", metadata.ClientID)
	}
	if strings.Join(metadata.DefaultScopes, " ") != "openid offline_access" {
		t.Fatalf("Scopes = %v", metadata.DefaultScopes)
	}
	if metadata.Audience != "https://api.example" || metadata.ResourceIndicator != "https://tunnel.example" {
		t.Fatalf("audience hints = %q / %q", metadata.Audience, metadata.ResourceIndicator)
	}

	env := map[string]string{
		"CLIENT_ID":             "env-cli",
		"CLIENT_DEFAULT_SCOPES": "openid",
		"CLIENT_AUDIENCE":       "https://env-api.example",
		"CLIENT_RESOURCE":       "https://env-tunnel.example",
	}
	cfg, err = parseServerConfig(metadataServerArgs(), func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("parseServerConfig with env: %v", err)
	}
	metadata = cfg.resourceMetadata()
	if metadata.ClientID != "env-cli" || strings.Join(metadata.DefaultScopes, " ") != "openid" {
		t.Fatalf("env hints not applied: %+v", metadata)
	}
	if metadata.Audience != "https://env-api.example" || metadata.ResourceIndicator != "https://env-tunnel.example" {
		t.Fatalf("env audience hints not applied: %+v", metadata)
	}
}

// TestPublishedMetadataURLDefaultsToTheServersOwn pins the ergonomics: one flag still
// covers the common case, where this server and its clients read the same document.
func TestPublishedMetadataURLDefaultsToTheServersOwn(t *testing.T) {
	const metadataURL = "https://idp.example/.well-known/oauth-authorization-server/tenant1"
	cfg, err := parseServerConfig(metadataServerArgs("--oidc-metadata-url", metadataURL), func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}
	if got := cfg.resourceMetadata().AuthorizationServerMetadataURL; got != metadataURL {
		t.Fatalf("published metadata URL = %q, want the server's own --oidc-metadata-url", got)
	}
}

// TestPublishedMetadataURLIsSeparatelySettable is the correction. The hint used to be
// cfg.OIDCMetadataURL verbatim, justified by "client and server read the same
// document, so a second value could only be set inconsistently" — a premise
// --oidc-jwks-uri breaks, since in that mode this server reads no metadata document at
// all. The two are different questions with different egress requirements.
func TestPublishedMetadataURLIsSeparatelySettable(t *testing.T) {
	const (
		serverSide = "https://idp.example/.well-known/oauth-authorization-server/server"
		clientSide = "https://idp.example/.well-known/oauth-authorization-server/clients"
	)
	cfg, err := parseServerConfig(metadataServerArgs(
		"--oidc-metadata-url", serverSide,
		"--client-oidc-metadata-url", clientSide,
	), func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}
	if got := cfg.resourceMetadata().AuthorizationServerMetadataURL; got != clientSide {
		t.Fatalf("published metadata URL = %q, want the client-facing value to win", got)
	}
	if cfg.OIDCMetadataURL != serverSide {
		t.Fatalf("OIDCMetadataURL = %q, want this server's own value untouched", cfg.OIDCMetadataURL)
	}
}

// TestPinnedJWKSCanStillPublishAMetadataURL is the configuration the old coupling made
// unexpressible, and the reason the split exists: a server isolated to the signing-key
// endpoint, still telling clients where the metadata document they need lives.
func TestPinnedJWKSCanStillPublishAMetadataURL(t *testing.T) {
	const clientSide = "https://idp.example/.well-known/oauth-authorization-server/tenant1"
	cfg, err := parseServerConfig(metadataServerArgs(
		"--oidc-jwks-uri", "https://keys.idp.example/jwks",
		"--client-oidc-metadata-url", clientSide,
	), func(string) string { return "" })
	if err != nil {
		t.Fatalf("pinned JWKS with a published metadata URL must be accepted: %v", err)
	}
	if got := cfg.resourceMetadata().AuthorizationServerMetadataURL; got != clientSide {
		t.Fatalf("published metadata URL = %q, want %q", got, clientSide)
	}
	if cfg.OIDCMetadataURL != "" {
		t.Fatalf("OIDCMetadataURL = %q, want it empty: publishing a hint must not give this server a document to fetch", cfg.OIDCMetadataURL)
	}
	// The mutual exclusion that remains is the one about *this* server's own fetch,
	// and it is still enforced.
	if _, err := parseServerConfig(metadataServerArgs(
		"--oidc-jwks-uri", "https://keys.idp.example/jwks",
		"--oidc-metadata-url", clientSide,
	), func(string) string { return "" }); err == nil {
		t.Fatal("--oidc-metadata-url with --oidc-jwks-uri must still be rejected")
	}
}

// TestPinnedJWKSNeverFetchesThePublishedMetadataURL is the isolation claim itself,
// end to end from the flags rather than inferred from two separate tests: configure
// pinned JWKS alongside a client-facing metadata URL, build the real validator, and
// assert the server made no request to that URL at all.
//
// Asserting the count rather than the config is the point. That the published value is
// not passed to NewJWTTokenValidator today is visible by reading `main`; that it is
// never *reached* is the property an operator writing an egress policy relies on, and
// only a counting endpoint can show it.
//
// A pinned-JWKS validator makes no startup request of any kind — keys are fetched
// lazily on the first token — so the fixture needs no signing material, and any
// request it records at all is a defect.
func TestPinnedJWKSNeverFetchesThePublishedMetadataURL(t *testing.T) {
	var requests atomic.Int64
	var paths []string
	var mu sync.Mutex
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		http.NotFound(w, r)
	}))
	defer idp.Close()

	cfg, err := parseServerConfig(metadataServerArgs(
		"--oidc-jwks-uri", idp.URL+"/keys",
		"--client-oidc-metadata-url", idp.URL+"/.well-known/oauth-authorization-server/tenant1",
	), func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}

	validator, mode, err := tunnelserver.NewJWTTokenValidator(context.Background(), tunnelserver.JWTValidatorConfig{
		Issuer:      cfg.Issuer,
		Audience:    cfg.TokenAudience,
		MetadataURL: cfg.OIDCMetadataURL,
		JWKSURI:     cfg.OIDCJWKSURI,
		HTTPClient:  idp.Client(),
	})
	if err != nil {
		t.Fatalf("create validator: %v", err)
	}
	if validator == nil {
		t.Fatal("validator is nil")
	}
	if mode != tunnelserver.DiscoveryModePinnedJWKS {
		t.Fatalf("discovery mode = %q, want %q", mode, tunnelserver.DiscoveryModePinnedJWKS)
	}
	if got := requests.Load(); got != 0 {
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("server made %d request(s) to the IdP (%v); pinned JWKS must reach neither the discovery host nor the client's metadata URL", got, paths)
	}
	// And the value it declined to fetch is still the one clients are told to use.
	if got := cfg.resourceMetadata().AuthorizationServerMetadataURL; got != idp.URL+"/.well-known/oauth-authorization-server/tenant1" {
		t.Fatalf("published metadata URL = %q, want the client-facing value", got)
	}
}

func TestPublishedMetadataURLReadsEnvAndIsValidated(t *testing.T) {
	const clientSide = "https://idp.example/meta"
	cfg, err := parseServerConfig(metadataServerArgs(), func(key string) string {
		if key == "CLIENT_OIDC_METADATA_URL" {
			return clientSide
		}
		return ""
	})
	if err != nil {
		t.Fatalf("parseServerConfig with env: %v", err)
	}
	if got := cfg.resourceMetadata().AuthorizationServerMetadataURL; got != clientSide {
		t.Fatalf("published metadata URL = %q, want the env value", got)
	}
	// Held to the same rule as the server's own URL, even though this process never
	// fetches it: publishing an unusable location to every client is worth refusing
	// where the operator can still see it.
	for _, bad := range []string{"http://idp.example/meta", "file:///etc/authunnel/meta.json", "not-a-url"} {
		_, err := parseServerConfig(metadataServerArgs("--client-oidc-metadata-url", bad), func(string) string { return "" })
		if err == nil {
			t.Fatalf("--client-oidc-metadata-url %q: expected rejection", bad)
		}
		if !strings.Contains(err.Error(), "--client-oidc-metadata-url") {
			t.Fatalf("error should name the flag to fix, got: %v", err)
		}
	}
}

// TestClientHintsRejectedWithoutPublishing catches a configuration that would
// silently do nothing: an operator who sets --client-id alongside
// --no-resource-metadata believes clients are being told something.
func TestClientHintsRejectedWithoutPublishing(t *testing.T) {
	for _, hint := range [][]string{
		{"--client-id", "authunnel-cli"},
		{"--client-default-scopes", "openid"},
		{"--client-audience", "https://api.example"},
		{"--client-resource", "https://tunnel.example"},
		// Publication-only, so with publishing off it can do nothing at all. Note
		// --oidc-metadata-url is deliberately absent from this list: that one also
		// drives this server's own validation, so it stays meaningful either way.
		{"--client-oidc-metadata-url", "https://idp.example/meta"},
	} {
		args := metadataServerArgs(append([]string{"--no-resource-metadata"}, hint...)...)
		_, err := parseServerConfig(args, func(string) string { return "" })
		if err == nil || !strings.Contains(err.Error(), "--no-resource-metadata") {
			t.Fatalf("%v with --no-resource-metadata: expected rejection, got %v", hint, err)
		}
		if !strings.Contains(err.Error(), hint[0]) {
			t.Fatalf("error should name the unpublishable hint, got: %v", err)
		}
	}
}

// TestMalformedClientHintsFailAtStartup keeps the good error where the operator
// is: a hint that no client could use must not wait to be refused by each of
// them in turn.
// A space in --client-id is deliberately *not* in this list: RFC 6749's *VSCHAR
// permits it, and the value is URL-encoded wherever it is used, so refusing it
// would reject a legal registration to catch a quoting mistake. A newline is the
// realistic copy-paste hazard and is refused.
func TestMalformedClientHintsFailAtStartup(t *testing.T) {
	for name, hint := range map[string][]string{
		"client ID with a newline": {"--client-id", "authunnel-cli\n"},
		"scope with a quote":       {"--client-default-scopes", `openid "profile"`},
		"resource with fragment":   {"--client-resource", "https://api.example#frag"},
		"relative resource":        {"--client-resource", "/api"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseServerConfig(metadataServerArgs(hint...), func(string) string { return "" })
			if err == nil {
				t.Fatalf("expected %s to be rejected at startup", name)
			}
			if !strings.Contains(err.Error(), hint[0]) {
				t.Fatalf("error should name the flag to fix, got: %v", err)
			}
		})
	}
}

// TestResourceURLRejectedAtStartupWhenUnfetchable is the server-side half: a
// value whose scheme no client could retrieve must fail here, not silently become
// a published identifier nothing can use.
func TestResourceURLRejectedAtStartupWhenUnfetchable(t *testing.T) {
	for name, value := range map[string]string{
		"ftp":            "ftp://tunnel.example/protected/tunnel",
		"websocket":      "wss://tunnel.example/protected/tunnel",
		"relative":       "/protected/tunnel",
		"fragment":       "https://tunnel.example/protected/tunnel#frag",
		"bare delimiter": "https://tunnel.example/protected/tunnel#",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseServerConfig(metadataServerArgs("--resource-url", value), func(string) string { return "" })
			if err == nil {
				t.Fatalf("--resource-url %q: expected rejection at startup", value)
			}
			if !strings.Contains(err.Error(), "--resource-url") {
				t.Fatalf("error should name the flag to fix, got: %v", err)
			}
		})
	}
}

func TestResourceURLPublishedFromFlagAndEnv(t *testing.T) {
	const declared = "https://tunnel.example/authunnel/protected/tunnel"

	cfg, err := parseServerConfig(metadataServerArgs("--resource-url", declared), func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}
	if got := cfg.resourceMetadata().ResourceURL; got != declared {
		t.Fatalf("ResourceURL = %q, want the flag value", got)
	}

	cfg, err = parseServerConfig(metadataServerArgs(), func(key string) string {
		if key == "RESOURCE_URL" {
			return declared
		}
		return ""
	})
	if err != nil {
		t.Fatalf("parseServerConfig with env: %v", err)
	}
	if got := cfg.resourceMetadata().ResourceURL; got != declared {
		t.Fatalf("ResourceURL = %q, want the env value", got)
	}
}

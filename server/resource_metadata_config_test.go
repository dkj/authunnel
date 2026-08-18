package main

import (
	"strings"
	"testing"
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
		"--client-scopes", "openid offline_access",
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
	if strings.Join(metadata.Scopes, " ") != "openid offline_access" {
		t.Fatalf("Scopes = %v", metadata.Scopes)
	}
	if metadata.Audience != "https://api.example" || metadata.ResourceIndicator != "https://tunnel.example" {
		t.Fatalf("audience hints = %q / %q", metadata.Audience, metadata.ResourceIndicator)
	}

	env := map[string]string{
		"CLIENT_ID":       "env-cli",
		"CLIENT_SCOPES":   "openid",
		"CLIENT_AUDIENCE": "https://env-api.example",
		"CLIENT_RESOURCE": "https://env-tunnel.example",
	}
	cfg, err = parseServerConfig(metadataServerArgs(), func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("parseServerConfig with env: %v", err)
	}
	metadata = cfg.resourceMetadata()
	if metadata.ClientID != "env-cli" || strings.Join(metadata.Scopes, " ") != "openid" {
		t.Fatalf("env hints not applied: %+v", metadata)
	}
	if metadata.Audience != "https://env-api.example" || metadata.ResourceIndicator != "https://env-tunnel.example" {
		t.Fatalf("env audience hints not applied: %+v", metadata)
	}
}

// TestAuthorizationServerMetadataURLHintTracksServerConfig pins that the hint is
// derived rather than separately configurable: the client and the server read the
// same authorization server's document, so a second flag could only be set
// inconsistently.
func TestAuthorizationServerMetadataURLHintTracksServerConfig(t *testing.T) {
	const metadataURL = "https://idp.example/.well-known/oauth-authorization-server/tenant1"
	cfg, err := parseServerConfig(metadataServerArgs("--oidc-metadata-url", metadataURL), func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}
	if got := cfg.resourceMetadata().AuthorizationServerMetadataURL; got != metadataURL {
		t.Fatalf("published metadata URL = %q, want the server's own --oidc-metadata-url", got)
	}
}

// TestClientHintsRejectedWithoutPublishing catches a configuration that would
// silently do nothing: an operator who sets --client-id alongside
// --no-resource-metadata believes clients are being told something.
func TestClientHintsRejectedWithoutPublishing(t *testing.T) {
	for _, hint := range [][]string{
		{"--client-id", "authunnel-cli"},
		{"--client-scopes", "openid"},
		{"--client-audience", "https://api.example"},
		{"--client-resource", "https://tunnel.example"},
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
		"scope with a quote":       {"--client-scopes", `openid "profile"`},
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

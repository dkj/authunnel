package main

import (
	"strings"
	"testing"
)

// baseClientArgs are the flags every managed-OIDC case needs so parsing reaches
// the URL validation rather than failing earlier.
func baseClientArgs(extra ...string) []string {
	args := []string{
		"--tunnel-url", "https://tunnel.example/protected/tunnel",
		"--oidc-issuer", "https://issuer.example",
		"--oidc-client-id", "authunnel-cli",
	}
	return append(args, extra...)
}

func TestParseClientConfigReadsMetadataURL(t *testing.T) {
	const metadataURL = "https://as.example/.well-known/oauth-authorization-server/tenant1"

	cfg, err := parseClientConfig(baseClientArgs("--oidc-metadata-url", metadataURL), func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseClientConfig returned error: %v", err)
	}
	if cfg.OIDCMetadataURL != metadataURL {
		t.Fatalf("OIDCMetadataURL = %q, want the flag value", cfg.OIDCMetadataURL)
	}
}

func TestParseClientConfigDefaultsMetadataURLEmpty(t *testing.T) {
	cfg, err := parseClientConfig(baseClientArgs(), func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseClientConfig returned error: %v", err)
	}
	if cfg.OIDCMetadataURL != "" {
		t.Fatalf("OIDCMetadataURL = %q, want empty by default", cfg.OIDCMetadataURL)
	}
}

// TestParseClientConfigMetadataURLWithoutIssuer pins that the override can stand
// in for the issuer. The document declares one, and with nothing configured to
// compare it against it is adopted — which is exactly the consistency check being
// traded away, not an oversight. See the metadataURL field comment in auth.go.
func TestParseClientConfigMetadataURLWithoutIssuer(t *testing.T) {
	cfg, err := parseClientConfig(
		[]string{
			"--tunnel-url", "https://tunnel.example/protected/tunnel",
			"--oidc-client-id", "authunnel-cli",
			"--oidc-metadata-url", "https://as.example/meta",
		},
		func(string) string { return "" },
	)
	if err != nil {
		t.Fatalf("--oidc-metadata-url should stand alone, got: %v", err)
	}
	if cfg.OIDCIssuer != "" {
		t.Fatalf("OIDCIssuer = %q, want it left empty for resolution to fill", cfg.OIDCIssuer)
	}
	if cfg.AuthMode != authModeOIDC {
		t.Fatalf("AuthMode = %q, want managed OIDC", cfg.AuthMode)
	}
}

// TestParseClientConfigFallsBackToDiscovery covers the other half of dropping the
// requirements: a configuration missing an essential value is not rejected, it is
// completed from the tunnel server. Each case asserts on ResourceURL, since that
// field being set is what turns the fetch on.
func TestParseClientConfigFallsBackToDiscovery(t *testing.T) {
	for name, args := range map[string][]string{
		"client ID only": {"--oidc-client-id", "authunnel-cli"},
		"issuer only":    {"--oidc-issuer", "https://issuer.example"},
		"metadata only":  {"--oidc-metadata-url", "https://as.example/meta"},
		"nothing":        {},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := parseClientConfig(
				append([]string{"--tunnel-url", "https://tunnel.example/protected/tunnel"}, args...),
				func(string) string { return "" },
			)
			if err != nil {
				t.Fatalf("parseClientConfig: %v", err)
			}
			if cfg.ResourceURL != "https://tunnel.example/protected/tunnel" {
				t.Fatalf("ResourceURL = %q, want the tunnel endpoint's resource identifier", cfg.ResourceURL)
			}
		})
	}
}

func TestParseClientConfigRejectsMetadataURLWithAccessToken(t *testing.T) {
	_, err := parseClientConfig(
		[]string{
			"--tunnel-url", "https://tunnel.example/protected/tunnel",
			"--oidc-metadata-url", "https://as.example/meta",
		},
		func(key string) string {
			if key == "ACCESS_TOKEN" {
				return "static-token"
			}
			return ""
		},
	)
	if err == nil || !strings.Contains(err.Error(), "ACCESS_TOKEN cannot be combined") {
		t.Fatalf("expected ACCESS_TOKEN and --oidc-metadata-url to conflict, got: %v", err)
	}
}

func TestParseClientConfigRejectsHTTPMetadataURL(t *testing.T) {
	_, err := parseClientConfig(
		baseClientArgs("--oidc-metadata-url", "http://as.example/meta"),
		func(string) string { return "" },
	)
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("expected http metadata URL to be rejected, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--oidc-metadata-url") {
		t.Fatalf("error should name the offending flag, got: %v", err)
	}
}

func TestParseClientConfigAcceptsHTTPMetadataURLWithInsecureFlag(t *testing.T) {
	// The issuer is http too: one flag relaxes both, since an operator
	// pointing at a local IdP needs them together.
	_, err := parseClientConfig(
		[]string{
			"--tunnel-url", "https://tunnel.example/protected/tunnel",
			"--oidc-issuer", "http://127.0.0.1:18080/realms/authunnel",
			"--oidc-client-id", "authunnel-cli",
			"--oidc-metadata-url", "http://127.0.0.1:18080/meta",
			"--insecure-oidc-issuer",
		},
		func(string) string { return "" },
	)
	if err != nil {
		t.Fatalf("--insecure-oidc-issuer should permit http on both URLs, got: %v", err)
	}
}

// TestParseClientConfigRejectsFileMetadataURL mirrors the server: the insecure
// flag relaxes transport security, it does not widen the permitted schemes.
func TestParseClientConfigRejectsFileMetadataURL(t *testing.T) {
	for _, args := range [][]string{
		baseClientArgs("--oidc-metadata-url", "file:///etc/authunnel/meta.json"),
		baseClientArgs("--oidc-metadata-url", "file:///etc/authunnel/meta.json", "--insecure-oidc-issuer"),
	} {
		_, err := parseClientConfig(args, func(string) string { return "" })
		if err == nil || !strings.Contains(err.Error(), `"file"`) {
			t.Fatalf("expected the file scheme to be rejected by name, got: %v", err)
		}
	}
}

// TestParseClientConfigRejectsFileIssuer covers what sharing the server's
// validator picked up for the client: --oidc-issuer previously reported a
// file:// value as a generic "not a valid URL" (it has no host), rather than
// naming the scheme. Both flags now use one rule.
func TestParseClientConfigRejectsFileIssuer(t *testing.T) {
	_, err := parseClientConfig(
		[]string{
			"--tunnel-url", "https://tunnel.example/protected/tunnel",
			"--oidc-issuer", "file:///etc/authunnel/issuer",
			"--oidc-client-id", "authunnel-cli",
			"--insecure-oidc-issuer",
		},
		func(string) string { return "" },
	)
	if err == nil || !strings.Contains(err.Error(), `"file"`) {
		t.Fatalf("expected the file scheme to be rejected by name, got: %v", err)
	}
}

func TestParseClientConfigRejectsMalformedMetadataURL(t *testing.T) {
	for _, value := range []string{"https://", "not-a-url", "ftp://as.example/meta"} {
		if _, err := parseClientConfig(
			baseClientArgs("--oidc-metadata-url", value),
			func(string) string { return "" },
		); err == nil {
			t.Fatalf("--oidc-metadata-url %q: expected rejection, got nil", value)
		}
	}
}

// TestParseClientConfigNoResourceMetadataRequiresCompleteConfig pins the earlier
// failure the flag buys. Without it these configurations are valid and complete
// themselves from the server; with it they cannot, and that is decidable here
// rather than at first use inside ssh's stderr.
func TestParseClientConfigNoResourceMetadataRequiresCompleteConfig(t *testing.T) {
	for name, args := range map[string][]string{
		"nothing":        {},
		"client ID only": {"--oidc-client-id", "authunnel-cli"},
		"issuer only":    {"--oidc-issuer", "https://issuer.example"},
	} {
		t.Run(name, func(t *testing.T) {
			base := []string{"--tunnel-url", "https://tunnel.example/protected/tunnel", "--no-resource-metadata"}
			_, err := parseClientConfig(append(base, args...), func(string) string { return "" })
			if err == nil {
				t.Fatalf("expected %s with --no-resource-metadata to be rejected at parse time", name)
			}
			if !strings.Contains(err.Error(), "--no-resource-metadata") {
				t.Fatalf("error should name the flag that makes this incomplete, got: %v", err)
			}
		})
	}
}

func TestParseClientConfigNoResourceMetadataAcceptsCompleteConfig(t *testing.T) {
	for name, args := range map[string][]string{
		"issuer and client ID":       {"--oidc-issuer", "https://issuer.example", "--oidc-client-id", "authunnel-cli"},
		"metadata URL and client ID": {"--oidc-metadata-url", "https://as.example/meta", "--oidc-client-id", "authunnel-cli"},
	} {
		t.Run(name, func(t *testing.T) {
			base := []string{"--tunnel-url", "https://tunnel.example/protected/tunnel", "--no-resource-metadata"}
			cfg, err := parseClientConfig(append(base, args...), func(string) string { return "" })
			if err != nil {
				t.Fatalf("parseClientConfig: %v", err)
			}
			if cfg.ResourceURL != "" {
				t.Fatalf("ResourceURL = %q, want no lookup target at all", cfg.ResourceURL)
			}
			// The scopes default belongs at parse time here: nothing will be
			// discovered, so leaving it empty would only defer the same value.
			if cfg.OIDCScopes != normalizeScopes(defaultOIDCScopes) {
				t.Fatalf("OIDCScopes = %q, want the default applied at parse time", cfg.OIDCScopes)
			}
		})
	}
}

// TestParseClientConfigRejectsNoResourceMetadataWithAccessToken keeps the flag
// from being a silent no-op: manual mode never looks anything up, so a flag
// refusing that lookup cannot take effect, and the server applies the same rule
// to a hint it would never publish.
func TestParseClientConfigRejectsNoResourceMetadataWithAccessToken(t *testing.T) {
	_, err := parseClientConfig(
		[]string{"--tunnel-url", "https://tunnel.example/protected/tunnel", "--no-resource-metadata"},
		func(key string) string {
			if key == "ACCESS_TOKEN" {
				return "static-token"
			}
			return ""
		},
	)
	if err == nil || !strings.Contains(err.Error(), "ACCESS_TOKEN cannot be combined") {
		t.Fatalf("expected the combination to be rejected, got: %v", err)
	}
}

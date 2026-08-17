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

// TestParseClientConfigMetadataURLRequiresIssuer pins that the override
// relocates the document without identifying the issuer — the document is still
// checked against --oidc-issuer, so it cannot stand in for it.
func TestParseClientConfigMetadataURLRequiresIssuer(t *testing.T) {
	_, err := parseClientConfig(
		[]string{
			"--tunnel-url", "https://tunnel.example/protected/tunnel",
			"--oidc-metadata-url", "https://as.example/meta",
		},
		func(string) string { return "" },
	)
	if err == nil || !strings.Contains(err.Error(), "--oidc-issuer") {
		t.Fatalf("expected --oidc-metadata-url without an issuer to be rejected, got: %v", err)
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

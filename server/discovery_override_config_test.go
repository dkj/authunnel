package main

import (
	"strings"
	"testing"
)

// baseServerArgs are the flags every discovery-override case needs so that
// parsing reaches the OIDC validation block rather than failing earlier.
func baseServerArgs(extra ...string) []string {
	args := []string{
		"--oidc-issuer", "https://issuer.example",
		"--token-audience", "authunnel-server",
		"--tls-cert", "/srv/server.crt",
		"--tls-key", "/srv/server.key",
		"--allow-open-egress",
	}
	return append(args, extra...)
}

func TestParseServerConfigReadsDiscoveryOverrideFlags(t *testing.T) {
	cfg, err := parseServerConfig(
		baseServerArgs("--oidc-metadata-url", "https://as.example/.well-known/oauth-authorization-server/tenant1"),
		func(string) string { return "" },
	)
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.OIDCMetadataURL != "https://as.example/.well-known/oauth-authorization-server/tenant1" {
		t.Fatalf("OIDCMetadataURL = %q, want the flag value", cfg.OIDCMetadataURL)
	}
	if cfg.OIDCJWKSURI != "" {
		t.Fatalf("OIDCJWKSURI = %q, want empty", cfg.OIDCJWKSURI)
	}

	cfg, err = parseServerConfig(
		baseServerArgs("--oidc-jwks-uri", "https://as.example/keys"),
		func(string) string { return "" },
	)
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.OIDCJWKSURI != "https://as.example/keys" {
		t.Fatalf("OIDCJWKSURI = %q, want the flag value", cfg.OIDCJWKSURI)
	}
}

func TestParseServerConfigReadsDiscoveryOverrideEnv(t *testing.T) {
	env := map[string]string{
		"OIDC_METADATA_URL": "https://as.example/meta",
	}
	cfg, err := parseServerConfig(baseServerArgs(), func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.OIDCMetadataURL != "https://as.example/meta" {
		t.Fatalf("OIDCMetadataURL = %q, want the env value", cfg.OIDCMetadataURL)
	}

	env = map[string]string{"OIDC_JWKS_URI": "https://as.example/env-keys"}
	cfg, err = parseServerConfig(baseServerArgs(), func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.OIDCJWKSURI != "https://as.example/env-keys" {
		t.Fatalf("OIDCJWKSURI = %q, want the env value", cfg.OIDCJWKSURI)
	}
}

func TestParseServerConfigFlagOverridesDiscoveryEnv(t *testing.T) {
	env := map[string]string{"OIDC_JWKS_URI": "https://env.example/keys"}
	cfg, err := parseServerConfig(
		baseServerArgs("--oidc-jwks-uri", "https://flag.example/keys"),
		func(k string) string { return env[k] },
	)
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.OIDCJWKSURI != "https://flag.example/keys" {
		t.Fatalf("OIDCJWKSURI = %q, want the flag to win over the env var", cfg.OIDCJWKSURI)
	}
}

func TestParseServerConfigRejectsBothDiscoveryOverrides(t *testing.T) {
	_, err := parseServerConfig(
		baseServerArgs(
			"--oidc-metadata-url", "https://as.example/meta",
			"--oidc-jwks-uri", "https://as.example/keys",
		),
		func(string) string { return "" },
	)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual exclusion error, got: %v", err)
	}
}

// Overrides change lookup location, not the issuer tokens must claim.
func TestParseServerConfigStillRequiresIssuerWithOverrides(t *testing.T) {
	for _, override := range [][]string{
		{"--oidc-metadata-url", "https://as.example/meta"},
		{"--oidc-jwks-uri", "https://as.example/keys"},
	} {
		args := append([]string{
			"--token-audience", "authunnel-server",
			"--tls-cert", "/srv/server.crt",
			"--tls-key", "/srv/server.key",
			"--allow-open-egress",
		}, override...)

		_, err := parseServerConfig(args, func(string) string { return "" })
		if err == nil || !strings.Contains(err.Error(), "--oidc-issuer") {
			t.Fatalf("%s without --oidc-issuer: expected issuer to still be required, got: %v", override[0], err)
		}
	}
}

func TestParseServerConfigRejectsHTTPDiscoveryOverrides(t *testing.T) {
	for _, override := range [][]string{
		{"--oidc-metadata-url", "http://as.example/meta"},
		{"--oidc-jwks-uri", "http://as.example/keys"},
	} {
		_, err := parseServerConfig(baseServerArgs(override...), func(string) string { return "" })
		if err == nil || !strings.Contains(err.Error(), "https://") {
			t.Fatalf("%s with http scheme: expected https rejection, got: %v", override[0], err)
		}
		if err != nil && !strings.Contains(err.Error(), override[0]) {
			t.Fatalf("error should name the offending flag %s, got: %v", override[0], err)
		}
	}
}

func TestParseServerConfigAcceptsHTTPDiscoveryOverridesWithInsecureFlag(t *testing.T) {
	for _, override := range [][]string{
		{"--oidc-metadata-url", "http://as.example/meta"},
		{"--oidc-jwks-uri", "http://as.example/keys"},
	} {
		// The development override applies consistently to all OIDC URLs.
		args := append([]string{
			"--oidc-issuer", "http://issuer.example",
			"--token-audience", "authunnel-server",
			"--tls-cert", "/srv/server.crt",
			"--tls-key", "/srv/server.key",
			"--allow-open-egress",
			"--insecure-oidc-issuer",
		}, override...)

		if _, err := parseServerConfig(args, func(string) string { return "" }); err != nil {
			t.Fatalf("%s with --insecure-oidc-issuer: unexpected error: %v", override[0], err)
		}
	}
}

func TestParseServerConfigRejectsFileJWKSURI(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		args := baseServerArgs("--oidc-jwks-uri", "file:///etc/authunnel/jwks.json")
		if insecure {
			args = append(args, "--insecure-oidc-issuer")
		}
		_, err := parseServerConfig(args, func(string) string { return "" })
		if err == nil || !strings.Contains(err.Error(), `"file"`) {
			t.Fatalf("insecure=%v: expected the file scheme to be rejected, got: %v", insecure, err)
		}
	}
}

func TestParseServerConfigRejectsMalformedDiscoveryOverrides(t *testing.T) {
	for _, override := range [][]string{
		{"--oidc-metadata-url", "https://"},
		{"--oidc-jwks-uri", "not-a-url"},
		{"--oidc-jwks-uri", "ftp://as.example/keys"},
	} {
		_, err := parseServerConfig(baseServerArgs(override...), func(string) string { return "" })
		if err == nil {
			t.Fatalf("%s %q: expected rejection, got nil", override[0], override[1])
		}
	}
}

func TestParseServerConfigDefaultsLeaveOverridesUnset(t *testing.T) {
	cfg, err := parseServerConfig(baseServerArgs(), func(string) string { return "" })
	if err != nil {
		t.Fatalf("parseServerConfig returned error: %v", err)
	}
	if cfg.OIDCMetadataURL != "" || cfg.OIDCJWKSURI != "" {
		t.Fatalf("expected both overrides unset, got metadata=%q jwks=%q", cfg.OIDCMetadataURL, cfg.OIDCJWKSURI)
	}
}

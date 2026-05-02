package tunnelserver

import (
	"net"
	"testing"
)

func mustParseAllowRule(t *testing.T, s string) allowRule {
	t.Helper()
	rule, err := ParseAllowRule(s)
	if err != nil {
		t.Fatalf("ParseAllowRule(%q) unexpected error: %v", s, err)
	}
	return rule
}

func TestParseAllowRuleValid(t *testing.T) {
	cases := []struct {
		input    string
		wantFQDN string
		wantCIDR string
		wantLo   int
		wantHi   int
	}{
		{"*.internal:22", "*.internal", "", 22, 22},
		{"*.internal:22-2222", "*.internal", "", 22, 2222},
		{"host.example.com:443", "host.example.com", "", 443, 443},
		{"10.0.0.0/8:443", "", "10.0.0.0/8", 443, 443},
		{"10.0.0.0/8:1-65535", "", "10.0.0.0/8", 1, 65535},
		{"192.168.0.0/16:22", "", "192.168.0.0/16", 22, 22},
		// Bare IPv4 literals — normalized to host-route CIDRs.
		{"10.0.0.1:443", "", "10.0.0.1/32", 443, 443},
		// Bracketed IPv6 notation (required for unambiguous host:port parsing).
		{"[::1]:22", "", "::1/128", 22, 22},
		{"[2001:db8::1]:443", "", "2001:db8::1/128", 443, 443},
		{"[::1/128]:22", "", "::1/128", 22, 22},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			rule, err := ParseAllowRule(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rule.ports.lo != tc.wantLo || rule.ports.hi != tc.wantHi {
				t.Errorf("ports: got [%d,%d] want [%d,%d]", rule.ports.lo, rule.ports.hi, tc.wantLo, tc.wantHi)
			}
			if tc.wantFQDN != "" {
				if rule.fqdn != tc.wantFQDN {
					t.Errorf("fqdn: got %q want %q", rule.fqdn, tc.wantFQDN)
				}
				if rule.cidr != nil {
					t.Errorf("expected nil cidr, got %v", rule.cidr)
				}
			}
			if tc.wantCIDR != "" {
				if rule.cidr == nil {
					t.Errorf("expected non-nil cidr for %q", tc.wantCIDR)
				} else if got := rule.cidr.String(); got != tc.wantCIDR {
					t.Errorf("cidr: got %q want %q", got, tc.wantCIDR)
				}
				if rule.fqdn != "" {
					t.Errorf("expected empty fqdn, got %q", rule.fqdn)
				}
			}
		})
	}
}

func TestParseAllowRuleInvalid(t *testing.T) {
	cases := []string{
		"*.internal",        // no colon
		"*.internal:0",      // port 0
		"*.internal:65536",  // port out of range
		"*.internal:100-50", // lo > hi
		"*.internal:abc",    // non-numeric port
		"10.999.0.0/8:22",   // bad CIDR
		"[bad:22",           // bad glob pattern (unmatched bracket)
		":22",               // empty host
		"[notanip]:22",      // brackets but not a valid IP or CIDR
		"[]:22",             // empty brackets
		"::1:22",            // unbracketed IPv6 — ambiguous whether :22 is port or address tail
		"2001:db8::1",       // unbracketed IPv6, no port — LastIndex splits wrong
		"2001:db8::1:443",   // unbracketed IPv6, port ambiguous — LastIndex splits wrong
	}

	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			_, err := ParseAllowRule(tc)
			if err == nil {
				t.Errorf("expected error for %q, got nil", tc)
			}
		})
	}
}

func TestParseAllowRuleCaseFolding(t *testing.T) {
	rule := mustParseAllowRule(t, "*.INTERNAL:22")
	if rule.fqdn != "*.internal" {
		t.Errorf("expected fqdn to be lowercased, got %q", rule.fqdn)
	}
}

func TestParseAllowlistFromCSV(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		al, err := ParseAllowlistFromCSV("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(al) != 0 {
			t.Errorf("expected empty allowlist, got %d rules", len(al))
		}
	})

	t.Run("two rules", func(t *testing.T) {
		al, err := ParseAllowlistFromCSV("*.internal:22, 10.0.0.0/8:443")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(al) != 2 {
			t.Fatalf("expected 2 rules, got %d", len(al))
		}
	})

	t.Run("invalid entry returns error", func(t *testing.T) {
		_, err := ParseAllowlistFromCSV("*.internal:22,badentry,10.0.0.0/8:443")
		if err == nil {
			t.Fatal("expected error for invalid entry, got nil")
		}
	})
}

func TestAllowlistPermits(t *testing.T) {
	ip10 := net.ParseIP("10.1.2.3")
	ip192 := net.ParseIP("192.168.1.1")
	ip1 := net.ParseIP("1.2.3.4")

	ruleHostPort := mustParseAllowRule(t, "*.internal:5432")
	ruleCIDRPort := mustParseAllowRule(t, "10.0.0.0/8:443")
	ruleHostRange := mustParseAllowRule(t, "*.internal:22-2222")
	ruleBareIPv4 := mustParseAllowRule(t, "10.0.0.1:443")
	ruleIPv6 := mustParseAllowRule(t, "[::1]:22")

	cases := []struct {
		name string
		al   Allowlist
		fqdn string
		ip   net.IP
		port int
		want bool
	}{
		{
			name: "empty allowlist permits all",
			al:   Allowlist{},
			fqdn: "anything", ip: ip1, port: 9999,
			want: true,
		},
		{
			name: "hostname match port match",
			al:   Allowlist{ruleHostPort},
			fqdn: "db.internal", ip: nil, port: 5432,
			want: true,
		},
		{
			name: "hostname match port miss",
			al:   Allowlist{ruleHostPort},
			fqdn: "db.internal", ip: nil, port: 80,
			want: false,
		},
		{
			name: "hostname miss port match",
			al:   Allowlist{ruleHostPort},
			fqdn: "db.external", ip: nil, port: 5432,
			want: false,
		},
		{
			name: "CIDR match port match",
			al:   Allowlist{ruleCIDRPort},
			fqdn: "", ip: ip10, port: 443,
			want: true,
		},
		{
			name: "CIDR miss port match",
			al:   Allowlist{ruleCIDRPort},
			fqdn: "", ip: ip192, port: 443,
			want: false,
		},
		{
			name: "CIDR rule no IP available",
			al:   Allowlist{ruleCIDRPort},
			fqdn: "", ip: nil, port: 443,
			want: false,
		},
		{
			name: "hostname rule no FQDN (IP-type request)",
			al:   Allowlist{ruleHostPort},
			fqdn: "", ip: ip10, port: 5432,
			want: false,
		},
		{
			name: "case-insensitive FQDN match",
			al:   Allowlist{ruleHostPort},
			fqdn: "DB.Internal", ip: nil, port: 5432,
			want: true,
		},
		{
			name: "port range inclusive low boundary",
			al:   Allowlist{ruleHostRange},
			fqdn: "host.internal", ip: nil, port: 22,
			want: true,
		},
		{
			name: "port range inclusive high boundary",
			al:   Allowlist{ruleHostRange},
			fqdn: "host.internal", ip: nil, port: 2222,
			want: true,
		},
		{
			name: "port range outside boundary",
			al:   Allowlist{ruleHostRange},
			fqdn: "host.internal", ip: nil, port: 2223,
			want: false,
		},
		{
			name: "multiple rules first matches",
			al:   Allowlist{ruleHostRange, ruleCIDRPort},
			fqdn: "host.internal", ip: nil, port: 22,
			want: true,
		},
		{
			name: "multiple rules second matches",
			al:   Allowlist{ruleHostRange, ruleCIDRPort},
			fqdn: "", ip: ip10, port: 443,
			want: true,
		},
		{
			name: "multiple rules none match",
			al:   Allowlist{ruleHostRange, ruleCIDRPort},
			fqdn: "host.external", ip: ip1, port: 22,
			want: false,
		},
		// Bare IP rules must match IP-type SOCKS5 requests (FQDN == "").
		// If normalised to a glob they would silently never fire.
		{
			name: "bare IPv4 rule matches IP-type request",
			al:   Allowlist{ruleBareIPv4},
			fqdn: "", ip: net.ParseIP("10.0.0.1"), port: 443,
			want: true,
		},
		{
			name: "bare IPv4 rule does not match different IP",
			al:   Allowlist{ruleBareIPv4},
			fqdn: "", ip: net.ParseIP("10.0.0.2"), port: 443,
			want: false,
		},
		{
			name: "IPv6 rule matches IP-type request",
			al:   Allowlist{ruleIPv6},
			fqdn: "", ip: net.ParseIP("::1"), port: 22,
			want: true,
		},
		{
			name: "IPv6 rule does not match different address",
			al:   Allowlist{ruleIPv6},
			fqdn: "", ip: net.ParseIP("::2"), port: 22,
			want: false,
		},
		// filepath.Match uses '/' as separator so '*' matches '.', meaning
		// *.internal matches multi-level subdomains like a.b.internal.
		{
			name: "glob wildcard matches multi-level subdomain",
			al:   Allowlist{ruleHostPort},
			fqdn: "a.b.internal", ip: nil, port: 5432,
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.al.Permits(tc.fqdn, tc.ip, tc.port)
			if got != tc.want {
				t.Errorf("Permits(%q, %v, %d) = %v, want %v", tc.fqdn, tc.ip, tc.port, got, tc.want)
			}
		})
	}
}

package tunnelserver

import (
	"net"
	"sort"
	"testing"
)

func TestParseIPBlock(t *testing.T) {
	cases := []struct {
		input    string
		wantCIDR string
	}{
		{"127.0.0.0/8", "127.0.0.0/8"},
		{"169.254.169.254", "169.254.169.254/32"},
		{"127.0.0.1", "127.0.0.1/32"},
		{"[::1]", "::1/128"},
		{"[::1/128]", "::1/128"},
		{"[fe80::/10]", "fe80::/10"},
		{"::1/128", "::1/128"},
		{"  127.0.0.1  ", "127.0.0.1/32"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseIPBlock(tc.input)
			if err != nil {
				t.Fatalf("ParseIPBlock(%q) unexpected error: %v", tc.input, err)
			}
			if got.cidr == nil {
				t.Fatalf("ParseIPBlock(%q) returned nil cidr", tc.input)
			}
			if s := got.cidr.String(); s != tc.wantCIDR {
				t.Errorf("ParseIPBlock(%q) cidr = %q, want %q", tc.input, s, tc.wantCIDR)
			}
			if got.label != tc.wantCIDR {
				t.Errorf("ParseIPBlock(%q) label = %q, want %q (operator-supplied entries label themselves with the CIDR string)", tc.input, got.label, tc.wantCIDR)
			}
		})
	}
}

func TestParseIPBlockInvalid(t *testing.T) {
	cases := []string{
		"",               // empty
		"   ",            // whitespace
		"[::1",           // unmatched bracket
		"::1]",           // unmatched bracket
		"[]",             // empty brackets
		"notanip",        // not an IP or CIDR
		"10.999.0.0/8",   // bad CIDR
		"192.168.0.1/40", // bad mask
		"[notanip]",      // brackets but content invalid
		"[notanip/8]",    // brackets, contains slash, but bad CIDR
	}

	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			_, err := ParseIPBlock(tc)
			if err == nil {
				t.Errorf("expected error for %q, got nil", tc)
			}
		})
	}
}

func TestParseIPBlocklistFromCSV(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		bl, err := ParseIPBlocklistFromCSV("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(bl) != 0 {
			t.Errorf("expected empty blocklist, got %d entries", len(bl))
		}
	})

	t.Run("whitespace only", func(t *testing.T) {
		bl, err := ParseIPBlocklistFromCSV("   ,   ")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(bl) != 0 {
			t.Errorf("expected empty blocklist for whitespace-only input, got %d", len(bl))
		}
	})

	t.Run("multiple entries", func(t *testing.T) {
		bl, err := ParseIPBlocklistFromCSV("127.0.0.0/8, 169.254.169.254, [::1]")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(bl) != 3 {
			t.Fatalf("expected 3 entries, got %d", len(bl))
		}
	})

	t.Run("invalid entry returns error", func(t *testing.T) {
		_, err := ParseIPBlocklistFromCSV("127.0.0.0/8,not-an-ip,169.254.169.254")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestIPBlocklistBlocks(t *testing.T) {
	def := DefaultIPBlocklist()

	cases := []struct {
		name      string
		ip        net.IP
		wantBlock bool
		wantLabel string
	}{
		{"nil IP", nil, false, ""},
		{"public IPv4", net.ParseIP("8.8.8.8"), false, ""},
		{"public IPv6", net.ParseIP("2606:4700:4700::1111"), false, ""},
		{"RFC1918 10/8 stays usable", net.ParseIP("10.0.0.1"), false, ""},
		{"RFC1918 192.168/16 stays usable", net.ParseIP("192.168.1.1"), false, ""},
		{"RFC1918 172.16/12 stays usable", net.ParseIP("172.16.5.5"), false, ""},
		{"CGNAT stays usable", net.ParseIP("100.64.0.1"), false, ""},
		{"IPv6 ULA stays usable", net.ParseIP("fd00::1"), false, ""},
		{"IPv4 loopback", net.ParseIP("127.0.0.1"), true, "loopback"},
		{"IPv4 loopback range", net.ParseIP("127.250.0.1"), true, "loopback"},
		{"IPv6 loopback", net.ParseIP("::1"), true, "loopback"},
		{"IPv4-mapped IPv6 loopback", net.ParseIP("::ffff:127.0.0.1"), true, "loopback"},
		{"IPv4 link-local", net.ParseIP("169.254.0.1"), true, "link_local_ipv4"},
		{"IPv4 IMDS", net.ParseIP("169.254.169.254"), true, "link_local_ipv4"},
		{"IPv6 link-local", net.ParseIP("fe80::1"), true, "link_local_ipv6"},
		{"IPv4 unspecified literal", net.ParseIP("0.0.0.0"), true, "unspecified"},
		{"IPv6 unspecified literal", net.ParseIP("::"), true, "unspecified"},
		{"IPv4 multicast", net.ParseIP("224.0.0.1"), true, "multicast"},
		{"IPv6 multicast", net.ParseIP("ff02::1"), true, "multicast"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotBlock, gotLabel := def.Blocks(tc.ip)
			if gotBlock != tc.wantBlock || gotLabel != tc.wantLabel {
				t.Errorf("Blocks(%v) = (%v, %q), want (%v, %q)", tc.ip, gotBlock, gotLabel, tc.wantBlock, tc.wantLabel)
			}
		})
	}
}

func TestIPBlocklistEmptyDoesNotBlock(t *testing.T) {
	var bl IPBlocklist
	if blocked, _ := bl.Blocks(net.ParseIP("127.0.0.1")); blocked {
		t.Fatal("empty blocklist must not block any address (matches --no-ip-block posture)")
	}
}

func TestIPBlocklistOperatorSuppliedEntryUsesCIDRLabel(t *testing.T) {
	// An operator who passes --ip-block 10.0.0.0/8 expects the deny log to
	// identify the matching range without forcing them to invent a category
	// name. Verify the label is the CIDR string itself.
	r, err := ParseIPBlock("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseIPBlock: %v", err)
	}
	bl := IPBlocklist{r}
	blocked, label := bl.Blocks(net.ParseIP("10.5.5.5"))
	if !blocked {
		t.Fatal("expected operator-supplied range to block matching IP")
	}
	if label != "10.0.0.0/8" {
		t.Errorf("expected label to echo the CIDR string, got %q", label)
	}
}

func TestDefaultIPBlocklistLabels(t *testing.T) {
	// Stable label set: alerting and dashboards key off these strings, so
	// removals/renames must be deliberate. This test catches accidental drift.
	def := DefaultIPBlocklist()
	gotLabels := make(map[string]struct{}, len(def))
	for _, r := range def {
		gotLabels[r.label] = struct{}{}
	}
	want := []string{"loopback", "link_local_ipv4", "link_local_ipv6", "unspecified", "multicast"}
	sort.Strings(want)
	gotSlice := make([]string, 0, len(gotLabels))
	for l := range gotLabels {
		gotSlice = append(gotSlice, l)
	}
	sort.Strings(gotSlice)
	if len(gotSlice) != len(want) {
		t.Fatalf("default label set: got %v, want %v", gotSlice, want)
	}
	for i := range want {
		if gotSlice[i] != want[i] {
			t.Fatalf("default label set: got %v, want %v", gotSlice, want)
		}
	}
}

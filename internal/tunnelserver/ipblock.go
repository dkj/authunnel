package tunnelserver

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ipBlockRange is one entry in an IPBlocklist.
//
// label is a short, log-safe reason string. Default-list entries carry a
// categorical label such as "loopback" or "link_local_ipv4" so operators can
// alert on classes of denial; operator-supplied entries default to the CIDR
// string itself, which is self-describing in logs without forcing the
// operator to invent a name.
type ipBlockRange struct {
	cidr  *net.IPNet
	label string
}

// IPBlocklist is a list of IP/CIDR ranges that are denied as resolved
// destinations regardless of what an Allowlist permits. The block check is
// applied after the allowlist; if both fire, deny wins.
//
// An empty IPBlocklist disables the guard entirely (the --no-ip-block
// posture). A non-empty list — typically the DefaultIPBlocklist plus or
// minus operator-supplied entries — protects against hostname rules being
// steered to loopback, cloud-instance metadata services, or other
// link-local targets via DNS that an attacker can influence.
type IPBlocklist []ipBlockRange

// Blocks reports whether ip falls within any range in the blocklist. The
// returned label is the matching range's reason string for logging.
//
// IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) are normalised to their
// IPv4 form before matching, so a single 127.0.0.0/8 entry catches both
// representations of loopback.
func (b IPBlocklist) Blocks(ip net.IP) (bool, string) {
	if ip == nil || len(b) == 0 {
		return false, ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	for _, r := range b {
		if r.cidr.Contains(ip) {
			return true, r.label
		}
	}
	return false, ""
}

// DefaultIPBlocklist is the set of resolved-IP ranges that authunnel
// refuses to dial unless the operator passes --no-ip-block or supplies a
// different --ip-block list.
//
// RFC1918 (10/8, 172.16/12, 192.168/16), CGNAT (100.64/10), and IPv6 ULA
// (fc00::/7) are deliberately not in this list because tunnelling to
// private services is authunnel's core use case.
func DefaultIPBlocklist() IPBlocklist {
	must := func(label, cidr string) ipBlockRange {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			// The defaults are compile-time constants; a parse failure is a bug.
			panic(fmt.Errorf("default ip-block %q: %w", cidr, err))
		}
		return ipBlockRange{cidr: n, label: label}
	}
	return IPBlocklist{
		must("loopback", "127.0.0.0/8"),
		must("loopback", "::1/128"),
		must("link_local_ipv4", "169.254.0.0/16"),
		must("link_local_ipv6", "fe80::/10"),
		must("unspecified", "0.0.0.0/8"),
		must("unspecified", "::/128"),
		must("multicast", "224.0.0.0/4"),
		must("multicast", "ff00::/8"),
	}
}

// ParseIPBlock parses a single --ip-block entry. Accepted forms:
//
//	CIDR             e.g. 127.0.0.0/8
//	bare IP          e.g. 127.0.0.1            (normalised to /32 or /128)
//	bracketed IPv6   e.g. [::1] or [fe80::/10] (brackets stripped before parsing)
//
// Unlike --allow rules there is no ":port" component; the blocklist is
// destination-IP-only.
func ParseIPBlock(s string) (ipBlockRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ipBlockRange{}, errors.New("ip-block entry is empty")
	}
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 || end != len(s)-1 {
			return ipBlockRange{}, fmt.Errorf("ip-block %q: malformed bracketed address", s)
		}
		s = s[1:end]
		if s == "" {
			return ipBlockRange{}, errors.New("ip-block entry is empty")
		}
	}
	if strings.Contains(s, "/") {
		_, network, err := net.ParseCIDR(s)
		if err != nil {
			return ipBlockRange{}, fmt.Errorf("ip-block %q: %w", s, err)
		}
		return ipBlockRange{cidr: network, label: network.String()}, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ipBlockRange{}, fmt.Errorf("ip-block %q: not a valid IP or CIDR", s)
	}
	var cidr *net.IPNet
	if ip4 := ip.To4(); ip4 != nil {
		cidr = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
	} else {
		cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
	}
	return ipBlockRange{cidr: cidr, label: cidr.String()}, nil
}

// ParseIPBlocklistFromCSV parses a comma-separated list of --ip-block
// entries (the IP_BLOCK environment variable). An empty string returns an
// empty IPBlocklist without error. All parse errors are collected and
// returned together.
func ParseIPBlocklistFromCSV(csv string) (IPBlocklist, error) {
	if strings.TrimSpace(csv) == "" {
		return nil, nil
	}
	var (
		ranges IPBlocklist
		errs   []string
	)
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		r, err := ParseIPBlock(part)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		ranges = append(ranges, r)
	}
	if len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return ranges, nil
}

// IPBlocklistFlag implements flag.Value for a repeatable --ip-block flag.
// Each invocation of Set appends one parsed range to the slice pointed to
// by Ranges.
type IPBlocklistFlag struct {
	Ranges *IPBlocklist
}

func (f *IPBlocklistFlag) String() string { return "" }

func (f *IPBlocklistFlag) Set(value string) error {
	r, err := ParseIPBlock(value)
	if err != nil {
		return err
	}
	*f.Ranges = append(*f.Ranges, r)
	return nil
}

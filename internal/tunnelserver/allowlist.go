package tunnelserver

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

// portRange is a closed, inclusive port interval [lo, hi] validated to 1–65535.
type portRange struct{ lo, hi int }

func (pr portRange) contains(port int) bool { return port >= pr.lo && port <= pr.hi }

// allowRule is one parsed --allow entry.
// Exactly one of cidr or fqdn is populated.
type allowRule struct {
	cidr  *net.IPNet // non-nil for CIDR-based rules
	fqdn  string     // non-empty lowercase glob pattern for hostname-based rules
	ports portRange
}

// Allowlist holds zero or more connection-filter rules.
//
// An empty Allowlist means open mode: all destinations are permitted.
// A non-empty Allowlist means restrictive mode: a destination is permitted
// only when at least one rule matches both the host and the port.
type Allowlist []allowRule

// Permits reports whether a connection to the given destination is allowed.
//
// fqdn is the hostname as requested by the SOCKS5 client (empty for IP-type
// requests). ip is the resolved address (nil only for pure IP-type requests
// that carry no FQDN). port is the destination port.
//
// Matching rules:
//   - CIDR rules fire when ip is non-nil and the IP falls within the network.
//   - Hostname rules fire when fqdn is non-empty and the lower-cased fqdn
//     matches the glob pattern.
//   - go-socks5 resolves FQDN-type requests to an IP before calling Allow, so
//     for those requests both fqdn and ip are typically populated and both CIDR
//     and hostname rules can match. Pure IP-type requests (DestAddr.FQDN == "")
//     only match CIDR rules.
func (al Allowlist) Permits(fqdn string, ip net.IP, port int) bool {
	if len(al) == 0 {
		return true // open mode: no restrictions configured
	}
	lowerFQDN := strings.ToLower(fqdn)
	for _, rule := range al {
		if !rule.ports.contains(port) {
			continue
		}
		if rule.cidr != nil && ip != nil && rule.cidr.Contains(ip) {
			return true
		}
		if rule.fqdn != "" && lowerFQDN != "" {
			if matched, _ := filepath.Match(rule.fqdn, lowerFQDN); matched {
				return true
			}
		}
	}
	return false
}

// ParseAllowRule parses a single allow-rule string of the form:
//
//	host-glob:port          e.g. *.internal:22
//	host-glob:lo-hi         e.g. *.internal:22-2222
//	CIDR:port               e.g. 10.0.0.0/8:443
//	CIDR:lo-hi              e.g. 10.0.0.0/8:1-65535
//
// The host part is treated as a CIDR when it contains a '/', otherwise as a
// case-insensitive glob pattern matched with filepath.Match semantics.
// filepath.Match uses '/' as its path separator, so '*' matches any sequence
// of characters including '.', meaning *.internal matches both foo.internal
// and a.b.internal (multi-level subdomains). '**' is not special.
func ParseAllowRule(s string) (allowRule, error) {
	// Split on the final colon to separate host from port part.
	// We use the last colon so IPv6 CIDRs such as ::1/128:22 would work,
	// though CIDR notation conventionally uses '/' not ':' for the prefix length.
	lastColon := strings.LastIndex(s, ":")
	if lastColon < 0 {
		return allowRule{}, fmt.Errorf("allow rule %q: missing ':' between host and port", s)
	}
	host := s[:lastColon]
	portPart := s[lastColon+1:]

	if host == "" {
		return allowRule{}, fmt.Errorf("allow rule %q: host part is empty", s)
	}

	pr, err := parsePortRange(portPart)
	if err != nil {
		return allowRule{}, fmt.Errorf("allow rule %q: %w", s, err)
	}

	var rule allowRule
	rule.ports = pr

	// Strip optional [] brackets (conventional bracketed-IPv6 notation, e.g. [::1]).
	// Bracketed syntax makes LastIndex-based port splitting unambiguous for IPv6.
	// If brackets are present the content must parse as an IP or CIDR; brackets
	// around a hostname glob are rejected to prevent silent mismatches.
	effectiveHost := host
	bracketed := strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]")
	if bracketed {
		effectiveHost = host[1 : len(host)-1]
	}

	if strings.Contains(effectiveHost, "/") {
		// CIDR rule
		_, network, err := net.ParseCIDR(effectiveHost)
		if err != nil {
			return allowRule{}, fmt.Errorf("allow rule %q: invalid CIDR %q: %w", s, effectiveHost, err)
		}
		rule.cidr = network
	} else if ip := net.ParseIP(effectiveHost); ip != nil {
		// Bare IP literal — normalize to a host-route CIDR (/32 for IPv4,
		// /128 for IPv6) so it matches IP-type SOCKS5 requests correctly.
		// Without this, the rule would be stored as a hostname glob and silently
		// never fire, because IP-type SOCKS5 requests arrive with FQDN == "".
		//
		// Unbracketed IPv6 addresses are rejected even when net.ParseIP accepts
		// the host part, because the last-colon split is ambiguous: the segment
		// after the final colon could be the port or the tail of the address.
		// Require [addr]:port notation to make intent unambiguous.
		if ip.To4() == nil && !bracketed {
			return allowRule{}, fmt.Errorf("allow rule %q: IPv6 address %q must use bracketed notation e.g. [%s]:%s", s, effectiveHost, effectiveHost, portPart)
		}
		if ip4 := ip.To4(); ip4 != nil {
			rule.cidr = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
		} else {
			rule.cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		}
	} else if bracketed {
		// Brackets were present but the content is not a valid IP or CIDR.
		return allowRule{}, fmt.Errorf("allow rule %q: bracketed host %q is not a valid IP address or CIDR", s, effectiveHost)
	} else {
		// Hostname glob rule — validate the pattern and normalize to lower case.
		// DNS host names never contain colons; a colon here means the operator
		// wrote an unbracketed IPv6 literal and the port split was wrong.
		// Fail fast rather than storing a glob that will never match.
		lower := strings.ToLower(effectiveHost)
		if strings.Contains(lower, ":") {
			return allowRule{}, fmt.Errorf("allow rule %q: host %q looks like an IPv6 address; use bracketed notation e.g. [%s]:%s", s, effectiveHost, effectiveHost, portPart)
		}
		if _, err := filepath.Match(lower, ""); errors.Is(err, filepath.ErrBadPattern) {
			return allowRule{}, fmt.Errorf("allow rule %q: invalid glob pattern %q: %w", s, host, err)
		}
		rule.fqdn = lower
	}

	return rule, nil
}

// ParseAllowlistFromCSV parses a comma-separated list of allow-rule strings.
// An empty string returns an empty Allowlist without error.
// All parse errors are collected and returned together.
func ParseAllowlistFromCSV(csv string) (Allowlist, error) {
	if strings.TrimSpace(csv) == "" {
		return nil, nil
	}
	var (
		rules Allowlist
		errs  []string
	)
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		rule, err := ParseAllowRule(part)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		rules = append(rules, rule)
	}
	if len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return rules, nil
}

// AllowlistFlag implements flag.Value for a repeatable --allow flag.
// Each invocation of Set appends one parsed rule to the slice pointed to by Rules.
type AllowlistFlag struct {
	Rules *Allowlist
}

func (f *AllowlistFlag) String() string { return "" }

func (f *AllowlistFlag) Set(value string) error {
	rule, err := ParseAllowRule(strings.TrimSpace(value))
	if err != nil {
		return err
	}
	*f.Rules = append(*f.Rules, rule)
	return nil
}

// parsePortRange parses "port" or "lo-hi" into a portRange.
func parsePortRange(s string) (portRange, error) {
	if idx := strings.Index(s, "-"); idx >= 0 {
		lo, err := parsePort(s[:idx])
		if err != nil {
			return portRange{}, fmt.Errorf("invalid port range low value: %w", err)
		}
		hi, err := parsePort(s[idx+1:])
		if err != nil {
			return portRange{}, fmt.Errorf("invalid port range high value: %w", err)
		}
		if lo > hi {
			return portRange{}, fmt.Errorf("port range %q: low end %d exceeds high end %d", s, lo, hi)
		}
		return portRange{lo: lo, hi: hi}, nil
	}
	port, err := parsePort(s)
	if err != nil {
		return portRange{}, fmt.Errorf("invalid port: %w", err)
	}
	return portRange{lo: port, hi: port}, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%q is not a valid port number", s)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d is out of range 1–65535", n)
	}
	return n, nil
}

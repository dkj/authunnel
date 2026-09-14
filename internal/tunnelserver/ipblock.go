package tunnelserver

import "authunnel/internal/ipblock"

// The resolved-IP deny-list moved to internal/ipblock when the client needed the
// same policy for addresses named by a remote metadata document. These aliases
// keep the server-facing names — they appear in flag wiring, logs, and tests —
// while there is exactly one definition of what is blocked.
type (
	// IPBlocklist is the resolved-IP deny-list applied after the allowlist.
	IPBlocklist = ipblock.List
	// IPBlocklistFlag parses repeatable --ip-block values.
	IPBlocklistFlag = ipblock.ListFlag
)

// DefaultIPBlocklist is the built-in protected set: loopback, IPv4/IPv6
// link-local (including cloud IMDS), unspecified, and multicast.
func DefaultIPBlocklist() IPBlocklist { return ipblock.Default() }

// ParseIPBlocklistFromCSV parses the comma-separated IP_BLOCK environment form.
func ParseIPBlocklistFromCSV(csv string) (IPBlocklist, error) { return ipblock.ParseListFromCSV(csv) }

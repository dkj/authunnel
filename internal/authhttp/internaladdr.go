package authhttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"authunnel/internal/ipblock"
)

// The addresses refused below are ipblock.Default(): loopback, IPv4/IPv6
// link-local (including the cloud instance-metadata address 169.254.169.254),
// unspecified, and multicast. Deliberately *not* RFC1918, CGNAT or IPv6 ULA — an
// authorization server on a private network is an ordinary corporate deployment,
// and refusing it would break far more than it protected.
//
// This matters only for values a *remote* party chose. A configured issuer is the
// operator's own decision and is not filtered; a discovered one arrives from a
// tunnel server that could name anything, and RFC 9728 §7.7 calls out exactly
// this — a resource server steering a client's own auth traffic at addresses only
// the client can reach.
//
// Two layers, because neither covers the other's case:
//
//   - CheckPublicAddress resolves a URL's host up front. It is the only option for
//     the authorization_endpoint, which is handed to the OS URL dispatcher rather
//     than fetched by us, so there is no connection of ours to guard.
//   - RefuseInternalAddresses guards each request's own destination, and — when
//     the connection is made directly — the dial as well. The dial layer is what
//     closes the gap the static check leaves: the attacker chose the hostname, so
//     they control its DNS, and a name that resolves publicly during the check can
//     resolve to loopback a moment later. Checking at dial time and connecting to
//     the address that was checked is the only version of that which holds.
//
// **An HTTP proxy removes the address checks, so what happens then turns on whether
// anything else binds the origin — and for https, something does.**
//
// Through a proxy the destination is resolved by the *proxy*, so neither the address
// that was checked nor the address that was dialled describes where the traffic went.
//
// For an https destination that does not matter. The transport issues CONNECT and
// then performs its own TLS handshake with the origin, validating the certificate
// against the name it asked for; the proxy is a blind relay. A rebound internal
// service cannot complete that handshake — the attacker owns the name but not that
// service's key — so it can neither deliver a document nor receive a credential. TLS
// is the binding, and address pinning was only ever standing in for it. Such requests
// are allowed, and the address checks are skipped rather than applied: with a proxy in
// play the local resolver's answer is not the one that will be used, and a proxied
// network often has no local answer at all.
//
// For a plaintext destination there is nothing to fall back on, and a proxy fetching
// an internal http endpoint on this client's behalf is exactly the RFC 9728 §7.7
// pivot. Those requests are refused. Plaintext discovery already requires
// --insecure-oidc-issuer, so the refusal does not arise in a normal deployment.
//
// One limit this cannot close, stated rather than glossed: a TLS-terminating proxy
// with its CA installed locally *is* the origin as far as certificate validation is
// concerned, so it can serve internal content under any name. That is a trust the
// operator established deliberately, and the control for it is the proxy's own egress
// policy, not anything on this side.
//
// Two earlier versions of this comment were wrong in opposite directions — one
// exempted the proxy hop and called the residual exposure documented, the other
// claimed every proxied request was refused and that zero-configuration discovery
// therefore could not work behind a proxy. Neither matched the code by the time it
// was read. If the rule changes again, this paragraph is the first thing to update.

// resolveTimeout bounds the lookup CheckPublicAddress performs. Short: it is one
// DNS query, and it sits on the interactive login path.
const resolveTimeout = 5 * time.Second

// lookupIPAddr is the single point of name resolution in this package.
//
// It is a variable so a test can assert *which* code paths resolve — and, more to
// the point, which must not. HostIsAlwaysLocal deciding whether to relax every
// other check here must not depend on a name service, because the host it is
// deciding about belongs to the party these checks constrain.
var lookupIPAddr = net.DefaultResolver.LookupIPAddr

// CheckPublicAddress refuses a URL whose host resolves to an address in
// ipblock.Default(). label names the field for the error.
//
// Every resolved address must be acceptable, not merely the first: a name with
// both a public and a loopback answer is the obvious way to slip past a check
// that stops at one.
//
// A resolution failure is *not* a refusal — an unreachable name is an ordinary
// network problem, and reporting it as ErrUnsafeTransport would tell callers that
// retrying cannot help when it might.
func CheckPublicAddress(ctx context.Context, label, rawURL string) error {
	host, err := hostOf(label, rawURL)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip != nil {
		return checkIP(label, host, ip)
	}
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	addrs, err := lookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve %s %q: %w", label, host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("resolve %s %q: no addresses", label, host)
	}
	for _, addr := range addrs {
		if err := checkIP(label, host, addr.IP); err != nil {
			return err
		}
	}
	return nil
}

// HostIsAlwaysLocal reports whether rawURL names *this machine* in a way that no
// name service can change: a loopback literal, or a name RFC 6761 §6.3 reserves for
// loopback.
//
// It answers the question a caller needs before applying any of this — whether the
// resource server is the client's own machine, in which case a local authorization
// server is the expected answer rather than an attack, and the guards would do
// nothing but break a development setup.
//
// **This set is narrower than ipblock.Default(), and the difference is the point.**
// Those are two different questions, and an earlier version answered both with the
// one list:
//
//   - the refusal set asks "may a remote party send this client here" — no, for
//     loopback, link-local, IMDS, unspecified and multicast alike;
//   - this asks "is this host the machine we are running on" — true only of
//     loopback.
//
// Reusing the refusal set meant a tunnel URL pointing at 169.254.169.254 was
// classified as local and switched off *every* guard, including the one protecting
// that very address. "The tunnel server is the instance metadata service" is the last
// circumstance in which to start trusting what it says. Link-local, multicast and
// unspecified either name something other than this machine or cannot carry a tunnel
// at all, so none of them belongs here.
//
// 0.0.0.0 and :: are excluded too, though a connection to them cannot leave the host:
// they are not a spelling any documented setup uses, and one clear refusal that
// --oidc-issuer answers costs less than a standing invitation to wonder why an
// unspecified address counts as an identity.
//
// **It deliberately resolves nothing**, which is the other half of the point. An
// earlier version resolved the host and treated any blocked answer as local. The host
// in question is the tunnel server's — which in the threat model this guard exists for
// is the *attacker's* — so its DNS is theirs to choose: two A records, one public and
// one loopback, classified their server as local and switched every downstream guard
// off. A guard whose activation condition is supplied by the party it constrains is
// not a guard.
//
// What the narrowness costs: a development host that reaches its tunnel through a
// private alias (say dev.authunnel.test in /etc/hosts) is not recognised, so a
// loopback authorization server discovered from it is refused. The way through is the
// one every other opinionated check here has — configure the values, with
// --oidc-issuer and --oidc-client-id, which are the operator's own decision and are
// not filtered.
func HostIsAlwaysLocal(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		// IsLoopback covers the IPv4-mapped IPv6 spelling, so ::ffff:127.0.0.1 is
		// not a way around either side of this.
		return ip.IsLoopback()
	}
	// RFC 6761 §6.3: "localhost" and anything under it are reserved, and resolvers
	// are required to map them to loopback. A public name cannot be one, so this
	// cannot be claimed by a remote party.
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// RefuseInternalAddresses returns a shallow copy of base that refuses to reach
// ipblock.Default() addresses: every directly-connected request's destination is
// checked, and the connection goes to the address that was checked rather than to a
// name that could resolve differently. A request that would travel via an HTTP proxy
// is refused when plaintext and allowed when https, for the reasons at the top of
// this file.
//
// The copy matters for the same reason it does in RefuseTransportDowngrade: the
// caller's client is shared with other auth traffic and must not acquire this
// policy as a side effect.
func RefuseInternalAddresses(base *http.Client) *http.Client {
	guarded := *base
	inner := base.Transport
	if inner == nil {
		inner = http.DefaultTransport
	}
	if transport, ok := inner.(*http.Transport); ok {
		cloned := transport.Clone()
		cloned.DialContext = guardedDialer(cloned.DialContext)
		// proxyFor is captured so the guard can refuse a request the transport
		// would send via a proxy, where nothing below can pin an address.
		guarded.Transport = &destinationGuard{next: cloned, proxyFor: cloned.Proxy}
		return &guarded
	}
	// A caller supplying its own RoundTripper has no dialer of ours to guard, so
	// only the destination check is available. That is the shape tests use when
	// they inject a transport, and it is strictly better than the nothing this
	// used to install.
	guarded.Transport = &destinationGuard{next: inner}
	return &guarded
}

// proxiedDialKey marks a request whose connection goes to a proxy, so the dialer
// leaves that address alone: it is the operator's own proxy rather than anything a
// metadata document named, and checking it would refuse a loopback proxy — a common
// corporate shape — for no benefit.
type proxiedDialKey struct{}

// destinationGuard checks where each request is actually addressed, and how it
// would get there, before the transport acts on either.
//
// It is the only layer with access to the destination rather than the dial
// address, which is what lets it recognise the proxied case at all. It also covers
// redirects for free, since net/http issues each hop as its own RoundTrip.
type destinationGuard struct {
	next     http.RoundTripper
	proxyFor func(*http.Request) (*url.URL, error)
}

func (g *destinationGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	// The proxy question comes first, because its answer decides whether the
	// address checks below describe anything real: once a proxy is in play they
	// report on a lookup that is not the one the connection will use.
	if g.proxyFor != nil {
		proxyURL, err := g.proxyFor(req)
		if err != nil {
			return nil, err
		}
		if proxyURL != nil {
			if req.URL.Scheme != "https" {
				return nil, refusef("refusing to reach %s over %s via the proxy at %s: a proxy resolves the destination itself, and plaintext offers nothing to verify it against, so this client cannot tell where configuration discovered from a remote party would send its traffic. Add the host to NO_PROXY if it is directly reachable, or configure --oidc-issuer and --oidc-client-id explicitly",
					req.URL.Host, req.URL.Scheme, proxyURL.Host)
			}
			// https via a proxy: the transport issues CONNECT and then handshakes
			// with the origin itself, validating the certificate against this
			// name, so the origin is bound without help from us. The address
			// checks are skipped rather than applied — the local resolver's answer
			// is not the one the connection will use, and a proxied network often
			// has no local answer to give — and the dial is exempted, since it goes
			// to the proxy.
			return g.next.RoundTrip(req.WithContext(context.WithValue(req.Context(), proxiedDialKey{}, true)))
		}
	}
	if err := CheckPublicAddress(req.Context(), "address", req.URL.String()); err != nil {
		return nil, err
	}
	return g.next.RoundTrip(req)
}

func guardedDialer(inner func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if inner == nil {
		inner = dialer.DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if proxied, _ := ctx.Value(proxiedDialKey{}).(bool); proxied {
			return inner(ctx, network, address)
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, refusef("cannot parse dial address %q", address)
		}
		if ip := net.ParseIP(host); ip != nil {
			if err := checkIP("address", host, ip); err != nil {
				return nil, err
			}
			return inner(ctx, network, address)
		}
		addrs, err := lookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, addr := range addrs {
			if err := checkIP("address", host, addr.IP); err != nil {
				return nil, err
			}
			conn, err := inner(ctx, network, net.JoinHostPort(addr.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no addresses for %q", host)
		}
		return nil, lastErr
	}
}

func checkIP(label, host string, ip net.IP) error {
	if blocked, reason := ipblock.Default().Blocks(ip); blocked {
		return refusef("%s %q resolves to %s (%s); refusing to reach an internal address named by a remote metadata document",
			label, host, ip, reason)
	}
	return nil
}

func hostOf(label, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", refusef("%s %q is not a valid URL: %v", label, rawURL, err)
	}
	host := u.Hostname()
	if host == "" {
		return "", refusef("%s %q has no host", label, rawURL)
	}
	return strings.ToLower(host), nil
}

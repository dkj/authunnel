package authhttp

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"authunnel/internal/ipblock"
)

func TestCheckPublicAddressRefusesInternalLiterals(t *testing.T) {
	for _, rawURL := range []string{
		"http://127.0.0.1:8080/meta",
		"http://127.9.9.9/meta",
		"https://[::1]/meta",
		// The cloud instance-metadata service, the reason link-local is in the
		// set at all.
		"http://169.254.169.254/latest/meta-data/",
		"https://[fe80::1]/meta",
		"http://0.0.0.0/meta",
		// IPv4-mapped IPv6 must not be a way around the IPv4 ranges.
		"http://[::ffff:127.0.0.1]/meta",
	} {
		err := CheckPublicAddress(context.Background(), "authorization_servers[0]", rawURL)
		if err == nil {
			t.Fatalf("CheckPublicAddress(%q): expected refusal", rawURL)
		}
		if !errors.Is(err, ErrUnsafeTransport) {
			t.Fatalf("CheckPublicAddress(%q) = %v, want it to be %v", rawURL, err, ErrUnsafeTransport)
		}
	}
}

// TestCheckPublicAddressAllowsPrivateNetworks pins the deliberate limit of this
// guard. An authorization server on RFC1918, CGNAT or IPv6 ULA is an ordinary
// corporate deployment; refusing those would break far more than it protected,
// and tunnelling to private networks is what authunnel is for.
func TestCheckPublicAddressAllowsPrivateNetworks(t *testing.T) {
	for _, rawURL := range []string{
		"https://10.1.2.3/meta",
		"https://172.16.0.1/meta",
		"https://192.168.1.1/meta",
		"https://100.64.0.1/meta",
		"https://[fd00::1]/meta",
		"https://93.184.216.34/meta",
	} {
		if err := CheckPublicAddress(context.Background(), "authorization_servers[0]", rawURL); err != nil {
			t.Fatalf("CheckPublicAddress(%q) = %v, want accepted", rawURL, err)
		}
	}
}

// TestCheckPublicAddressResolvesNames covers the case the literals above do not:
// the attacker picks a *name*, and it is the resolved address that matters.
func TestCheckPublicAddressResolvesNames(t *testing.T) {
	err := CheckPublicAddress(context.Background(), "token_endpoint", "https://localhost:9999/token")
	if err == nil || !errors.Is(err, ErrUnsafeTransport) {
		t.Fatalf("error = %v, want a name resolving to loopback to be refused as %v", err, ErrUnsafeTransport)
	}
	if !strings.Contains(err.Error(), "token_endpoint") {
		t.Fatalf("error should name the field, got: %v", err)
	}
}

// TestCheckPublicAddressDoesNotRefuseUnresolvable keeps "unreachable" and
// "refused" apart. Reporting a DNS failure as ErrUnsafeTransport would tell the
// caller retrying cannot help, and it can.
func TestCheckPublicAddressDoesNotRefuseUnresolvable(t *testing.T) {
	err := CheckPublicAddress(context.Background(), "issuer", "https://nonexistent.invalid/meta")
	if err != nil && errors.Is(err, ErrUnsafeTransport) {
		t.Fatalf("error = %v, want an unresolvable name not to be a refusal", err)
	}
}

// TestHostIsAlwaysLocal pins the activation condition for relaxing every other
// check here, and the property that makes it safe: it consults no name service,
// so the party the guards constrain cannot satisfy it.
func TestHostIsAlwaysLocal(t *testing.T) {
	for rawURL, want := range map[string]bool{
		"http://127.0.0.1:8443/protected/tunnel":  true,
		"http://127.9.9.9/tunnel":                 true,
		"https://[::1]/protected/tunnel":          true,
		"http://[::ffff:127.0.0.1]/tunnel":        true,
		"http://localhost:8443/protected/tunnel":  true,
		"http://LOCALHOST:8443/protected/tunnel":  true,
		"http://dev.localhost:8443/tunnel":        true,
		"https://93.184.216.34/tunnel":            false,
		"https://10.0.0.1/tunnel":                 false,
		"https://tunnel.example/protected/tunnel": false,
		// Refused *and* not local: these are two different questions, and using
		// one list for both meant a tunnel URL at the instance metadata service
		// switched off the guard protecting that very address.
		"http://169.254.169.254/tunnel": false,
		"http://169.254.1.1/tunnel":     false,
		"https://[fe80::1]/tunnel":      false,
		"http://224.0.0.1/tunnel":       false,
		"https://[ff02::1]/tunnel":      false,
		"http://0.0.0.0:8443/tunnel":    false,
		"http://[::]:8443/tunnel":       false,
		// The attack the DNS-free rule exists to stop: a name an attacker owns
		// cannot be classified local however it resolves, and a name that merely
		// *looks* local-ish is still just a name.
		"https://localhost.attacker.example/tunnel": false,
		"https://not-localhost/tunnel":              false,
		"https://nonexistent.invalid/tunnel":        false,
		"":                                          false,
		"::not a url":                               false,
	} {
		if got := HostIsAlwaysLocal(rawURL); got != want {
			t.Fatalf("HostIsAlwaysLocal(%q) = %v, want %v", rawURL, got, want)
		}
	}
}

// TestHostIsAlwaysLocalIgnoresResolution is the regression guard for the finding
// itself. "localhost" resolves to loopback and a public name does not, but that is
// not why the answers differ — nothing here resolves anything, which is what stops
// a tunnel host answering with both a public and a loopback address from switching
// the guards off.
func TestHostIsAlwaysLocalIgnoresResolution(t *testing.T) {
	// Resolvable to loopback via the resolver, yet not a reserved name: it must
	// not count, or the classification is back to being DNS-driven.
	if HostIsAlwaysLocal("http://ip6-localhost.attacker.example/tunnel") {
		t.Fatal("a non-reserved name must not be local however it resolves")
	}
	// And the reserved name needs no lookup to be recognised, so this holds with
	// no network at all.
	if !HostIsAlwaysLocal("http://localhost/tunnel") {
		t.Fatal("localhost is reserved for loopback by RFC 6761 and must be recognised without resolving")
	}
}

// TestRefuseInternalAddressesGuardsTheDial is the layer the static check cannot
// provide: the attacker controls DNS for the name they chose, so a check that
// passes can be followed by a connection somewhere else. The guard is what makes
// the address that was checked the address that is dialled.
func TestRefuseInternalAddressesGuardsTheDial(t *testing.T) {
	loopback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"http://internal.example"}`))
	}))
	defer loopback.Close()

	// Control: the unguarded client reaches it, so the refusal below is
	// attributable to the guard and not to the fixture.
	if _, err := loopback.Client().Get(loopback.URL); err != nil {
		t.Fatalf("unguarded control request failed: %v", err)
	}

	guarded := RefuseInternalAddresses(loopback.Client())
	_, err := guarded.Get(loopback.URL)
	if err == nil {
		t.Fatal("expected the guarded client to refuse a loopback destination")
	}
	if !errors.Is(err, ErrUnsafeTransport) {
		t.Fatalf("error = %v, want it to be %v", err, ErrUnsafeTransport)
	}
}

// TestRefuseInternalAddressesLeavesTheCallersClientAlone mirrors the same
// property RefuseTransportDowngrade has: the client passed in is shared with
// other auth traffic and must not acquire this policy as a side effect.
func TestRefuseInternalAddressesLeavesTheCallersClientAlone(t *testing.T) {
	loopback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer loopback.Close()

	base := loopback.Client()
	_ = RefuseInternalAddresses(base)
	if _, err := base.Get(loopback.URL); err != nil {
		t.Fatalf("the original client should be unaffected, got: %v", err)
	}
}

// TestRefuseInternalAddressesRefusesPlaintextThroughAProxy covers the case where a
// proxy genuinely removes the protection: past the proxy the *proxy* resolves the
// destination, so a name can answer publicly here and internally there, and over
// plaintext there is nothing to check the result against. The proxy fetching an
// internal http endpoint on this client's behalf is the RFC 9728 §7.7 pivot.
//
// The proxy here is on loopback, a common corporate shape: note the refusal is for
// being plaintext-via-proxy, not for the proxy being loopback, and that nothing
// reaches it at all.
func TestRefuseInternalAddressesRefusesPlaintextThroughAProxy(t *testing.T) {
	var proxied []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = append(proxied, r.URL.String())
		_, _ = w.Write([]byte(`{"issuer":"http://reached-through-the-proxy.example"}`))
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	viaProxy := func() *http.Client {
		return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	}

	// Control: unguarded, the proxy fetches an internal destination on the
	// client's behalf. This is the capability being removed, and asserting it
	// keeps the refusals below attributable to the guard.
	if _, err := viaProxy().Get("http://169.254.169.254/latest/meta-data/"); err != nil {
		t.Fatalf("unguarded control request through the proxy failed: %v", err)
	}
	if len(proxied) != 1 {
		t.Fatalf("proxy saw %v, want the control request to have reached it", proxied)
	}

	guarded := RefuseInternalAddresses(viaProxy())
	for _, destination := range []string{
		// The internal destination the control just reached.
		"http://169.254.169.254/latest/meta-data/",
		// And a *public* one, which the address rules would happily allow: this
		// is refused purely for being plaintext through a proxy.
		"http://93.184.216.34/meta",
	} {
		_, err := guarded.Get(destination)
		if err == nil {
			t.Fatalf("GET %s: expected a proxied request to be refused", destination)
		}
		if !errors.Is(err, ErrUnsafeTransport) {
			t.Fatalf("GET %s: error = %v, want it to be %v", destination, err, ErrUnsafeTransport)
		}
		if !strings.Contains(err.Error(), "NO_PROXY") || !strings.Contains(err.Error(), "--oidc-issuer") {
			t.Fatalf("GET %s: error = %v, want both ways forward named", destination, err)
		}
	}
	if len(proxied) != 1 {
		t.Fatalf("proxy saw %v, want nothing beyond the unguarded control request", proxied)
	}
}

// TestRefuseInternalAddressesAllowsDirectRequestsWhenAProxyIsConfigured pins that
// the refusal is per request, not per client. http.ProxyFromEnvironment returns no
// proxy for many destinations even when the variables are set, and those requests
// must still work — otherwise setting HTTP_PROXY at all would disable discovery
// wholesale.
//
// The assertion is that a direct request *succeeds*. An earlier version only checked
// that a (loopback, therefore refused) request's error did not mention the proxy,
// which a mutant refusing every non-proxied request passed happily.
func TestRefuseInternalAddressesAllowsDirectRequestsWhenAProxyIsConfigured(t *testing.T) {
	var served int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		_, _ = w.Write([]byte(`{}`))
	}))
	defer target.Close()

	// A proxy function that declines to proxy anything — the shape of NO_PROXY
	// covering the destination — and a dialer that reports the address it was given,
	// so a public destination can be exercised without leaving the machine.
	client := &http.Client{Transport: &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Redirect the "public" destination at the local fixture, after the
			// guard has judged it.
			if strings.HasPrefix(address, "93.184.216.34:") {
				address = strings.TrimPrefix(target.URL, "http://")
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}}
	guarded := RefuseInternalAddresses(client)

	// The direct request to an acceptable address goes through.
	response, err := guarded.Get("http://93.184.216.34/meta")
	if err != nil {
		t.Fatalf("a direct request must not be refused merely because a proxy function is configured: %v", err)
	}
	_ = response.Body.Close()
	if served != 1 {
		t.Fatalf("the destination served %d requests, want the direct request delivered", served)
	}

	// And a direct request to a refused address is still refused — on its address,
	// with no mention of a proxy, since none applies.
	_, err = guarded.Get(target.URL)
	if err == nil {
		t.Fatal("expected the loopback destination to be refused on its address")
	}
	if !errors.Is(err, ErrUnsafeTransport) {
		t.Fatalf("error = %v, want %v", err, ErrUnsafeTransport)
	}
	if strings.Contains(err.Error(), "via the proxy") {
		t.Fatalf("error = %v, want no proxy refusal when no proxy applies", err)
	}
}

// connectRelay is a blind CONNECT proxy that relays every tunnel to one address,
// whatever host was asked for. It is the rebinding attack in its strongest form:
// the "proxy resolves the name differently" step, performed unconditionally.
//
// Deliberately not a TLS-terminating proxy. One that terminates TLS *is* the origin
// as far as certificate validation goes, which is a trust the operator installs a
// CA for and which no check on this side can substitute for.
func connectRelay(t *testing.T, to string) *url.URL {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			downstream, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer downstream.Close()
				if _, err := http.ReadRequest(bufio.NewReader(downstream)); err != nil {
					return
				}
				upstream, err := net.Dial("tcp", to)
				if err != nil {
					return
				}
				defer upstream.Close()
				_, _ = io.WriteString(downstream, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() { _, _ = io.Copy(upstream, downstream) }()
				_, _ = io.Copy(downstream, upstream)
			}()
		}
	}()
	proxyURL, err := url.Parse("http://" + listener.Addr().String())
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return proxyURL
}

// TestHTTPSThroughAProxyIsAllowedAndBoundByTLS is the reason the refusal above is
// scoped to plaintext rather than applied to every proxied request.
//
// The relay sends every connection to one origin regardless of the name requested,
// which is the rebinding an address check cannot see through. It does not matter:
// the transport handshakes with the origin itself and validates the certificate
// against the name it asked for, so a rebound service cannot deliver a document. The
// control proves the relay does deliver content when the name matches, which is what
// makes the failure attributable to the certificate rather than to the fixture.
func TestHTTPSThroughAProxyIsAllowedAndBoundByTLS(t *testing.T) {
	var served int
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		_, _ = w.Write([]byte(`{"issuer":"https://example.com"}`))
	}))
	defer origin.Close()

	pool := x509.NewCertPool()
	pool.AddCert(origin.Certificate())
	guarded := RefuseInternalAddresses(&http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(connectRelay(t, origin.Listener.Addr().String())),
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}})

	// Allowed, and reaching the origin: the guard neither refuses the proxy nor
	// applies address checks that would need a local answer for this name.
	// httptest's certificate covers example.com, so this verifies.
	if _, err := guarded.Get("https://example.com/.well-known/oauth-protected-resource"); err != nil {
		t.Fatalf("https through a proxy should be allowed: %v", err)
	}
	if served != 1 {
		t.Fatalf("origin served %d requests, want the proxied request delivered", served)
	}

	// The rebinding attempt: a name the attacker owns, relayed to the same origin.
	// TLS is what refuses it, which is the binding the address checks were only
	// ever standing in for.
	_, err := guarded.Get("https://rebound.example/.well-known/oauth-protected-resource")
	if err == nil {
		t.Fatal("expected certificate validation to reject content from another origin")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("error = %v, want the certificate check to be what refused it", err)
	}
	if served != 1 {
		t.Fatalf("origin served %d requests, want the rebound handshake to have failed before any request", served)
	}
}

// TestProxiedHTTPSNeedsNoLocalResolution pins the reason the address checks are
// skipped rather than merely uninformative on the proxied path: in a proxied network
// DNS for external names is often the proxy's job, so a name with no local answer
// must still work.
func TestProxiedHTTPSNeedsNoLocalResolution(t *testing.T) {
	restore := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = restore })
	lookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		return nil, fmt.Errorf("no local answer for %q, as in a proxied network", host)
	}

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer origin.Close()
	pool := x509.NewCertPool()
	pool.AddCert(origin.Certificate())

	guarded := RefuseInternalAddresses(&http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(connectRelay(t, origin.Listener.Addr().String())),
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}})
	if _, err := guarded.Get("https://example.com/meta"); err != nil {
		t.Fatalf("a proxied https request must not require a local lookup: %v", err)
	}
}

// TestRelaxationIsNarrowerThanRefusal pins the asymmetry directly, as a property
// over the whole refusal set rather than a list of examples: every address the guard
// refuses must be checked, and only the loopback ones may also relax it.
//
// Written this way because the bug was not a wrong entry in a list — it was reusing
// one list to answer two questions. A property test fails if a future entry is added
// to ipblock.Default() and quietly inherits "local" along with "refused".
func TestRelaxationIsNarrowerThanRefusal(t *testing.T) {
	representative := map[string]bool{ // address -> may it relax the guard
		"127.0.0.1":       true,
		"127.9.9.9":       true,
		"::1":             true,
		"169.254.169.254": false,
		"169.254.1.1":     false,
		"fe80::1":         false,
		"224.0.0.1":       false,
		"ff02::1":         false,
		"0.0.0.0":         false,
		"::":              false,
	}
	for address, mayRelax := range representative {
		ip := net.ParseIP(address)
		if ip == nil {
			t.Fatalf("fixture %q is not an address", address)
		}
		refused, _ := ipblock.Default().Blocks(ip)
		if !refused {
			t.Fatalf("%s is expected to be in the refusal set; this test compares the two sets and needs it there", address)
		}

		host := address
		if ip.To4() == nil {
			host = "[" + address + "]"
		}
		local := HostIsAlwaysLocal("http://" + host + "/protected/tunnel")
		if local != mayRelax {
			t.Fatalf("%s: refused=%v local=%v, want local=%v — the relaxation set must contain only loopback",
				address, refused, local, mayRelax)
		}
		if local && !ip.IsLoopback() {
			t.Fatalf("%s relaxes the guard without being loopback", address)
		}
	}
}

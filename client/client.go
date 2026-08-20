package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"

	"authunnel/internal/authhttp"
	"authunnel/internal/authmeta"
	"authunnel/internal/safefs"
	"authunnel/internal/security"
	"authunnel/internal/wsconn"
)

var version = "dev"

const (
	socksVersion5       = 0x05
	socksCmdConnect     = 0x01
	socksAtypIPv4       = 0x01
	socksAtypDomain     = 0x03
	socksAtypIPv6       = 0x04
	socksReplySucceeded = 0x00
)

type authMode string

const (
	authModeManual authMode = "manual"
	authModeOIDC   authMode = "oidc"
)

// clientConfig captures command-line and environment driven behavior for the client process.
type clientConfig struct {
	AuthMode authMode

	AccessToken string

	// Every OIDC value below is optional. What is not supplied is discovered
	// from the tunnel server's RFC 9728 protected-resource metadata; see
	// ResourceURL. What is supplied always wins over what is discovered.
	OIDCIssuer string
	// OIDCMetadataURL overrides the well-known path derived from OIDCIssuer.
	// It changes only where the metadata document is fetched from, and it makes
	// OIDCIssuer unnecessary: with no issuer configured, the one the document
	// declares is adopted.
	//
	// What that gives up is the consistency check the issuer used to provide.
	// The document declares its own issuer, so with a value to compare against,
	// an honest-but-wrong metadata URL (staging for production, one tenant for
	// another) fails locally instead of after a browser login. With nothing to
	// compare against, it does not. Note this was never a trust anchor either
	// way: the issuer in the document is self-asserted and proves nothing about
	// the host serving it.
	OIDCMetadataURL  string
	OIDCClientID     string
	OIDCAudience     string
	OIDCResource     string
	OIDCScopes       string
	OIDCCache        string
	OIDCNoBrowser    bool
	OIDCRedirectPort int

	// NoResourceMetadata refuses the lookup outright: this client will not ask
	// the tunnel server for configuration, and every OIDC value it needs must be
	// supplied here.
	//
	// Not the same thing as supplying everything, which also results in no
	// lookup. That is an *outcome* of the configuration being complete; this is a
	// *prohibition*, so it still holds after someone shortens the ProxyCommand
	// line, and it is visible in that line rather than inferred from the absence
	// of a gap. It also moves the failure earlier: with the lookup refused,
	// completeness is knowable at parse time, so an incomplete configuration
	// fails before ssh has spawned anything instead of mid-connection.
	//
	// The name mirrors the server's --no-resource-metadata deliberately: same
	// document, opposite direction. There it means do not publish; here it means
	// do not read.
	NoResourceMetadata bool

	// ResourceURL is the tunnel endpoint's resource identifier, derived from
	// TunnelURL, and set only when some essential OIDC value is missing and the
	// lookup has not been refused. It is what the client fetches
	// protected-resource metadata from, so its emptiness is what guarantees a
	// fully-configured invocation makes no additional request.
	ResourceURL string

	TunnelURL        string
	UnixSocketPath   string
	ProxyCommandMode bool
	TargetHost       string
	TargetPort       int

	InsecureOIDCIssuer bool
	InsecureTunnelURL  bool

	HTTPClient     *http.Client
	AuthHTTPClient *http.Client
	Stdin          io.ReadCloser
	Stdout         io.Writer
	Stderr         io.Writer
	BrowserOpener  browserOpener
}

func clientUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: authunnel-client [flags] [host port]

Connection (required):

  --tunnel-url <url>           Tunnel endpoint URL. Secure schemes: https:// or
                               wss://. Plaintext http:// or ws:// requires
                               --insecure-tunnel-url
  AUTHUNNEL_TUNNEL_URL         Same, via environment variable (flag takes precedence)

Choose one operating mode (mutually exclusive):

  --proxycommand               SSH ProxyCommand mode; requires host and port arguments
                               (all other flags still apply)
  --unix-socket <path>         Expose a local SOCKS5 unix socket (default: proxy.sock)
                               (default mode when --proxycommand is not set)

Authentication:

  Managed OIDC is used unless ACCESS_TOKEN is set, and needs no configuration of its own:
  whatever is not given below is read from the tunnel server's RFC 9728 protected-resource
  metadata, which names its authorization server and may publish the client ID, scopes and
  audience to use. A value you do give always wins over the published one.

  Supply these to override what the server publishes, when it publishes nothing
  (--no-resource-metadata on the server side), or alongside --no-resource-metadata here to
  refuse the lookup entirely:

    --oidc-issuer <url>          OIDC issuer for managed login
    --oidc-client-id <id>        OIDC client ID
    --oidc-metadata-url <url>    Authorization server metadata document URL, overriding the well-known
                                 path derived from --oidc-issuer. For an authorization server publishing
                                 RFC 8414 metadata at a path the OIDC derivation cannot construct. Usable
                                 without --oidc-issuer, in which case the document's own issuer is
                                 adopted rather than checked.
    --oidc-audience <string>     Auth0-style 'audience' parameter requested during managed login
    --oidc-resource <url>        RFC 8707 'resource' parameter; sets the token 'aud' on providers that bind it (e.g. AWS Cognito)
    --oidc-scopes <scopes>       Space-delimited OIDC scopes (default: the scopes the server publishes,
                                 else openid offline_access)
    --oidc-cache <path>          Token cache path for managed OIDC login
    --oidc-no-browser            Print the authorization URL without opening a browser
    --oidc-redirect-port <port>  Loopback port for OIDC callback; 0 = random port
    --no-resource-metadata       Never read configuration from the tunnel server; --oidc-client-id
                                 and one of --oidc-issuer / --oidc-metadata-url are then required,
                                 and a missing one fails at startup rather than at first use

  Manual token (not recommended; for testing only), mutually exclusive with the above:

    ACCESS_TOKEN                 Bearer token via environment variable

Other:

  version, --version           Print version and exit

Development / unsafe overrides (do not use in production):

  --insecure-oidc-issuer       Allow non-HTTPS OIDC issuer and metadata URLs, discovered as well
                               as configured
  --insecure-tunnel-url        Allow a non-HTTPS tunnel endpoint URL
`)
}

// resourceURLForTunnel turns the tunnel URL into the resource identifier the
// protected-resource metadata is looked up under, and which the cached
// credentials for that tunnel are scoped to.
//
// The websocket schemes are rewritten to their HTTP equivalents because that is
// what they already are on the wire — github.com/coder/websocket sends the
// upgrade request over http(s) — and RFC 9728's derivation is defined for http
// and https.
//
// **The query is part of the identifier and is kept.** The WebSocket dial sends it,
// so `?tenant=a` and `?tenant=b` are two resources as far as the server is
// concerned. Dropping it here would collapse them to one identifier — one set of
// discovered configuration and, since the identifier is the cache key, one set of
// cached credentials — so a token obtained for one tenant would be presented for
// the other.
//
// The fragment is dropped rather than refused, because this is where the client
// sanitises its *own* input: a fragment is never sent on the wire, so one in
// --tunnel-url is inert, and failing discovery over it would be a worse answer
// than ignoring it. A fragment arriving in a *document* is refused instead — see
// authmeta.NormalizeResourceIdentifier.
func resourceURLForTunnel(tunnelURL string) (string, error) {
	u, err := url.Parse(tunnelURL)
	if err != nil {
		return "", fmt.Errorf("--tunnel-url %q is not a valid URL", tunnelURL)
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	}
	// Built from the escaped path so an encoded separator survives: assigning
	// url.URL.Path would re-encode from the decoded form, turning
	// /tenant%2Fone/tunnel into /tenant/one/tunnel and merging two resources a
	// path-routing proxy keeps apart — into one discovery result and one cache
	// entry. The fragment is dropped by omission, which is the intent.
	resourceURL, err := url.Parse(u.Scheme + "://" + u.Host + u.EscapedPath())
	if err != nil {
		return "", fmt.Errorf("--tunnel-url %q is not a valid URL", tunnelURL)
	}
	authmeta.CarryQuery(resourceURL, u)
	return resourceURL.String(), nil
}

func main() {
	// Before anything can log: errors reaching this terminal include text chosen by
	// the tunnel server and by whatever authorization server it named, and some of
	// that text is formatted by dependencies rather than here. See safeLogWriter.
	installSafeLogging()

	cfg, err := parseClientConfig(os.Args[1:], os.Getenv)
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	source, err := newAuthTokenSource(cfg)
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	if err := security.Harden(); err != nil {
		log.Fatalf("harden failed: %v", err)
	}

	ctx := context.Background()
	if cfg.ProxyCommandMode {
		if err := runProxyCommandMode(ctx, cfg, source); err != nil {
			log.Fatalf("proxycommand mode failed: %v", err)
		}
		return
	}

	if err := runUnixSocketMode(ctx, cfg, source); err != nil {
		log.Fatalf("unix socket mode failed: %v", err)
	}
}

// parseClientConfig keeps auth-mode selection explicit so developers can reason
// about startup behavior from one place. Manual token mode and managed OIDC are
// intentionally mutually exclusive to avoid surprising precedence rules.
func parseClientConfig(args []string, getenv func(string) string) (clientConfig, error) {
	cfg := clientConfig{
		AccessToken:   getenv("ACCESS_TOKEN"),
		Stdin:         os.Stdin,
		Stdout:        os.Stdout,
		Stderr:        os.Stderr,
		BrowserOpener: defaultBrowserOpener,
	}

	if len(args) > 0 && args[0] == "help" {
		clientUsage(os.Stdout)
		return cfg, flag.ErrHelp
	}
	if len(args) > 0 && args[0] == "version" {
		fmt.Fprintln(os.Stdout, version)
		return cfg, flag.ErrHelp
	}

	fs := flag.NewFlagSet("authunnel-client", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var showVersion bool
	fs.BoolVar(&showVersion, "version", false, "Print version and exit")
	fs.StringVar(&cfg.TunnelURL, "tunnel-url", getenv("AUTHUNNEL_TUNNEL_URL"), "Tunnel endpoint URL. Secure schemes: https:// or wss://. Plaintext http:// or ws:// requires --insecure-tunnel-url. Falls back to AUTHUNNEL_TUNNEL_URL.")
	fs.StringVar(&cfg.UnixSocketPath, "unix-socket", "proxy.sock", "Unix socket path for local SOCKS5 clients")
	fs.BoolVar(&cfg.ProxyCommandMode, "proxycommand", false, "Run as ssh ProxyCommand helper. Requires host and port positional arguments.")
	fs.StringVar(&cfg.OIDCIssuer, "oidc-issuer", "", "OIDC issuer used for managed login")
	fs.StringVar(&cfg.OIDCMetadataURL, "oidc-metadata-url", "",
		"Authorization server metadata document URL, overriding the well-known path derived from --oidc-issuer. For an authorization server publishing RFC 8414 metadata at a path the OIDC derivation cannot construct. Usable without --oidc-issuer, in which case the document's own issuer is adopted rather than checked against one.")
	fs.StringVar(&cfg.OIDCClientID, "oidc-client-id", "", "OIDC client ID used for managed login")
	fs.StringVar(&cfg.OIDCAudience, "oidc-audience", "", "Auth0-style 'audience' parameter requested during managed login")
	fs.StringVar(&cfg.OIDCResource, "oidc-resource", "", "RFC 8707 'resource' parameter requested during managed login; sets the token 'aud' on providers that bind it (e.g. AWS Cognito)")
	// Empty rather than the default value, so "not set" stays distinguishable
	// from "set to the default": the resource server's published default must be
	// able to win over the fallback but not over an explicit choice.
	fs.StringVar(&cfg.OIDCScopes, "oidc-scopes", "", "Space-delimited OIDC scopes for managed login (default: the scopes the tunnel server publishes, else \"openid offline_access\")")
	fs.StringVar(&cfg.OIDCCache, "oidc-cache", "", "Token cache path for managed OIDC login")
	fs.BoolVar(&cfg.OIDCNoBrowser, "oidc-no-browser", false, "Print the OIDC authorization URL without attempting to open a browser")
	fs.IntVar(&cfg.OIDCRedirectPort, "oidc-redirect-port", 0, "Loopback port for the OIDC callback listener; 0 chooses a random port")
	fs.BoolVar(&cfg.NoResourceMetadata, "no-resource-metadata", false,
		"Do not read OIDC configuration from the tunnel server's protected-resource metadata; every value must then be passed as a flag")
	fs.BoolVar(&cfg.InsecureOIDCIssuer, "insecure-oidc-issuer", false, "Allow non-HTTPS OIDC issuer and metadata URLs (development only; do not use in production)")
	fs.BoolVar(&cfg.InsecureTunnelURL, "insecure-tunnel-url", false, "Allow a non-HTTPS tunnel endpoint URL (development only; do not use in production)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			clientUsage(os.Stdout)
		}
		return cfg, err
	}
	if showVersion {
		fmt.Fprintln(os.Stdout, version)
		return cfg, flag.ErrHelp
	}

	var oidcScopesSet bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "oidc-scopes" {
			oidcScopesSet = true
		}
	})

	hasOIDC := cfg.OIDCIssuer != "" || cfg.OIDCClientID != ""
	if cfg.OIDCRedirectPort < 0 || cfg.OIDCRedirectPort > 65535 {
		return cfg, errors.New("--oidc-redirect-port must be between 0 and 65535")
	}
	if cfg.OIDCRedirectPort != 0 && cfg.OIDCRedirectPort < 1024 {
		return cfg, errors.New("--oidc-redirect-port must be 0 (random) or >= 1024; low ports are unavailable after capability hardening")
	}
	// --no-resource-metadata is in this list even though it creates no precedence
	// ambiguity — manual mode never looks anything up — because a flag that
	// cannot take effect is a configuration error, not a no-op. Same rule the
	// server applies to a --client-* hint it would never publish.
	if cfg.AccessToken != "" && (hasOIDC || cfg.OIDCMetadataURL != "" || cfg.OIDCAudience != "" || cfg.OIDCResource != "" || cfg.OIDCRedirectPort != 0 || cfg.OIDCCache != "" || cfg.OIDCNoBrowser || cfg.NoResourceMetadata || oidcScopesSet) {
		return cfg, errors.New("ACCESS_TOKEN cannot be combined with managed OIDC flags")
	}
	// Managed OIDC needs a client identity and somewhere to find the
	// authorization server's metadata. Neither is required as a flag, because
	// both are already known to the server being connected to: when either is
	// missing the tunnel server is asked for it, and --tunnel-url (checked below)
	// is the only mandatory flag.
	incomplete := cfg.OIDCClientID == "" || (cfg.OIDCIssuer == "" && cfg.OIDCMetadataURL == "")
	needsDiscovery := cfg.AccessToken == "" && !cfg.NoResourceMetadata && incomplete
	// Derived from needsDiscovery rather than restating its condition, so there is
	// one definition of "the tunnel server will be asked". Restated, the two could
	// disagree — and the disagreement would be invisible, since a configuration
	// that is complete produces no lookup either way. This phrasing also means a
	// test that the flag rejects an incomplete configuration is a test that the
	// flag suppresses the lookup: break the suppression and this stops firing.
	if cfg.AccessToken == "" && incomplete && !needsDiscovery {
		return cfg, errors.New("--no-resource-metadata requires --oidc-client-id and one of --oidc-issuer or --oidc-metadata-url: with the tunnel server lookup refused, nothing else can supply them")
	}

	if cfg.AccessToken != "" {
		cfg.AuthMode = authModeManual
	} else {
		cfg.AuthMode = authModeOIDC
		if err := applyManagedOIDCDefaults(&cfg, needsDiscovery); err != nil {
			return cfg, err
		}
	}

	if cfg.TunnelURL == "" {
		return cfg, errors.New("tunnel endpoint URL is required: pass --tunnel-url or set AUTHUNNEL_TUNNEL_URL")
	}
	tunnelU, err := url.Parse(cfg.TunnelURL)
	if err != nil || tunnelU.Host == "" {
		return cfg, fmt.Errorf("--tunnel-url %q is not a valid URL", cfg.TunnelURL)
	}
	// github.com/coder/websocket accepts ws/wss and rewrites them to
	// http/https for the authenticated upgrade request, so all four schemes
	// are usable here. Secure schemes (https/wss) are allowed by default;
	// plaintext schemes (http/ws) require the explicit insecure override.
	switch tunnelU.Scheme {
	case "https", "wss":
	case "http", "ws":
		if !cfg.InsecureTunnelURL {
			return cfg, errors.New("--tunnel-url must use a secure scheme (https:// or wss://); use --insecure-tunnel-url to allow plaintext http:// or ws:// (development only)")
		}
	default:
		return cfg, errors.New("--tunnel-url must use one of https://, wss://, http://, or ws://")
	}
	if err := validateOIDCValues(cfg); err != nil {
		return cfg, err
	}
	if needsDiscovery {
		// Derived after --tunnel-url has been validated, so this cannot produce
		// a resource identifier from a URL the client would have refused.
		resourceURL, err := resourceURLForTunnel(cfg.TunnelURL)
		if err != nil {
			return cfg, err
		}
		cfg.ResourceURL = resourceURL
	}

	if cfg.ProxyCommandMode {
		positional := fs.Args()
		if len(positional) != 2 {
			return cfg, errors.New("proxycommand mode requires host and port positional arguments")
		}
		cfg.TargetHost = positional[0]
		port, err := strconv.Atoi(positional[1])
		if err != nil || port < 1 || port > 65535 {
			return cfg, fmt.Errorf("invalid target port %q", positional[1])
		}
		cfg.TargetPort = port
	}

	return cfg, nil
}

// applyManagedOIDCDefaults fills in what managed mode needs and the operator did
// not supply. Called only in managed mode, after needsDiscovery is known.
func applyManagedOIDCDefaults(cfg *clientConfig, needsDiscovery bool) error {
	cfg.OIDCScopes = normalizeScopes(cfg.OIDCScopes)
	// The scope default is applied here only when nothing will be discovered.
	// Applying it unconditionally would make the fallback indistinguishable from
	// an explicit choice, and the resource server's published default could then
	// never win — the resolver applies the same default itself when the document
	// offers none.
	if cfg.OIDCScopes == "" && !needsDiscovery {
		cfg.OIDCScopes = normalizeScopes(defaultOIDCScopes)
	}
	if cfg.OIDCCache == "" {
		cachePath, err := defaultOIDCCachePath()
		if err != nil {
			return err
		}
		cfg.OIDCCache = cachePath
	}
	return nil
}

// validateOIDCValues applies the shape rules to whatever OIDC values were
// configured. Everything here is optional, so each check is skipped when its
// value is absent; the equivalents for *discovered* values live in
// internal/authmeta, deliberately holding remote input to the same rules.
func validateOIDCValues(cfg clientConfig) error {
	// One rule for both URLs, shared with the server so the two cannot drift:
	// https required unless --insecure-oidc-issuer, other schemes rejected by
	// name rather than as a generic "not a valid URL".
	for _, checked := range []struct{ flag, value string }{
		{"--oidc-issuer", cfg.OIDCIssuer},
		{"--oidc-metadata-url", cfg.OIDCMetadataURL},
	} {
		if checked.value == "" {
			continue
		}
		if err := authhttp.CheckConfiguredURL(checked.flag, checked.value, cfg.InsecureOIDCIssuer); err != nil {
			return err
		}
	}
	if cfg.OIDCResource != "" {
		// RFC 8707 resource indicators: the value MUST be an absolute URI and
		// MUST NOT contain a fragment. Validated up front so a malformed value
		// surfaces as a clear startup error rather than a confusing failure at
		// the provider partway through the browser login.
		if err := authmeta.ValidateResourceIndicator(cfg.OIDCResource); err != nil {
			return fmt.Errorf("--oidc-resource: %w", err)
		}
	}
	return nil
}

// runUnixSocketMode exposes a local unix-domain SOCKS5 endpoint, with each accepted
// connection tunneled via a dedicated authenticated websocket connection.
func runUnixSocketMode(ctx context.Context, cfg clientConfig, source authTokenSource) error {
	if err := ensureUnixSocketDir(cfg.UnixSocketPath); err != nil {
		return err
	}

	if err := safefs.SafelyRemoveExistingSocket(cfg.UnixSocketPath); err != nil {
		return err
	}

	var proxyListen net.Listener
	// umask 0o077 ensures the socket inode is created with owner-only
	// permissions in the first place, closing the window in which another
	// local user could have connected between bind and the follow-up Chmod.
	if err := safefs.WithUmask(0o077, func() error {
		listener, listenErr := net.Listen("unix", cfg.UnixSocketPath)
		if listenErr != nil {
			return listenErr
		}
		proxyListen = listener
		return nil
	}); err != nil {
		return fmt.Errorf("unix socket listen problem: %w", err)
	}
	defer proxyListen.Close()
	defer os.Remove(cfg.UnixSocketPath)
	// Belt-and-braces tightening for platforms/filesystems that do not honour
	// umask on AF_UNIX bind.
	if err := tightenUnixSocketPermissions(cfg.UnixSocketPath); err != nil {
		return err
	}

	log.Printf("listening for local SOCKS5 clients on unix socket %s", cfg.UnixSocketPath)
	for {
		localConn, err := proxyListen.Accept()
		if err != nil {
			return fmt.Errorf("accept problem: %w", err)
		}

		go func(conn net.Conn) {
			if err := handleSOCKSClient(ctx, cfg, source, conn); err != nil {
				log.Printf("connection failed: %v", err)
			}
		}(localConn)
	}
}

func ensureUnixSocketDir(unixSocketPath string) error {
	// A bare filename resolves to "." — the current working directory.
	// EnsurePrivateDir canonicalises via filepath.Abs + EvalSymlinks before
	// validating, so the cwd is subject to the same ancestor/ownership
	// rules as any explicit path. We intentionally do not exempt it: binding
	// a socket under a shared cwd (e.g. /tmp) is exactly the attack we're
	// defending against.
	return safefs.EnsurePrivateDir(filepath.Dir(unixSocketPath))
}

func tightenUnixSocketPermissions(unixSocketPath string) error {
	if err := os.Chmod(unixSocketPath, 0o600); err != nil {
		return fmt.Errorf("failed to set socket permissions on %q: %w", unixSocketPath, err)
	}
	return nil
}

func handleSOCKSClient(ctx context.Context, cfg clientConfig, source authTokenSource, localConn net.Conn) error {
	token, err := source.AccessToken(ctx, true)
	if err != nil {
		_ = localConn.Close()
		return fmt.Errorf("resolve access token: %w", err)
	}

	wsConn, _, err := dialTunnelWithRecovery(ctx, cfg, source, token)
	if err != nil {
		_ = localConn.Close()
		return fmt.Errorf("websocket dial failed: %w", err)
	}

	// Scope the context to this tunnel so the control-message goroutine
	// exits when proxy() returns, avoiding goroutine leaks in unix-socket
	// mode where many connections are handled sequentially.
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	remoteConn := wsconn.New(connCtx, wsConn)
	go handleControlMessages(connCtx, remoteConn, source)
	proxy(localConn, remoteConn)
	return nil
}

// runProxyCommandMode is designed for SSH ProxyCommand integration:
//
//	ProxyCommand /path/to/client --proxycommand %h %p
//
// It opens a websocket tunnel, performs SOCKS5 CONNECT for the target host/port,
// then bridges stdin/stdout with the resulting network stream. A background
// goroutine handles server-initiated control messages (expiry warnings, token
// refresh) so the tunnel can be extended without disrupting the SSH session.
func runProxyCommandMode(ctx context.Context, cfg clientConfig, source authTokenSource) error {
	token, err := source.AccessToken(ctx, true)
	if err != nil {
		return fmt.Errorf("resolve access token: %w", err)
	}

	wsConn, _, err := dialTunnelWithRecovery(ctx, cfg, source, token)
	if err != nil {
		return fmt.Errorf("websocket dial failed: %w", err)
	}
	defer wsConn.CloseNow()

	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	remoteConn := wsconn.New(connCtx, wsConn)
	defer remoteConn.Close()

	go handleControlMessages(connCtx, remoteConn, source)

	if err := performSOCKS5Connect(remoteConn, cfg.TargetHost, cfg.TargetPort); err != nil {
		return fmt.Errorf("socks5 connect failed: %w", err)
	}

	stdioConn := &stdioConn{in: cfg.Stdin, out: cfg.Stdout}
	proxy(stdioConn, remoteConn)
	return nil
}

// dialTunnelWithRecovery dials, and on a rejection gives the token source one
// chance to notice that the server's configuration has moved.
//
// The case this exists for: a cached access token that is still valid by its own
// `exp` is returned without resolving anything, which is the fast path working as
// designed. If the server has since changed issuer, client ID or audience, that
// token is refused on every invocation and nothing in the flow ever looks at the
// server's metadata again — the user is locked out until the cache expires or
// they delete it by hand.
//
// Exactly one retry, and only when re-resolution shows the configuration actually
// changed; see TokenAfterRejection. Both conditions matter: without the first this
// could loop, and without the second every rejection — a disabled account, a
// revoked scope — would open a browser that cannot help.
//
// 403 counts alongside 401, and this is the part worth reading twice. The
// server answers a token that failed validation with 403 — wrong issuer, wrong
// audience, bad signature — and reserves 401 for a missing or malformed header.
// The configuration-changed case therefore arrives as a 403, which by RFC 7235
// carries no WWW-Authenticate challenge and so carries no `resource_metadata`
// either. Keying this recovery on the challenge, as the RFC 9728 §5.2 flow
// suggests, would miss every case it exists for; keying it on the status code
// catches them. tunnelserver's TestChallengeAbsentOnSuccessAndOnForbidden pins
// the server half of that.
func dialTunnelWithRecovery(ctx context.Context, cfg clientConfig, source authTokenSource, token string) (*websocket.Conn, *http.Response, error) {
	conn, resp, err := dialTunnel(ctx, cfg, token)
	if err == nil || !isAuthRejection(err) {
		return conn, resp, err
	}
	replacement, retryErr := source.TokenAfterRejection(ctx)
	if retryErr != nil {
		// Report what the server said, not what re-resolution then hit: the
		// rejection is the user's actual problem and the recovery attempt was
		// ours.
		log.Printf("re-reading server configuration after a rejected token failed: %v", retryErr)
		return conn, resp, err
	}
	if replacement == "" {
		return conn, resp, err
	}
	log.Println("server configuration changed; retrying with a token obtained under the new one")
	return dialTunnel(ctx, cfg, replacement)
}

// isAuthRejection reports whether the server refused the credential, as opposed
// to refusing the request for capacity or rate reasons.
func isAuthRejection(err error) bool {
	var dialErr *tunnelDialError
	if !errors.As(err, &dialErr) {
		return false
	}
	return dialErr.StatusCode == http.StatusUnauthorized || dialErr.StatusCode == http.StatusForbidden
}

func dialTunnel(ctx context.Context, cfg clientConfig, token string) (*websocket.Conn, *http.Response, error) {
	options := &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	}
	if cfg.HTTPClient != nil {
		options.HTTPClient = cfg.HTTPClient
	}
	conn, resp, err := websocket.Dial(ctx, cfg.TunnelURL, options)
	if err != nil && resp != nil {
		// The server rejected the upgrade with a real HTTP response. The
		// coder/websocket error wraps the body snippet but does not expose
		// the status code or headers, so decorate the error here with the
		// information operators need to distinguish 401 (auth) from 429/503
		// (admission limits) and to honour Retry-After manually.
		return conn, resp, &tunnelDialError{
			StatusCode: resp.StatusCode,
			RetryAfter: resp.Header.Get("Retry-After"),
			Err:        err,
		}
	}
	return conn, resp, err
}

// tunnelDialError augments a websocket dial failure with the server's HTTP
// status and Retry-After header so the CLI can print a message that tells
// the operator what went wrong and whether to retry.
type tunnelDialError struct {
	StatusCode int
	RetryAfter string
	Err        error
}

func (e *tunnelDialError) Error() string {
	msg := e.categoryMessage()
	if e.RetryAfter != "" && (e.StatusCode == http.StatusTooManyRequests || e.StatusCode == http.StatusServiceUnavailable) {
		return fmt.Sprintf("%s (retry after %s)", msg, e.RetryAfter)
	}
	return msg
}

func (e *tunnelDialError) Unwrap() error { return e.Err }

func (e *tunnelDialError) categoryMessage() string {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return "tunnel authentication rejected"
	case http.StatusForbidden:
		return "tunnel authorization rejected"
	case http.StatusTooManyRequests:
		return "tunnel rate-limited by server"
	case http.StatusServiceUnavailable:
		return "tunnel server at capacity"
	default:
		// Unhandled status: preserve the underlying coder/websocket message
		// (which carries the server's body snippet) so operators debugging an
		// unexpected upgrade failure do not lose diagnostic detail.
		if e.Err != nil {
			return fmt.Sprintf("tunnel dial rejected with HTTP %d: %v", e.StatusCode, e.Err)
		}
		return fmt.Sprintf("tunnel dial rejected with HTTP %d", e.StatusCode)
	}
}

// handleControlMessages reads from the MultiplexConn's control channel and
// responds to server-initiated longevity messages.
//
// Every string taken from a control message is logged with %q. These are chosen by
// the tunnel server, they reach a terminal under ssh and a log aggregator after
// that, and none of them passes through a parser that would reject control bytes —
// so raw output would let the far end rewrite the line reporting it or forge a
// record beside it.
//
// When the server warns that the token is about to expire, the client attempts to
// obtain a fresh token and sends it back over the control channel.
func handleControlMessages(ctx context.Context, conn *wsconn.MultiplexConn, source authTokenSource) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-conn.ControlChan():
			if !ok {
				return
			}
			switch msg.Type {
			case "expiry_warning":
				var payload struct {
					Reason string `json:"reason"`
				}
				_ = json.Unmarshal(msg.Data, &payload)
				if payload.Reason != "token" {
					log.Printf("server warning: connection expiring due to %q", payload.Reason)
					continue
				}
				newToken, err := source.AccessToken(ctx, false)
				if err != nil {
					log.Printf("token refresh failed: %v", err)
					continue
				}
				tokenData, _ := json.Marshal(map[string]string{"access_token": newToken})
				if err := conn.SendControl(wsconn.ControlMessage{
					Type: "token_refresh",
					Data: tokenData,
				}); err != nil {
					log.Printf("failed to send refreshed token: %v", err)
				}
			case "token_accepted":
				log.Println("server accepted refreshed token")
			case "token_rejected":
				var payload struct {
					Reason string `json:"reason"`
				}
				_ = json.Unmarshal(msg.Data, &payload)
				log.Printf("server rejected token refresh: %q", payload.Reason)
			case "disconnect":
				var payload struct {
					Reason string `json:"reason"`
				}
				_ = json.Unmarshal(msg.Data, &payload)
				log.Printf("server disconnecting: %q", payload.Reason)
				_ = conn.Close()
				return
			}
		}
	}
}

// performSOCKS5Connect performs a minimal no-auth SOCKS5 handshake and CONNECT request.
func performSOCKS5Connect(conn net.Conn, targetHost string, targetPort int) error {
	// Client greeting: SOCKS5, 1 auth method, no-authentication.
	if _, err := conn.Write([]byte{socksVersion5, 0x01, 0x00}); err != nil {
		return fmt.Errorf("write greeting: %w", err)
	}

	greetingResponse := make([]byte, 2)
	if _, err := io.ReadFull(conn, greetingResponse); err != nil {
		return fmt.Errorf("read greeting response: %w", err)
	}
	if greetingResponse[0] != socksVersion5 {
		return fmt.Errorf("unexpected socks version in greeting response: %d", greetingResponse[0])
	}
	if greetingResponse[1] != 0x00 {
		return fmt.Errorf("server does not accept no-authentication method: %d", greetingResponse[1])
	}

	request, err := buildSOCKS5ConnectRequest(targetHost, targetPort)
	if err != nil {
		return err
	}
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("write connect request: %w", err)
	}

	if err := readSOCKS5ConnectReply(conn); err != nil {
		return err
	}
	return nil
}

// buildSOCKS5ConnectRequest emits the minimal CONNECT frame the server-side
// SOCKS implementation expects after the no-auth greeting has completed.
func buildSOCKS5ConnectRequest(targetHost string, targetPort int) ([]byte, error) {
	if targetPort < 1 || targetPort > 65535 {
		return nil, fmt.Errorf("invalid target port: %d", targetPort)
	}

	request := []byte{socksVersion5, socksCmdConnect, 0x00}
	if ip := net.ParseIP(targetHost); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, socksAtypIPv4)
			request = append(request, ipv4...)
		} else {
			request = append(request, socksAtypIPv6)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(targetHost) == 0 || len(targetHost) > 255 {
			return nil, fmt.Errorf("target host length must be between 1 and 255")
		}
		// #nosec G115 -- length is range-checked on the preceding line.
		request = append(request, socksAtypDomain, byte(len(targetHost)))
		request = append(request, []byte(targetHost)...)
	}

	// #nosec G115 -- targetPort is range-checked at the top of this function.
	request = append(request, byte(targetPort>>8), byte(targetPort))
	return request, nil
}

// readSOCKS5ConnectReply consumes the remainder of the CONNECT reply so the
// bridged application stream starts aligned on the first payload byte.
func readSOCKS5ConnectReply(conn net.Conn) error {
	replyHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, replyHeader); err != nil {
		return fmt.Errorf("read connect reply header: %w", err)
	}

	if replyHeader[0] != socksVersion5 {
		return fmt.Errorf("unexpected socks version in connect reply: %d", replyHeader[0])
	}
	if replyHeader[1] != socksReplySucceeded {
		return fmt.Errorf("connect rejected with reply code %d", replyHeader[1])
	}

	var addrLen int
	switch replyHeader[3] {
	case socksAtypIPv4:
		addrLen = 4
	case socksAtypIPv6:
		addrLen = 16
	case socksAtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return fmt.Errorf("read domain length from connect reply: %w", err)
		}
		addrLen = int(lenBuf[0])
	default:
		return fmt.Errorf("unexpected address type in connect reply: %d", replyHeader[3])
	}

	remaining := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, remaining); err != nil {
		return fmt.Errorf("read remaining connect reply bytes: %w", err)
	}
	return nil
}

// stdioConn adapts stdin/stdout into a net.Conn-like type usable by proxy().
type stdioConn struct {
	in        io.ReadCloser
	out       io.Writer
	closeOnce sync.Once
	closeErr  error
}

func (s *stdioConn) Read(p []byte) (int, error)  { return s.in.Read(p) }
func (s *stdioConn) Write(p []byte) (int, error) { return s.out.Write(p) }
func (s *stdioConn) Close() error {
	s.closeOnce.Do(func() {
		// Closing stdin in ProxyCommand mode is intentional so blocked reads
		// are interrupted and proxy shutdown can complete deterministically.
		s.closeErr = s.in.Close()
	})
	return s.closeErr
}
func (s *stdioConn) LocalAddr() net.Addr                { return dummyAddr("stdio-local") }
func (s *stdioConn) RemoteAddr() net.Addr               { return dummyAddr("stdio-remote") }
func (s *stdioConn) SetDeadline(_ time.Time) error      { return nil }
func (s *stdioConn) SetReadDeadline(_ time.Time) error  { return nil }
func (s *stdioConn) SetWriteDeadline(_ time.Time) error { return nil }

// dummyAddr provides minimal net.Addr support for stdioConn.
type dummyAddr string

func (d dummyAddr) Network() string { return "stdio" }
func (d dummyAddr) String() string  { return string(d) }

func proxy(conn1, conn2 net.Conn) {
	log.Println("proxy function routine started")
	defer conn1.Close()
	defer conn2.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn1, conn2)
		// Signal peer that no more data is coming. Full Close is acceptable here
		// because both endpoints are tunnel/session scoped and are torn down once
		// either side stops producing bytes.
		_ = conn1.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn2, conn1)
		// Mirror the same shutdown semantics in the opposite direction.
		_ = conn2.Close()
	}()

	wg.Wait()
	log.Println("proxy function routine finished")
}

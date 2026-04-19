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

	OIDCIssuer       string
	OIDCClientID     string
	OIDCAudience     string
	OIDCScopes       string
	OIDCCache        string
	OIDCNoBrowser    bool
	OIDCRedirectPort int

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

Choose one operating mode (mutually exclusive):

  --proxycommand               SSH ProxyCommand mode; requires host and port arguments
                               (all other flags still apply)
  --unix-socket <path>         Expose a local SOCKS5 unix socket (default: proxy.sock)
                               (default mode when --proxycommand is not set)

Choose one authentication method (mutually exclusive):

  Managed OIDC (typical):
    --oidc-issuer <url>          OIDC issuer for managed login (required with --oidc-client-id)
    --oidc-client-id <id>        OIDC client ID (required with --oidc-issuer)
    --oidc-audience <string>     Audience/resource requested during managed login
    --oidc-scopes <scopes>       Space-delimited OIDC scopes (default: openid offline_access)
    --oidc-cache <path>          Token cache path for managed OIDC login
    --oidc-no-browser            Print the authorization URL without opening a browser
    --oidc-redirect-port <port>  Loopback port for OIDC callback; 0 = random port

  Manual token (not recommended; for testing only):
    --access-token <token>       Bearer token passed as a flag
    ACCESS_TOKEN                 Bearer token via environment variable

Connection (one of these is required):

  --tunnel-url <url>           Tunnel endpoint URL. Secure schemes: https:// or
                               wss://. Plaintext http:// or ws:// requires
                               --insecure-tunnel-url
  AUTHUNNEL_TUNNEL_URL         Same, via environment variable (flag takes precedence)

Other:

  version, --version           Print version and exit

Development / unsafe overrides (do not use in production):

  --insecure-oidc-issuer       Allow a non-HTTPS OIDC issuer URL
  --insecure-tunnel-url        Allow a non-HTTPS tunnel endpoint URL
`)
}

func main() {
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
	fs.StringVar(&cfg.AccessToken, "access-token", cfg.AccessToken, "Bearer token for manual authentication (not recommended; prefer OIDC or ACCESS_TOKEN env var)")
	fs.StringVar(&cfg.TunnelURL, "tunnel-url", getenv("AUTHUNNEL_TUNNEL_URL"), "Tunnel endpoint URL. Secure schemes: https:// or wss://. Plaintext http:// or ws:// requires --insecure-tunnel-url. Falls back to AUTHUNNEL_TUNNEL_URL.")
	fs.StringVar(&cfg.UnixSocketPath, "unix-socket", "proxy.sock", "Unix socket path for local SOCKS5 clients")
	fs.BoolVar(&cfg.ProxyCommandMode, "proxycommand", false, "Run as ssh ProxyCommand helper. Requires host and port positional arguments.")
	fs.StringVar(&cfg.OIDCIssuer, "oidc-issuer", "", "OIDC issuer used for managed login")
	fs.StringVar(&cfg.OIDCClientID, "oidc-client-id", "", "OIDC client ID used for managed login")
	fs.StringVar(&cfg.OIDCAudience, "oidc-audience", "", "Audience/resource requested during managed login")
	fs.StringVar(&cfg.OIDCScopes, "oidc-scopes", "openid offline_access", "Space-delimited OIDC scopes for managed login")
	fs.StringVar(&cfg.OIDCCache, "oidc-cache", "", "Token cache path for managed OIDC login")
	fs.BoolVar(&cfg.OIDCNoBrowser, "oidc-no-browser", false, "Print the OIDC authorization URL without attempting to open a browser")
	fs.IntVar(&cfg.OIDCRedirectPort, "oidc-redirect-port", 0, "Loopback port for the OIDC callback listener; 0 chooses a random port")
	fs.BoolVar(&cfg.InsecureOIDCIssuer, "insecure-oidc-issuer", false, "Allow a non-HTTPS OIDC issuer URL (development only; do not use in production)")
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
	if cfg.AccessToken != "" && (hasOIDC || cfg.OIDCAudience != "" || cfg.OIDCRedirectPort != 0 || cfg.OIDCCache != "" || cfg.OIDCNoBrowser || oidcScopesSet) {
		return cfg, errors.New("--access-token / ACCESS_TOKEN cannot be combined with managed OIDC flags")
	}
	if (cfg.OIDCIssuer == "") != (cfg.OIDCClientID == "") {
		return cfg, errors.New("managed OIDC mode requires both --oidc-issuer and --oidc-client-id")
	}
	if cfg.AccessToken == "" && cfg.OIDCIssuer == "" {
		return cfg, errors.New("either ACCESS_TOKEN or both --oidc-issuer and --oidc-client-id are required")
	}

	if cfg.AccessToken != "" {
		cfg.AuthMode = authModeManual
	} else {
		cfg.AuthMode = authModeOIDC
		cfg.OIDCScopes = normalizeScopes(cfg.OIDCScopes)
		if cfg.OIDCScopes == "" {
			cfg.OIDCScopes = normalizeScopes("openid offline_access")
		}
		if cfg.OIDCCache == "" {
			cachePath, err := defaultOIDCCachePath()
			if err != nil {
				return cfg, err
			}
			cfg.OIDCCache = cachePath
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
	if cfg.OIDCIssuer != "" {
		issuerU, err := url.Parse(cfg.OIDCIssuer)
		if err != nil || issuerU.Host == "" {
			return cfg, fmt.Errorf("--oidc-issuer %q is not a valid URL", cfg.OIDCIssuer)
		}
		if issuerU.Scheme != "https" && !cfg.InsecureOIDCIssuer {
			return cfg, errors.New("--oidc-issuer must use an https:// URL; use --insecure-oidc-issuer to allow plaintext (development only)")
		}
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

// runUnixSocketMode exposes a local unix-domain SOCKS5 endpoint, with each accepted
// connection tunneled via a dedicated authenticated websocket connection.
func runUnixSocketMode(ctx context.Context, cfg clientConfig, source authTokenSource) error {
	if err := ensureUnixSocketDir(cfg.UnixSocketPath); err != nil {
		return err
	}

	if err := safelyRemoveExistingSocket(cfg.UnixSocketPath); err != nil {
		return err
	}

	var proxyListen net.Listener
	// umask 0o077 ensures the socket inode is created with owner-only
	// permissions in the first place, closing the window in which another
	// local user could have connected between bind and the follow-up Chmod.
	if err := withUmask(0o077, func() error {
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
	// ensurePrivateDir canonicalises via filepath.Abs + EvalSymlinks before
	// validating, so the cwd is subject to the same ancestor/ownership
	// rules as any explicit path. We intentionally do not exempt it: binding
	// a socket under a shared cwd (e.g. /tmp) is exactly the attack we're
	// defending against.
	return ensurePrivateDir(filepath.Dir(unixSocketPath))
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

	wsConn, _, err := dialTunnel(ctx, cfg, token)
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

	wsConn, _, err := dialTunnel(ctx, cfg, token)
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
// responds to server-initiated longevity messages. When the server warns that
// the token is about to expire, the client attempts to obtain a fresh token
// and sends it back over the control channel.
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
					log.Printf("server warning: connection expiring due to %s", payload.Reason)
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
				log.Printf("server rejected token refresh: %s", payload.Reason)
			case "disconnect":
				var payload struct {
					Reason string `json:"reason"`
				}
				_ = json.Unmarshal(msg.Data, &payload)
				log.Printf("server disconnecting: %s", payload.Reason)
				conn.Close()
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
		request = append(request, socksAtypDomain, byte(len(targetHost)))
		request = append(request, []byte(targetHost)...)
	}

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

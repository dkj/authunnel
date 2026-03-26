package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"nhooyr.io/websocket"
)

const (
	socksVersion5       = 0x05
	socksCmdConnect     = 0x01
	socksAtypIPv4       = 0x01
	socksAtypDomain     = 0x03
	socksAtypIPv6       = 0x04
	socksReplySucceeded = 0x00
)

// clientConfig captures command-line and environment driven behavior for the client process.
type clientConfig struct {
	AccessToken      string
	WebSocketURL     string
	UnixSocketPath   string
	ProxyCommandMode bool
	TargetHost       string
	TargetPort       int
	LoginMode        bool
	Issuer           string
	OAuthClientID    string
	OAuthScopes      string
	RedirectURL      string
}

func main() {
	cfg, err := parseClientConfig()
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	ctx := context.Background()
	if cfg.AccessToken == "" && cfg.LoginMode {
		token, err := loginForAccessToken(ctx, cfg)
		if err != nil {
			log.Fatalf("interactive login failed: %v", err)
		}
		cfg.AccessToken = token
		log.Printf("interactive login succeeded; received access token")
	}

	if cfg.ProxyCommandMode {
		if err := runProxyCommandMode(ctx, cfg); err != nil {
			log.Fatalf("proxycommand mode failed: %v", err)
		}
		return
	}

	if err := runUnixSocketMode(ctx, cfg); err != nil {
		log.Fatalf("unix socket mode failed: %v", err)
	}
}

func parseClientConfig() (clientConfig, error) {
	cfg := clientConfig{}
	cfg.AccessToken = os.Getenv("ACCESS_TOKEN")
	cfg.Issuer = os.Getenv("ISSUER")
	cfg.OAuthClientID = os.Getenv("CLIENT_ID")

	flag.StringVar(&cfg.WebSocketURL, "ws-url", "https://localhost:8443/protected/socks", "WebSocket URL for the authenticated socks tunnel endpoint")
	flag.StringVar(&cfg.UnixSocketPath, "unix-socket", "proxy.sock", "Unix socket path for local SOCKS5 clients")
	flag.BoolVar(&cfg.ProxyCommandMode, "proxycommand", false, "Run as ssh ProxyCommand helper. Requires host and port positional arguments.")
	flag.BoolVar(&cfg.LoginMode, "login", false, "Perform interactive OAuth2 authorization-code login to obtain an access token.")
	flag.StringVar(&cfg.Issuer, "issuer", cfg.Issuer, "OIDC issuer URL used for interactive login, e.g. https://example.okta.com/oauth2/default")
	flag.StringVar(&cfg.OAuthClientID, "oauth-client-id", cfg.OAuthClientID, "OAuth2 public client ID used for interactive login")
	flag.StringVar(&cfg.OAuthScopes, "oauth-scopes", "openid profile email", "Space-delimited scopes requested during interactive login")
	flag.StringVar(&cfg.RedirectURL, "redirect-url", "http://127.0.0.1:18085/callback", "Redirect URL for interactive login callback")
	flag.Parse()

	if cfg.AccessToken == "" && !cfg.LoginMode {
		return cfg, errors.New("ACCESS_TOKEN environment variable is required unless --login is used")
	}
	if cfg.LoginMode {
		if cfg.Issuer == "" {
			return cfg, errors.New("--issuer (or ISSUER env var) is required when --login is used")
		}
		if cfg.OAuthClientID == "" {
			return cfg, errors.New("--oauth-client-id (or CLIENT_ID env var) is required when --login is used")
		}
	}

	if cfg.ProxyCommandMode {
		args := flag.Args()
		if len(args) != 2 {
			return cfg, errors.New("proxycommand mode requires host and port positional arguments")
		}
		cfg.TargetHost = args[0]
		port, err := strconv.Atoi(args[1])
		if err != nil || port < 1 || port > 65535 {
			return cfg, fmt.Errorf("invalid target port %q", args[1])
		}
		cfg.TargetPort = port
	}

	return cfg, nil
}

type oidcDiscoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// loginForAccessToken performs a browser-based OAuth2 authorization code flow with PKCE.
// It starts a temporary local callback server that receives the authorization code.
func loginForAccessToken(ctx context.Context, cfg clientConfig) (string, error) {
	authURL, tokenURL, err := discoverOIDCEndpoints(ctx, cfg.Issuer)
	if err != nil {
		return "", err
	}

	redirectParsed, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URL %q: %w", cfg.RedirectURL, err)
	}

	state, err := randomURLSafeString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate OAuth state: %w", err)
	}
	pkceVerifier, err := randomURLSafeString(64)
	if err != nil {
		return "", fmt.Errorf("failed to generate PKCE verifier: %w", err)
	}
	challenge := pkceS256Challenge(pkceVerifier)

	oauthConfig := oauth2.Config{
		ClientID:    cfg.OAuthClientID,
		RedirectURL: cfg.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: strings.Fields(cfg.OAuthScopes),
	}

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	server := &http.Server{
		Addr: redirectParsed.Host,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != redirectParsed.Path {
				http.NotFound(w, r)
				return
			}
			if r.URL.Query().Get("state") != state {
				http.Error(w, "invalid state", http.StatusBadRequest)
				select {
				case errCh <- errors.New("state mismatch in OAuth callback"):
				default:
				}
				return
			}
			code := r.URL.Query().Get("code")
			if code == "" {
				http.Error(w, "missing code", http.StatusBadRequest)
				select {
				case errCh <- errors.New("missing authorization code in callback"):
				default:
				}
				return
			}
			_, _ = w.Write([]byte("Authunnel login succeeded. You can close this browser tab."))
			select {
			case codeCh <- code:
			default:
			}
		}),
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case errCh <- fmt.Errorf("callback server failed: %w", err):
			default:
			}
		}
	}()
	defer server.Shutdown(context.Background())

	loginURL := oauthConfig.AuthCodeURL(state,
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	log.Printf("Open this URL to authenticate:\n%s", loginURL)

	select {
	case code := <-codeCh:
		token, err := oauthConfig.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", pkceVerifier))
		if err != nil {
			return "", fmt.Errorf("token exchange failed: %w", err)
		}
		if token.AccessToken == "" {
			return "", errors.New("token exchange returned empty access token")
		}
		return token.AccessToken, nil
	case err := <-errCh:
		return "", err
	case <-time.After(5 * time.Minute):
		return "", errors.New("timed out waiting for OAuth callback")
	}
}

func discoverOIDCEndpoints(ctx context.Context, issuer string) (authURL, tokenURL string, err error) {
	wellKnown := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create discovery request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("discovery request failed with status %d", resp.StatusCode)
	}
	var doc oidcDiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", "", fmt.Errorf("failed to decode discovery document: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return "", "", errors.New("discovery document missing authorization_endpoint or token_endpoint")
	}
	return doc.AuthorizationEndpoint, doc.TokenEndpoint, nil
}

func randomURLSafeString(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func pkceS256Challenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// runUnixSocketMode exposes a local unix-domain SOCKS5 endpoint, with each accepted
// connection tunneled via a dedicated authenticated websocket connection.
func runUnixSocketMode(ctx context.Context, cfg clientConfig) error {
	if err := ensureUnixSocketDir(cfg.UnixSocketPath); err != nil {
		return err
	}

	if err := os.Remove(cfg.UnixSocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove stale socket %q: %w", cfg.UnixSocketPath, err)
	}

	proxyListen, err := net.Listen("unix", cfg.UnixSocketPath)
	if err != nil {
		return fmt.Errorf("unix socket listen problem: %w", err)
	}
	defer proxyListen.Close()
	defer os.Remove(cfg.UnixSocketPath)

	log.Printf("listening for local SOCKS5 clients on unix socket %s", cfg.UnixSocketPath)
	for {
		localConn, err := proxyListen.Accept()
		if err != nil {
			return fmt.Errorf("accept problem: %w", err)
		}

		go func(conn net.Conn) {
			if err := handleSOCKSClient(ctx, cfg, conn); err != nil {
				log.Printf("connection failed: %v", err)
			}
		}(localConn)
	}
}

func ensureUnixSocketDir(unixSocketPath string) error {
	dir := filepath.Dir(unixSocketPath)
	if dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory for socket %q: %w", unixSocketPath, err)
	}
	return nil
}

func handleSOCKSClient(ctx context.Context, cfg clientConfig, localConn net.Conn) error {
	wsConn, _, err := websocket.Dial(ctx, cfg.WebSocketURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + cfg.AccessToken}},
	})
	if err != nil {
		_ = localConn.Close()
		return fmt.Errorf("websocket dial failed: %w", err)
	}

	remoteConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)
	proxy(localConn, remoteConn)
	return nil
}

// runProxyCommandMode is designed for SSH ProxyCommand integration:
//
//	ProxyCommand /path/to/client --proxycommand %h %p
//
// It opens a websocket tunnel, performs SOCKS5 CONNECT for the target host/port,
// then bridges stdin/stdout with the resulting network stream.
func runProxyCommandMode(ctx context.Context, cfg clientConfig) error {
	wsConn, _, err := websocket.Dial(ctx, cfg.WebSocketURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + cfg.AccessToken}},
	})
	if err != nil {
		return fmt.Errorf("websocket dial failed: %w", err)
	}
	defer wsConn.CloseNow()

	remoteConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)
	defer remoteConn.Close()

	if err := performSOCKS5Connect(remoteConn, cfg.TargetHost, cfg.TargetPort); err != nil {
		return fmt.Errorf("socks5 connect failed: %w", err)
	}

	stdioConn := &stdioConn{in: os.Stdin, out: os.Stdout}
	proxy(stdioConn, remoteConn)
	return nil
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
		// Signal peer that no more data is coming.
		_ = conn1.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn2, conn1)
		// Signal peer that no more data is coming.
		_ = conn2.Close()
	}()

	wg.Wait()
	log.Println("proxy function routine finished")
}

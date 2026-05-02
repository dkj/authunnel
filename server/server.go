package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/time/rate"

	"authunnel/internal/authhttp"
	"authunnel/internal/safefs"
	"authunnel/internal/security"
	"authunnel/internal/tunnelserver"
)

var version = "dev"

// maxTunnelOpenRate caps both TunnelOpenRate (float64) and TunnelOpenBurst (int)
// within an auditable, operationally meaningful range and guarantees the
// auto-derived burst (ceil(rate)) fits comfortably in int.
const maxTunnelOpenRate = 10_000
const maxExpiryGrace = time.Hour

// startupAuthTimeout bounds OIDC discovery during server startup. It sits
// above the per-call HTTP timeout in authhttp.NewBoundedClient so the
// underlying HTTP transport is the closer error source, while staying well
// under any plausible operator patience for a stalled issuer.
const startupAuthTimeout = 30 * time.Second

// httpServerMaxHeaderBytes lowers the request-header memory cap from Go's
// 1 MB default. The new bound sits comfortably above the bearer-token cap
// (8 KiB) plus standard WebSocket upgrade headers, but cuts the worst-case
// anonymous-request memory cost by about 64x.
const httpServerMaxHeaderBytes = 16 * 1024

type serverConfig struct {
	Issuer        string
	TokenAudience string
	ListenAddr    string
	// TLS files mode
	TLSCertPath string
	TLSKeyPath  string
	// ACME mode
	ACMEDomains  []string
	ACMECacheDir string
	// Plaintext mode (behind a TLS-terminating reverse proxy)
	PlaintextBehindProxy bool
	// Development override: allow non-HTTPS OIDC issuer
	InsecureOIDCIssuer bool
	LogLevel           slog.Level
	AllowRules         tunnelserver.Allowlist
	// AllowOpenEgress is the explicit opt-in for running without an allowlist.
	// Startup fails when both this flag and --allow rules are absent so the
	// default posture is restrictive; operators who genuinely want full egress
	// have to say so.
	AllowOpenEgress bool
	// IPBlockRanges is the resolved-IP deny-list applied after the allowlist.
	// Default-populated to tunnelserver.DefaultIPBlocklist() when neither
	// --ip-block nor --no-ip-block is set. Independent of the egress posture:
	// works the same in restrictive and open modes.
	IPBlockRanges tunnelserver.IPBlocklist
	// NoIPBlock disables the resolved-IP guard entirely. Mutually exclusive
	// with --ip-block / IP_BLOCK.
	NoIPBlock bool
	// Connection longevity
	MaxConnectionDuration   time.Duration // hard max tunnel lifetime; 0 = unlimited
	NoConnectionTokenExpiry bool          // when true, tunnel lifetime is NOT tied to access token expiry
	ExpiryWarning           time.Duration // warning period before either limit
	ExpiryGrace             time.Duration // grace period beyond token exp for cached-token providers, max 1h

	// Admission and resource limits
	MaxConcurrentTunnels int           // global cap; 0 = unlimited
	MaxTunnelsPerUser    int           // per-subject concurrent cap; 0 = unlimited
	TunnelOpenRate       float64       // per-subject rate (tunnels/sec); 0 = disabled, max 10000
	TunnelOpenBurst      int           // per-subject token-bucket burst; defaults to ceil(rate) when rate>0, max 10000
	DialTimeout          time.Duration // per-outbound-dial timeout; default 10s

	// Pre-auth IP rate limit for every authenticated route (/protected,
	// /protected/, any /protected/*, and /protected/tunnel). Off by
	// default; opt in by setting PreAuthRate. Burst defaults to ceil(rate)
	// when unset.
	PreAuthRate  float64
	PreAuthBurst int
}

func serverUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: authunnel-server [flags]

Flags and their environment variable equivalents:

  --oidc-issuer <url>        OIDC issuer URL for JWT discovery and validation (env: OIDC_ISSUER)
  --token-audience <string>  Audience required in validated access tokens (env: TOKEN_AUDIENCE)
  --listen-addr <addr>       Listen address (env: LISTEN_ADDR, default: :8443 for TLS-files, :443 for ACME, :8080 for plaintext-behind-reverse-proxy)
  --log-level <level>        Log level: debug, info, warn, or error (env: LOG_LEVEL, default: info)
  --allow <rule>             Restrict outbound connections to matching targets (repeatable; env: ALLOW_RULES comma-separated).
                             Rule formats: host-glob:port, host-glob:lo-hi, CIDR:port, CIDR:lo-hi, [IPv6]:port, [IPv6]:lo-hi.
                             IPv6 addresses must use bracketed notation, e.g. [::1]:22.
                             At least one --allow rule is required unless --allow-open-egress is set.
  --allow-open-egress        Explicit opt-in for running with no allowlist; authenticated clients may CONNECT to any
                             destination the server process can reach (env: ALLOW_OPEN_EGRESS=true). Mutually exclusive
                             with --allow. Use only when the risk of arbitrary egress is acceptable for the deployment.
  --ip-block <range>         Resolved-IP deny-list applied after --allow (repeatable; env: IP_BLOCK comma-separated).
                             Accepts CIDR (127.0.0.0/8), bare IP (127.0.0.1), or bracketed IPv6 ([::1] / [fe80::/10]).
                             When neither --ip-block nor --no-ip-block is set, defaults to a built-in protected set:
                             loopback, IPv4/IPv6 link-local (incl. 169.254.169.254 IMDS), unspecified, and multicast.
                             RFC1918, CGNAT, and IPv6 ULA are NOT in the default set. Applies in both restrictive
                             and --allow-open-egress modes; deny wins over --allow.
  --no-ip-block              Disable the resolved-IP guard entirely (env: NO_IP_BLOCK=true). Mutually exclusive with
                             --ip-block. Use only when the deployment legitimately needs to reach addresses in the
                             default protected set and a tighter --ip-block list is not sufficient.

TLS mode (choose exactly one):

  --tls-cert <path>          Path to the TLS certificate PEM file (env: TLS_CERT_FILE)
  --tls-key <path>           Path to the TLS private key PEM file (env: TLS_KEY_FILE)

  --acme-domain <host>       Domain for automatic ACME/Let's Encrypt certificate (repeatable; env: ACME_DOMAINS comma-separated)
  --acme-cache-dir <dir>     Directory to cache ACME certificates (env: ACME_CACHE_DIR, default: /var/cache/authunnel/acme)

  --plaintext-behind-reverse-proxy
                             Serve plain HTTP, trusting a TLS-terminating reverse proxy for transport security.
                             X-Forwarded-Proto and X-Forwarded-Host are used for WebSocket origin checks.
                             (env: PLAINTEXT_BEHIND_REVERSE_PROXY=true)

Connection longevity:

  --max-connection-duration <duration>
                             Hard maximum tunnel lifetime, e.g. 4h or 30m (env: MAX_CONNECTION_DURATION, default: 0 = unlimited)
  --no-connection-token-expiry
                             Do not tie tunnel lifetime to access token expiry; tunnels persist regardless of
                             token expiry (env: NO_CONNECTION_TOKEN_EXPIRY=true; by default, expiry IS enforced)
  --expiry-warning <duration>
                             Warning period before either longevity limit (env: EXPIRY_WARNING, default: 3m)
  --expiry-grace <duration>
                             Grace period beyond token exp for providers that cache access tokens; the
                             connection deadline becomes exp + grace (env: EXPIRY_GRACE, default: 0, max: 1h)

Admission and resource limits:

  --max-concurrent-tunnels <n>
                             Maximum concurrent tunnels across all users (env: MAX_CONCURRENT_TUNNELS, default: 0 = unlimited).
                             Over-capacity requests are rejected with HTTP 503 before the WebSocket upgrade.
  --max-tunnels-per-user <n>
                             Maximum concurrent tunnels per user, keyed on the token subject claim
                             (env: MAX_TUNNELS_PER_USER, default: 0 = unlimited). Over-cap requests get HTTP 429.
  --tunnel-open-rate <rate>
                             Sustained tunnel-open rate per user, tunnels/second as a float
                             (env: TUNNEL_OPEN_RATE, default: 0 = disabled, max: 10000). Rate-exceeding requests get HTTP 429.
  --tunnel-open-burst <n>    Burst size for --tunnel-open-rate (env: TUNNEL_OPEN_BURST, default: ceil(rate), max: 10000)
  --dial-timeout <duration>  Per-outbound-dial timeout (env: DIAL_TIMEOUT, default: 10s). Zero disables the
                             timeout and lets authenticated users tie up goroutines on blackholed destinations;
                             not recommended.
  --preauth-rate <rate>      Per-source-IP rate limit applied before token parsing on every authenticated
                             route (/protected, /protected/, any /protected/*, and /protected/tunnel),
                             requests/second as a float (env: PREAUTH_RATE, default: 0 = disabled, max: 10000).
                             Behind a properly configured edge load balancer that already rate-limits
                             anonymous traffic this can stay off; enable it for direct exposure where
                             oversized headers, junk JWTs, or unknown-kid bursts would otherwise reach the
                             validator. When --plaintext-behind-reverse-proxy is set, the limiter keys on the
                             leftmost X-Forwarded-For entry, falling back to the TCP peer address; otherwise
                             it always keys on the TCP peer.
  --preauth-burst <n>        Burst size for --preauth-rate (env: PREAUTH_BURST, default: ceil(rate), max: 10000)

Other:

  version, --version         Print version and exit

Development / unsafe overrides (do not use in production):

  --insecure-oidc-issuer     Allow a non-HTTPS OIDC issuer URL (env: INSECURE_OIDC_ISSUER=true)
`)
}

func main() {
	cfg, err := parseServerConfig(os.Args[1:], os.Getenv)
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	logHandler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel})
	logger := slog.New(logHandler)
	slog.SetDefault(logger)
	stdLogger := slog.NewLogLogger(logHandler, slog.LevelError)
	log.SetFlags(0)
	log.SetOutput(stdLogger.Writer())

	if err != nil {
		logger.Error("invalid configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}

	logger.Info("server_starting", slog.String("version", version))
	if cfg.AllowOpenEgress {
		logger.Warn("egress_mode_open",
			slog.String("mode", "open"),
			slog.String("hint", "--allow-open-egress is set; authenticated clients may CONNECT to any destination reachable by the server"),
		)
	} else {
		logger.Info("egress_mode_allowlist",
			slog.String("mode", "allowlist"),
			slog.Int("rules", len(cfg.AllowRules)),
		)
	}
	if cfg.NoIPBlock {
		logger.Warn("ip_block_disabled",
			slog.String("hint", "--no-ip-block is set; resolved-IP guard is off and authenticated clients may reach loopback, link-local, or metadata-service destinations subject only to the allowlist"),
		)
	} else {
		logger.Info("ip_block_active", slog.Int("ranges", len(cfg.IPBlockRanges)))
	}
	if cfg.NoConnectionTokenExpiry && cfg.MaxConnectionDuration == 0 {
		logger.Warn("connection_lifetime_unbounded",
			slog.String("hint", "--no-connection-token-expiry is set and --max-connection-duration is 0; authenticated tunnels have no enforced lifetime cap and will only close on transport failure or client disconnect"),
		)
	}

	if len(cfg.ACMEDomains) > 0 {
		if err := checkACMECacheDir(cfg.ACMECacheDir); err != nil {
			logger.Error("acme_cache_dir_error", slog.String("path", cfg.ACMECacheDir), slog.String("error", err.Error()))
			os.Exit(1)
		}
	} else if !cfg.PlaintextBehindProxy {
		// File-based TLS path: refuse to start if the key file would be
		// readable by another local user. Cert files are public material and
		// are not validated.
		if err := safefs.EnsureUnreadableByOthers(cfg.TLSKeyPath); err != nil {
			logger.Error("tls_key_file_unsafe", slog.String("path", cfg.TLSKeyPath), slog.String("error", err.Error()))
			os.Exit(1)
		}
	}

	authHTTPClient := authhttp.NewBoundedClient()
	discoveryCtx, cancelDiscovery := context.WithTimeout(context.Background(), startupAuthTimeout)
	validator, err := tunnelserver.NewJWTTokenValidator(discoveryCtx, cfg.Issuer, cfg.TokenAudience, authHTTPClient)
	cancelDiscovery()
	if err != nil {
		logger.Error("create token validator", slog.String("error", err.Error()))
		os.Exit(1)
	}

	admitter := tunnelserver.NewAdmitter(tunnelserver.AdmissionConfig{
		GlobalMax:    cfg.MaxConcurrentTunnels,
		PerUserMax:   cfg.MaxTunnelsPerUser,
		PerUserRate:  rate.Limit(cfg.TunnelOpenRate),
		PerUserBurst: cfg.TunnelOpenBurst,
	})
	preAuth := tunnelserver.NewPreAuthLimiter(tunnelserver.PreAuthConfig{
		Rate:  rate.Limit(cfg.PreAuthRate),
		Burst: cfg.PreAuthBurst,
	})
	serverMux := tunnelserver.NewHandler(validator, tunnelserver.NewObservedSOCKSServer(stdLogger, cfg.AllowRules, cfg.IPBlockRanges, cfg.DialTimeout),
		tunnelserver.HandlerOptions{
			TrustForwardedProto: cfg.PlaintextBehindProxy,
			Longevity: tunnelserver.LongevityConfig{
				MaxDuration:      cfg.MaxConnectionDuration,
				ImplementsExpiry: !cfg.NoConnectionTokenExpiry,
				ExpiryWarning:    cfg.ExpiryWarning,
				ExpiryGrace:      cfg.ExpiryGrace,
			},
			Admission:                admitter,
			PreAuth:                  preAuth,
			PreAuthTrustForwardedFor: cfg.PlaintextBehindProxy,
		})
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           tunnelserver.NewRequestLoggingMiddleware(logger, serverMux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    httpServerMaxHeaderBytes,
	}
	// Bind first so CAP_NET_BIND_SERVICE (needed for port < 1024) is used
	// before capabilities are dropped.
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		logger.Error("server_listen_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := security.Harden(); err != nil {
		logger.Error("harden_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	switch {
	case len(cfg.ACMEDomains) > 0:
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.ACMEDomains...),
			Cache:      autocert.DirCache(cfg.ACMECacheDir),
		}
		logger.Info("server_listening", slog.String("listen_addr", cfg.ListenAddr), slog.String("mode", "acme"))
		tlsListener := tls.NewListener(ln, m.TLSConfig())
		if err := httpServer.Serve(tlsListener); err != nil {
			logger.Error("server_exited", slog.String("error", err.Error()))
			os.Exit(1)
		}
	case cfg.PlaintextBehindProxy:
		logger.Info("server_listening", slog.String("listen_addr", cfg.ListenAddr), slog.String("mode", "plaintext"))
		if err := httpServer.Serve(ln); err != nil {
			logger.Error("server_exited", slog.String("error", err.Error()))
			os.Exit(1)
		}
	default:
		logger.Info("server_listening", slog.String("listen_addr", cfg.ListenAddr), slog.String("mode", "tls"))
		if err := httpServer.ServeTLS(ln, cfg.TLSCertPath, cfg.TLSKeyPath); err != nil {
			logger.Error("server_exited", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}
}

func parseServerConfig(args []string, getenv func(string) string) (serverConfig, error) {
	cfg := serverConfig{
		Issuer:        getenv("OIDC_ISSUER"),
		TokenAudience: getenv("TOKEN_AUDIENCE"),
		TLSCertPath:   getenv("TLS_CERT_FILE"),
		TLSKeyPath:    getenv("TLS_KEY_FILE"),
		ACMECacheDir:  "/var/cache/authunnel/acme",
		LogLevel:      slog.LevelInfo,
		ExpiryWarning: 3 * time.Minute,
		DialTimeout:   10 * time.Second,
	}
	if listenAddr := getenv("LISTEN_ADDR"); listenAddr != "" {
		cfg.ListenAddr = listenAddr
	}
	if cacheDir := getenv("ACME_CACHE_DIR"); cacheDir != "" {
		cfg.ACMECacheDir = cacheDir
	}
	if getenv("PLAINTEXT_BEHIND_REVERSE_PROXY") == "true" {
		cfg.PlaintextBehindProxy = true
	}
	if getenv("INSECURE_OIDC_ISSUER") == "true" {
		cfg.InsecureOIDCIssuer = true
	}
	if getenv("ALLOW_OPEN_EGRESS") == "true" {
		cfg.AllowOpenEgress = true
	}
	if getenv("NO_IP_BLOCK") == "true" {
		cfg.NoIPBlock = true
	}
	if v := getenv("MAX_CONNECTION_DURATION"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("MAX_CONNECTION_DURATION: %w", err)
		}
		if d < 0 {
			return cfg, fmt.Errorf("MAX_CONNECTION_DURATION: must not be negative")
		}
		cfg.MaxConnectionDuration = d
	}
	if getenv("NO_CONNECTION_TOKEN_EXPIRY") == "true" {
		cfg.NoConnectionTokenExpiry = true
	}
	if v := getenv("EXPIRY_WARNING"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("EXPIRY_WARNING: %w", err)
		}
		if d < 0 {
			return cfg, fmt.Errorf("EXPIRY_WARNING: must not be negative")
		}
		cfg.ExpiryWarning = d
	}
	if v := getenv("EXPIRY_GRACE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("EXPIRY_GRACE: %w", err)
		}
		if d < 0 || d > maxExpiryGrace {
			return cfg, fmt.Errorf("EXPIRY_GRACE: must be between 0 and %s", maxExpiryGrace)
		}
		cfg.ExpiryGrace = d
	}
	if v := getenv("MAX_CONCURRENT_TUNNELS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return cfg, fmt.Errorf("MAX_CONCURRENT_TUNNELS: %w", err)
		}
		if n < 0 {
			return cfg, fmt.Errorf("MAX_CONCURRENT_TUNNELS: must not be negative")
		}
		cfg.MaxConcurrentTunnels = n
	}
	if v := getenv("MAX_TUNNELS_PER_USER"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return cfg, fmt.Errorf("MAX_TUNNELS_PER_USER: %w", err)
		}
		if n < 0 {
			return cfg, fmt.Errorf("MAX_TUNNELS_PER_USER: must not be negative")
		}
		cfg.MaxTunnelsPerUser = n
	}
	if v := getenv("TUNNEL_OPEN_RATE"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return cfg, fmt.Errorf("TUNNEL_OPEN_RATE: %w", err)
		}
		// strconv.ParseFloat accepts NaN and ±Inf. Negative values are also not a
		// meaningful operator policy. Reject all of those up front, and cap large
		// finite values so auto-deriving ceil(rate) stays explicit and bounded.
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > maxTunnelOpenRate {
			return cfg, fmt.Errorf("TUNNEL_OPEN_RATE: must be a non-negative finite number not exceeding %d", maxTunnelOpenRate)
		}
		cfg.TunnelOpenRate = f
	}
	if v := getenv("TUNNEL_OPEN_BURST"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return cfg, fmt.Errorf("TUNNEL_OPEN_BURST: %w", err)
		}
		if n < 0 || n > maxTunnelOpenRate {
			return cfg, fmt.Errorf("TUNNEL_OPEN_BURST: must be between 0 and %d", maxTunnelOpenRate)
		}
		cfg.TunnelOpenBurst = n
	}
	if v := getenv("DIAL_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("DIAL_TIMEOUT: %w", err)
		}
		if d < 0 {
			return cfg, fmt.Errorf("DIAL_TIMEOUT: must not be negative")
		}
		cfg.DialTimeout = d
	}
	if v := getenv("PREAUTH_RATE"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return cfg, fmt.Errorf("PREAUTH_RATE: %w", err)
		}
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > maxTunnelOpenRate {
			return cfg, fmt.Errorf("PREAUTH_RATE: must be a non-negative finite number not exceeding %d", maxTunnelOpenRate)
		}
		cfg.PreAuthRate = f
	}
	if v := getenv("PREAUTH_BURST"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return cfg, fmt.Errorf("PREAUTH_BURST: %w", err)
		}
		if n < 0 || n > maxTunnelOpenRate {
			return cfg, fmt.Errorf("PREAUTH_BURST: must be between 0 and %d", maxTunnelOpenRate)
		}
		cfg.PreAuthBurst = n
	}

	envLogLevel := getenv("LOG_LEVEL")
	envAllowRules := getenv("ALLOW_RULES")
	envIPBlock := getenv("IP_BLOCK")
	envACMEDomains := getenv("ACME_DOMAINS")
	logLevelFlagSet := false
	listenAddrFlagSet := false

	if len(args) > 0 && args[0] == "help" {
		serverUsage(os.Stdout)
		return cfg, flag.ErrHelp
	}
	if len(args) > 0 && args[0] == "version" {
		fmt.Fprintln(os.Stdout, version)
		return cfg, flag.ErrHelp
	}

	fs := flag.NewFlagSet("authunnel-server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var showVersion bool
	fs.BoolVar(&showVersion, "version", false, "Print version and exit")
	fs.StringVar(&cfg.Issuer, "oidc-issuer", cfg.Issuer, "OIDC issuer used for JWT discovery and validation")
	fs.StringVar(&cfg.TokenAudience, "token-audience", cfg.TokenAudience, "Audience required in validated access tokens")
	fs.StringVar(&cfg.TLSCertPath, "tls-cert", cfg.TLSCertPath, "Path to the TLS certificate PEM file")
	fs.StringVar(&cfg.TLSKeyPath, "tls-key", cfg.TLSKeyPath, "Path to the TLS private key PEM file")
	fs.StringVar(&cfg.ACMECacheDir, "acme-cache-dir", cfg.ACMECacheDir, "Directory to cache ACME certificates")
	fs.BoolVar(&cfg.PlaintextBehindProxy, "plaintext-behind-reverse-proxy", cfg.PlaintextBehindProxy,
		"Serve plain HTTP, trusting a TLS-terminating reverse proxy for transport security; X-Forwarded-Proto and X-Forwarded-Host are used for WebSocket origin checks")
	fs.BoolVar(&cfg.InsecureOIDCIssuer, "insecure-oidc-issuer", cfg.InsecureOIDCIssuer,
		"Allow a non-HTTPS OIDC issuer URL (development only; do not use in production)")
	fs.BoolVar(&cfg.AllowOpenEgress, "allow-open-egress", cfg.AllowOpenEgress,
		"Explicit opt-in for running without an allowlist; mutually exclusive with --allow")
	fs.BoolVar(&cfg.NoIPBlock, "no-ip-block", cfg.NoIPBlock,
		"Disable the resolved-IP guard entirely; mutually exclusive with --ip-block (env: NO_IP_BLOCK=true)")
	fs.Func("listen-addr", "Listen address", func(value string) error {
		cfg.ListenAddr = value
		listenAddrFlagSet = true
		return nil
	})
	fs.Func("acme-domain", "Domain for ACME certificate (repeatable)", func(value string) error {
		if strings.TrimSpace(value) == "" {
			return errors.New("--acme-domain value cannot be empty")
		}
		cfg.ACMEDomains = append(cfg.ACMEDomains, strings.TrimSpace(value))
		return nil
	})
	fs.Var(&tunnelserver.AllowlistFlag{Rules: &cfg.AllowRules}, "allow",
		"Restrict outbound connections to matching targets (repeatable; env: ALLOW_RULES comma-separated). Rule: host-glob:port, host-glob:lo-hi, CIDR:port, CIDR:lo-hi, [IPv6]:port, [IPv6]:lo-hi. IPv6 requires bracketed notation e.g. [::1]:22. At least one rule is required unless --allow-open-egress is set.")
	fs.Var(&tunnelserver.IPBlocklistFlag{Ranges: &cfg.IPBlockRanges}, "ip-block",
		"Resolved-IP deny-list applied after --allow (repeatable; env: IP_BLOCK comma-separated). Accepts CIDR, bare IP, or bracketed IPv6. Defaults to loopback, IPv4/IPv6 link-local (incl. IMDS), unspecified, and multicast when unset. Mutually exclusive with --no-ip-block.")
	fs.Func("log-level", "Structured log level: debug, info, warn, or error", func(value string) error {
		level, err := parseServerLogLevel(value)
		if err != nil {
			return err
		}
		cfg.LogLevel = level
		logLevelFlagSet = true
		return nil
	})
	fs.Func("max-connection-duration", "Hard maximum tunnel lifetime, e.g. 4h or 30m; 0 = unlimited", func(value string) error {
		d, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		if d < 0 {
			return fmt.Errorf("must not be negative")
		}
		cfg.MaxConnectionDuration = d
		return nil
	})
	fs.BoolVar(&cfg.NoConnectionTokenExpiry, "no-connection-token-expiry", cfg.NoConnectionTokenExpiry,
		"Do not tie tunnel lifetime to access token expiry; tunnels persist regardless of token expiry")
	fs.Func("expiry-warning", "Warning period before either longevity limit (default: 3m)", func(value string) error {
		d, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		if d < 0 {
			return fmt.Errorf("must not be negative")
		}
		cfg.ExpiryWarning = d
		return nil
	})
	fs.Func("expiry-grace", "Grace period beyond token exp for providers that cache access tokens (default: 0, max 1h)", func(value string) error {
		d, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		if d < 0 || d > maxExpiryGrace {
			return fmt.Errorf("must be between 0 and %s", maxExpiryGrace)
		}
		cfg.ExpiryGrace = d
		return nil
	})
	fs.Func("max-concurrent-tunnels", "Maximum concurrent tunnels across all users; 0 = unlimited", func(value string) error {
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		if n < 0 {
			return fmt.Errorf("must not be negative")
		}
		cfg.MaxConcurrentTunnels = n
		return nil
	})
	fs.Func("max-tunnels-per-user", "Maximum concurrent tunnels per user (subject); 0 = unlimited", func(value string) error {
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		if n < 0 {
			return fmt.Errorf("must not be negative")
		}
		cfg.MaxTunnelsPerUser = n
		return nil
	})
	fs.Func("tunnel-open-rate", "Sustained tunnel-open rate per user in tunnels/second; 0 = disabled, max 10000", func(value string) error {
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return err
		}
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > maxTunnelOpenRate {
			return fmt.Errorf("must be a non-negative finite number not exceeding %d", maxTunnelOpenRate)
		}
		cfg.TunnelOpenRate = f
		return nil
	})
	fs.Func("tunnel-open-burst", "Burst size for --tunnel-open-rate; defaults to ceil(rate) when rate > 0, max 10000", func(value string) error {
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		if n < 0 || n > maxTunnelOpenRate {
			return fmt.Errorf("must be between 0 and %d", maxTunnelOpenRate)
		}
		cfg.TunnelOpenBurst = n
		return nil
	})
	fs.Func("dial-timeout", "Per-outbound-dial timeout, e.g. 10s; 0 = unlimited (not recommended)", func(value string) error {
		d, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		if d < 0 {
			return fmt.Errorf("must not be negative")
		}
		cfg.DialTimeout = d
		return nil
	})
	fs.Func("preauth-rate", "Per-source-IP rate limit on every authenticated route (/protected, /protected/, any /protected/*, and /protected/tunnel) before token parsing, requests/second; 0 = disabled, max 10000", func(value string) error {
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return err
		}
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > maxTunnelOpenRate {
			return fmt.Errorf("must be a non-negative finite number not exceeding %d", maxTunnelOpenRate)
		}
		cfg.PreAuthRate = f
		return nil
	})
	fs.Func("preauth-burst", "Burst size for --preauth-rate; defaults to ceil(rate) when rate > 0, max 10000", func(value string) error {
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		if n < 0 || n > maxTunnelOpenRate {
			return fmt.Errorf("must be between 0 and %d", maxTunnelOpenRate)
		}
		cfg.PreAuthBurst = n
		return nil
	})
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			serverUsage(os.Stdout)
		}
		return cfg, err
	}
	if showVersion {
		fmt.Fprintln(os.Stdout, version)
		return cfg, flag.ErrHelp
	}
	if !logLevelFlagSet && envLogLevel != "" {
		level, err := parseServerLogLevel(envLogLevel)
		if err != nil {
			return cfg, err
		}
		cfg.LogLevel = level
	}
	if envAllowRules != "" {
		envRules, err := tunnelserver.ParseAllowlistFromCSV(envAllowRules)
		if err != nil {
			return cfg, fmt.Errorf("ALLOW_RULES: %w", err)
		}
		// Env rules form the baseline; --allow flags (already appended during
		// fs.Parse) are additive on top.
		cfg.AllowRules = append(envRules, cfg.AllowRules...)
	}
	if envIPBlock != "" {
		envRanges, err := tunnelserver.ParseIPBlocklistFromCSV(envIPBlock)
		if err != nil {
			return cfg, fmt.Errorf("IP_BLOCK: %w", err)
		}
		// Env ranges form the baseline; --ip-block flags (already appended
		// during fs.Parse) are additive on top.
		cfg.IPBlockRanges = append(envRanges, cfg.IPBlockRanges...)
	}
	if envACMEDomains != "" {
		// Env domains form the baseline; --acme-domain flags are additive on top.
		// Filter empty entries so that ACME_DOMAINS=example.com, (trailing comma)
		// or ACME_DOMAINS=, don't silently inject empty strings into the whitelist.
		flagDomains := cfg.ACMEDomains
		cfg.ACMEDomains = nil
		for _, d := range strings.Split(envACMEDomains, ",") {
			if d = strings.TrimSpace(d); d != "" {
				cfg.ACMEDomains = append(cfg.ACMEDomains, d)
			}
		}
		cfg.ACMEDomains = append(cfg.ACMEDomains, flagDomains...)
	}

	// Apply per-mode listen address defaults if not explicitly set.
	if cfg.ListenAddr == "" && !listenAddrFlagSet {
		switch {
		case len(cfg.ACMEDomains) > 0:
			cfg.ListenAddr = ":443"
		case cfg.PlaintextBehindProxy:
			cfg.ListenAddr = ":8080"
		default:
			cfg.ListenAddr = ":8443"
		}
	}

	if cfg.Issuer == "" {
		return cfg, errors.New("--oidc-issuer or OIDC_ISSUER is required")
	}
	issuerU, err := url.Parse(cfg.Issuer)
	if err != nil || issuerU.Host == "" {
		return cfg, fmt.Errorf("--oidc-issuer %q is not a valid URL", cfg.Issuer)
	}
	if issuerU.Scheme != "https" && !cfg.InsecureOIDCIssuer {
		return cfg, errors.New("--oidc-issuer must use an https:// URL; use --insecure-oidc-issuer or INSECURE_OIDC_ISSUER=true to allow plaintext (development only)")
	}
	if cfg.TokenAudience == "" {
		return cfg, errors.New("--token-audience or TOKEN_AUDIENCE is required")
	}
	if cfg.ListenAddr == "" {
		return cfg, errors.New("--listen-addr or LISTEN_ADDR cannot be empty")
	}

	// Validate TLS mode mutual exclusion.
	tlsFilesMode := cfg.TLSCertPath != "" || cfg.TLSKeyPath != ""
	acmeMode := len(cfg.ACMEDomains) > 0
	plaintextMode := cfg.PlaintextBehindProxy

	modes := 0
	for _, active := range []bool{tlsFilesMode, acmeMode, plaintextMode} {
		if active {
			modes++
		}
	}
	if modes > 1 {
		return cfg, errors.New("only one of --tls-cert/--tls-key, --acme-domain, or --plaintext-behind-reverse-proxy may be specified")
	}
	if modes == 0 {
		return cfg, errors.New("one of --tls-cert/--tls-key, --acme-domain, or --plaintext-behind-reverse-proxy is required")
	}

	// Egress posture: default-deny. The server refuses to start without either
	// a non-empty allowlist or an explicit opt-in for broad-access mode, so
	// authenticated tunnels cannot silently become a general-purpose TCP pivot
	// into loopback, metadata, or internal control-plane destinations.
	switch {
	case len(cfg.AllowRules) == 0 && !cfg.AllowOpenEgress:
		return cfg, errors.New("at least one --allow rule is required, or pass --allow-open-egress (ALLOW_OPEN_EGRESS=true) to explicitly opt into open mode")
	case len(cfg.AllowRules) > 0 && cfg.AllowOpenEgress:
		return cfg, errors.New("--allow-open-egress is mutually exclusive with --allow/ALLOW_RULES; pick one egress posture")
	}

	// IP block posture: default-on with the protected ranges. --no-ip-block
	// is the loud opt-out; --ip-block lets operators replace the default set
	// with a custom one. The two are mutually exclusive so the operator's
	// intent is unambiguous on startup.
	switch {
	case len(cfg.IPBlockRanges) > 0 && cfg.NoIPBlock:
		return cfg, errors.New("--no-ip-block is mutually exclusive with --ip-block/IP_BLOCK; pick one ip-block posture")
	case len(cfg.IPBlockRanges) == 0 && !cfg.NoIPBlock:
		cfg.IPBlockRanges = tunnelserver.DefaultIPBlocklist()
	}

	// Admission sub-validation. Burst defaults to ceil(rate) when rate is
	// positive but burst was not explicitly set, which gives a sensible
	// minimum without forcing operators to tune both knobs.
	if cfg.TunnelOpenBurst > 0 && cfg.TunnelOpenRate == 0 {
		return cfg, errors.New("--tunnel-open-burst requires --tunnel-open-rate to be set")
	}
	if cfg.TunnelOpenRate > 0 && cfg.TunnelOpenBurst == 0 {
		// TunnelOpenRate validation above caps the value, so ceil(rate) remains
		// bounded and the derived burst fits cleanly in int.
		burst := int(math.Ceil(cfg.TunnelOpenRate))
		if burst < 1 {
			burst = 1
		}
		cfg.TunnelOpenBurst = burst
	}

	// Pre-auth rate-limit sub-validation, mirroring the per-subject limiter
	// above: burst defaults to ceil(rate) when rate is positive, and a burst
	// without a positive rate is rejected as ambiguous.
	if cfg.PreAuthBurst > 0 && cfg.PreAuthRate == 0 {
		return cfg, errors.New("--preauth-burst requires --preauth-rate to be set")
	}
	if cfg.PreAuthRate > 0 && cfg.PreAuthBurst == 0 {
		burst := int(math.Ceil(cfg.PreAuthRate))
		if burst < 1 {
			burst = 1
		}
		cfg.PreAuthBurst = burst
	}

	// Per-mode sub-validation.
	switch {
	case tlsFilesMode:
		if cfg.TLSCertPath == "" {
			return cfg, errors.New("--tls-cert or TLS_CERT_FILE is required when --tls-key is provided")
		}
		if cfg.TLSKeyPath == "" {
			return cfg, errors.New("--tls-key or TLS_KEY_FILE is required when --tls-cert is provided")
		}
	case acmeMode:
		if cfg.ACMECacheDir == "" {
			return cfg, errors.New("--acme-cache-dir or ACME_CACHE_DIR cannot be empty")
		}
	}

	return cfg, nil
}

func checkACMECacheDir(dir string) error {
	// autocert.DirCache writes Let's Encrypt private keys into this directory.
	// The same POSIX ancestor + leaf-mode rules that protect the OIDC token
	// cache directory apply here verbatim. EnsurePrivateDir creates the
	// directory 0o700 if missing and validates an existing one without
	// silently relaxing or tightening it.
	if err := safefs.EnsurePrivateDir(dir); err != nil {
		return err
	}
	// Safety alone does not prove writability: a current-owned 0o500 directory
	// passes EnsurePrivateDir but autocert would later fail to persist
	// certificates during issuance or renewal. Probe with a temp file so the
	// failure surfaces at startup instead of mid-handshake.
	f, err := os.CreateTemp(dir, ".acme-probe-*")
	if err != nil {
		return fmt.Errorf("ACME cache directory is not writable: %w", err)
	}
	_ = f.Close()
	_ = os.Remove(f.Name())
	return nil
}

func parseServerLogLevel(value string) (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToLower(strings.TrimSpace(value)))); err != nil {
		return slog.LevelInfo, errors.New("invalid log level: use debug, info, warn, or error")
	}
	return level, nil
}

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

	"authunnel/internal/security"
	"authunnel/internal/tunnelserver"
)

var version = "dev"

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
	LogLevel      slog.Level
	AllowRules    tunnelserver.Allowlist
	// Connection longevity
	MaxConnectionDuration      time.Duration // hard max tunnel lifetime; 0 = unlimited
	NoConnectionTokenExpiry bool          // when true, tunnel lifetime is NOT tied to access token expiry
	ExpiryWarning              time.Duration // warning period before either limit
	ExpiryGrace                time.Duration // grace period beyond token exp for cached-token providers

	// Admission and resource limits
	MaxConcurrentTunnels int           // global cap; 0 = unlimited
	MaxTunnelsPerUser    int           // per-subject concurrent cap; 0 = unlimited
	TunnelOpenRate       float64       // per-subject rate (tunnels/sec); 0 = disabled
	TunnelOpenBurst      int           // per-subject token-bucket burst; defaults to ceil(rate) when rate>0
	DialTimeout          time.Duration // per-outbound-dial timeout; default 10s
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
                             With no rules, all connections are allowed.

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
                             connection deadline becomes exp + grace (env: EXPIRY_GRACE, default: 0)

Admission and resource limits:

  --max-concurrent-tunnels <n>
                             Maximum concurrent tunnels across all users (env: MAX_CONCURRENT_TUNNELS, default: 0 = unlimited).
                             Over-capacity requests are rejected with HTTP 503 before the WebSocket upgrade.
  --max-tunnels-per-user <n>
                             Maximum concurrent tunnels per user, keyed on the token subject claim
                             (env: MAX_TUNNELS_PER_USER, default: 0 = unlimited). Over-cap requests get HTTP 429.
  --tunnel-open-rate <rate>
                             Sustained tunnel-open rate per user, tunnels/second as a float
                             (env: TUNNEL_OPEN_RATE, default: 0 = disabled). Rate-exceeding requests get HTTP 429.
  --tunnel-open-burst <n>    Burst size for --tunnel-open-rate (env: TUNNEL_OPEN_BURST, default: ceil(rate))
  --dial-timeout <duration>  Per-outbound-dial timeout (env: DIAL_TIMEOUT, default: 10s). Zero disables the
                             timeout and lets authenticated users tie up goroutines on blackholed destinations;
                             not recommended.

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

	if len(cfg.ACMEDomains) > 0 {
		if err := checkACMECacheDir(cfg.ACMECacheDir); err != nil {
			logger.Error("acme_cache_dir_error", slog.String("path", cfg.ACMECacheDir), slog.String("error", err.Error()))
			os.Exit(1)
		}
	}

	validator, err := tunnelserver.NewJWTTokenValidator(context.Background(), cfg.Issuer, cfg.TokenAudience, http.DefaultClient)
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
	serverMux := tunnelserver.NewHandler(validator, tunnelserver.NewObservedSOCKSServer(stdLogger, cfg.AllowRules, cfg.DialTimeout),
		tunnelserver.HandlerOptions{
			TrustForwardedProto: cfg.PlaintextBehindProxy,
			Longevity: tunnelserver.LongevityConfig{
				MaxDuration:      cfg.MaxConnectionDuration,
				ImplementsExpiry: !cfg.NoConnectionTokenExpiry,
				ExpiryWarning:    cfg.ExpiryWarning,
				ExpiryGrace:      cfg.ExpiryGrace,
			},
			Admission: admitter,
		})
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           tunnelserver.NewRequestLoggingMiddleware(logger, serverMux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
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
		Issuer:                     getenv("OIDC_ISSUER"),
		TokenAudience:              getenv("TOKEN_AUDIENCE"),
		TLSCertPath:                getenv("TLS_CERT_FILE"),
		TLSKeyPath:                 getenv("TLS_KEY_FILE"),
		ACMECacheDir:               "/var/cache/authunnel/acme",
		LogLevel:                   slog.LevelInfo,
		ExpiryWarning: 3 * time.Minute,
		DialTimeout:                10 * time.Second,
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
		if d < 0 {
			return cfg, fmt.Errorf("EXPIRY_GRACE: must not be negative")
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
		if f < 0 {
			return cfg, fmt.Errorf("TUNNEL_OPEN_RATE: must not be negative")
		}
		cfg.TunnelOpenRate = f
	}
	if v := getenv("TUNNEL_OPEN_BURST"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return cfg, fmt.Errorf("TUNNEL_OPEN_BURST: %w", err)
		}
		if n < 0 {
			return cfg, fmt.Errorf("TUNNEL_OPEN_BURST: must not be negative")
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

	envLogLevel := getenv("LOG_LEVEL")
	envAllowRules := getenv("ALLOW_RULES")
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
		"Restrict outbound connections to matching targets (repeatable; env: ALLOW_RULES comma-separated). Rule: host-glob:port, host-glob:lo-hi, CIDR:port, CIDR:lo-hi, [IPv6]:port, [IPv6]:lo-hi. IPv6 requires bracketed notation e.g. [::1]:22. With no rules all connections are allowed.")
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
	fs.Func("expiry-grace", "Grace period beyond token exp for providers that cache access tokens (default: 0)", func(value string) error {
		d, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		if d < 0 {
			return fmt.Errorf("must not be negative")
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
	fs.Func("tunnel-open-rate", "Sustained tunnel-open rate per user in tunnels/second; 0 = disabled", func(value string) error {
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return err
		}
		if f < 0 {
			return fmt.Errorf("must not be negative")
		}
		cfg.TunnelOpenRate = f
		return nil
	})
	fs.Func("tunnel-open-burst", "Burst size for --tunnel-open-rate; defaults to ceil(rate) when rate > 0", func(value string) error {
		n, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		if n < 0 {
			return fmt.Errorf("must not be negative")
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

	// Admission sub-validation. Burst defaults to ceil(rate) when rate is
	// positive but burst was not explicitly set, which gives a sensible
	// minimum without forcing operators to tune both knobs.
	if cfg.TunnelOpenBurst > 0 && cfg.TunnelOpenRate == 0 {
		return cfg, errors.New("--tunnel-open-burst requires --tunnel-open-rate to be set")
	}
	if cfg.TunnelOpenRate > 0 && cfg.TunnelOpenBurst == 0 {
		burst := int(math.Ceil(cfg.TunnelOpenRate))
		if burst < 1 {
			burst = 1
		}
		cfg.TunnelOpenBurst = burst
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create ACME cache directory: %w", err)
	}
	f, err := os.CreateTemp(dir, ".acme-probe-*")
	if err != nil {
		return fmt.Errorf("ACME cache directory is not writable: %w", err)
	}
	f.Close()
	os.Remove(f.Name())
	return nil
}

func parseServerLogLevel(value string) (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToLower(strings.TrimSpace(value)))); err != nil {
		return slog.LevelInfo, errors.New("invalid log level: use debug, info, warn, or error")
	}
	return level, nil
}

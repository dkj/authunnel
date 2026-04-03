package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"authunnel/internal/security"
	"authunnel/internal/tunnelserver"
)

type serverConfig struct {
	Issuer        string
	TokenAudience string
	ListenAddr    string
	TLSCertPath   string
	TLSKeyPath    string
	LogLevel      slog.Level
	AllowRules    tunnelserver.Allowlist
}

func serverUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: authunnel-server [flags]

Flags and their environment variable equivalents:

  --oidc-issuer <url>        OIDC issuer URL for JWT discovery and validation (env: OIDC_ISSUER)
  --token-audience <string>  Audience required in validated access tokens (env: TOKEN_AUDIENCE)
  --listen-addr <addr>       HTTPS listen address (env: LISTEN_ADDR, default: :8443)
  --tls-cert <path>          Path to the TLS certificate PEM file (env: TLS_CERT_FILE)
  --tls-key <path>           Path to the TLS private key PEM file (env: TLS_KEY_FILE)
  --log-level <level>        Log level: debug, info, warn, or error (env: LOG_LEVEL, default: info)
  --allow <rule>             Restrict outbound connections to matching targets (repeatable; env: ALLOW_RULES comma-separated).
                             Rule formats: host-glob:port, host-glob:lo-hi, CIDR:port, CIDR:lo-hi, [IPv6]:port, [IPv6]:lo-hi.
                             IPv6 addresses must use bracketed notation, e.g. [::1]:22.
                             With no rules, all connections are allowed.
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

	validator, err := tunnelserver.NewJWTTokenValidator(context.Background(), cfg.Issuer, cfg.TokenAudience, http.DefaultClient)
	if err != nil {
		logger.Error("create token validator", slog.String("error", err.Error()))
		os.Exit(1)
	}

	serverMux := tunnelserver.NewHandler(validator, tunnelserver.NewObservedSOCKSServer(stdLogger, cfg.AllowRules))
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
		logger.Warn("harden_failed", slog.String("error", err.Error()))
	}
	logger.Info("server_listening", slog.String("listen_addr", cfg.ListenAddr))
	if err := httpServer.ServeTLS(ln, cfg.TLSCertPath, cfg.TLSKeyPath); err != nil {
		logger.Error("server_exited", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func parseServerConfig(args []string, getenv func(string) string) (serverConfig, error) {
	cfg := serverConfig{
		Issuer:        getenv("OIDC_ISSUER"),
		TokenAudience: getenv("TOKEN_AUDIENCE"),
		ListenAddr:    ":8443",
		TLSCertPath:   getenv("TLS_CERT_FILE"),
		TLSKeyPath:    getenv("TLS_KEY_FILE"),
		LogLevel:      slog.LevelInfo,
	}
	if listenAddr := getenv("LISTEN_ADDR"); listenAddr != "" {
		cfg.ListenAddr = listenAddr
	}

	envLogLevel := getenv("LOG_LEVEL")
	envAllowRules := getenv("ALLOW_RULES")
	logLevelFlagSet := false

	if len(args) > 0 && args[0] == "help" {
		serverUsage(os.Stdout)
		return cfg, flag.ErrHelp
	}

	fs := flag.NewFlagSet("authunnel-server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.Issuer, "oidc-issuer", cfg.Issuer, "OIDC issuer used for JWT discovery and validation")
	fs.StringVar(&cfg.TokenAudience, "token-audience", cfg.TokenAudience, "Audience required in validated access tokens")
	fs.StringVar(&cfg.ListenAddr, "listen-addr", cfg.ListenAddr, "HTTPS listen address")
	fs.StringVar(&cfg.TLSCertPath, "tls-cert", cfg.TLSCertPath, "Path to the TLS certificate PEM file")
	fs.StringVar(&cfg.TLSKeyPath, "tls-key", cfg.TLSKeyPath, "Path to the TLS private key PEM file")
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
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			serverUsage(os.Stdout)
		}
		return cfg, err
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

	if cfg.Issuer == "" {
		return cfg, errors.New("--oidc-issuer or OIDC_ISSUER is required")
	}
	if cfg.TokenAudience == "" {
		return cfg, errors.New("--token-audience or TOKEN_AUDIENCE is required")
	}
	if cfg.TLSCertPath == "" {
		return cfg, errors.New("--tls-cert or TLS_CERT_FILE is required")
	}
	if cfg.TLSKeyPath == "" {
		return cfg, errors.New("--tls-key or TLS_KEY_FILE is required")
	}
	if cfg.ListenAddr == "" {
		return cfg, errors.New("--listen-addr or LISTEN_ADDR cannot be empty")
	}

	return cfg, nil
}

func parseServerLogLevel(value string) (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToLower(strings.TrimSpace(value)))); err != nil {
		return slog.LevelInfo, errors.New("invalid log level: use debug, info, warn, or error")
	}
	return level, nil
}

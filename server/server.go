package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	socks5 "github.com/armon/go-socks5"

	"authunnel/internal/tunnelserver"
)

type serverConfig struct {
	Issuer        string
	TokenAudience string
	ListenAddr    string
	TLSCertPath   string
	TLSKeyPath    string
}

func main() {
	logHandler := slog.NewJSONHandler(os.Stderr, nil)
	logger := slog.New(logHandler)
	slog.SetDefault(logger)
	stdLogger := slog.NewLogLogger(logHandler, slog.LevelInfo)
	log.SetFlags(0)
	log.SetOutput(stdLogger.Writer())

	cfg, err := parseServerConfig(os.Args[1:], os.Getenv)
	if err != nil {
		logger.Error("invalid configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}

	validator, err := tunnelserver.NewJWTTokenValidator(context.Background(), cfg.Issuer, cfg.TokenAudience, http.DefaultClient)
	if err != nil {
		logger.Error("create token validator", slog.String("error", err.Error()))
		os.Exit(1)
	}

	socks, err := socks5.New(&socks5.Config{
		Logger: stdLogger,
	})
	if err != nil {
		logger.Error("create socks5 server", slog.String("error", err.Error()))
		os.Exit(1)
	}

	serverMux := tunnelserver.NewHandler(validator, socks)
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           tunnelserver.NewRequestLoggingMiddleware(logger, serverMux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	logger.Info("server_listening", slog.String("listen_addr", cfg.ListenAddr))
	if err := httpServer.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath); err != nil {
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
	}
	if listenAddr := getenv("LISTEN_ADDR"); listenAddr != "" {
		cfg.ListenAddr = listenAddr
	}

	fs := flag.NewFlagSet("authunnel-server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.Issuer, "oidc-issuer", cfg.Issuer, "OIDC issuer used for JWT discovery and validation")
	fs.StringVar(&cfg.TokenAudience, "token-audience", cfg.TokenAudience, "Audience required in validated access tokens")
	fs.StringVar(&cfg.ListenAddr, "listen-addr", cfg.ListenAddr, "HTTPS listen address")
	fs.StringVar(&cfg.TLSCertPath, "tls-cert", cfg.TLSCertPath, "Path to the TLS certificate PEM file")
	fs.StringVar(&cfg.TLSKeyPath, "tls-key", cfg.TLSKeyPath, "Path to the TLS private key PEM file")
	if err := fs.Parse(args); err != nil {
		return cfg, err
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

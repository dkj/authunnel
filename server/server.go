package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	socks5 "github.com/armon/go-socks5"
	"github.com/gorilla/handlers"

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
	cfg, err := parseServerConfig(os.Args[1:], os.Getenv)
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	validator, err := tunnelserver.NewJWTTokenValidator(context.Background(), cfg.Issuer, cfg.TokenAudience, http.DefaultClient)
	if err != nil {
		log.Fatalf("error creating token validator: %s", err.Error())
	}

	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		log.Fatalf("error creating SOCKS5 server: %s", err.Error())
	}

	serverMux := tunnelserver.NewHandler(validator, socks)
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handlers.LoggingHandler(os.Stderr, serverMux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Printf("listening on %s", cfg.ListenAddr)
	log.Fatal(httpServer.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath))
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

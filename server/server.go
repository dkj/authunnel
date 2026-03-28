package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	socks5 "github.com/armon/go-socks5"
	"github.com/gorilla/handlers"

	"authunnel/internal/tunnelserver"
)

func main() {
	issuer := os.Getenv("ISSUER")
	audience := os.Getenv("TOKEN_AUDIENCE")
	if issuer == "" {
		log.Fatal("ISSUER is required")
	}
	if audience == "" {
		log.Fatal("TOKEN_AUDIENCE is required")
	}

	validator, err := tunnelserver.NewJWTTokenValidator(context.Background(), issuer, audience, http.DefaultClient)
	if err != nil {
		log.Fatalf("error creating token validator: %s", err.Error())
	}

	socks, err := socks5.New(&socks5.Config{})
	if err != nil {
		log.Fatalf("error creating SOCKS5 server: %s", err.Error())
	}

	serverMux := tunnelserver.NewHandler(validator, socks)
	httpServer := &http.Server{
		Addr:              ":8443",
		Handler:           handlers.LoggingHandler(os.Stderr, serverMux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Fatal(httpServer.ListenAndServeTLS("../cert.pem", "../key.pem"))
}

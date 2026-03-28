package main

import (
	"context"
	"log"
	"net/http"
	"os"

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
	log.Fatal(http.ListenAndServeTLS(":8443", "../cert.pem", "../key.pem", handlers.LoggingHandler(os.Stderr, serverMux)))
}

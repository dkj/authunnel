package main

// Package main in poc/server implements a server connected to
// with a TLS and OAuth2 access token client.

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rs"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	socks5 "github.com/armon/go-socks5"

	"github.com/gorilla/handlers"

	"nhooyr.io/websocket"
)

func main() {
	// run a TLS webserver which can check OAuth2 access token

	// access token validation setip
	client_id := os.Getenv("CLIENT_ID")
	client_secret := os.Getenv("CLIENT_SECRET")
	issuer := os.Getenv("ISSUER")
	oauth2provider, err := rs.NewResourceServerClientCredentials(context.TODO(), issuer, client_id, client_secret)
	if err != nil {
		log.Fatalf("error creating provider %s", err.Error())
	}

	// create a socks5 server backend
	socks, err := socks5.New(&socks5.Config{}) //TODOs: Resolver? Just one?

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK " + time.Now().String()))
	})

	http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		ok := checkToken(w, r, oauth2provider)
		if !ok {
			return
		}
		w.Write([]byte("Protected OK " + time.Now().String()))
	})

	http.HandleFunc("/protected/socks", func(w http.ResponseWriter, r *http.Request) {
		ok := checkToken(w, r, oauth2provider)
		if !ok {
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUpgradeRequired)
			return
		}
		defer c.CloseNow()
		socks.ServeConn(websocket.NetConn(r.Context(), c, websocket.MessageBinary))
	})

	log.Fatal(http.ListenAndServeTLS(":8443", "../cert.pem", "../key.pem", handlers.LoggingHandler(os.Stderr, http.DefaultServeMux)))
}

func checkToken(w http.ResponseWriter, r *http.Request, provider rs.ResourceServer) bool {
	auth := r.Header.Get("authorization")
	if auth == "" {
		http.Error(w, "auth header missing", http.StatusUnauthorized)
		return false
	}
	if !strings.HasPrefix(auth, oidc.PrefixBearer) {
		http.Error(w, "invalid header", http.StatusUnauthorized)
		return false
	}
	token := strings.TrimPrefix(auth, oidc.PrefixBearer)
	resp, err := rs.Introspect[*oidc.IntrospectionResponse](r.Context(), provider, token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return false
	}
	log.Println("resp.Active is ", resp.Active)
	if !resp.Active {
		http.Error(w, "token is not active", http.StatusForbidden)
		return false
	}
	return true
}

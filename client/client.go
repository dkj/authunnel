package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	"nhooyr.io/websocket"
)

func main() {
	access_token := os.Getenv("ACCESS_TOKEN")
	ctx := context.Background()

	proxylisten, err := net.Listen("unix", "proxy.sock")
	if err != nil {
		log.Println("unix socket problem ", err)
		return
	}
	for {
		wsconn, _, err := websocket.Dial(ctx, "https://localhost:8443/protected/socks", &websocket.DialOptions{
			HTTPHeader: http.Header{"Authorization": {"Bearer " + access_token}},
		})
		if err != nil {
			log.Fatalln("connection failed with ", err)
		}
		defer wsconn.CloseNow()

		rconn := websocket.NetConn(ctx, wsconn, websocket.MessageBinary)
		lconn, err := proxylisten.Accept()
		if err != nil {
			log.Println("accept problem ", err)
		}
		go proxy(lconn, rconn)
	}

	// wsconn.Close(websocket.StatusNormalClosure, "")

}

func proxy(conn1, conn2 net.Conn) {
	log.Println("proxy function routine started")
	defer conn1.Close()
	defer conn2.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(conn1, conn2)
		// Signal peer that no more data is coming.
		conn1.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn2, conn1)
		// Signal peer that no more data is coming.
		conn2.Close()
	}()

	wg.Wait()
	log.Println("proxy function routine finished")
}

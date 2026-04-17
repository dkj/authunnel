package wsconn_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"authunnel/internal/wsconn"
)

// dialTestServer starts an httptest server that upgrades to WebSocket and
// returns the server-side MultiplexConn along with a client-side MultiplexConn.
func dialTestServer(t *testing.T) (server *wsconn.MultiplexConn, client *wsconn.MultiplexConn) {
	t.Helper()
	serverReady := make(chan *wsconn.MultiplexConn, 1)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on IPv4 loopback: %v", err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("server websocket accept: %v", err)
			return
		}
		mc := wsconn.New(r.Context(), c)
		serverReady <- mc
		<-r.Context().Done()
	}))
	ts.Listener = ln
	ts.Start()
	t.Cleanup(ts.Close)

	ctx := context.Background()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("client websocket dial: %v", err)
	}
	clientConn := wsconn.New(ctx, c)
	t.Cleanup(func() { clientConn.Close() })

	select {
	case sc := <-serverReady:
		t.Cleanup(func() { sc.Close() })
		return sc, clientConn
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server connection")
		return nil, nil
	}
}

// drainBinary starts a background goroutine that reads binary data from conn,
// which causes text frames to be dispatched to the control channel. Returns
// a channel that receives all binary data read.
func drainBinary(conn *wsconn.MultiplexConn) <-chan []byte {
	ch := make(chan []byte, 16)
	go func() {
		defer close(ch)
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			ch <- data
		}
	}()
	return ch
}

func TestBinaryDataRoundTrip(t *testing.T) {
	server, client := dialTestServer(t)

	payload := []byte("hello socks5 world")
	dataCh := drainBinary(server)

	if _, err := client.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case got := <-dataCh:
		if string(got) != string(payload) {
			t.Fatalf("server read %q, want %q", got, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server read")
	}
}

func TestControlMessageRouting(t *testing.T) {
	server, client := dialTestServer(t)

	// Start a reader on client so text frames are dispatched.
	drainBinary(client)

	msg := wsconn.ControlMessage{
		Type: "expiry_warning",
		Data: mustMarshalJSON(t, map[string]string{"reason": "token"}),
	}
	if err := server.SendControl(msg); err != nil {
		t.Fatalf("server send control: %v", err)
	}

	select {
	case received := <-client.ControlChan():
		if received.Type != "expiry_warning" {
			t.Fatalf("got control type %q, want %q", received.Type, "expiry_warning")
		}
		var payload map[string]string
		if err := json.Unmarshal(received.Data, &payload); err != nil {
			t.Fatalf("unmarshal control data: %v", err)
		}
		if payload["reason"] != "token" {
			t.Fatalf("got reason %q, want %q", payload["reason"], "token")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for control message")
	}
}

func TestInterleavedControlAndData(t *testing.T) {
	server, client := dialTestServer(t)

	// Server sends: control, binary, control, binary.
	if err := server.SendControl(wsconn.ControlMessage{Type: "msg1"}); err != nil {
		t.Fatalf("send control 1: %v", err)
	}
	if _, err := server.Write([]byte("data1")); err != nil {
		t.Fatalf("write data 1: %v", err)
	}
	if err := server.SendControl(wsconn.ControlMessage{Type: "msg2"}); err != nil {
		t.Fatalf("send control 2: %v", err)
	}
	if _, err := server.Write([]byte("data2")); err != nil {
		t.Fatalf("write data 2: %v", err)
	}

	// Client Read should return only binary data, dispatching text frames
	// to the control channel.
	buf := make([]byte, 256)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read 1: %v", err)
	}
	if got := string(buf[:n]); got != "data1" {
		t.Fatalf("read 1 got %q, want %q", got, "data1")
	}

	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("read 2: %v", err)
	}
	if got := string(buf[:n]); got != "data2" {
		t.Fatalf("read 2 got %q, want %q", got, "data2")
	}

	// Both control messages should be available.
	var controlTypes []string
	for i := 0; i < 2; i++ {
		select {
		case msg := <-client.ControlChan():
			controlTypes = append(controlTypes, msg.Type)
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for control message %d", i+1)
		}
	}
	if controlTypes[0] != "msg1" || controlTypes[1] != "msg2" {
		t.Fatalf("control messages out of order: %v", controlTypes)
	}
}

func TestSendControlFromClient(t *testing.T) {
	server, client := dialTestServer(t)

	// Start a reader on server so text frames are dispatched.
	drainBinary(server)

	msg := wsconn.ControlMessage{
		Type: "token_refresh",
		Data: mustMarshalJSON(t, map[string]string{"access_token": "new-token"}),
	}
	if err := client.SendControl(msg); err != nil {
		t.Fatalf("client send control: %v", err)
	}

	select {
	case received := <-server.ControlChan():
		if received.Type != "token_refresh" {
			t.Fatalf("got type %q, want %q", received.Type, "token_refresh")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for control message on server")
	}
}

func TestBidirectionalBinaryData(t *testing.T) {
	server, client := dialTestServer(t)

	// Server -> Client
	if _, err := server.Write([]byte("from-server")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	buf := make([]byte, 256)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if got := string(buf[:n]); got != "from-server" {
		t.Fatalf("client got %q, want %q", got, "from-server")
	}

	// Client -> Server
	if _, err := client.Write([]byte("from-client")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	n, err = server.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if got := string(buf[:n]); got != "from-client" {
		t.Fatalf("server got %q, want %q", got, "from-client")
	}
}

// TestConcurrentWriteAndSendControl exercises the writeMu path by firing
// binary Write and SendControl calls concurrently from multiple goroutines.
// Without the mutex the WebSocket library panics or produces corrupt frames.
func TestConcurrentWriteAndSendControl(t *testing.T) {
	server, client := dialTestServer(t)
	dataCh := drainBinary(client)
	// Also drain control messages on the client side.
	go func() {
		for range client.ControlChan() {
		}
	}()

	const goroutines = 10
	const iterations = 20
	done := make(chan struct{}, goroutines*2)

	// Half the goroutines send binary data.
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < iterations; j++ {
				if _, err := server.Write([]byte("bin")); err != nil {
					return
				}
			}
		}(i)
	}

	// The other half send control messages.
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < iterations; j++ {
				msg := wsconn.ControlMessage{Type: "ping"}
				if err := server.SendControl(msg); err != nil {
					return
				}
			}
		}(i)
	}

	// Wait for all goroutines to finish.
	for i := 0; i < goroutines*2; i++ {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for concurrent writers")
		}
	}

	// Drain remaining data to make sure nothing panicked.
	server.Close()
	for range dataCh {
	}
}

// TestNormalCloseReturnsEOF verifies that when the peer sends a normal close
// frame (StatusNormalClosure), Read returns io.EOF rather than a raw
// websocket.CloseError. This is critical because go-socks5 (and anything using
// io.Copy) treats any non-nil, non-EOF error as a session failure, which would
// log clean SSH disconnects as socks_session_failed warnings.
func TestNormalCloseReturnsEOF(t *testing.T) {
	server, client := dialTestServer(t)

	// Close the server side cleanly.
	server.Close()

	// The client-side Read should return io.EOF, not a CloseError.
	buf := make([]byte, 1)
	_, err := client.Read(buf)
	if err == nil {
		t.Fatal("expected error from Read after peer close, got nil")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %T: %v", err, err)
	}
}

// TestOversizedControlFrameDiscarded verifies that a text frame larger than
// maxControlFrameSize (64 KiB) is silently discarded without killing the
// connection. Subsequent normal-sized control and binary messages must still
// be delivered.
func TestOversizedControlFrameDiscarded(t *testing.T) {
	// We need a raw *websocket.Conn on the sending side so we can write an
	// oversized text frame without going through MultiplexConn.SendControl
	// (which would JSON-marshal a reasonable-sized struct).
	serverReady := make(chan *websocket.Conn, 1)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		serverReady <- c
		<-r.Context().Done()
	}))
	ts.Listener = ln
	ts.Start()
	t.Cleanup(ts.Close)

	ctx := context.Background()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	clientWS, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	client := wsconn.New(ctx, clientWS)
	t.Cleanup(func() { client.Close() })

	rawServer := <-serverReady
	// Disable the server-side read limit too so our large write doesn't fail.
	rawServer.SetReadLimit(-1)
	t.Cleanup(func() { rawServer.Close(websocket.StatusNormalClosure, "") })

	// Start reading on the client side so frames are dispatched.
	drainBinary(client)

	// Send a text frame that exceeds 64 KiB.
	oversized := make([]byte, 70*1024)
	for i := range oversized {
		oversized[i] = 'X'
	}
	if err := rawServer.Write(ctx, websocket.MessageText, oversized); err != nil {
		t.Fatalf("write oversized text frame: %v", err)
	}

	// Follow it with a normal control message.
	normal, _ := json.Marshal(wsconn.ControlMessage{
		Type: "ping",
		Data: json.RawMessage(`{}`),
	})
	if err := rawServer.Write(ctx, websocket.MessageText, normal); err != nil {
		t.Fatalf("write normal text frame: %v", err)
	}

	// The oversized frame should be discarded; the normal one should arrive.
	select {
	case msg := <-client.ControlChan():
		if msg.Type != "ping" {
			t.Fatalf("expected ping, got %s", msg.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for control message after oversized frame — connection may have been killed")
	}
}

func mustMarshalJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return data
}

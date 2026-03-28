package tunnelserver

import (
	"bufio"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClearHijackedConnDeadlinesRemovesInheritedTimeouts(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	if err := serverConn.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("set inherited deadline: %v", err)
	}

	wrapped := clearHijackedConnDeadlines(fakeHijackResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             serverConn,
		rw:               bufio.NewReadWriter(bufio.NewReader(serverConn), bufio.NewWriter(serverConn)),
	})

	hijacker, ok := wrapped.(interface {
		Hijack() (net.Conn, *bufio.ReadWriter, error)
	})
	if !ok {
		t.Fatalf("wrapped response writer does not expose Hijack")
	}

	conn, _, err := hijacker.Hijack()
	if err != nil {
		t.Fatalf("hijack: %v", err)
	}
	defer conn.Close()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := conn.Read(buf)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("read returned before data was written: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	if _, err := clientConn.Write([]byte{0x42}); err != nil {
		t.Fatalf("write to peer: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read after clearing deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for read after peer write")
	}
}

type fakeHijackResponseWriter struct {
	*httptest.ResponseRecorder
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (w fakeHijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, w.rw, nil
}

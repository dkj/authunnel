package main

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestProxyForwardsBidirectionalTraffic validates that proxy copies bytes
// in both directions between the two tunnel endpoints.
func TestProxyForwardsBidirectionalTraffic(t *testing.T) {
	leftApp, leftProxy := net.Pipe()
	rightProxy, rightApp := net.Pipe()

	done := make(chan struct{})
	go func() {
		proxy(leftProxy, rightProxy)
		close(done)
	}()

	// Forward left->right.
	leftToRight := []byte("hello-through-tunnel")
	if _, err := leftApp.Write(leftToRight); err != nil {
		t.Fatalf("write left->right failed: %v", err)
	}
	receivedRight := make([]byte, len(leftToRight))
	if err := rightApp.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline right failed: %v", err)
	}
	if _, err := io.ReadFull(rightApp, receivedRight); err != nil {
		t.Fatalf("read left->right failed: %v", err)
	}
	if string(receivedRight) != string(leftToRight) {
		t.Fatalf("left->right payload mismatch: got %q want %q", string(receivedRight), string(leftToRight))
	}

	// Forward right->left.
	rightToLeft := []byte("reply-through-tunnel")
	if _, err := rightApp.Write(rightToLeft); err != nil {
		t.Fatalf("write right->left failed: %v", err)
	}
	receivedLeft := make([]byte, len(rightToLeft))
	if err := leftApp.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline left failed: %v", err)
	}
	if _, err := io.ReadFull(leftApp, receivedLeft); err != nil {
		t.Fatalf("read right->left failed: %v", err)
	}
	if string(receivedLeft) != string(rightToLeft) {
		t.Fatalf("right->left payload mismatch: got %q want %q", string(receivedLeft), string(rightToLeft))
	}

	// Close application ends to let proxy goroutines exit.
	_ = leftApp.Close()
	_ = rightApp.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("proxy did not exit after closing both application endpoints")
	}
}

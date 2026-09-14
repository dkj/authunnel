package authmeta

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
)

// craftedStatusLine answers one request with a status line whose reason phrase
// carries control bytes.
//
// It has to be a raw listener: net/http/httptest builds the status line from the
// code, and Go's *client* parser passes whatever reason phrase arrives straight into
// Response.Status without validating it — verified, not assumed, which is why this
// fixture exists rather than a note saying the field looks harmless.
func craftedStatusLine(t *testing.T, reasonPhrase string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
			return
		}
		fmt.Fprintf(conn, "HTTP/1.1 403 %s\r\nContent-Length: 2\r\n\r\n{}", reasonPhrase)
	}()
	return "http://" + listener.Addr().String()
}

// TestHTTPReasonPhraseIsNotDisplayed pins that the status in an error comes from this
// process rather than from the wire. The reason phrase is the part of a response that
// looks least attacker-influenced and is not: a custom endpoint can put an escape
// sequence there, and the numeric code is the only part a client should act on anyway.
func TestHTTPReasonPhraseIsNotDisplayed(t *testing.T) {
	base := craftedStatusLine(t, "Forbidden"+injectedControlBytes)

	_, err := FetchAuthorizationServer(context.Background(), http.DefaultClient, "", base+"/meta")
	if err == nil {
		t.Fatal("expected the 403 to be reported")
	}
	if strings.ContainsAny(err.Error(), "\x1b\r") {
		t.Fatalf("the error carries the wire reason phrase: %q", err.Error())
	}
	if strings.Contains(err.Error(), "all is well") {
		t.Fatalf("the error repeats the crafted phrase: %q", err.Error())
	}
	// And it still says something useful, from Go's own table.
	if !strings.Contains(err.Error(), "403 Forbidden") {
		t.Fatalf("error = %v, want the code and the local status text", err)
	}
}

func TestLocalStatusFallsBackToTheCode(t *testing.T) {
	if got := localStatus(599); got != "599" {
		t.Fatalf("localStatus(599) = %q, want the bare code for an unknown status", got)
	}
	if got := localStatus(http.StatusForbidden); got != "403 Forbidden" {
		t.Fatalf("localStatus(403) = %q", got)
	}
}

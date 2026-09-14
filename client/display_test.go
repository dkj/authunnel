package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"authunnel/internal/authmeta"
	"authunnel/internal/wsconn"
)

// injectedControlBytes is what a tunnel server may legally put in a JSON string:
// control characters travel as \u escapes and encoding/json decodes them into the
// Go string, so nothing between the wire and the display rejects them.
const injectedControlBytes = "\x1b[2K\rall is well"

// assertEscapedForDisplay checks that attacker-chosen bytes were escaped rather than
// passed through to a terminal or a log.
//
// The hazard is concrete: an escape sequence can erase or rewrite the line reporting
// it and a carriage return can overwrite it, so a refusal can be made to read as a
// success — and under ssh this output is the user's terminal. The same bytes reaching
// a log aggregator forge a neighbouring record.
func assertEscapedForDisplay(t *testing.T, what, text string) {
	t.Helper()
	if strings.ContainsAny(text, "\x1b\r\x00") {
		t.Fatalf("%s contains raw control bytes: %q", what, text)
	}
	if !strings.Contains(text, `\x1b`) {
		t.Fatalf("%s should render the escape in quoted form, got: %s", what, text)
	}
}

// TestIgnoredMetadataURLIsEscapedWhenAnnounced covers the sink that round seven
// created: the hint is announced *before* it is validated, deliberately, so this is
// the one place a wholly unchecked remote string reaches the operator's terminal.
//
// Note what makes it reachable — url.Parse refuses control characters, so a hint
// carrying them fails the same-origin comparison and takes exactly the branch that
// prints it.
func TestIgnoredMetadataURLIsEscapedWhenAnnounced(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	fixture.setDocument(func(d *authmeta.ProtectedResource) {
		d.AuthorizationServerMetadataURL = "https://elsewhere.example/meta" + injectedControlBytes
	})

	output := &strings.Builder{}
	source := fixture.discoverySource(t, failingOpener(t))
	source.issuer = fixture.Issuer
	source.output = output

	if err := source.resolve(context.Background()); err != nil {
		t.Fatalf("the hint should be ignored rather than fail the flow: %v", err)
	}
	assertEscapedForDisplay(t, "the announcement", output.String())
}

// TestControlMessageReasonsAreEscapedInTheLog covers three messages whose text the
// tunnel server chooses outright. Pre-existing sinks rather than ones this work
// added, and in the same threat model — a string from the far end reaching the user's
// terminal under ssh, and a log aggregator after that — so they are held to the same
// rule.
func TestControlMessageReasonsAreEscapedInTheLog(t *testing.T) {
	for _, messageType := range []string{"expiry_warning", "token_rejected", "disconnect"} {
		t.Run(messageType, func(t *testing.T) {
			logged := &lockedBuffer{}
			flags := log.Flags()
			log.SetOutput(logged)
			log.SetFlags(0)
			t.Cleanup(func() {
				log.SetOutput(os.Stderr)
				log.SetFlags(flags)
			})

			serverConn, clientConn := wsPair(t)
			drainBinaryFrames(t, clientConn)
			drainBinaryFrames(t, serverConn)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go handleControlMessages(ctx, clientConn, &fakeTokenSource{token: "t"})

			// "network" rather than "token" for the expiry warning, so the branch
			// that logs the reason is the one taken.
			payload, err := json.Marshal(map[string]string{"reason": "network " + injectedControlBytes})
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			if err := serverConn.SendControl(wsconn.ControlMessage{Type: messageType, Data: payload}); err != nil {
				t.Fatalf("send control message: %v", err)
			}

			deadline := time.Now().Add(2 * time.Second)
			for logged.String() == "" && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if logged.String() == "" {
				t.Fatalf("%s produced no log line", messageType)
			}
			assertEscapedForDisplay(t, messageType+" log line", logged.String())
		})
	}
}

// lockedBuffer is a bytes.Buffer that can be read while the logging goroutine
// writes to it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestSafeLogWriterEscapesControlBytes covers the boundary that catches text this
// code never formats.
func TestSafeLogWriterEscapesControlBytes(t *testing.T) {
	for name, tt := range map[string]struct{ in, want string }{
		"escape sequence":      {"refused " + injectedControlBytes + "\n", `refused \x1b[2K\rall is well` + "\n"},
		"interior newline":     {"line one\nforged: line two\n", `line one\nforged: line two` + "\n"},
		"clean text unchanged": {"nothing to escape here\n", "nothing to escape here\n"},
		"no trailing newline":  {"partial " + injectedControlBytes, `partial \x1b[2K\rall is well`},
	} {
		t.Run(name, func(t *testing.T) {
			out := &strings.Builder{}
			n, err := newSafeLogWriter(out).Write([]byte(tt.in))
			if err != nil {
				t.Fatalf("Write: %v", err)
			}
			// The log package treats a short count as a failure, so the writer
			// reports the caller's length rather than the expanded one.
			if n != len(tt.in) {
				t.Fatalf("Write returned %d, want the input length %d", n, len(tt.in))
			}
			if out.String() != tt.want {
				t.Fatalf("wrote %q, want %q", out.String(), tt.want)
			}
		})
	}
}

// TestTokenEndpointErrorIsEscapedAtTheDisplayBoundary is the finding itself, end to
// end through the real oauth2 code path.
//
// A non-conforming token endpoint response — anything that is not an OAuth error
// object — is embedded raw in oauth2.RetrieveError.Error(), reason phrase included.
// There is no format verb here to fix: the bytes appear when the dependency renders
// itself, which is why the escaping lives at the boundary where errors are displayed.
// In zero-configuration mode the tunnel server chooses that endpoint.
//
// Which path actually reaches a display is worth stating, because the two differ. A
// failed *refresh* is swallowed: tokenForResolvedIdentity treats anything that is not
// a refusal as grounds for interactive login, so those bytes are discarded rather than
// printed — confirmed by running the real binary against this fixture, which sat
// waiting for a browser callback instead of reporting. The *code exchange* returns its
// error, and so does a refresh when there is no fallback to take. The boundary covers
// all of them, which is the argument for putting it there rather than at each site.
func TestTokenEndpointErrorIsEscapedAtTheDisplayBoundary(t *testing.T) {
	var issuer string
	hostile := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSONForTest(t, w, map[string]string{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/auth",
				"token_endpoint":         issuer + "/token",
			})
		case "/token":
			// Deliberately not an OAuth error object, which is what sends oauth2
			// down the branch that prints the body verbatim.
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("upstream exploded " + injectedControlBytes))
		default:
			http.NotFound(w, r)
		}
	}))
	issuer = hostile.URL

	source := newTestSource(t, issuer, hostile.Client(), failingOpener(t))
	writeTokenCacheForTest(t, source.cachePath, tokenCache{
		Issuer:       issuer,
		ClientID:     "authunnel-cli",
		Scopes:       normalizeScopes("openid offline_access"),
		AccessToken:  "expired",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-time.Minute),
	})

	// refreshToken directly rather than AccessToken: a 500 from the token endpoint
	// is not a refusal, so AccessToken would correctly fall through to interactive
	// login and the error under test would be replaced by the login's own.
	ctx := context.Background()
	if err := source.resolve(ctx); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	cache, err := source.loadCache()
	if err != nil {
		t.Fatalf("loadCache: %v", err)
	}
	_, err = source.refreshToken(ctx, cache)
	if err == nil {
		t.Fatal("expected the refresh against a failing token endpoint to error")
	}
	// The raw error carries the bytes: that is the dependency's doing, and the
	// premise of the fix rather than something to correct at the source.
	if !strings.ContainsAny(err.Error(), "\x1b\r") {
		t.Skipf("oauth2 no longer embeds the raw body (%v); the boundary test is then moot", err)
	}

	logged := &lockedBuffer{}
	flags := log.Flags()
	log.SetOutput(newSafeLogWriter(logged))
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	})
	// Exactly what main() does with a failure.
	log.Printf("proxycommand mode failed: %v", err)
	assertEscapedForDisplay(t, "the displayed error", logged.String())
}

// TestInstallSafeLoggingWiresTheBoundary covers the production wiring rather than the
// writer, which is the gap a mutation found: deleting the installation broke no test,
// because every test installed the writer itself.
//
// It does not cover main's single call to this function — main is not reachable from a
// test — so that line remains the untested link, noted in docs/DEVELOPMENT.md. This
// catches the two failures that are reachable: the function becoming a no-op, and the
// writer ceasing to escape.
func TestInstallSafeLoggingWiresTheBoundary(t *testing.T) {
	previous := log.Writer()
	flags := log.Flags()
	t.Cleanup(func() {
		log.SetOutput(previous)
		log.SetFlags(flags)
	})

	installSafeLogging()
	if _, ok := log.Writer().(*safeLogWriter); !ok {
		t.Fatalf("log output is %T, want the escaping writer", log.Writer())
	}

	// And it escapes in fact, not merely by type: redirect the installed writer's
	// destination and put control bytes through the standard logger.
	captured := &lockedBuffer{}
	log.SetOutput(&safeLogWriter{to: captured})
	log.SetFlags(0)
	log.Printf("failed: %s", injectedControlBytes)
	assertEscapedForDisplay(t, "the installed boundary", captured.String())
}

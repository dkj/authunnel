package main

import (
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"unicode"
)

// safeLogWriter escapes control characters in everything written through it,
// preserving a single trailing newline.
//
// It exists because quoting untrusted values at each site does not scale to values
// this code never formats. golang.org/x/oauth2 embeds a non-conforming token
// endpoint response *body* in RetrieveError.Error(), and the HTTP reason phrase with
// it; wrapping that with %w and printing it with %v puts whatever the endpoint chose
// on the terminal, and in zero-configuration mode the tunnel server chooses that
// endpoint. There is no format verb in this repository to fix — the bytes appear when
// the dependency renders itself.
//
// So the escaping belongs at the boundary where text reaches a person: installed on
// the standard logger, it covers every log call in this binary, including ones in
// code that has not been written yet and errors from libraries that have not been
// audited. Per-site %q remains worthwhile where a value is known to be remote and
// should read as delimited, and for output that does not go through the logger — the
// two are complementary rather than redundant, and each has its own test.
//
// The trailing newline the log package appends is preserved so records stay one to a
// line; interior newlines are escaped, which is exactly the log-injection defence.
//
// The server needs no equivalent: it routes the standard logger into slog with a JSON
// handler, and JSON encoding escapes control characters as a matter of course.
type safeLogWriter struct{ to io.Writer }

// installSafeLogging points the standard logger at stderr through the escaping
// writer. Called from main before anything can log.
//
// Extracted so a test can exercise the wiring rather than only the writer. Be clear
// about what that covers: it catches this function becoming a no-op and the writer
// ceasing to escape, and it cannot catch main dropping the call, because main is not
// reachable from a test. That one line is the untested link, listed among the known
// gaps in docs/DEVELOPMENT.md rather than papered over.
func installSafeLogging() {
	log.SetOutput(newSafeLogWriter(os.Stderr))
}

func newSafeLogWriter(to io.Writer) io.Writer { return &safeLogWriter{to: to} }

func (w *safeLogWriter) Write(p []byte) (int, error) {
	payload, trailing := p, ""
	if n := len(p); n > 0 && p[n-1] == '\n' {
		payload, trailing = p[:n-1], "\n"
	}
	if _, err := io.WriteString(w.to, escapeControlRunes(string(payload))+trailing); err != nil {
		return 0, err
	}
	// The caller is told its own length was written. An escaped string is longer
	// than the input, and io.Writer's contract is that a short count means a
	// failure — reporting the expanded length would have the log package treat a
	// success as one.
	return len(p), nil
}

// escapeControlRunes renders control characters the way %q does and leaves
// everything else — including non-ASCII text — exactly as it was, so ordinary
// messages are unchanged byte for byte.
func escapeControlRunes(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	for _, r := range s {
		switch {
		case !unicode.IsControl(r):
			out.WriteRune(r)
		default:
			// strconv.QuoteRune renders exactly as %q does, mnemonics and all:
			// '\r' rather than '\x0d'. Trimming its surrounding quotes is what
			// makes the claim above ("the way %q does") true rather than
			// approximate, and keeps this output identical to the per-site
			// quoting elsewhere.
			quoted := strconv.QuoteRune(r)
			out.WriteString(quoted[1 : len(quoted)-1])
		}
	}
	return out.String()
}

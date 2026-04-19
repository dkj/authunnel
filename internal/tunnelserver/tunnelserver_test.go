package tunnelserver

import (
	"bufio"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestValidateStandardClaims(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	exp := now.Add(time.Hour)

	tests := []struct {
		name     string
		claims   *oidc.AccessTokenClaims
		wantErr  bool
		errMatch string
	}{
		{
			name:   "pass_minimal",
			claims: &oidc.AccessTokenClaims{TokenClaims: oidc.TokenClaims{Subject: "user-1", Expiration: oidc.FromTime(exp)}},
		},
		{
			name: "pass_iat_in_past",
			claims: &oidc.AccessTokenClaims{TokenClaims: oidc.TokenClaims{
				Subject:    "user-1",
				Expiration: oidc.FromTime(exp),
				IssuedAt:   oidc.FromTime(now.Add(-5 * time.Minute)),
			}},
		},
		{
			name: "pass_iat_within_skew",
			claims: &oidc.AccessTokenClaims{TokenClaims: oidc.TokenClaims{
				Subject:    "user-1",
				Expiration: oidc.FromTime(exp),
				IssuedAt:   oidc.FromTime(now.Add(5 * time.Second)),
			}},
		},
		{
			name:     "fail_missing_subject",
			claims:   &oidc.AccessTokenClaims{TokenClaims: oidc.TokenClaims{Expiration: oidc.FromTime(exp)}},
			wantErr:  true,
			errMatch: "missing subject",
		},
		{
			name: "fail_iat_in_future",
			claims: &oidc.AccessTokenClaims{TokenClaims: oidc.TokenClaims{
				Subject:    "user-1",
				Expiration: oidc.FromTime(exp),
				IssuedAt:   oidc.FromTime(now.Add(5 * time.Minute)),
			}},
			wantErr:  true,
			errMatch: "iat",
		},
		{
			name: "fail_nbf_after_exp",
			claims: &oidc.AccessTokenClaims{TokenClaims: oidc.TokenClaims{
				Subject:    "user-1",
				Expiration: oidc.FromTime(exp),
				NotBefore:  oidc.FromTime(exp.Add(time.Minute)),
			}},
			wantErr:  true,
			errMatch: "after exp",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateStandardClaims(tc.claims, now)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errMatch != "" && !strings.Contains(err.Error(), tc.errMatch) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errMatch)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCheckTokenUsableBy(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		nbf      time.Time
		usableBy time.Time
		wantErr  bool
	}{
		{name: "pass_no_nbf", usableBy: now},
		{name: "pass_nbf_in_past", nbf: now.Add(-time.Minute), usableBy: now},
		{name: "pass_nbf_equals_usableBy", nbf: now, usableBy: now},
		{
			// Refresh-style: nbf before the current connection deadline → accepted.
			name:     "pass_refresh_future_nbf_within_deadline",
			nbf:      now.Add(10 * time.Minute),
			usableBy: now.Add(11 * time.Minute),
		},
		{
			// Admission-style: caller pre-adds tokenClockSkew to time.Now()
			// to tolerate IdP clock drift. nbf within that skew is accepted.
			name:     "pass_admission_nbf_within_skew_when_caller_adds_skew",
			nbf:      now.Add(5 * time.Second),
			usableBy: now.Add(tokenClockSkew),
		},
		{
			name:     "fail_admission_future_nbf",
			nbf:      now.Add(10 * time.Minute),
			usableBy: now,
			wantErr:  true,
		},
		{
			// Refresh-style: strict comparison. nbf even a second past
			// the configured deadline is rejected — no implicit skew is
			// applied, so the refresh handover cannot stretch the
			// enforcement window beyond exp + grace.
			name:     "fail_refresh_nbf_just_past_deadline",
			nbf:      now.Add(5 * time.Minute).Add(time.Second),
			usableBy: now.Add(5 * time.Minute),
			wantErr:  true,
		},
		{
			name:     "fail_refresh_nbf_after_deadline",
			nbf:      now.Add(10 * time.Minute),
			usableBy: now.Add(5 * time.Minute),
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := &oidc.AccessTokenClaims{TokenClaims: oidc.TokenClaims{Subject: "user-1"}}
			if !tc.nbf.IsZero() {
				claims.NotBefore = oidc.FromTime(tc.nbf)
			}
			err := checkTokenUsableBy(claims, tc.usableBy)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

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

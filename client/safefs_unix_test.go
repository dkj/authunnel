//go:build !windows

package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"authunnel/internal/safefs"
)

// These tests live in package main because they exercise client-internal
// helpers (ensureUnixSocketDir, acquireFileLock, managedOIDCTokenSource) that
// drive the safefs package. The pure safefs tests are in
// internal/safefs/safefs_unix_test.go.

func TestEnsureUnixSocketDirValidatesCurrentWorkingDirForBareSocketPath(t *testing.T) {
	// Without the cwd-exemption removal, `--unix-socket proxy.sock` bypassed
	// all safety checks. Verify the default path now goes through the full
	// validation: chdir into a group-writable dir and confirm a bare socket
	// filename is rejected.
	badCwd := filepath.Join(t.TempDir(), "shared-cwd")
	if err := os.MkdirAll(badCwd, 0o775); err != nil {
		t.Fatalf("seed badCwd: %v", err)
	}
	if err := os.Chmod(badCwd, 0o775); err != nil {
		t.Fatalf("chmod badCwd: %v", err)
	}
	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(badCwd); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalWd) })

	err = ensureUnixSocketDir("proxy.sock")
	if err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("expected bare socket path to trigger cwd validation, got %v", err)
	}
}

func TestAcquireFileLockRejectsGroupWritableLockDirectory(t *testing.T) {
	// The lock file lives alongside the token cache, so the same safety rule
	// applies: refuse to create advisory locks (and by extension, the cache)
	// inside a directory another local user can write to.
	dir := filepath.Join(t.TempDir(), "perm")
	if err := os.MkdirAll(dir, 0o775); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	_, err := acquireFileLock(context.Background(), filepath.Join(dir, "tokens.json.lock"))
	if err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("expected group/world writable rejection from acquireFileLock, got %v", err)
	}
}

func TestManagedOIDCTokenSourceRejectsGroupWritableCacheDirectory(t *testing.T) {
	// AccessToken must refuse to write tokens into a directory another local
	// user can modify. Exercise the top-level entry point so both the cache
	// dir check and the file lock path go through the safety helper.
	provider := newFakeOIDCProvider(t)
	cacheDir := filepath.Join(t.TempDir(), "shared-config")
	if err := os.MkdirAll(cacheDir, 0o775); err != nil {
		t.Fatalf("seed cache dir: %v", err)
	}
	if err := os.Chmod(cacheDir, 0o775); err != nil {
		t.Fatalf("chmod cache dir: %v", err)
	}
	source := &managedOIDCTokenSource{
		issuer:      provider.issuer(),
		clientID:    "authunnel-cli",
		scopes:      normalizeScopes("openid offline_access"),
		cachePath:   filepath.Join(cacheDir, "tokens.json"),
		httpClient:  provider.server.Client(),
		output:      io.Discard,
		openBrowser: func(context.Context, string) error { return nil },
		now:         time.Now,
	}
	_, err := source.AccessToken(context.Background(), true)
	if err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("expected cache-dir safety rejection, got %v", err)
	}
}

func TestRunUnixSocketModeCreatesSocketWithOwnerOnlyModeUnderPermissiveUmask(t *testing.T) {
	// Prove the umask dance in runUnixSocketMode: if the process umask is
	// relaxed (0o022, a common default), net.Listen("unix", ...) would bind
	// with 0o755 without the WithUmask wrapper, briefly letting any local
	// user connect before tightenUnixSocketPermissions runs.
	previous := syscall.Umask(0o022)
	defer syscall.Umask(previous)

	dir, err := os.MkdirTemp("", "safefs-")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "proxy.sock")

	// Exercise exactly the same sequence runUnixSocketMode performs,
	// stopping before the blocking Accept loop.
	if err := ensureUnixSocketDir(path); err != nil {
		t.Fatalf("ensureUnixSocketDir: %v", err)
	}
	if err := safefs.SafelyRemoveExistingSocket(path); err != nil {
		t.Fatalf("SafelyRemoveExistingSocket: %v", err)
	}
	var listener net.Listener
	if err := safefs.WithUmask(0o077, func() error {
		l, err := net.Listen("unix", path)
		if err != nil {
			return err
		}
		listener = l
		return nil
	}); err != nil {
		t.Fatalf("listen under tight umask: %v", err)
	}
	defer listener.Close()
	defer os.Remove(path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := info.Mode().Perm() &^ os.ModeType; got&0o077 != 0 {
		t.Fatalf("socket has group/world permissions before Chmod: %#o", got)
	}
}

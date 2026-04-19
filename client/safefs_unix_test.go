//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestEnsurePrivateDirCreatesMissingDirectoryWithOwnerOnlyMode(t *testing.T) {
	// The combination of MkdirAll + Chmod must overcome a permissive umask,
	// otherwise operators relying on defaults would silently end up with
	// 0o755 token caches on shared hosts. Exercise the code with a relaxed
	// umask to prove the Chmod is load-bearing.
	previous := syscall.Umask(0o022)
	defer syscall.Umask(previous)

	dir := filepath.Join(t.TempDir(), "authunnel")
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatalf("ensurePrivateDir failed: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("unexpected permissions: got %#o want %#o", got, 0o700)
	}
}

func TestEnsurePrivateDirAcceptsExisting0o755OwnedByCurrentUser(t *testing.T) {
	// 0o755 is not group- or world-writable, so the plan's criteria allow it.
	// This locks that behaviour in so a future change does not accidentally
	// refuse ordinary home directories.
	dir := filepath.Join(t.TempDir(), "already-exists")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatalf("ensurePrivateDir on 0o755 owned dir should succeed: %v", err)
	}
	// It must not silently tighten an existing directory — operator intent wins.
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("existing dir permissions were modified: got %#o want %#o", got, 0o755)
	}
}

func TestEnsurePrivateDirRejectsGroupWritableDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "group-writable")
	if err := os.MkdirAll(dir, 0o775); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	err := ensurePrivateDir(dir)
	if err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("expected group/world writable rejection, got %v", err)
	}
}

func TestEnsurePrivateDirRejectsWorldWritableDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "world-writable")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	err := ensurePrivateDir(dir)
	if err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("expected group/world writable rejection, got %v", err)
	}
}

func TestEnsurePrivateDirRejectsStickyWorldWritableDirectory(t *testing.T) {
	// Sticky-bit world-writable is the classic /tmp shape. The plan calls it
	// out explicitly: the operator must create a private subdirectory rather
	// than binding the socket or writing the token cache directly into /tmp.
	dir := filepath.Join(t.TempDir(), "sticky-tmp")
	if err := os.MkdirAll(dir, 0o1777); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.Chmod(dir, 0o1777); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	err := ensurePrivateDir(dir)
	if err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("expected rejection for sticky 1777 dir, got %v", err)
	}
}

func TestEnsurePrivateDirRejectsGroupWritableAncestor(t *testing.T) {
	// The classic path-swapping attack: the leaf is 0o700 owned by us, but
	// an ancestor is group-writable without the sticky bit, so any member
	// of the group can rename(2) the leaf subtree out of the way and
	// substitute their own between validation and bind. Must be rejected.
	outer := filepath.Join(t.TempDir(), "shared-team")
	if err := os.MkdirAll(outer, 0o775); err != nil {
		t.Fatalf("seed outer: %v", err)
	}
	if err := os.Chmod(outer, 0o775); err != nil {
		t.Fatalf("chmod outer: %v", err)
	}
	inner := filepath.Join(outer, "authunnel")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatalf("seed inner: %v", err)
	}
	if err := os.Chmod(inner, 0o700); err != nil {
		t.Fatalf("chmod inner: %v", err)
	}
	err := ensurePrivateDir(inner)
	if err == nil || !strings.Contains(err.Error(), "ancestor directory") {
		t.Fatalf("expected ancestor rejection, got %v", err)
	}
	if !strings.Contains(err.Error(), "without the sticky bit") {
		t.Fatalf("error should explain sticky-bit rationale, got %v", err)
	}
}

func TestEnsurePrivateDirRejectsGroupWritableSymlinkAncestor(t *testing.T) {
	// Symlink-entry race: the operator passes /shared/authunnel where
	// /shared/authunnel is a symlink to a private dir under their home.
	// Validating only the resolved target leaves /shared/ — whose entry
	// for `authunnel` can be rewritten by any group member — unchecked.
	// The un-resolved walk must catch this.
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.MkdirAll(shared, 0o775); err != nil {
		t.Fatalf("seed shared: %v", err)
	}
	if err := os.Chmod(shared, 0o775); err != nil {
		t.Fatalf("chmod shared: %v", err)
	}
	privateTarget := filepath.Join(t.TempDir(), "alice-home")
	if err := os.MkdirAll(privateTarget, 0o700); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.Chmod(privateTarget, 0o700); err != nil {
		t.Fatalf("chmod target: %v", err)
	}
	link := filepath.Join(shared, "authunnel")
	if err := os.Symlink(privateTarget, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := ensurePrivateDir(link)
	if err == nil || !strings.Contains(err.Error(), "ancestor directory") {
		t.Fatalf("expected rejection of group-writable symlink parent, got %v", err)
	}
	// The rejection must identify the un-resolved parent (`shared`), not
	// just the resolved target's own ancestry. Otherwise the symlink-swap
	// attack is still live.
	if !strings.Contains(err.Error(), shared) {
		t.Fatalf("error should name the un-resolved parent %q, got %v", shared, err)
	}
}

func TestEnsurePrivateDirAcceptsStickyWorldWritableAncestor(t *testing.T) {
	// POSIX sticky-bit semantics: rename(2)/unlink(2) on entries inside a
	// sticky directory are restricted to the entry's owner, so a world-
	// writable but sticky ancestor (like /tmp itself) does not let a peer
	// swap our private subtree. Accept it.
	outer := filepath.Join(t.TempDir(), "sticky-scratch")
	if err := os.MkdirAll(outer, 0o700); err != nil {
		t.Fatalf("seed outer: %v", err)
	}
	// os.FileMode carries the sticky flag out-of-band from the perm bits,
	// and syscallMode only sets S_ISVTX when os.ModeSticky is present —
	// so passing 0o1777 as a raw literal does not actually set sticky.
	if err := os.Chmod(outer, os.ModeSticky|0o777); err != nil {
		t.Fatalf("chmod outer with sticky: %v", err)
	}
	inner := filepath.Join(outer, "authunnel")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatalf("seed inner: %v", err)
	}
	if err := os.Chmod(inner, 0o700); err != nil {
		t.Fatalf("chmod inner: %v", err)
	}
	if err := ensurePrivateDir(inner); err != nil {
		t.Fatalf("sticky world-writable ancestor should be accepted, got %v", err)
	}
}

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

func TestEnsurePrivateDirRejectsNonDirectoryPath(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	err := ensurePrivateDir(filePath)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("expected non-directory rejection, got %v", err)
	}
}

func TestSafelyRemoveExistingSocketNoOpOnMissingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nothing-here.sock")
	if err := safelyRemoveExistingSocket(path); err != nil {
		t.Fatalf("missing path should be a no-op: %v", err)
	}
}

func TestSafelyRemoveExistingSocketRefusesToRemoveRegularFile(t *testing.T) {
	// Without a type check, stale-socket cleanup could silently unlink a
	// regular file the operator placed at the socket path — e.g. a log file
	// accidentally created with the same name. Refuse instead.
	path := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(path, []byte("important"), 0o600); err != nil {
		t.Fatalf("seed regular file: %v", err)
	}
	err := safelyRemoveExistingSocket(path)
	if err == nil || !strings.Contains(err.Error(), "not a unix-domain socket") {
		t.Fatalf("expected refusal to remove regular file, got %v", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("regular file was unexpectedly removed: %v", statErr)
	}
}

func TestSafelyRemoveExistingSocketRemovesActualSocket(t *testing.T) {
	// macOS caps sun_path at ~104 chars, so use a short /tmp-backed dir rather
	// than t.TempDir() which nests inside a long test-specific path.
	dir, err := os.MkdirTemp("", "safefs-")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "proxy.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Close the listener but leave the socket inode in place, mimicking the
	// stale socket left behind by a previous crashed client process.
	listener.Close()

	if err := safelyRemoveExistingSocket(path); err != nil {
		t.Fatalf("safelyRemoveExistingSocket failed: %v", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected socket to be removed, got %v", statErr)
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
	// with 0o755 without the withUmask wrapper, briefly letting any local
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
	if err := safelyRemoveExistingSocket(path); err != nil {
		t.Fatalf("safelyRemoveExistingSocket: %v", err)
	}
	var listener net.Listener
	if err := withUmask(0o077, func() error {
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

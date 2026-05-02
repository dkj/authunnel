//go:build !windows

package safefs

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestEnsurePrivateDirCreatesMissingDirectoryWithOwnerOnlyMode(t *testing.T) {
	// The combination of MkdirAll + Chmod must overcome a permissive umask,
	// otherwise operators relying on defaults would silently end up with
	// 0o755 token caches on shared hosts. Exercise the code with a relaxed
	// umask to prove the Chmod is load-bearing.
	previous := syscall.Umask(0o022)
	defer syscall.Umask(previous)

	dir := filepath.Join(t.TempDir(), "authunnel")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatalf("EnsurePrivateDir failed: %v", err)
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
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatalf("EnsurePrivateDir on 0o755 owned dir should succeed: %v", err)
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
	err := EnsurePrivateDir(dir)
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
	err := EnsurePrivateDir(dir)
	if err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("expected group/world writable rejection, got %v", err)
	}
}

func TestEnsurePrivateDirRejectsStickyWorldWritableDirectory(t *testing.T) {
	// Sticky-bit world-writable is the classic /tmp shape. The operator must
	// create a private subdirectory rather than binding the socket or writing
	// the token cache directly into /tmp.
	dir := filepath.Join(t.TempDir(), "sticky-tmp")
	if err := os.MkdirAll(dir, 0o1777); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.Chmod(dir, 0o1777); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	err := EnsurePrivateDir(dir)
	if err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("expected rejection for sticky 1777 dir, got %v", err)
	}
}

func TestEnsurePrivateDirRejectsGroupWritableAncestor(t *testing.T) {
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
	err := EnsurePrivateDir(inner)
	if err == nil || !strings.Contains(err.Error(), "ancestor directory") {
		t.Fatalf("expected ancestor rejection, got %v", err)
	}
	if !strings.Contains(err.Error(), "without the sticky bit") {
		t.Fatalf("error should explain sticky-bit rationale, got %v", err)
	}
}

func TestEnsurePrivateDirRejectsGroupWritableSymlinkAncestor(t *testing.T) {
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
	err := EnsurePrivateDir(link)
	if err == nil || !strings.Contains(err.Error(), "ancestor directory") {
		t.Fatalf("expected rejection of group-writable symlink parent, got %v", err)
	}
	if !strings.Contains(err.Error(), shared) {
		t.Fatalf("error should name the un-resolved parent %q, got %v", shared, err)
	}
}

func TestEnsurePrivateDirAcceptsStickyWorldWritableAncestor(t *testing.T) {
	outer := filepath.Join(t.TempDir(), "sticky-scratch")
	if err := os.MkdirAll(outer, 0o700); err != nil {
		t.Fatalf("seed outer: %v", err)
	}
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
	if err := EnsurePrivateDir(inner); err != nil {
		t.Fatalf("sticky world-writable ancestor should be accepted, got %v", err)
	}
}

func TestEnsurePrivateDirRejectsNonDirectoryPath(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	err := EnsurePrivateDir(filePath)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("expected non-directory rejection, got %v", err)
	}
}

func TestSafelyRemoveExistingSocketNoOpOnMissingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nothing-here.sock")
	if err := SafelyRemoveExistingSocket(path); err != nil {
		t.Fatalf("missing path should be a no-op: %v", err)
	}
}

func TestSafelyRemoveExistingSocketRefusesToRemoveRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(path, []byte("important"), 0o600); err != nil {
		t.Fatalf("seed regular file: %v", err)
	}
	err := SafelyRemoveExistingSocket(path)
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
	listener.Close()

	if err := SafelyRemoveExistingSocket(path); err != nil {
		t.Fatalf("SafelyRemoveExistingSocket failed: %v", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected socket to be removed, got %v", statErr)
	}
}

func TestEnsurePrivateFileReturnsErrNotExistOnMissingPath(t *testing.T) {
	// Callers (token cache loadCache) treat a missing file as first-run.
	// Surface os.ErrNotExist verbatim so errors.Is keeps working.
	path := filepath.Join(t.TempDir(), "nothing-here.json")
	err := EnsurePrivateFile(path)
	if err == nil {
		t.Fatalf("missing path should error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestEnsurePrivateFileAcceptsOwnerOnlyRegularFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	path := filepath.Join(dir, "tokens.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := EnsurePrivateFile(path); err != nil {
		t.Fatalf("0o600 file should be accepted, got %v", err)
	}
}

func TestEnsurePrivateFileRejectsGroupReadable(t *testing.T) {
	// The whole point of the new check: a pre-existing tokens.json with the
	// group-readable bit must be rejected even though saveCache writes 0o600.
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	path := filepath.Join(dir, "tokens.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	err := EnsurePrivateFile(path)
	if err == nil || !strings.Contains(err.Error(), "group/world permission bits") {
		t.Fatalf("expected group/world rejection, got %v", err)
	}
}

func TestEnsurePrivateFileRejectsSymlink(t *testing.T) {
	// Even if the symlink target is a perfectly safe 0o600 file, the symlink
	// entry itself can be re-pointed by a peer with write access to the
	// link's parent. Refuse rather than dereference.
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	link := filepath.Join(dir, "tokens.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := EnsurePrivateFile(link)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestEnsurePrivateFileRejectsForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown to a foreign uid")
	}
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	path := filepath.Join(dir, "tokens.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	const nobodyUID = 65534
	if err := os.Chown(path, nobodyUID, nobodyUID); err != nil {
		t.Fatalf("chown: %v", err)
	}
	err := EnsurePrivateFile(path)
	if err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("expected foreign-owner rejection, got %v", err)
	}
}

func TestEnsurePrivateFileRejectsPermissiveResolvedAncestorAboveSymlinkedParent(t *testing.T) {
	// EnsurePrivateFile's contract advertises ancestor coverage even when the
	// caller did not run EnsurePrivateDir first. Walking only the lexical
	// parent chain misses any directory above the target of a symlinked
	// parent component, because filepath.Dir advances lexically while
	// os.Stat dereferences each step. The two-chain walk catches that.
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	if err := os.MkdirAll(shared, 0o775); err != nil {
		t.Fatalf("seed shared: %v", err)
	}
	if err := os.Chmod(shared, 0o775); err != nil {
		t.Fatalf("chmod shared: %v", err)
	}
	private := filepath.Join(shared, "private")
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatalf("seed private: %v", err)
	}
	cache := filepath.Join(private, "tokens.json")
	if err := os.WriteFile(cache, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	// link's lexical parent is `root`, which is safe. Its symlink-resolved
	// parent chain leads through `shared`, which is group/world writable
	// without sticky and must be rejected.
	link := filepath.Join(root, "private-link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := EnsurePrivateFile(filepath.Join(link, "tokens.json"))
	if err == nil || !strings.Contains(err.Error(), "ancestor directory") {
		t.Fatalf("expected resolved-ancestor rejection, got %v", err)
	}
	if !strings.Contains(err.Error(), shared) {
		t.Fatalf("error should name the resolved permissive ancestor %q, got %v", shared, err)
	}
}

func TestEnsurePrivateFileRejectsNonRegularFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	subdir := filepath.Join(dir, "tokens.json")
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatalf("seed subdir: %v", err)
	}
	err := EnsurePrivateFile(subdir)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected not-a-regular-file rejection, got %v", err)
	}
}

func TestEnsureUnreadableByOthersAcceptsOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	path := filepath.Join(dir, "server.key")
	if err := os.WriteFile(path, []byte("KEY"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if err := EnsureUnreadableByOthers(path); err != nil {
		t.Fatalf("0o600 key should be accepted, got %v", err)
	}
}

func TestEnsureUnreadableByOthersAcceptsReadOnly(t *testing.T) {
	// 0o400 is the strictest sensible mode for an immutable distro-installed
	// key. Make sure the validator does not insist on the owner having write.
	dir := filepath.Join(t.TempDir(), "tls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	path := filepath.Join(dir, "server.key")
	if err := os.WriteFile(path, []byte("KEY"), 0o400); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := EnsureUnreadableByOthers(path); err != nil {
		t.Fatalf("0o400 key should be accepted, got %v", err)
	}
}

func TestEnsureUnreadableByOthersRejectsGroupReadable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	path := filepath.Join(dir, "server.key")
	if err := os.WriteFile(path, []byte("KEY"), 0o644); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	err := EnsureUnreadableByOthers(path)
	if err == nil || !strings.Contains(err.Error(), "group/world permission bits") {
		t.Fatalf("expected group/world rejection, got %v", err)
	}
}

func TestEnsureUnreadableByOthersAcceptsRootOwnedKeyOnPosix(t *testing.T) {
	// Distro/ACME tooling routinely installs TLS keys root-owned, and
	// EnsureUnreadableByOthers explicitly allows that even when the server
	// runs as a different uid. Only exercisable as root.
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown the key to root")
	}
	dir := filepath.Join(t.TempDir(), "tls")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	path := filepath.Join(dir, "server.key")
	if err := os.WriteFile(path, []byte("KEY"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatalf("chown root: %v", err)
	}
	if err := EnsureUnreadableByOthers(path); err != nil {
		t.Fatalf("root-owned 0o600 key should be accepted, got %v", err)
	}
}

func TestEnsureUnreadableByOthersRejectsForeignUnprivilegedOwner(t *testing.T) {
	// A 0o600 key owned by some other unprivileged uid is readable by THAT
	// uid — exactly the property "unreadable by others" is meant to exclude.
	// Mode bits alone are not enough; ownership has to match the
	// ancestor-walk rule (current uid or root).
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown to a foreign uid")
	}
	dir := filepath.Join(t.TempDir(), "tls")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	path := filepath.Join(dir, "server.key")
	if err := os.WriteFile(path, []byte("KEY"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	const nobodyUID = 65534
	if err := os.Chown(path, nobodyUID, nobodyUID); err != nil {
		t.Fatalf("chown nobody: %v", err)
	}
	err := EnsureUnreadableByOthers(path)
	if err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("expected foreign-owner rejection, got %v", err)
	}
}

func TestEnsureUnreadableByOthersProbesReadabilityAtStartup(t *testing.T) {
	// A 0o000 key owned by the current user passes the leaf mode check
	// (no group/world bits) and the ownership check (current uid), but the
	// running process still cannot read it. The startup probe surfaces that
	// before ServeTLS rather than mid-handshake.
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX permission checks; cannot exercise read failure")
	}
	dir := filepath.Join(t.TempDir(), "tls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	path := filepath.Join(dir, "server.key")
	if err := os.WriteFile(path, []byte("KEY"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod 0o000: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	err := EnsureUnreadableByOthers(path)
	if err == nil || !strings.Contains(err.Error(), "open key file") {
		t.Fatalf("expected readability probe to fail, got %v", err)
	}
}

func TestEnsureUnreadableByOthersFollowsSymlinkToSafeTarget(t *testing.T) {
	// Canonical certbot layout: live/<domain>/privkey.pem is a symlink into
	// archive/<domain>/. Refusing all symlinks would break this; the resolved
	// target's mode is what matters.
	root := t.TempDir()
	live := filepath.Join(root, "live", "example.com")
	archive := filepath.Join(root, "archive", "example.com")
	for _, d := range []string{live, archive} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("seed %q: %v", d, err)
		}
	}
	target := filepath.Join(archive, "privkey1.pem")
	if err := os.WriteFile(target, []byte("KEY"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	link := filepath.Join(live, "privkey.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := EnsureUnreadableByOthers(link); err != nil {
		t.Fatalf("certbot-style symlink to 0o600 target should be accepted: %v", err)
	}
}

func TestEnsureUnreadableByOthersRejectsSymlinkToPermissiveTarget(t *testing.T) {
	// Following symlinks must not skip the mode check on the resolved target:
	// a symlink to a 0o644 key is just as readable as the bare 0o644 file.
	dir := filepath.Join(t.TempDir(), "tls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	target := filepath.Join(dir, "real.key")
	if err := os.WriteFile(target, []byte("KEY"), 0o644); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatalf("chmod target: %v", err)
	}
	link := filepath.Join(dir, "server.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := EnsureUnreadableByOthers(link)
	if err == nil || !strings.Contains(err.Error(), "group/world permission bits") {
		t.Fatalf("expected mode rejection on resolved target, got %v", err)
	}
}

func TestEnsureUnreadableByOthersRejectsSymlinkUnderPermissiveUnresolvedParent(t *testing.T) {
	// The two-chain ancestor walk: even if the resolved target is in a safe
	// directory, a symlink whose un-resolved parent is group/world writable
	// without sticky lets a peer rewrite the link entry between validation
	// and ServeTLS opening the key.
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	if err := os.MkdirAll(shared, 0o775); err != nil {
		t.Fatalf("seed shared: %v", err)
	}
	if err := os.Chmod(shared, 0o775); err != nil {
		t.Fatalf("chmod shared: %v", err)
	}
	private := filepath.Join(root, "private")
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatalf("seed private: %v", err)
	}
	target := filepath.Join(private, "real.key")
	if err := os.WriteFile(target, []byte("KEY"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	link := filepath.Join(shared, "server.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := EnsureUnreadableByOthers(link)
	if err == nil || !strings.Contains(err.Error(), "ancestor directory") {
		t.Fatalf("expected un-resolved parent rejection, got %v", err)
	}
	if !strings.Contains(err.Error(), shared) {
		t.Fatalf("error should name the un-resolved parent %q, got %v", shared, err)
	}
}

func TestEnsureUnreadableByOthersRejectsUnsafeAncestor(t *testing.T) {
	// A 0o600 key under a group-writable ancestor without sticky lets a peer
	// rename(2) the key out from under us. The ancestor walk catches that
	// even when the file mode itself is correct.
	outer := filepath.Join(t.TempDir(), "shared-team")
	if err := os.MkdirAll(outer, 0o775); err != nil {
		t.Fatalf("seed outer: %v", err)
	}
	if err := os.Chmod(outer, 0o775); err != nil {
		t.Fatalf("chmod outer: %v", err)
	}
	inner := filepath.Join(outer, "tls")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatalf("seed inner: %v", err)
	}
	if err := os.Chmod(inner, 0o700); err != nil {
		t.Fatalf("chmod inner: %v", err)
	}
	path := filepath.Join(inner, "server.key")
	if err := os.WriteFile(path, []byte("KEY"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	err := EnsureUnreadableByOthers(path)
	if err == nil || !strings.Contains(err.Error(), "ancestor directory") {
		t.Fatalf("expected ancestor rejection, got %v", err)
	}
}

func TestWithUmaskCreatesOwnerOnlyFiles(t *testing.T) {
	previous := syscall.Umask(0o022)
	defer syscall.Umask(previous)

	dir, err := os.MkdirTemp("", "safefs-")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "proxy.sock")

	var listener net.Listener
	if err := WithUmask(0o077, func() error {
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

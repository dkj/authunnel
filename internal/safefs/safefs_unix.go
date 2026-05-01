//go:build !windows

// Package safefs provides POSIX-aware filesystem helpers for files and
// directories that hold private material (OIDC token caches, advisory lock
// files, unix-domain sockets, TLS private keys). The helpers fail closed when
// they cannot prove the path is safe for another local user not to read or
// rewrite, so callers can skip ad-hoc permission checks at each use site.
package safefs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// EnsurePrivateDir makes dir usable as a location for private per-user files
// (unix-domain sockets, OIDC token caches, lock files) on shared POSIX hosts.
//
// If dir does not exist it is created 0o700 and Chmod-tightened afterwards so
// the umask cannot leave group/world bits set. If dir already exists it is
// left untouched: the operator's intentional directory permissions are
// preserved, but validated before we agree to write secrets into them.
//
// Validation fails closed if the directory is group- or world-writable, or if
// it is owned by another local user. It also walks every ancestor up to the
// filesystem root: any ancestor a peer can rename(2) past lets them swap the
// whole subtree between validation and use, so we reject ancestors that are
// group/world writable without the sticky bit, or owned by some other
// unprivileged local user.
func EnsurePrivateDir(dir string) error {
	_, statErr := os.Stat(dir)
	switch {
	case statErr == nil:
		// Existing directory: validate only.
	case errors.Is(statErr, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create directory %q: %w", dir, err)
		}
		// MkdirAll honours the process umask, so re-tighten explicitly.
		// #nosec G302 -- 0o700 is correct for a *directory* (owner needs
		// exec bit to enter); gosec's rule assumes the target is a file.
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("tighten directory %q: %w", dir, err)
		}
	default:
		return fmt.Errorf("stat directory %q: %w", dir, statErr)
	}
	return validatePrivateDir(dir)
}

// EnsurePrivateFile validates an existing file that holds private material
// (an OIDC token cache, an advisory lock target). It fails closed if the path
// is a symlink, is not a regular file, has any group/world mode bits, or is
// owned by another uid. The parent directory's ancestor chain is also
// re-walked so a permissive ancestor is caught even if the caller forgot to
// run EnsurePrivateDir first.
//
// A missing file surfaces as os.ErrNotExist; callers decide whether that is
// fatal (TLS key) or expected (first-run token cache).
func EnsurePrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("file %q is a symlink; refusing to follow into private storage", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", path)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("file %q has group/world permission bits (mode %#o); refusing to read as private material — re-create with 0600", path, mode)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		// #nosec G115 -- POSIX uids fit in uint32; stdlib does this same conversion.
		if uid := uint32(os.Getuid()); stat.Uid != uid {
			return fmt.Errorf("file %q is owned by uid %d, not the current user (uid %d); refusing to read private material owned by another user", path, stat.Uid, uid)
		}
	}
	return walkParentAncestors(path)
}

// EnsureUnreadableByOthers validates a file that other local users must not
// be able to read (TLS private keys). Two invariants:
//
//   - mode & 0o077 == 0 on the resolved target — no group or world bits.
//   - The resolved target is owned by the current user or root. This mirrors
//     the ancestor-walk rule: any other unprivileged owner is, by definition,
//     someone who can read the key, so accepting that ownership would defeat
//     the "unreadable by others" contract. Allowing root preserves the common
//     case where ACME tooling or distro packaging installs the key root-owned
//     and an authunnel server running as a different uid reads it via group
//     ACLs or capabilities.
//
// Symlinks are followed deliberately. The canonical certbot layout points
// /etc/letsencrypt/live/<domain>/privkey.pem at /etc/letsencrypt/archive/...,
// and refusing all symlinks here would break a very common deployment. The
// resolved target's mode and ownership are what get enforced, and BOTH the
// un-resolved and resolved parent chains are walked: that is what rules out
// a peer renaming a symlink entry between this validation and ServeTLS
// opening the key, mirroring the two-chain pattern used for private
// directories.
//
// A best-effort readability probe runs last so that a key the server cannot
// actually read (e.g. ACL mismatch, missing group membership) surfaces as a
// startup error rather than a mid-handshake failure inside ServeTLS.
func EnsureUnreadableByOthers(path string) error {
	abs, real, err := resolvePath(path)
	if err != nil {
		return err
	}
	info, err := os.Lstat(real)
	if err != nil {
		return fmt.Errorf("stat resolved key file %q: %w", real, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", real)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("file %q has group/world permission bits (mode %#o); other local users could read the private key — re-create with 0600 (or 0400)", real, mode)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		// #nosec G115 -- POSIX uids fit in uint32; stdlib does this same conversion.
		uid := uint32(os.Getuid())
		if stat.Uid != uid && stat.Uid != 0 {
			return fmt.Errorf("file %q is owned by uid %d, not the current user (uid %d) or root; that owner can read the private key, so 0600 alone does not make it private", real, stat.Uid, uid)
		}
	}
	if err := walkBothAncestorChains(abs, real); err != nil {
		return err
	}
	// #nosec G304 -- path is the operator-supplied TLS key, already validated
	// for type, mode, ownership, and ancestor safety above.
	f, err := os.Open(real)
	if err != nil {
		return fmt.Errorf("open key file %q: %w", real, err)
	}
	_ = f.Close()
	return nil
}

// resolvePath returns the absolute and symlink-resolved forms of path,
// formatted in the error wording that every caller uses verbatim.
func resolvePath(path string) (abs, real string, err error) {
	abs, err = filepath.Abs(path)
	if err != nil {
		return "", "", fmt.Errorf("resolve absolute path of %q: %w", path, err)
	}
	real, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return "", "", fmt.Errorf("resolve symlinks of %q: %w", path, err)
	}
	return abs, real, nil
}

// walkBothAncestorChains checks every directory above abs and above real for
// rename(2) safety. Either chain alone is insufficient:
//
//   - The lexical parent chain of abs catches a peer with write access to the
//     directory containing an intermediate symlink, who could otherwise
//     rewrite the symlink entry between validation and use.
//   - The lexical parent chain of real catches a permissive directory above
//     the symlink target — which the un-resolved walk skips entirely because
//     filepath.Dir advances lexically while os.Stat dereferences each step.
//
// Visited entries are deduplicated so the second walk is cheap when no
// symlinks are involved.
func walkBothAncestorChains(abs, real string) error {
	visited := make(map[string]struct{})
	for _, start := range [2]string{filepath.Dir(abs), filepath.Dir(real)} {
		if err := walkAncestorSafety(start, visited); err != nil {
			return err
		}
	}
	return nil
}

// walkParentAncestors is the path-only convenience wrapper for callers that
// have not already resolved the path.
func walkParentAncestors(path string) error {
	abs, real, err := resolvePath(path)
	if err != nil {
		return err
	}
	return walkBothAncestorChains(abs, real)
}

func validatePrivateDir(dir string) error {
	abs, real, err := resolvePath(dir)
	if err != nil {
		return err
	}
	leafInfo, err := os.Stat(real)
	if err != nil {
		return fmt.Errorf("stat directory %q: %w", real, err)
	}
	if !leafInfo.IsDir() {
		return fmt.Errorf("%q is not a directory", real)
	}
	if err := checkLeafSafety(real, leafInfo); err != nil {
		return err
	}
	return walkBothAncestorChains(abs, real)
}

func walkAncestorSafety(start string, visited map[string]struct{}) error {
	current := start
	for {
		if _, done := visited[current]; done {
			return nil
		}
		visited[current] = struct{}{}
		info, err := os.Stat(current)
		if err != nil {
			return fmt.Errorf("stat ancestor %q: %w", current, err)
		}
		if err := checkAncestorSafety(current, info); err != nil {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

// checkLeafSafety enforces the strict rule for the directory that will
// actually contain the socket, cache, or lock file: no group/world write bits
// at all, owned by the current user.
func checkLeafSafety(path string, info os.FileInfo) error {
	if mode := info.Mode().Perm(); mode&0o022 != 0 {
		return fmt.Errorf("directory %q is group/world writable (mode %#o); create a private subdirectory (mode 0700) before pointing authunnel at it", path, mode)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	// #nosec G115 -- POSIX uids fit in uint32; stdlib does this same conversion.
	if uid := uint32(os.Getuid()); stat.Uid != uid {
		return fmt.Errorf("directory %q is owned by uid %d, not by the current user (uid %d); refusing to write private files into a directory owned by another user", path, stat.Uid, uid)
	}
	return nil
}

// checkAncestorSafety enforces a looser but still defensive rule on every
// directory above the leaf. POSIX rename(2)/unlink(2) on an entry requires
// write permission on the containing directory, with the sticky bit
// restricting that right to the entry's owner. So an ancestor is safe when
// it is either not writable by others, or writable but sticky. Ownership
// must also be trusted: root or the current user. Any other unprivileged
// owner could hand write access to an accomplice at any moment.
func checkAncestorSafety(path string, info os.FileInfo) error {
	mode := info.Mode()
	if mode.Perm()&0o022 != 0 && mode&os.ModeSticky == 0 {
		return fmt.Errorf("ancestor directory %q is group/world writable without the sticky bit (mode %#o); a peer could rename or replace the private subdirectory between validation and use", path, mode.Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	// #nosec G115 -- POSIX uids fit in uint32; stdlib does this same conversion.
	uid := uint32(os.Getuid())
	if stat.Uid != uid && stat.Uid != 0 {
		return fmt.Errorf("ancestor directory %q is owned by uid %d, not the current user (uid %d) or root; refusing to trust an ancestor owned by another unprivileged user", path, stat.Uid, uid)
	}
	return nil
}

// SafelyRemoveExistingSocket clears a stale unix-domain socket without
// accidentally clobbering an unrelated file. Callers must have already
// validated the parent directory through EnsurePrivateDir so no other local
// user can race the Lstat/Remove pair.
func SafelyRemoveExistingSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat existing path %q: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove %q: not a unix-domain socket", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok {
		// #nosec G115 -- POSIX uids fit in uint32; stdlib does this same conversion.
		if uid := uint32(os.Getuid()); stat.Uid != uid {
			return fmt.Errorf("refusing to remove socket %q owned by uid %d, not the current user (uid %d)", path, stat.Uid, uid)
		}
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %q: %w", path, err)
	}
	return nil
}

// WithUmask runs fn with the process umask temporarily restricted, so files
// fn creates (notably the unix-domain socket bound by net.Listen) inherit
// owner-only permissions without a window during which another local user
// could connect. The process-wide nature of umask is acceptable here: the
// client is single-process and this is only used briefly at startup.
func WithUmask(umask int, fn func() error) error {
	previous := syscall.Umask(umask)
	defer syscall.Umask(previous)
	return fn()
}

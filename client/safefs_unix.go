//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ensurePrivateDir makes dir usable as a location for private per-user files
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
func ensurePrivateDir(dir string) error {
	_, statErr := os.Stat(dir)
	switch {
	case statErr == nil:
		// Existing directory: validate only.
	case errors.Is(statErr, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create directory %q: %w", dir, err)
		}
		// MkdirAll honours the process umask, so re-tighten explicitly.
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("tighten directory %q: %w", dir, err)
		}
	default:
		return fmt.Errorf("stat directory %q: %w", dir, statErr)
	}
	return validatePrivateDir(dir)
}

func validatePrivateDir(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve absolute path of %q: %w", dir, err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("resolve symlinks of %q: %w", dir, err)
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
	// Walk ancestors of BOTH the un-resolved absolute path and the
	// symlink-resolved path. The resolved walk proves the real target
	// directory lives under safe ancestors. The un-resolved walk proves
	// every directory whose entry we traverse (including the directory
	// containing any intermediate symlink) is safe against rename(2):
	// otherwise a peer with write access to a symlink's parent could
	// rewrite the symlink entry between our validation and the caller's
	// subsequent use of the original, un-resolved path.
	visited := make(map[string]struct{})
	for _, start := range [2]string{filepath.Dir(abs), filepath.Dir(real)} {
		if err := walkAncestorSafety(start, visited); err != nil {
			return err
		}
	}
	return nil
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
	uid := uint32(os.Getuid())
	if stat.Uid != uid && stat.Uid != 0 {
		return fmt.Errorf("ancestor directory %q is owned by uid %d, not the current user (uid %d) or root; refusing to trust an ancestor owned by another unprivileged user", path, stat.Uid, uid)
	}
	return nil
}

// safelyRemoveExistingSocket clears a stale unix-domain socket without
// accidentally clobbering an unrelated file. Callers must have already
// validated the parent directory through ensurePrivateDir so no other local
// user can race the Lstat/Remove pair.
func safelyRemoveExistingSocket(path string) error {
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
		if uid := uint32(os.Getuid()); stat.Uid != uid {
			return fmt.Errorf("refusing to remove socket %q owned by uid %d, not the current user (uid %d)", path, stat.Uid, uid)
		}
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %q: %w", path, err)
	}
	return nil
}

// withUmask runs fn with the process umask temporarily restricted, so files
// fn creates (notably the unix-domain socket bound by net.Listen) inherit
// owner-only permissions without a window during which another local user
// could connect. The process-wide nature of umask is acceptable here: the
// client is single-process and this is only used briefly at startup.
func withUmask(umask int, fn func() error) error {
	previous := syscall.Umask(umask)
	defer syscall.Umask(previous)
	return fn()
}

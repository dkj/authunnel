//go:build windows

// Package safefs provides POSIX-aware filesystem helpers for files and
// directories that hold private material. NTFS uses ACLs rather than POSIX
// mode bits, so the Windows implementation only checks existence and type.
// Full ACL inspection is intentionally out of scope.
package safefs

import (
	"errors"
	"fmt"
	"os"
)

// EnsurePrivateDir is the Windows counterpart to the POSIX helper. NTFS uses
// ACLs rather than POSIX mode bits, so we cannot meaningfully check
// "group/world writable" from here; the standard Go MkdirAll inherits the
// parent directory ACL, and the documented default paths live under
// %AppData%, which is already scoped to the current user by Windows.
//
// We therefore limit ourselves to making sure the path exists and is a
// directory, so the caller can write into it without ambiguity. Full ACL
// inspection is intentionally out of scope for this hardening pass.
func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory %q: %w", dir, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat directory %q: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", dir)
	}
	return nil
}

// EnsurePrivateFile is the Windows counterpart. POSIX mode bits do not exist
// on NTFS, so this verifies only that the path is an existing regular file.
// Symlink rejection is preserved on Windows where Lstat surfaces ModeSymlink
// for symlink reparse points.
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
	return nil
}

// EnsureUnreadableByOthers is the Windows counterpart. POSIX mode bits do
// not exist on NTFS; ACL inspection is out of scope. Symlinks are followed
// so that callers can point at certbot-style paths if they exist on
// Windows; the resolved target must be an existing regular file.
func EnsureUnreadableByOthers(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", path)
	}
	return nil
}

// SafelyRemoveExistingSocket clears a stale AF_UNIX socket file without
// clobbering an unrelated filesystem entry. Windows represents AF_UNIX
// socket files as reparse points and recent Go versions surface them with
// os.ModeSocket set in the file mode, so we apply the same "socket only"
// rule as the POSIX build. Anything else — regular file, directory,
// symlink, junction, or any other reparse point — is refused rather than
// silently removed. On hosts where the socket is not marked ModeSocket
// this refuses cleanup and surfaces a clear error to the operator, which
// is preferable to accidentally deleting an unrelated directory or
// junction that happens to share the configured socket path.
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
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %q: %w", path, err)
	}
	return nil
}

// WithUmask is a no-op on Windows: there is no POSIX umask, and the caller's
// explicit Chmod after bind is the portable way to constrain the resulting
// file permissions.
func WithUmask(_ int, fn func() error) error {
	return fn()
}

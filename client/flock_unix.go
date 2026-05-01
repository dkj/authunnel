//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"authunnel/internal/safefs"
)

// acquireFileLock coordinates concurrent client processes that share the same
// token cache using an OS-backed advisory lock. The lock file is never deleted;
// the kernel releases the lock when the owning process exits, which avoids both
// age-based lock stealing and stale lock files after crashes.
func acquireFileLock(ctx context.Context, lockPath string) (func(), error) {
	if err := safefs.EnsurePrivateDir(filepath.Dir(lockPath)); err != nil {
		return nil, fmt.Errorf("prepare lock directory: %w", err)
	}
	// #nosec G304 -- lockPath is derived from the client's own config, not
	// from per-request user input. EnsurePrivateDir above proves the parent
	// directory cannot be renamed or replaced by another local user; it does
	// NOT prove lockPath itself is not a symlink. Inside a validated private
	// directory only the current user (or root) could have planted such a
	// symlink, so the residual risk collapses to self-trust, which is the
	// trust boundary authunnel relies on throughout.
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open cache lock %q: %w", lockPath, err)
	}
	for {
		// #nosec G115 -- file.Fd() returns a POSIX fd that always fits in int;
		// syscall.Flock's signature requires int.
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return func() {
				// #nosec G115 -- see above; fd fits in int.
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
			}, nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("lock cache lock %q: %w", lockPath, err)
		}

		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

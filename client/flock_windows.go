//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"authunnel/internal/safefs"

	"golang.org/x/sys/windows"
)

// acquireFileLock coordinates concurrent client processes that share the same
// token cache using an OS-backed advisory lock via LockFileEx. The lock file is
// never deleted; the OS releases the lock when the owning process exits, which
// avoids both age-based lock stealing and stale lock files after crashes.
func acquireFileLock(ctx context.Context, lockPath string) (func(), error) {
	if err := safefs.EnsurePrivateDir(filepath.Dir(lockPath)); err != nil {
		return nil, fmt.Errorf("prepare lock directory: %w", err)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open cache lock %q: %w", lockPath, err)
	}
	handle := windows.Handle(file.Fd())
	// ol specifies the byte range to lock (offset 0, length 1). For a lock file
	// that only coordinates process access, locking a single byte is sufficient.
	ol := new(windows.Overlapped)
	for {
		// LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY gives a non-blocking
		// exclusive lock, returning ERROR_LOCK_VIOLATION when another process holds it.
		err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
		if err == nil {
			return func() {
				_ = windows.UnlockFileEx(handle, 0, 1, 0, ol)
				_ = file.Close()
			}, nil
		}
		if err != windows.ERROR_LOCK_VIOLATION {
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

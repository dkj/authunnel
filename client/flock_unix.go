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
)

// acquireFileLock coordinates concurrent client processes that share the same
// token cache using an OS-backed advisory lock. The lock file is never deleted;
// the kernel releases the lock when the owning process exits, which avoids both
// age-based lock stealing and stale lock files after crashes.
func acquireFileLock(ctx context.Context, lockPath string) (func(), error) {
	if err := ensurePrivateDir(filepath.Dir(lockPath)); err != nil {
		return nil, fmt.Errorf("prepare lock directory: %w", err)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open cache lock %q: %w", lockPath, err)
	}
	for {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return func() {
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

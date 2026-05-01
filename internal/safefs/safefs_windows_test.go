//go:build windows

package safefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The Windows build of safefs intentionally diverges from POSIX: NTFS uses
// ACLs rather than mode bits, and ACL inspection is out of scope for this
// hardening pass. These tests pin the contract so a future change does not
// silently start enforcing POSIX semantics on Windows (or vice-versa).

func TestEnsurePrivateFileAcceptsRegularFileRegardlessOfModeBits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	// 0o644 on Windows still ends up with NTFS ACLs inherited from the parent;
	// the mode-bit argument is largely ignored. This is the documented
	// limitation — the test asserts that EnsurePrivateFile does not refuse
	// such a file, because mode-bit checks would be meaningless on NTFS.
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := EnsurePrivateFile(path); err != nil {
		t.Fatalf("EnsurePrivateFile should accept any regular file on Windows, got %v", err)
	}
}

func TestEnsurePrivateFileRejectsMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	err := EnsurePrivateFile(path)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestEnsurePrivateFileRejectsDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dir")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	err := EnsurePrivateFile(path)
	if err == nil {
		t.Fatalf("expected directory rejection")
	}
}

func TestEnsureUnreadableByOthersAcceptsRegularFileRegardlessOfModeBits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(path, []byte("KEY"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := EnsureUnreadableByOthers(path); err != nil {
		t.Fatalf("EnsureUnreadableByOthers should accept any regular file on Windows, got %v", err)
	}
}

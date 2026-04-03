//go:build linux

package security

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Harden drops all Linux capabilities on every OS thread and sets
// PR_SET_NO_NEW_PRIVS so neither this process nor any child it spawns can
// regain elevated privileges.
//
// PR_SET_NO_NEW_PRIVS and capset(2) are thread-scoped on Linux. This function
// uses syscall.AllThreadsSyscall / AllThreadsSyscall6 (Go 1.16+) to apply
// them to every OS thread the Go runtime is currently managing, so no goroutine
// (which may be scheduled onto any thread) retains elevated privileges after
// this returns.
//
// Call this after binding any low-numbered ports (< 1024) but before handling
// untrusted input, so that CAP_NET_BIND_SERVICE is consumed before it is dropped.
func Harden() error {
	// Prevent privilege escalation via setuid/file-capability exec on all threads.
	if err := allThreadsPrctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}

	// Drop the bounding capability set on all threads so capabilities cannot be
	// regained by executing a binary with file capabilities.
	for cap := uintptr(0); cap <= 63; cap++ {
		// Ignore errors: EINVAL is expected for numbers beyond CAP_LAST_CAP.
		allThreadsPrctl(unix.PR_CAPBSET_DROP, cap, 0, 0, 0) //nolint:errcheck
	}

	// Zero all capability sets (effective, permitted, inheritable) on every thread.
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	var data [2]unix.CapUserData // version 3 uses two entries; zero value = no capabilities
	_, _, errno := syscall.AllThreadsSyscall(
		syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("capset (all threads): %w", errno)
	}

	return nil
}

func allThreadsPrctl(option, arg2, arg3, arg4, arg5 uintptr) error {
	_, _, errno := syscall.AllThreadsSyscall6(
		syscall.SYS_PRCTL,
		option, arg2, arg3, arg4, arg5, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

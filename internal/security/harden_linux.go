//go:build linux

package security

import (
	"errors"
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
// IMPORTANT: this binary must be built with CGO_ENABLED=0. When cgo is enabled,
// AllThreadsSyscall6 returns ENOTSUP and the syscalls are never applied, causing
// this function to fail silently with "operation not supported".
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
	// We iterate up to 63 so kernels newer than this build still drop every
	// cap they know about without us hard-coding CAP_LAST_CAP. Two errors are
	// tolerated:
	//
	//   - EINVAL: the cap number is beyond CAP_LAST_CAP on the running kernel.
	//     This is the kernel's documented way of telling us we have run off
	//     the end of its cap table.
	//
	//   - EPERM: the process does not hold CAP_SETPCAP, which is the normal
	//     situation for any unprivileged invocation (authunnel run as a
	//     regular user) and for a binary granted only a single file cap such
	//     as `setcap cap_net_bind_service=ep`. In both cases Harden() has
	//     already applied PR_SET_NO_NEW_PRIVS above, which is what actually
	//     defeats privilege escalation via exec of a file-capability binary;
	//     the bounding-set drop is belt-and-braces on top of that. Failing
	//     the whole of Harden() here would break normal non-root start-up
	//     without strengthening the guarantee no_new_privs has already made.
	//
	// Any other error (a thread-specific AllThreadsSyscall6 failure, a future
	// kernel regression, ...) is surfaced as a real hardening failure so we
	// never silently return success with the bounding set only partly dropped.
	for cap := uintptr(0); cap <= 63; cap++ {
		err := allThreadsPrctl(unix.PR_CAPBSET_DROP, cap, 0, 0, 0)
		if err == nil || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EPERM) {
			continue
		}
		return fmt.Errorf("PR_CAPBSET_DROP %d: %w", cap, err)
	}

	// Zero all capability sets (effective, permitted, inheritable) on every thread.
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	var data [2]unix.CapUserData // version 3 uses two entries; zero value = no capabilities
	// #nosec G103 -- capset(2) is a raw syscall whose ABI requires pointers to
	// the header and data structs passed as uintptrs. unsafe.Pointer conversion
	// is mandatory; there is no safe wrapper in golang.org/x/sys/unix that
	// supports the AllThreadsSyscall variant we need here.
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

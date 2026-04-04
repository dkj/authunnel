//go:build !linux

package security

// Harden is a no-op on non-Linux platforms.
// Linux capability dropping is implemented in harden_linux.go.
func Harden() error {
	return nil
}

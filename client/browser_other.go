//go:build !windows

package main

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

func defaultBrowserOpener(ctx context.Context, url string) error {
	var name string
	switch runtime.GOOS {
	case "darwin":
		name = "open"
	default:
		// Linux and most Unix desktops use xdg-open. Unsupported platforms still
		// get the URL printed to stderr, so browser launch remains best-effort.
		name = "xdg-open"
	}

	commandCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// #nosec G204 -- `name` is picked from a fixed two-element set above; `url`
	// is passed as argv (no shell), so there is no command injection surface.
	// The url itself is the OIDC auth URL constructed from the configured IDP;
	// trusting the IDP is an inherent assumption of the OIDC flow.
	if err := exec.CommandContext(commandCtx, name, url).Run(); err != nil {
		return fmt.Errorf("launch %s: %w", name, err)
	}
	return nil
}

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
	//
	// The scheme matters independently of shell quoting: open and xdg-open
	// dispatch on it and will launch whatever application is registered, not
	// only a browser. "It came from the IdP" is not sufficient on its own —
	// over a plaintext metadata fetch (development, behind
	// --insecure-oidc-issuer) the document is modifiable in transit, so the
	// supplier is whoever is on the network path. What makes this safe is that
	// authhttp.CheckEndpointURL has already restricted the authorization
	// endpoint to http/https with a host, in every mode, before the URL is
	// built. Keep that check if this code is refactored.
	if err := exec.CommandContext(commandCtx, name, url).Run(); err != nil {
		return fmt.Errorf("launch %s: %w", name, err)
	}
	return nil
}

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
	if err := exec.CommandContext(commandCtx, name, url).Run(); err != nil {
		return fmt.Errorf("launch %s: %w", name, err)
	}
	return nil
}

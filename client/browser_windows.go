//go:build windows

package main

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows"
)

func defaultBrowserOpener(_ context.Context, url string) error {
	// exec.Command("cmd", "/c", "start", url) is unreliable for OIDC URLs:
	// cmd.exe treats & as a command separator, splitting the URL before start
	// sees it. Even with quoting, start treats the first quoted token as the
	// window title. ShellExecute bypasses the shell entirely, so the URL is
	// passed verbatim to the default browser.
	urlPtr, err := windows.UTF16PtrFromString(url)
	if err != nil {
		return fmt.Errorf("encode URL for ShellExecute: %w", err)
	}
	op, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return fmt.Errorf("encode operation for ShellExecute: %w", err)
	}
	return windows.ShellExecute(0, op, urlPtr, nil, nil, windows.SW_SHOWNORMAL)
}

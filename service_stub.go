//go:build !windows

package main

// maybeRunService is a no-op on non-Windows platforms.
func maybeRunService() bool { return false }

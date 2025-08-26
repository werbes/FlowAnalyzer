//go:build windows && ignore

package main

// This file is disabled by default (requires -tags=ignore). Present only to avoid
// accidental symbol duplication. Use service_windows.go on Windows instead.
func maybeRunService() bool { return false }

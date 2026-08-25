//go:build linux

package main

// runsHere reports whether a command can do its work on this operating system.
//
// On Linux, all of them.
func runsHere(cmd string) error { return nil }

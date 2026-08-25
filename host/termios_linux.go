//go:build linux

package main

import "golang.org/x/sys/unix"

// The termios ioctls, which are spelled differently on each kernel (P6-12).
//
// Linux calls them TCGETS and TCSETS; darwin calls the same two operations
// TIOCGETA and TIOCSETA. Everything around them in shell.go is identical, so the
// difference is two constants rather than two implementations — and naming them
// here keeps the terminal code readable as one thing.
const (
	getTermios = unix.TCGETS
	setTermios = unix.TCSETS
)

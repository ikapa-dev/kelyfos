//go:build !linux

package main

import "golang.org/x/sys/unix"

// The same two ioctls under the names darwin gives them (P6-12).
//
// `kelyfos shell` does not run on darwin — nothing that needs a guest does — but
// this package has to compile there for `doctor` and `verify` to exist at all,
// and a build tag around the whole file would have been a larger lie than two
// constants.
const (
	getTermios = unix.TIOCGETA
	setTermios = unix.TIOCSETA
)

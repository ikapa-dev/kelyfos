package main

import (
	"os"
	"sync"
	"syscall"
)

// The process umask, read once (P6-18).
//
// This exists because of a regression P6-6 introduced and P6-18's suite run
// caught. Exporting a report used to be `os.Create(dest)`, which makes a file
// with mode `0666 &^ umask` — 0644 on a normal machine. P6-6 made the export
// atomic, rendering beside the destination and renaming into place so that a
// failed export could not truncate a good report; but `os.CreateTemp` creates
// with **0600**, and a rename carries the mode with it. So every exported report
// silently became owner-only.
//
// It looked like nothing until a report had to be read by somebody other than
// the user who made it: the `caps` workflow's artifact upload failed with
// `EACCES` on `team.html`, because the demo runs under sudo and the runner that
// uploads does not. A report is a document written to be handed to somebody —
// that is the entire point of `kelyfos verify` — so owner-only was never a
// decision, just the default of a function that was chosen for a different
// reason.
//
// Restoring `os.Create`'s behaviour rather than hardcoding 0644 is deliberate:
// somebody running with `umask 077` chose that, and a security tool that widens
// a file past the user's own umask to fix its own bug has traded one silent
// surprise for a worse one.
//
// Read once, before anything else runs. `syscall.Umask` is a get-and-set with no
// read-only form, so it has to set the mask to read it and set it back; doing
// that once under a `sync.Once`, at the start of an export, keeps the window in
// which another goroutine could create a file with the wrong mask as small as it
// can be made.
var (
	umaskOnce  sync.Once
	umaskValue os.FileMode
)

func processUmask() os.FileMode {
	umaskOnce.Do(func() {
		m := syscall.Umask(0)
		syscall.Umask(m)
		umaskValue = os.FileMode(m)
	})
	return umaskValue
}

// createMode is the mode os.Create would have produced here.
func createMode() os.FileMode { return 0o666 &^ processUmask() }

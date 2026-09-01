//go:build !linux && !darwin

package main

// hostTotalMemMiB has no source to read on a platform this project does not
// target. ok is false, and the ceiling layer stays out of the way rather than
// guessing.
func hostTotalMemMiB() (int, bool) {
	return 0, false
}

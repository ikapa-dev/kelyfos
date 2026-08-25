//go:build !linux

package sandbox

import "os/exec"

// placeInCgroup does nothing where there are no cgroups (P6-12).
//
// Not an apology for the platform: on darwin nothing reaches this. `kelyfos run`
// and everything else that boots a machine refuses before it gets here, because
// there is no /dev/kvm and no Firecracker — see the refusal in host/main.go,
// which names the way in rather than letting a user discover a missing device.
//
// This file exists so the package compiles for darwin at all, which is what lets
// a Mac run `kelyfos doctor` and `kelyfos verify`.
func placeInCgroup(cmd *exec.Cmd, fd int) {}

//go:build linux

package sandbox

import "os/exec"

// placeInCgroup puts the VMM in its slice at clone time (P6-12).
//
// clone3's CLONE_INTO_CGROUP, which is what SysProcAttr.UseCgroupFD asks for. It
// matters that this happens at clone rather than after: a process moved into a
// cgroup a moment after it starts is a process that ran unbudgeted for that
// moment, and a quota with a hole in it is the kind of cap this project refuses
// to claim (E1-2).
//
// Behind a build tag because those two fields exist only on Linux, and they are
// the entire compile-level difference between this CLI and a macOS one.
func placeInCgroup(cmd *exec.Cmd, fd int) {
	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = fd
}

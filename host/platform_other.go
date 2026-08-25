//go:build !linux

package main

import "fmt"

// What a KelyfOS binary can do on a machine with no KVM (P6-12).
//
// Firecracker needs Linux and /dev/kvm. On macOS that means a Lima VM, and the
// owner's ruling is that a macOS user never types `limactl` — `kelyfos doctor`
// owns that layer.
//
// So the binary is not a Linux binary that happens to link: it is a smaller
// program that says so. Every command that needs a guest refuses **with the way
// in**, rather than starting, reaching for a device that is not there, and
// failing somewhere a person has to read a stack trace to understand.
//
// What does work here works for a reason rather than by accident:
//
//   - `doctor` is the whole point — it provisions, starts, stops and reports on
//     the Linux layer, and prints the in-VM doctor's own output.
//   - `verify` reads a file. A person sent an exported report should be able to
//     check it on the machine they were sent it on, and that machine is often
//     this one. It needs no guest, no daemon and no network.
//   - `version` and `help` answer questions about the binary itself.
//
// What this does **not** do is pretend to `--- same commands everywhere`. That
// needs a transport across `limactl shell`, and an interrupt does not cross it:
// a Ctrl-C would orphan a microVM and silently discard the workspace it was
// syncing back. P4-7's wording promised it and P6-12 withdrew the promise.
var worksOnDarwin = map[string]bool{
	"doctor": true, "verify": true,
	"version": true, "--version": true, "-v": true,
	"help": true, "-h": true, "--help": true,
}

func runsHere(cmd string) error {
	if worksOnDarwin[cmd] {
		return nil
	}
	return fmt.Errorf(`kelyfos %s needs Linux and /dev/kvm, and this is macOS.

    The guest runs in a Lima VM, and kelyfos owns that layer so you do not have
    to type limactl:

        kelyfos doctor --setup     provision the VM and start it
        kelyfos doctor             what the layer is doing now

    Then run kelyfos inside it. What works on this machine is doctor, verify,
    version and help — verify included, because a report somebody sent you
    should be checkable on the machine they sent it to.`, cmd)
}

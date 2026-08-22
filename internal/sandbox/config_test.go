package sandbox

import "strings"

import "testing"

func TestBootArgsOmitRootAndReadOnly(t *testing.T) {
	// Firecracker inserts root= and ro itself from the drive flags; emitting
	// them here would put each option on the command line twice.
	for _, arch := range []string{"aarch64", "x86_64"} {
		args := bootArgs(arch, true)
		for _, forbidden := range []string{"root=", " ro ", "8250.nr_uarts"} {
			if strings.Contains(" "+args+" ", forbidden) {
				t.Errorf("%s boot args must not contain %q: %s", arch, forbidden, args)
			}
		}
		for _, required := range []string{"console=ttyS0", "init=/init", "nomodule", "pci=off"} {
			if !strings.Contains(args, required) {
				t.Errorf("%s boot args missing %q: %s", arch, required, args)
			}
		}
	}
}

func TestI8042KnobsAreX86Only(t *testing.T) {
	if strings.Contains(bootArgs("aarch64", true), "i8042") {
		t.Error("aarch64 has no i8042 controller; the knobs must not be passed")
	}
	if !strings.Contains(bootArgs("x86_64", true), "i8042.noaux") {
		t.Error("x86_64 should pass the i8042 knobs to save boot time")
	}
}

func TestQuietIsOptional(t *testing.T) {
	if strings.Contains(bootArgs("aarch64", false), "quiet") {
		t.Error("verbose boot must not pass quiet")
	}
	if !strings.Contains(bootArgs("aarch64", true), "quiet") {
		t.Error("quiet boot must pass quiet")
	}
}

func TestKernelArtifactIsUncompressedPerArch(t *testing.T) {
	if a, _ := KernelArtifact("aarch64"); a != "Image" {
		t.Errorf("aarch64 must boot the uncompressed Image, got %q", a)
	}
	if a, _ := KernelArtifact("x86_64"); a != "vmlinux" {
		t.Errorf("x86_64 must boot the uncompressed ELF vmlinux, got %q", a)
	}
	if _, err := KernelArtifact("riscv64"); err == nil {
		t.Error("an unsupported architecture must be an error, not a guess")
	}
}

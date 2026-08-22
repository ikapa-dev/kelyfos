package sandbox

import (
	"net"
	"strings"
	"testing"
)

func TestBootArgsOmitRootAndReadOnly(t *testing.T) {
	// Firecracker inserts root= and ro itself from the drive flags; emitting
	// them here would put each option on the command line twice.
	for _, arch := range []string{"aarch64", "x86_64"} {
		args := bootArgs(arch, true, nil, false)
		for _, forbidden := range []string{"root=", " ro ", "8250.nr_uarts"} {
			if strings.Contains(" "+args+" ", forbidden) {
				t.Errorf("%s boot args must not contain %q: %s", arch, forbidden, args)
			}
		}
		// PID 1 is the supervisor itself since P2-1 — there is no /init script.
		for _, required := range []string{"console=ttyS0", "init=/sbin/kelyfos-supervisor", "nomodule", "pci=off"} {
			if !strings.Contains(args, required) {
				t.Errorf("%s boot args missing %q: %s", arch, required, args)
			}
		}
	}
}

func TestI8042KnobsAreX86Only(t *testing.T) {
	if strings.Contains(bootArgs("aarch64", true, nil, false), "i8042") {
		t.Error("aarch64 has no i8042 controller; the knobs must not be passed")
	}
	if !strings.Contains(bootArgs("x86_64", true, nil, false), "i8042.noaux") {
		t.Error("x86_64 should pass the i8042 knobs to save boot time")
	}
}

func TestQuietIsOptional(t *testing.T) {
	if strings.Contains(bootArgs("aarch64", false, nil, false), "quiet") {
		t.Error("verbose boot must not pass quiet")
	}
	if !strings.Contains(bootArgs("aarch64", true, nil, false), "quiet") {
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

func TestNoNICMeansNoNetworkBootArgs(t *testing.T) {
	// With no allowlist there is no Network, and therefore nothing on the
	// command line that could configure an interface the machine does not have.
	args := bootArgs("aarch64", true, nil, false)
	for _, forbidden := range []string{"ip=", "kelyfos.proxy="} {
		if strings.Contains(args, forbidden) {
			t.Errorf("a sandbox with no egress must not carry %q: %s", forbidden, args)
		}
	}
}

func TestNetworkBootArgsConfigureTheNIC(t *testing.T) {
	n := &Network{
		TAP:       "kelyfos00112233",
		HostIP:    net.IPv4(169, 254, 1, 1),
		GuestIP:   net.IPv4(169, 254, 1, 2),
		Netmask:   "255.255.255.252",
		ProxyPort: 41234,
	}
	args := bootArgs("aarch64", true, n, false)
	for _, want := range []string{
		"ip=169.254.1.2::169.254.1.1:255.255.255.252::eth0:off",
		"kelyfos.proxy=169.254.1.1:41234",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("boot args missing %q: %s", want, args)
		}
	}
}

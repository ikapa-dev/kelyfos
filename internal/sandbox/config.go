package sandbox

import (
	"fmt"
	"runtime"
	"strings"
)

// FirecrackerConfig is the machine configuration KelyfOS writes for
// `firecracker --config-file`. Only the fields KelyfOS sets are modelled;
// Firecracker rejects unknown fields, so this is a whitelist by construction.
type FirecrackerConfig struct {
	BootSource    BootSource    `json:"boot-source"`
	Drives        []Drive       `json:"drives"`
	MachineConfig MachineConfig `json:"machine-config"`
	Vsock         *Vsock        `json:"vsock,omitempty"`
}

type BootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
}

type Drive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type MachineConfig struct {
	VcpuCount  int `json:"vcpu_count"`
	MemSizeMib int `json:"mem_size_mib"`
}

// Vsock is the hybrid vsock device. UDSPath is a host Unix socket that
// Firecracker creates and owns; it is not the Firecracker API socket, and no
// host vsock kernel module is involved (docs/protocol.md §1).
type Vsock struct {
	GuestCID uint32 `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

// bootArgs builds the guest kernel command line.
//
// Deliberately absent: root= and ro. Firecracker inserts both itself from the
// drive's is_root_device and is_read_only flags (src/vmm/src/builder.rs), and
// repeating them here would put the same option on the command line twice.
//
// Also absent: 8250.nr_uarts=0, which is in Firecracker's own default cmdline.
// It disables the serial port, and KelyfOS wants a console — it is the only way
// to see why a guest failed before the supervisor is up.
func bootArgs(arch string, quiet bool) string {
	args := []string{
		"reboot=k",        // no BIOS to reboot through; ask KVM to reset
		"panic=1",         // a panicked sandbox should die, not sit there
		"nomodule",        // belt to the kernel config's braces: no modules exist
		"swiotlb=noforce", // no bounce buffers; there is no real DMA here
		"console=ttyS0",   // ns16550a on both arches — see docs/protocol.md
		"pci=off",         // Firecracker exposes virtio over MMIO, not PCI
		"init=/init",      // the image has no /sbin/init: BR2_INIT_NONE
	}
	if arch == "x86_64" {
		// Stop the kernel probing a PS/2 controller Firecracker does not
		// emulate. Pure boot-time saving, and meaningless on aarch64 where the
		// i8042 does not exist.
		args = append(args, "i8042.noaux", "i8042.nomux", "i8042.dumbkbd")
	}
	if quiet {
		args = append(args, "quiet")
	}
	return strings.Join(args, " ")
}

// HostArch reports the build host's architecture using the project's spelling
// (aarch64 / x86_64) rather than Go's (arm64 / amd64).
func HostArch() string {
	switch runtime.GOARCH {
	case "arm64":
		return "aarch64"
	case "amd64":
		return "x86_64"
	default:
		return runtime.GOARCH
	}
}

// KernelArtifact is the file Firecracker boots for an architecture. Both are
// uncompressed: Firecracker boots the raw Image on aarch64 and the ELF vmlinux
// on x86_64, never Image.gz and never bzImage.
func KernelArtifact(arch string) (string, error) {
	switch arch {
	case "aarch64":
		return "Image", nil
	case "x86_64":
		return "vmlinux", nil
	default:
		return "", fmt.Errorf("unsupported architecture %q", arch)
	}
}

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
	"golang.org/x/sys/unix"
)

// FirecrackerVersion is the version pinned in versions.mk, stamped in at build
// time so the binary can check the environment against the same pin the build
// used rather than a number someone typed twice.
var FirecrackerVersion = "unknown"

// hostKind is the Linux layer a user is running on. Every fix message depends
// on it: "install Lima" is useless advice on a bare server, and "run
// wsl --update" is nonsense on a Mac.
type hostKind int

const (
	hostBareLinux hostKind = iota
	hostLima
	hostWSL2
	hostMacOS
	hostOther
)

func (h hostKind) String() string {
	switch h {
	case hostBareLinux:
		return "bare Linux"
	case hostLima:
		return "Lima VM (macOS host)"
	case hostWSL2:
		return "WSL2 (Windows host)"
	case hostMacOS:
		return "macOS"
	default:
		return "unknown"
	}
}

func detectHost() hostKind {
	if runtime.GOOS == "darwin" {
		return hostMacOS
	}
	if runtime.GOOS != "linux" {
		return hostOther
	}
	if blob, err := os.ReadFile("/proc/version"); err == nil {
		v := strings.ToLower(string(blob))
		if strings.Contains(v, "microsoft") || strings.Contains(v, "wsl") {
			return hostWSL2
		}
	}
	// Lima names the guest lima-<instance> and leaves its marker behind.
	if name, err := os.Hostname(); err == nil && strings.HasPrefix(name, "lima-") {
		return hostLima
	}
	if _, err := os.Stat("/mnt/lima-cidata"); err == nil {
		return hostLima
	}
	return hostBareLinux
}

type check struct {
	name   string
	ok     bool
	detail string
	fix    string
}

func doctorCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos doctor", flag.ExitOnError)
	arch := fs.String("arch", sandbox.HostArch(), "architecture to check images for")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: kelyfos doctor\n\nChecks that this machine can run KelyfOS, and says exactly how to fix what cannot.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	host := detectHost()
	fmt.Printf("kelyfos doctor — %s, %s\n\n", host, *arch)

	// If this is not a Linux machine with KVM, every later check is both
	// guaranteed to fail and about to offer advice that makes no sense here —
	// "sudo modprobe kvm_intel" and "sudo apt install" are not things a Mac
	// user can act on. One correct instruction beats seven wrong ones.
	if platform := checkPlatform(host); !platform.ok {
		fmt.Printf("  [FAIL] %-22s %s\n", platform.name, platform.detail)
		for _, line := range strings.Split(platform.fix, "\n") {
			fmt.Printf("         %s\n", line)
		}
		fmt.Println("\nThen run `kelyfos doctor` again inside the Linux layer, where the\n" +
			"remaining checks can actually tell you something.")
		return &exitError{code: 1}
	}

	images := checkImages(*arch)
	checks := []check{
		checkPlatform(host),
		checkKVM(host),
		checkFirecracker(),
		checkTUN(host),
		checkNetTools(),
		checkWorkspaceTools(),
		images,
		checkDisk(images.ok),
	}

	var failed int
	for _, c := range checks {
		mark := "ok  "
		if !c.ok {
			mark = "FAIL"
			failed++
		}
		fmt.Printf("  [%s] %-22s %s\n", mark, c.name, c.detail)
		if !c.ok && c.fix != "" {
			for _, line := range strings.Split(c.fix, "\n") {
				fmt.Printf("         %s\n", line)
			}
		}
	}

	fmt.Println()
	if failed == 0 {
		fmt.Println("all checks passed — this machine can run KelyfOS")
		return nil
	}
	// A doctor that exits 0 having found problems is useless in a script.
	fmt.Printf("%d check(s) failed\n", failed)
	return &exitError{code: 1}
}

func checkPlatform(host hostKind) check {
	switch host {
	case hostMacOS:
		return check{"platform", false, "macOS — Firecracker only runs on Linux/KVM",
			"KelyfOS needs a Linux layer. On Apple Silicon (M3 or newer, macOS 15+):\n" +
				"    brew install lima\n" +
				"    limactl start --name kelyfos-dev dev/lima.yaml\n" +
				"    limactl shell kelyfos-dev"}
	case hostOther:
		return check{"platform", false, runtime.GOOS + " is not supported",
			"KelyfOS runs on Linux with KVM. See dev/lima.yaml (macOS) or dev/wsl2.md (Windows)."}
	default:
		return check{"platform", true, host.String(), ""}
	}
}

func checkKVM(host hostKind) check {
	fd, err := unix.Open("/dev/kvm", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		detail := "/dev/kvm: " + err.Error()
		fix := ""
		switch {
		case os.IsNotExist(err):
			switch host {
			case hostLima:
				fix = "The Lima VM has no nested virtualization. It needs an Apple M3 or newer,\n" +
					"macOS 15+, and dev/lima.yaml's vmType: vz with nestedVirtualization: true.\n" +
					"Recreate it:  limactl delete kelyfos-dev && limactl start --name kelyfos-dev dev/lima.yaml"
			case hostWSL2:
				fix = "Add to %UserProfile%\\.wslconfig:\n" +
					"    [wsl2]\n    nestedVirtualization=true\n" +
					"then, from an elevated PowerShell:  wsl --update && wsl --shutdown"
			default:
				fix = "This machine has no KVM. Check that virtualization is enabled in the BIOS\n" +
					"and that the kvm module is loaded:  sudo modprobe kvm_intel  (or kvm_amd)"
			}
		case os.IsPermission(err):
			fix = "You are not permitted to open /dev/kvm. Add yourself to the kvm group:\n" +
				"    sudo usermod -aG kvm \"$USER\"   # then log out and back in\n" +
				"or install the udev rule KelyfOS uses:\n" +
				"    echo 'KERNEL==\"kvm\", GROUP=\"kvm\", MODE=\"0666\", OPTIONS+=\"static_node=kvm\"' \\\n" +
				"      | sudo tee /etc/udev/rules.d/99-kelyfos-kvm.rules\n" +
				"    sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=kvm"
		}
		return check{"/dev/kvm", false, detail, fix}
	}
	defer unix.Close(fd)

	// Opening it proves permission; the ioctl proves it actually works, which
	// is the difference between a device node and a hypervisor.
	version, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), 0xAE00, 0)
	if errno != 0 {
		return check{"/dev/kvm", false, "KVM_GET_API_VERSION failed: " + errno.Error(),
			"The device exists but does not answer. Nested virtualization may be half-enabled."}
	}
	return check{"/dev/kvm", true, fmt.Sprintf("usable, KVM API version %d", version), ""}
}

func checkFirecracker() check {
	path, err := exec.LookPath("firecracker")
	if err != nil {
		return check{"firecracker", false, "not on PATH",
			"Install the pinned release:  bash dev/install-firecracker.sh"}
	}
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return check{"firecracker", false, "found at " + path + " but would not run: " + err.Error(),
			"Reinstall:  bash dev/install-firecracker.sh"}
	}
	// "Firecracker v1.16.1" on the first line.
	got := ""
	if fields := strings.Fields(strings.SplitN(string(out), "\n", 2)[0]); len(fields) >= 2 {
		got = fields[1]
	}
	if FirecrackerVersion != "unknown" && got != FirecrackerVersion {
		return check{"firecracker", false,
			fmt.Sprintf("%s, but this build pins %s", got, FirecrackerVersion),
			"Match the pin in versions.mk:  bash dev/install-firecracker.sh"}
	}
	return check{"firecracker", true, got + " (matches versions.mk)", ""}
}

func checkTUN(host hostKind) check {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return check{"/dev/net/tun", false, "missing — egress (--allow) will not work",
			"Load the module:  sudo modprobe tun\nSandboxes without --allow are unaffected."}
	}
	return check{"/dev/net/tun", true, "present (egress available)", ""}
}

func checkNetTools() check {
	var missing []string
	for _, tool := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		return check{"egress tooling", false, "missing " + strings.Join(missing, ", "),
			"Needed only for --allow:  sudo apt install -y iproute2 nftables"}
	}
	if err := sandbox.CheckPrivileges(); err != nil {
		return check{"egress tooling", false, "present, but privileges are missing",
			"Creating a TAP and loading nftables rules needs passwordless sudo.\n" +
				"Sandboxes without --allow are unaffected."}
	}
	return check{"egress tooling", true, "ip, nft, and privileges to use them", ""}
}

func checkWorkspaceTools() check {
	var missing []string
	for _, tool := range []string{"mke2fs", "debugfs"} {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		return check{"workspace tooling", false, "missing " + strings.Join(missing, ", "),
			"Needed only for --workspace:  sudo apt install -y e2fsprogs"}
	}
	return check{"workspace tooling", true, "mke2fs, debugfs (--workspace available)", ""}
}

func checkImages(arch string) check {
	dir := sandbox.ImageDir(arch)
	kernel, err := sandbox.KernelArtifact(arch)
	if err != nil {
		return check{"guest image", false, err.Error(), ""}
	}
	var missing []string
	for _, f := range []string{kernel, "rootfs.ext4"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return check{"guest image", false, "missing " + strings.Join(missing, ", ") + " in " + dir,
			fmt.Sprintf("Build it:  make image ARCH=%s\n(the first build downloads and compiles a toolchain and takes a while)", arch)}
	}
	// The manifest is part of a usable image, not a nicety: without it the
	// sandbox refuses to boot (D21). Doctor reporting the image as fine and
	// the very next command failing is exactly the kind of check that trains
	// people to ignore it.
	m, err := sandbox.ReadManifest(dir)
	if err != nil {
		return check{"guest image", false, "no readable image.json in " + dir,
			fmt.Sprintf("This image predates the manifest, or was copied without it.\nRebuild:  make image ARCH=%s\nOr fetch: make fetch-image ARCH=%s", arch, arch)}
	}
	return check{"guest image", true, fmt.Sprintf("%s (%s, built %s)", dir, m.Flavor, m.Built), ""}
}

func checkDisk(haveImages bool) check {
	root := sandbox.Root()
	if err := os.MkdirAll(root, 0o755); err != nil {
		return check{"disk space", false, "cannot use " + root + ": " + err.Error(), ""}
	}
	var st unix.Statfs_t
	if err := unix.Statfs(root, &st); err != nil {
		return check{"disk space", false, "cannot measure " + root, ""}
	}
	free := int64(st.Bavail) * int64(st.Bsize)

	// Two very different numbers, and quoting the wrong one is how a check
	// becomes noise. Building a guest from source unpacks a cross toolchain and
	// a kernel tree — tens of gigabytes. Running an already-built image needs
	// room for snapshots and workspace copies and little else.
	need, why := int64(5<<30), "to run (snapshots and workspace copies)"
	if !haveImages {
		need, why = 25<<30, "to build a guest from source (toolchain and kernel trees)"
	}
	detail := fmt.Sprintf("%.1f GiB free in %s", float64(free)/(1<<30), root)
	if free < need {
		return check{"disk space", false,
			fmt.Sprintf("%s, want %d GiB %s", detail, need>>30, why),
			"Free some space, or point KELYFOS_CACHE at a roomier filesystem.\n" +
				"Old build trees are reclaimable:  rm -rf ~/.cache/kelyfos/build/<arch>-<flavor>"}
	}
	return check{"disk space", true, detail + " (enough " + why + ")", ""}
}

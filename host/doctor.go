package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
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
	// warn marks a check that is worth printing but must never flip the
	// exit code: unlike every other FAIL here, crossing the session-records
	// size bound (checkSessionsSize) changes nothing about whether this
	// machine can currently run KelyfOS — docs/retention.md says so in as
	// many words — so counting it toward "N check(s) failed" would make a
	// script treat past session history as a reason to stop, the way it
	// correctly treats a missing jailer or no free disk (S3). Ignored when
	// ok is true.
	warn bool
}

func doctorCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos doctor", flag.ExitOnError)
	arch := fs.String("arch", sandbox.HostArch(), "architecture to check images for")
	// The Linux layer, on the platform that needs one (P6-12). On Linux these
	// are accepted and refused with one sentence, rather than being absent —
	// a flag that exists on one platform and is an unknown flag on the other
	// teaches a person that the tool is two tools.
	setup := fs.Bool("setup", false, "macOS: provision and start the Linux layer, then check inside it")
	recreate := fs.Bool("recreate", false, "macOS: delete the Linux layer and provision it again")
	stop := fs.Bool("stop", false, "macOS: stop the Linux layer")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: kelyfos doctor\n\nChecks that this machine can run KelyfOS, and says exactly how to fix what cannot.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	if *setup || *recreate || *stop {
		if err := layerCommand(*setup, *recreate, *stop, *arch); err != nil {
			return err
		}
		return nil
	}

	host := detectHost()
	fmt.Printf("kelyfos doctor — %s, %s\n\n", host, *arch)

	// If this is not a Linux machine with KVM, every later check is both
	// guaranteed to fail and about to offer advice that makes no sense here —
	// "sudo modprobe kvm_intel" and "sudo apt install" are not things a Mac
	// user can act on. One correct instruction beats seven wrong ones.
	// macOS is a supported platform with a layer under it, not a failure, and
	// since P6-12 this command owns that layer. So the report is the layer's:
	// what state it is in, whether it matches the configuration this binary
	// carries, and then the in-VM doctor's own output — which is where the
	// checks that mean anything actually run (P6-12).
	//
	// The old shape printed `[FAIL] platform` and told a Mac user to type
	// limactl. Both halves of that are now wrong: the platform is fine and the
	// user does not type limactl.
	if runtime.GOOS == "darwin" {
		return layerReport(*arch)
	}

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
		checkJailer(),
		checkWorkspaceTools(),
		images,
		checkDisk(images.ok),
		checkSessionsSize(),
	}

	var failed int
	for _, c := range checks {
		mark := "ok  "
		switch {
		case !c.ok && c.warn:
			mark = "warn"
		case !c.ok:
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

	var warned int
	for _, c := range checks {
		if !c.ok && c.warn {
			warned++
		}
	}

	fmt.Println()
	if failed == 0 {
		if warned > 0 {
			fmt.Printf("this machine can run KelyfOS — %d warning(s) above are advisory only\n", warned)
		} else {
			fmt.Println("all checks passed — this machine can run KelyfOS")
		}
		return nil
	}
	// A doctor that exits 0 having found problems is useless in a script.
	// warned is not added to this count: it exists so a script can tell
	// "cannot run" from "can run, but look at this."
	fmt.Printf("%d check(s) failed\n", failed)
	return &exitError{code: 1}
}

func checkPlatform(host hostKind) check {
	switch host {
	case hostMacOS:
		// The fix names kelyfos rather than limactl, because since P6-12 this
		// command owns the layer: a macOS user provisioning it by hand would be
		// making an instance kelyfos cannot then tell them anything about.
		return check{name: "platform", ok: false, detail: "macOS — Firecracker only runs on Linux/KVM", fix: "KelyfOS runs the guest in a Linux layer, and looks after it for you.\n" +
			"On Apple Silicon (M3 or newer, macOS 15+):\n" +
			"    brew install lima\n" +
			"    kelyfos doctor --setup"}
	case hostOther:
		return check{name: "platform", ok: false, detail: runtime.GOOS + " is not supported", fix: "KelyfOS runs on Linux with KVM. See dev/lima.yaml (macOS) or dev/wsl2.md (Windows)."}
	default:
		return check{name: "platform", ok: true, detail: host.String(), fix: ""}
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
		return check{name: "/dev/kvm", ok: false, detail: detail, fix: fix}
	}
	defer unix.Close(fd)

	// Opening it proves permission; the ioctl proves it actually works, which
	// is the difference between a device node and a hypervisor.
	version, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), 0xAE00, 0)
	if errno != 0 {
		return check{name: "/dev/kvm", ok: false, detail: "KVM_GET_API_VERSION failed: " + errno.Error(), fix: "The device exists but does not answer. Nested virtualization may be half-enabled."}
	}
	return check{name: "/dev/kvm", ok: true, detail: fmt.Sprintf("usable, KVM API version %d", version), fix: ""}
}

func checkFirecracker() check {
	path, err := exec.LookPath("firecracker")
	if err != nil {
		return check{name: "firecracker", ok: false, detail: "not on PATH", fix: "Install the pinned release:  bash dev/install-firecracker.sh"}
	}
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return check{name: "firecracker", ok: false, detail: "found at " + path + " but would not run: " + err.Error(), fix: "Reinstall:  bash dev/install-firecracker.sh"}
	}
	// "Firecracker v1.16.1" on the first line.
	got := ""
	if fields := strings.Fields(strings.SplitN(string(out), "\n", 2)[0]); len(fields) >= 2 {
		got = fields[1]
	}
	if FirecrackerVersion != "unknown" && got != FirecrackerVersion {
		return check{name: "firecracker", ok: false, detail: fmt.Sprintf("%s, but this build pins %s", got, FirecrackerVersion), fix: "Match the pin in versions.mk:  bash dev/install-firecracker.sh"}
	}
	return check{name: "firecracker", ok: true, detail: got + " (matches versions.mk)", fix: ""}
}

func checkTUN(host hostKind) check {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return check{name: "/dev/net/tun", ok: false, detail: "missing — egress (--allow) will not work", fix: "Load the module:  sudo modprobe tun\nSandboxes without --allow are unaffected."}
	}
	return check{name: "/dev/net/tun", ok: true, detail: "present (egress available)", fix: ""}
}

func checkNetTools() check {
	var missing []string
	for _, tool := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		return check{name: "egress tooling", ok: false, detail: "missing " + strings.Join(missing, ", "), fix: "Needed only for --allow:  sudo apt install -y iproute2 nftables"}
	}
	if err := sandbox.CheckPrivileges(); err != nil {
		return check{name: "egress tooling", ok: false, detail: "present, but privileges are missing", fix: "Creating a TAP and loading nftables rules needs passwordless sudo.\n" +
			"Sandboxes without --allow are unaffected."}
	}
	return check{name: "egress tooling", ok: true, detail: "ip, nft, and privileges to use them", fix: ""}
}

// checkJailer is the one privilege check that is not optional, because a run is
// jailed by default (P5-1). Egress tooling is "needed only for --allow"; this is
// needed for `kelyfos run`.
func checkJailer() check {
	if err := sandbox.JailAvailable(); err != nil {
		return check{name: "jailer", ok: false, detail: "cannot run it", fix: "Firecracker runs inside the jailer \u2014 a chroot, a dropped uid, only the devices\n" +
			"it needs \u2014 and that needs passwordless sudo for the jailer alone:\n" +
			"    echo '" + sandbox.SudoersLine() + "' | sudo tee /etc/sudoers.d/kelyfos-jailer\n" +
			"    sudo chmod 0440 /etc/sudoers.d/kelyfos-jailer\n" +
			"`kelyfos run --no-jail` works without it and says so on every run."}
	}
	return check{name: "jailer", ok: true, detail: "present, with the privileges to use it", fix: ""}
}

func checkWorkspaceTools() check {
	var missing []string
	for _, tool := range []string{"mke2fs", "debugfs"} {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		return check{name: "workspace tooling", ok: false, detail: "missing " + strings.Join(missing, ", "), fix: "Needed only for --workspace:  sudo apt install -y e2fsprogs"}
	}
	return check{name: "workspace tooling", ok: true, detail: "mke2fs, debugfs (--workspace available)", fix: ""}
}

func checkImages(arch string) check {
	dir := sandbox.ImageDir(arch)
	kernel, err := sandbox.KernelArtifact(arch)
	if err != nil {
		return check{name: "guest image", ok: false, detail: err.Error(), fix: ""}
	}
	var missing []string
	for _, f := range []string{kernel, "rootfs.ext4"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return check{name: "guest image", ok: false, detail: "missing " + strings.Join(missing, ", ") + " in " + dir, fix: fmt.Sprintf("Build it:  make image ARCH=%s\n(the first build downloads and compiles a toolchain and takes a while)", arch)}
	}
	// The manifest is part of a usable image, not a nicety: without it the
	// sandbox refuses to boot (D21). Doctor reporting the image as fine and
	// the very next command failing is exactly the kind of check that trains
	// people to ignore it.
	m, err := sandbox.ReadManifest(dir)
	if err != nil {
		return check{name: "guest image", ok: false, detail: "no readable image.json in " + dir, fix: fmt.Sprintf("This image predates the manifest, or was copied without it.\nRebuild:  make image ARCH=%s\nOr fetch: make fetch-image ARCH=%s", arch, arch)}
	}
	return check{name: "guest image", ok: true, detail: fmt.Sprintf("%s (%s, built %s)", dir, m.Flavor, m.Built), fix: ""}
}

func checkDisk(haveImages bool) check {
	root := sandbox.Root()
	if err := os.MkdirAll(root, 0o755); err != nil {
		return check{name: "disk space", ok: false, detail: "cannot use " + root + ": " + err.Error(), fix: ""}
	}
	var st unix.Statfs_t
	if err := unix.Statfs(root, &st); err != nil {
		return check{name: "disk space", ok: false, detail: "cannot measure " + root, fix: ""}
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
		return check{name: "disk space", ok: false, detail: fmt.Sprintf("%s, want %d GiB %s", detail, need>>30, why), fix: "Free some space, or point KELYFOS_CACHE at a roomier filesystem.\n" +
			"Old build trees are reclaimable:  rm -rf ~/.cache/kelyfos/build/<arch>-<flavor>"}
	}
	return check{name: "disk space", ok: true, detail: detail + " (enough " + why + ")", fix: ""}
}

// sessionsSizeWarnBytes bounds ~/.cache/kelyfos/sessions/ the same way
// templateCacheBytes bounds the fork-template cache — a constant rather than
// a setting, because unlike retention (a compliance floor, [sessions]
// retention_days) this is advisory only: crossing it changes nothing about
// what KelyfOS does, only what doctor says (P7-5, D61).
const sessionsSizeWarnBytes = 1 << 30

// checkSessionsSize is P7-5's size warning (D61): the flight recorder's own
// history has never been pruned automatically — nothing deletes a session
// record on its own — so unlike the fork-template cache, which sweeps
// itself, this can only ever grow until someone runs
// `kelyfos sessions prune`. Framed as a FAIL with a fix, the same as disk
// space above, because doctor's own fix field is exactly the place to name
// the command that answers it.
func checkSessionsSize() check {
	root := recorder.SessionsDir(sandbox.Root())
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return check{name: "session records", ok: true, detail: "none recorded yet"}
	}
	if err != nil {
		// Unlike crossing the size bound below, an unreadable root is a real
		// problem doctor should say something about — a permissions error on
		// this machine's own cache directory is not advisory, but a FAIL
		// with no fix line was doctor's own S3 problem (an empty fix string
		// fails the check and offers zero guidance). warn stays false here
		// on purpose: this is the "cannot currently tell" case, not the
		// "can run fine, here is some history" case checkSessionsSize
		// otherwise exists for.
		return check{name: "session records", ok: false,
			detail: "cannot read " + root + ": " + err.Error(),
			fix: "Check that this user owns " + root + " and can read it:\n" +
				"    ls -la " + root + "\n" +
				"If it was created by another user or root, fix its ownership:\n" +
				"    sudo chown -R \"$USER\" " + root}
	}
	var total int64
	var n int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n++
		_ = filepath.Walk(filepath.Join(root, e.Name()), func(_ string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			total += info.Size()
			return nil
		})
	}
	return sessionsSizeCheck(root, n, total)
}

// sessionsSizeCheck is checkSessionsSize's own decision, split out so it can
// be tested without actually writing a gigabyte-scale file to disk to cross
// the bound — the same reason pruneEligible (host/sessions.go) is its own
// pure function rather than folded into sessionsPrune's directory walk.
func sessionsSizeCheck(root string, n int, total int64) check {
	detail := fmt.Sprintf("%d session(s), %.1f MiB in %s", n, float64(total)/(1<<20), root)
	if total < sessionsSizeWarnBytes {
		return check{name: "session records", ok: true, detail: detail}
	}
	// warn: true (S3) — crossing this bound changes nothing about whether
	// this machine can run KelyfOS, only what doctor says, unlike every
	// other FAIL in this file. Counting it toward the exit code would make
	// `kelyfos doctor` fail a script for a machine that runs fine and
	// merely has session history to prune.
	return check{name: "session records", ok: false, warn: true,
		detail: fmt.Sprintf("%s, over the %d GiB advisory bound", detail, sessionsSizeWarnBytes>>30),
		fix: "Nothing is deleted automatically — the flight recorder's own history grows until pruned.\n" +
			"    kelyfos sessions prune           deletes recorded sessions past the retention floor\n" +
			"    kelyfos sessions prune -dry-run  shows what that would delete first"}
}

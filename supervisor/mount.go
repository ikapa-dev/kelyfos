package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// setupRoot brings the machine up: pseudo-filesystems, then a writable overlay
// over the read-only root. It reports whether the overlay was established.
//
// This is what the phase-1 /init script did, moved into PID 1 itself (P2-1).
// The rules it inherits are the ones that matter for an init: never give up
// entirely, and degrade loudly rather than silently. A guest that boots on a
// read-only root and says so is diagnosable; one that fails to boot is a kernel
// panic and a support ticket.
func setupRoot() (overlay bool) {
	const nodev = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC

	mountOrWarn("proc", "/proc", "proc", nodev, "")
	mountOrWarn("sysfs", "/sys", "sysfs", nodev, "")
	protectFromOOMKiller()
	// The kernel mounts devtmpfs on /dev before starting PID 1
	// (CONFIG_DEVTMPFS_MOUNT), which is also why this process has a console.
	if !isMounted("/dev") {
		mountOrWarn("devtmpfs", "/dev", "devtmpfs", unix.MS_NOSUID, "mode=0755")
	}

	if err := setupOverlay(); err != nil {
		logf("warning: overlay setup failed, continuing on a read-only root: %v", err)
		mountOrWarn("tmpfs", "/tmp", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777")
		mountOrWarn("tmpfs", "/run", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755")
	} else {
		overlay = true
	}

	_ = os.MkdirAll("/dev/pts", 0o755)
	_ = os.MkdirAll("/dev/shm", 0o1777)
	mountOrWarn("devpts", "/dev/pts", "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "gid=5,mode=0620")
	mountOrWarn("tmpfs", "/dev/shm", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777")

	applyHostname()

	// Somewhere for work to happen. P3-10 replaces this with a real block device.
	_ = os.MkdirAll("/work", 0o755)
	return overlay
}

// overlayFlags is what the merged root — the filesystem the guest actually runs
// on — is mounted with. It was 0 until F10 of the 2026-08-28 review.
//
// A mount's flags are its own. The lower layer is the read-only image and the
// upper is a tmpfs already carrying MS_NOSUID|MS_NODEV, and neither lends
// anything to the merged mount on top, so this needed saying separately.
//
//	MS_NODEV   the second layer under F10. Landlock refuses the mknod, and if
//	           a node ever exists anyway — a future grant, a bug, a path the
//	           ruleset does not cover — the kernel will not open it as a
//	           device. The image ships no device node outside /dev, and /dev
//	           is a devtmpfs moved across afterwards with its own flags, so
//	           this takes nothing away from the guest.
//	MS_NOSUID  /bin/busybox in this image is mode 4755. Every process here is
//	           already root, so today the bit buys an attacker nothing and
//	           costs the guest nothing to drop — which is exactly when to drop
//	           it, rather than after something in this guest first runs as a
//	           uid that is not 0.
//
// MS_NOEXEC is not here and must not be: this is the filesystem the programs
// are on.
const overlayFlags = uintptr(unix.MS_NODEV | unix.MS_NOSUID)

// setupOverlay puts a tmpfs-backed overlayfs over the read-only root and moves
// into it. /mnt and /.oldroot already exist in the image because nothing can
// create a directory on a read-only root.
func setupOverlay() error {
	// The scratch cap, when the host set one. With no size= the guest kernel
	// applies its own default of half the machine's RAM — which is the
	// documented default, so it is left to the kernel rather than restated here
	// where it could drift (E1-5).
	opts := "mode=0755"
	if n := kernelParam("kelyfos.scratch"); n != "" {
		opts += ",size=" + n
		logf("scratch capped at %s", n)
	}
	if err := unix.Mount("tmpfs", "/mnt", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, opts); err != nil {
		return fmt.Errorf("tmpfs on /mnt: %w", err)
	}
	for _, d := range []string{"/mnt/upper", "/mnt/work", "/mnt/merged"} {
		if err := os.Mkdir(d, 0o755); err != nil && !os.IsExist(err) {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	if err := unix.Mount("overlay", "/mnt/merged", "overlay", overlayFlags,
		"lowerdir=/,upperdir=/mnt/upper,workdir=/mnt/work"); err != nil {
		return fmt.Errorf("overlay mount: %w", err)
	}

	// Carry the pseudo-filesystems across before the root changes underneath
	// them — including /dev, which holds the console this process logs to.
	for _, d := range []string{"/dev", "/proc", "/sys"} {
		if err := unix.Mount(d, "/mnt/merged"+d, "", unix.MS_MOVE, ""); err != nil {
			return fmt.Errorf("move %s: %w", d, err)
		}
	}

	if err := unix.Chdir("/mnt/merged"); err != nil {
		return fmt.Errorf("chdir: %w", err)
	}
	if err := unix.PivotRoot(".", ".oldroot"); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("chdir after pivot: %w", err)
	}
	// The old read-only root stays mounted at /.oldroot. Detaching it would mean
	// lazily unmounting the filesystem that holds this overlay's upper and work
	// directories — a subtlety with no benefit here.
	return nil
}

// applyHostname exists because the image has no init system to do it, so
// without this the guest calls itself "(none)" in every uname and log line.
// defaultPath is the PATH every command this supervisor starts is given, and —
// separately and for a different reason — the PATH this process itself uses.
//
// A guest's init inherits the kernel's environment, which is HOME and TERM and
// no PATH at all. Handing the *child* a PATH is not enough: os/exec resolves a
// bare command name against the **parent's** PATH before the child exists, so
// `exec.Command("python3")` in a process with no PATH fails to find a python3
// the machine plainly has. Everything routed through /bin/sh worked anyway,
// because a shell supplies its own default, which is why this stayed invisible
// until something was launched directly — a plugin, or an `exec` with no shell
// (E4-7).
const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// applyDefaultPath gives this process the PATH the kernel did not. Set rather
// than appended, and only when there is none: a PATH the host put on the kernel
// command line is the host's decision and is left alone.
func applyDefaultPath() {
	if os.Getenv("PATH") != "" {
		return
	}
	if err := os.Setenv("PATH", defaultPath); err != nil {
		logf("warning: could not set a default PATH: %v", err)
	}
}

func applyHostname() {
	blob, err := os.ReadFile("/etc/hostname")
	if err != nil {
		return
	}
	name := strings.TrimSpace(string(blob))
	if name == "" {
		return
	}
	if err := unix.Sethostname([]byte(name)); err != nil {
		logf("warning: could not set hostname: %v", err)
	}
}

// protectFromOOMKiller takes PID 1 off the OOM killer's list of candidates.
//
// This limits nothing — the RAM cap is the VM's hardware and stands whatever
// this process does (F-D2). What it buys is that the machine survives its own
// memory exhaustion long enough to report it. Without it the killer is free to
// pick the supervisor, and killing PID 1 is a kernel panic: the sandbox would
// die at exactly the moment E1-4 exists to make legible, and the user would see
// a VM that vanished rather than a named process that was killed.
//
// -1000 is the floor, and the same value systemd and container runtimes give
// their own init. Written after /proc is mounted, since that is where it lives;
// a failure here is worth a line on the console and nothing more, because the
// supervisor still works, it is just no longer immortal.
func protectFromOOMKiller() {
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("-1000\n"), 0o644); err != nil {
		logf("warning: could not exempt PID 1 from the OOM killer: %v", err)
	}
}

// kernelParam reads one kelyfos.* value from the kernel command line, which is
// the one thing in this machine the guest did not write.
func kernelParam(name string) string {
	blob, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	value := ""
	for _, field := range strings.Fields(string(blob)) {
		if v, ok := strings.CutPrefix(field, name+"="); ok {
			value = v
		}
	}
	return value
}

// restoreOOMScore undoes, for one child, the exemption PID 1 gave itself.
//
// oom_score_adj is inherited across fork, so without this every process the
// supervisor starts inherits -1000 and the OOM killer ends up with no candidate
// at all. That is not a safer machine, it is a worse one: the kernel prints
// "Out of memory and no killable processes" and panics, which is precisely the
// vanished-sandbox outcome E1-4 exists to replace. Measured directly — with the
// exemption inherited, a guest that should have killed one Python process
// instead died with nothing in its log.
//
// There is a window here and it is worth naming: between fork and this write the
// child is still exempt. It is the time it takes to exec, and a process cannot
// allocate its way to an OOM in it — measured, a command that reads its own
// oom_score_adj as its very first act already reads 0. The alternative designs
// are an unkillable machine or a killable PID 1, and neither is better.
func restoreOOMScore(pid int) {
	path := fmt.Sprintf("/proc/%d/oom_score_adj", pid)
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
		logf("warning: could not restore the OOM score of pid %d: %v", pid, err)
	}
}

func mountOrWarn(source, target, fstype string, flags uintptr, data string) {
	if err := unix.Mount(source, target, fstype, flags, data); err != nil {
		logf("warning: mount %s on %s: %v", fstype, target, err)
	}
}

func isMounted(target string) bool {
	blob, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	return bytes.Contains(blob, []byte(" "+target+" "))
}

// overlayActive reports whether the root is actually an overlayfs, which is a
// stronger statement than "the setup code did not return an error".
func overlayActive() bool {
	var st unix.Statfs_t
	if err := unix.Statfs("/", &st); err != nil {
		return false
	}
	const overlaySuperMagic = 0x794c7630
	return int64(st.Type) == overlaySuperMagic
}

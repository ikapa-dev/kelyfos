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

// setupOverlay puts a tmpfs-backed overlayfs over the read-only root and moves
// into it. /mnt and /.oldroot already exist in the image because nothing can
// create a directory on a read-only root.
func setupOverlay() error {
	if err := unix.Mount("tmpfs", "/mnt", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
		return fmt.Errorf("tmpfs on /mnt: %w", err)
	}
	for _, d := range []string{"/mnt/upper", "/mnt/work", "/mnt/merged"} {
		if err := os.Mkdir(d, 0o755); err != nil && !os.IsExist(err) {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	if err := unix.Mount("overlay", "/mnt/merged", "overlay", 0,
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

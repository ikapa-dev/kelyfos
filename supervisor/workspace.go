package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// mountWorkspace mounts the workspace disk at /work, if the host attached one.
//
// The device is pinned on the command line rather than discovered, because the
// supervisor should not be guessing which disk is which — the host knows, it
// attached them.
//
// This runs after the overlay is established: /work in the overlay is a
// directory in guest memory, and mounting over it is what makes writes land on
// a disk the host can read back afterwards (P3-10).
func mountWorkspace() (mounted bool) {
	blob, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return false
	}
	dev := ""
	for _, field := range strings.Fields(string(blob)) {
		if v, ok := strings.CutPrefix(field, "kelyfos.workspace="); ok {
			dev = v
		}
	}
	if dev == "" {
		return false
	}
	if err := os.MkdirAll("/work", 0o755); err != nil {
		logf("warning: /work: %v", err)
		return false
	}
	if err := unix.Mount(dev, "/work", "ext4", unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		logf("warning: could not mount workspace %s on /work: %v", dev, err)
		return false
	}
	logf("workspace mounted from %s on /work", dev)
	return true
}

// syncWorkspace flushes the workspace to disk before the machine goes down.
// The host reads the image straight afterwards, so anything still in the page
// cache would simply be lost.
func syncWorkspace() {
	unix.Sync()
}

// flushWorkspace makes the workspace's writes DETERMINISTICALLY durable: one
// syncfs(2) against the /work filesystem, which blocks until every write that
// filesystem has accepted is on the device, rather than sync(2)'s whole-machine
// best-effort. The host's shutdown handshake now waits for this: the ack it
// reads back over the control channel means "your files are on the disk",
// which is the guarantee IA-H1 found missing — a teardown that raced the ext4
// commit lost the run's last writes while reporting success.
func flushWorkspace() error {
	fd, err := unix.Open("/work", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		// No /work, no flush: a sandbox without a workspace has nothing whose
		// loss the handshake could hide.
		return nil
	}
	defer unix.Close(fd)
	if err := unix.Syncfs(fd); err != nil {
		return fmt.Errorf("syncfs /work: %w", err)
	}
	// The rest of the machine's writes — the record, the logs — are not the
	// host's to read back, but there is no reason to leave them dirty either.
	unix.Sync()
	return nil
}

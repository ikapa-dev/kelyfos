package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Bringing the guest's loopback interface up (E5-5, found by the E5 exit).
//
// A KelyfOS guest with no `--allow` has no NIC and no kernel `ip=` argument, and
// the kernel leaves `lo` DOWN. That is fine for a machine that only ever talks
// over vsock — and wrong for everything else it might reasonably do. A forwarded
// port dials `127.0.0.1` *inside* the guest, so `-p 8080:80` could not work on a
// sandbox with no network at all: the shape a forward is most useful for, and
// the one the whole vsock design exists to serve.
//
// Loopback is not a network path to anywhere. It is the machine talking to
// itself: a local server, a language runtime's own health check, a test suite
// binding 127.0.0.1. Leaving it down denies all of that to buy nothing, because
// no packet on `lo` can leave the machine by definition.
//
// Done here rather than in the image's init because there is no init: the
// supervisor is PID 1 (D3).
func bringUpLoopback() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket for SIOCSIFFLAGS: %w", err)
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	// Read the current flags rather than assuming them: setting IFF_UP alone
	// would clear whatever else the kernel had already set on the interface.
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("read lo flags: %w", err)
	}
	if ifr.Uint16()&unix.IFF_UP != 0 {
		return nil
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bring lo up: %w", err)
	}
	return nil
}

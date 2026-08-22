// Command kelyfos-supervisor is PID 1 inside a KelyfOS guest.
//
// It brings the machine up, reaps every orphan the kernel hands it, exposes the
// guest over vsock, and takes the machine down when the host asks. There is no
// shell, no getty and no init system behind it — this process is the whole of
// userspace management (P2-1, replacing the phase-1 /init script).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/vsock"
	"golang.org/x/sys/unix"
)

// Version is the supervisor build reported in the ready frame, so the host can
// log which guest it is talking to when the image and the CLI are different
// builds (docs/protocol.md §7).
const Version = "0.2.0-p2"

const (
	heartbeatInterval = 5 * time.Second
	shutdownGrace     = 2 * time.Second

	// Retry backoff for the guest-initiated channels. The first attempts are
	// deliberately aggressive: the virtio-vsock device is not always ready the
	// instant this process is, and a flat retry would add its whole interval to
	// every boot of a product whose headline number is boot-to-ready.
	dialBackoffMin = 1 * time.Millisecond
	dialBackoffMax = 200 * time.Millisecond
)

var isPID1 = os.Getpid() == 1

func main() {
	start := monotonic()

	if isPID1 {
		// Nothing has mounted anything yet, so there is no /proc to read and
		// no writable filesystem to log to — only the console the kernel gave
		// us. setupRoot changes that.
		setupRoot()
	}

	rp := newReaper()
	if isPID1 {
		rp.start()
	}

	shutdown := make(chan struct{}, 1)

	// Listeners are bound before readiness is announced. The host is entitled
	// to connect the instant it sees the ready frame, and a race there looks
	// like a mysterious connection refusal.
	if ln, err := vsock.Listen(proto.PortExec); err != nil {
		logf("cannot listen on exec port %d: %v", proto.PortExec, err)
	} else {
		go serveExec(ln, rp)
	}
	if ln, err := vsock.Listen(proto.PortControl); err != nil {
		logf("cannot listen on control port %d: %v", proto.PortControl, err)
	} else {
		go serveControl(ln, shutdown)
	}

	go announceReady(start)

	<-shutdown
	halt(shutdownGrace)
}

// serveExec answers the exec channel, one command per connection
// (docs/protocol.md §5.1).
func serveExec(ln net.Listener, rp *reaper) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			logf("exec accept: %v", err)
			return
		}
		go serveExecConn(conn, rp)
	}
}

// announceReady dials the host and keeps the ready channel alive. It retries,
// because the host may not have bound its end yet and because every connection
// is severed by a snapshot restore (docs/protocol.md §1.6).
func announceReady(start time.Duration) {
	bootID := newBootID()
	backoff := dialBackoffMin
	for {
		conn, err := vsock.Dial(proto.CIDHost, proto.PortReady)
		if err != nil {
			time.Sleep(backoff)
			if backoff < dialBackoffMax {
				backoff *= 2
			}
			continue
		}
		backoff = dialBackoffMin
		if err := pumpReady(conn, bootID, start); err != nil && !errors.Is(err, io.EOF) {
			logf("ready channel: %v", err)
		}
		conn.Close()
	}
}

func pumpReady(conn net.Conn, bootID string, start time.Duration) error {
	w := proto.NewWriter(conn)
	if err := w.Write(proto.Ready{
		V:           proto.Version,
		Type:        "ready",
		BootID:      bootID,
		Arch:        runtime.GOARCH,
		Kernel:      kernelRelease(),
		Supervisor:  Version,
		MonotonicNS: monotonic().Nanoseconds(),
		Overlay:     overlayActive(),
	}); err != nil {
		return err
	}
	for range time.Tick(heartbeatInterval) {
		if err := w.Write(proto.Heartbeat{
			V:        proto.Version,
			Type:     "heartbeat",
			UptimeMS: (monotonic() - start).Milliseconds(),
		}); err != nil {
			return err
		}
	}
	return nil
}

// logf writes to the console. There is no syslog and no log file: PID 1's
// diagnostics have to reach a human before the machine has a filesystem worth
// writing to.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "kelyfos-supervisor: "+format+"\n", args...)
}

func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "unknown"
	}
	return unix.ByteSliceToString(u.Release[:])
}

func monotonic() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)
}

// newBootID identifies one boot of one VM. Entropy this early can be poor, and
// after a snapshot restore N forks start from identical pool state, so this is
// an identifier and never a secret.
func newBootID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("pid%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

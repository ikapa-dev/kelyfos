// Command kelyfos-supervisor is the KelyfOS guest agent.
//
// Phase 1 (this version) is a stub launched by the /init script: it announces
// readiness on the guest-initiated ready channel, heartbeats, and accepts
// connections on the exec port so the transport can be proven end to end before
// any command execution exists. P1-6 implements exec; P2-1 makes this binary
// PID 1 and retires /init entirely.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
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
const Version = "0.1.0-p1"

const heartbeatInterval = 5 * time.Second

func main() {
	log.SetFlags(0)
	log.SetPrefix("kelyfos-supervisor: ")

	start := monotonic()

	// The exec listener is bound before announcing readiness. The host is
	// entitled to connect the instant it sees the ready frame, and a race
	// there would look like a mysterious connection refusal.
	execLn, err := vsock.Listen(proto.PortExec)
	if err != nil {
		log.Printf("cannot listen on exec port %d: %v", proto.PortExec, err)
	} else {
		go serveExec(execLn)
	}

	go announceReady(start)

	// Phase 1 has nothing else to do. Park forever rather than exiting: this
	// process is the guest's reason for being up, and returning from main would
	// leave a running VM with nobody listening.
	select {}
}

// announceReady dials the host and keeps the ready channel alive. It retries,
// because the host may not have bound its end yet and because every connection
// is severed by a snapshot restore (docs/protocol.md §1.6).
func announceReady(start time.Duration) {
	bootID := newBootID()
	overlay := overlayActive()
	for {
		conn, err := vsock.Dial(proto.CIDHost, proto.PortReady)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if err := pumpReady(conn, bootID, overlay, start); err != nil &&
			!errors.Is(err, io.EOF) {
			log.Printf("ready channel: %v", err)
		}
		conn.Close()
		time.Sleep(200 * time.Millisecond)
	}
}

func pumpReady(conn net.Conn, bootID string, overlay bool, start time.Duration) error {
	w := proto.NewWriter(conn)
	if err := w.Write(proto.Ready{
		V:           proto.Version,
		Type:        "ready",
		BootID:      bootID,
		Arch:        runtime.GOARCH,
		Kernel:      kernelRelease(),
		Supervisor:  Version,
		MonotonicNS: monotonic().Nanoseconds(),
		Overlay:     overlay,
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

// serveExec answers the exec channel. Phase 1 has no command execution, so it
// replies with a well-formed error frame rather than closing silently: a host
// that gets a valid exit frame saying "not implemented" is debuggable, one that
// gets a dropped connection cannot tell that from a crashed supervisor
// (docs/protocol.md §5.2).
func serveExec(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("exec accept: %v", err)
			return
		}
		go func() {
			defer conn.Close()
			var req proto.ExecRequest
			if err := proto.NewReader(conn).Read(&req); err != nil {
				return
			}
			code := -1
			_ = proto.NewWriter(conn).Write(proto.ExecResponse{
				V:      proto.Version,
				ID:     req.ID,
				Stream: proto.StreamExit,
				Code:   &code,
				Error: &proto.Error{
					Kind:    proto.ErrInternal,
					Message: "exec is not implemented in the phase-1 supervisor stub (P1-6)",
				},
			})
		}()
	}
}

// overlayActive reports whether /init managed to put a writable overlay over
// the read-only root. It is surfaced in the ready frame so a degraded boot is
// visible to the host instead of showing up later as a puzzling EROFS.
func overlayActive() bool {
	var st unix.Statfs_t
	if err := unix.Statfs("/", &st); err != nil {
		return false
	}
	const overlaySuperMagic = 0x794c7630
	return int64(st.Type) == overlaySuperMagic
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

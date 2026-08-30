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

	"github.com/ikapa-dev/kelyfos/internal/proto"
	"github.com/ikapa-dev/kelyfos/internal/vsock"
	"golang.org/x/sys/unix"
)

// Version is the supervisor build reported in the ready frame, so the host can
// log which guest it is talking to when the image and the CLI are different
// builds (docs/protocol.md §7).
//
// Stamped at build time, like the CLI's. It was a constant reading "0.2.0-p2"
// through v0.9 — so every boot printed, and every chain recorded, a version the
// guest had not been for seven releases. A field whose whole purpose is to say
// which build you are talking to is the last one that should be hand-maintained.
var Version = "dev"

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

// theTeam is this sandbox's team membership, or nil when it has none.
var theTeam *teamClient

func main() {
	// Before everything, including --dump-tools: this process may not be a
	// supervisor at all. When the supervisor confines a child it re-execs this
	// same binary, and that invocation must apply the profile and exec the real
	// program without touching a single thing PID 1 owns (P5-3, confine.go).
	if isConfineInvocation(os.Args) {
		runConfined(os.Args)
		return // unreachable: runConfined either execs or exits
	}

	// Before anything else, and deliberately before any mount: the guest's tool
	// surface, printed as the tools/list result it would advertise. `make docs`
	// runs this to generate the reference (E3-1), which makes the generated file
	// the guest's own answer rather than a transcription of it. It runs as an
	// ordinary process on the host, so it must touch nothing.
	// The per-flavor confinement profiles, printed the way the supervisor holds
	// them. `make docs` runs this to generate the reference, which makes the
	// documented profile the enforced one rather than a description of it
	// (P5-3, and the same argument as --dump-tools below).
	if len(os.Args) > 1 && os.Args[1] == "--dump-profile" {
		flavors := os.Args[2:]
		if len(flavors) == 0 {
			flavors = []string{"base", "dev"}
		}
		if err := DumpProfile(os.Stdout, flavors); err != nil {
			fmt.Fprintln(os.Stderr, "kelyfos-supervisor:", err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "--dump-tools" {
		if err := dumpTools(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "kelyfos-supervisor:", err)
			os.Exit(1)
		}
		return
	}

	start := monotonic()

	if isPID1 {
		// Nothing has mounted anything yet, so there is no /proc to read and
		// no writable filesystem to log to — only the console the kernel gave
		// us. setupRoot changes that.
		setupRoot()
		applyDefaultPath()
		mountWorkspace()
		// Mounted before anything can run, so a plugin's files are on disk
		// before the first tool call could ask for one. What launches them is
		// E4-7; this is the device and the manifest.
		thePlugins = mountPlugins()
		// After the mounts, because the profile names trees that only exist
		// once they are mounted, and before any channel is served, because
		// nothing may be spawned unconfined (P5-3).
		setupProfile()
	}

	// Egress, if this sandbox has any. Reading it here means every command
	// started from any channel inherits the same environment.
	if proxy := applyEgressEnv(); proxy != "" {
		logf("egress via proxy %s", proxy)
	}

	// Where a refused vsock peer is reported. The package's own default writes
	// to stderr so the refusal is never silent, but the console format belongs
	// to the supervisor (F3). Called at most once per listening port — a peer
	// that can reach the port at all can knock in a loop, and this writes to
	// PID 1's console; the listener keeps the count and prints it on Close.
	vsock.OnRefusedPeer = func(cid, peerPort, localPort uint32) {
		logf("vsock: refused a connection on port %d from CID %d:%d — only the host (CID %d) may connect",
			localPort, cid, peerPort, unix.VMADDR_CID_HOST)
	}

	rp := newReaper()
	if isPID1 {
		rp.start()
	}

	// The team channel, when the host put this sandbox in a team. Package-level
	// because the MCP session needs it and there is exactly one per machine —
	// a guest belongs to one team or to none, and it is told which on the
	// kernel command line rather than being allowed to decide.
	theTeam = newTeamClient()

	shutdown := make(chan struct{}, 1)

	// Guest-originated events. The queue is small and bounded on purpose: this
	// is PID 1, and a full queue must cost a dropped report rather than a
	// blocked init. A drop is logged to the console, which is the one place
	// left that cannot itself be starved.
	events := make(chan proto.GuestEvent, 64)
	go pumpEvents(events)
	guestEvents = events
	go watchKmsg(reportGuestEvent)

	// Plugins start before readiness is announced, and the handshake with each
	// one is paid for here rather than later.
	//
	// It would be cheaper to start them in the background, and it would be
	// wrong: ready means the machine is usable, and a machine whose tools/list
	// is still filling in is one an agent cannot tell apart from a machine that
	// never had those tools. A sandbox with plugins therefore takes longer to
	// become ready than one without, because being ready means more (E4-7).
	if len(thePlugins) > 0 {
		startPlugins(thePlugins, rp, reportGuestEvent)
	}

	// Loopback, always. A guest with no NIC still has to be able to talk to
	// itself — a forwarded port dials 127.0.0.1 inside this machine — and the
	// kernel leaves `lo` down when there is no `ip=` argument to process.
	if err := bringUpLoopback(); err != nil {
		logf("cannot bring up loopback: %v", err)
	}

	// Listeners are bound before readiness is announced. The host is entitled
	// to connect the instant it sees the ready frame, and a race there looks
	// like a mysterious connection refusal.
	if ln, err := vsock.Listen(proto.PortExec); err != nil {
		logf("cannot listen on exec port %d: %v", proto.PortExec, err)
	} else {
		go serveExec(ln, rp)
	}
	if ln, err := vsock.Listen(proto.PortMCP); err != nil {
		logf("cannot listen on mcp port %d: %v", proto.PortMCP, err)
	} else {
		go serveMCP(ln, rp)
	}
	// One connection is one interactive shell. Bound with the others, before
	// readiness, for the reason they all are: the host may connect the instant
	// it sees the ready frame.
	if ln, err := vsock.Listen(proto.PortShell); err != nil {
		logf("cannot listen on shell port %d: %v", proto.PortShell, err)
	} else {
		go serveShell(ln, rp)
	}
	// One connection is one forwarded TCP connection, dialled to this
	// machine's own loopback. Nothing crosses the TAP, so the firewall is
	// untouched by a forward (F-D7).
	if ln, err := vsock.Listen(proto.PortForward); err != nil {
		logf("cannot listen on forward port %d: %v", proto.PortForward, err)
	} else {
		go serveForward(ln)
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

// pumpEvents keeps the events channel connected and drains the queue into it.
//
// Same retry discipline as the ready channel and for the same two reasons: the
// host may not have bound its end yet, and a snapshot restore severs every
// connection with only the guest able to re-dial (docs/protocol.md §1.6). An
// event taken off the queue while the connection is down is held rather than
// dropped, so a reconnect does not cost the report that provoked it.
// guestEvents is the queue everything guest-side reports into. Package-level
// because the MCP session reports plugin calls from wherever a call lands, and
// threading a channel through every tool would be threading it through tools
// that will never use it.
var guestEvents chan<- proto.GuestEvent

// reportGuestEvent queues one report, dropping it if the host is not keeping
// up. Bounded on purpose: this is PID 1, and a full queue must cost a dropped
// report rather than a blocked init. The drop goes to the console, which is the
// one place left that cannot itself be starved.
func reportGuestEvent(ev proto.GuestEvent) {
	if guestEvents == nil {
		return
	}
	select {
	case guestEvents <- ev:
	default:
		logf("dropped a %s event: the host events channel is not keeping up", ev.Type)
	}
}

func pumpEvents(queue <-chan proto.GuestEvent) {
	var pending *proto.GuestEvent
	backoff := dialBackoffMin
	for {
		conn, err := vsock.Dial(proto.CIDHost, proto.PortEvents)
		if err != nil {
			time.Sleep(backoff)
			if backoff < dialBackoffMax {
				backoff *= 2
			}
			continue
		}
		backoff = dialBackoffMin
		w := proto.NewWriter(conn)
		for {
			ev := pending
			if ev == nil {
				next := <-queue
				ev = &next
			}
			if err := w.Write(ev); err != nil {
				pending = ev
				break
			}
			pending = nil
		}
		conn.Close()
	}
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
		V:            proto.Version,
		Type:         "ready",
		BootID:       bootID,
		Arch:         runtime.GOARCH,
		Kernel:       kernelRelease(),
		Supervisor:   Version,
		MonotonicNS:  monotonic().Nanoseconds(),
		Overlay:      overlayActive(),
		Profile:      profileSummary,
		ProfileError: profileError,
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

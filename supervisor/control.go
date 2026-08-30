package main

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/proto"
	"golang.org/x/sys/unix"
)

// serveControl answers the lifecycle channel (docs/protocol.md §5.4). Unlike
// exec it is long-lived: many request/response pairs on one connection.
func serveControl(ln net.Listener, shutdown chan<- struct{}) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleControl(conn, shutdown)
	}
}

func handleControl(conn net.Conn, shutdown chan<- struct{}) {
	defer conn.Close()
	r := proto.NewReader(conn)
	w := proto.NewWriter(conn)
	for {
		var req proto.ControlRequest
		if err := r.Read(&req); err != nil {
			if !errors.Is(err, io.EOF) {
				logf("control channel: %v", err)
			}
			return
		}
		// Every answer carries the confinement, not just the ones that were
		// asked for it: the host may reach a machine it did not boot, and the
		// posture is a property of the machine rather than of the question.
		resp := proto.ControlResponse{
			V: proto.Version, ID: req.ID, OK: true,
			Profile: profileSummary, ProfileError: profileError,
		}
		switch req.Op {
		case proto.OpPing:
			// Nothing to do: reaching this line is the answer.
		case proto.OpShutdown:
			// Answer before acting. Once the machine goes down there is no
			// channel left to answer on, and the host would be left unable to
			// tell an orderly shutdown from a crash.
			_ = w.Write(resp)
			select {
			case shutdown <- struct{}{}:
			default:
			}
			return
		case proto.OpTrust:
			if err := installTrustAnchor(req.CAPEM); err != nil {
				resp.OK = false
				resp.Error = &proto.Error{Kind: proto.ErrInternal, Message: err.Error()}
			}

		case proto.OpResync:
			if err := applyResync(&req); err != nil {
				resp.OK = false
				resp.Error = &proto.Error{Kind: proto.ErrInternal, Message: err.Error()}
			}
		default:
			resp.OK = false
			resp.Error = &proto.Error{
				Kind:    proto.ErrBadRequest,
				Message: "unknown control op " + req.Op,
			}
		}
		if err := w.Write(resp); err != nil {
			return
		}
	}
}

// halt takes the machine down: stop everything still running, flush what the
// filesystems have buffered, and power off.
//
// The grace period is short on purpose. This is an ephemeral sandbox, not a
// server draining connections — and the host is holding a timer of its own,
// after which it kills Firecracker outright.
func halt(grace time.Duration) {
	logf("shutting down")
	// A plugin about to be killed by this is not a plugin that crashed. Said
	// before the signal goes out, so the report is suppressed rather than
	// raced against (E4-8): plugin.crash should mean something went wrong, not
	// that the machine stopped.
	stopping.Store(true)
	syncWorkspace()

	// Everything except PID 1. TERM first so a command can finish writing.
	_ = unix.Kill(-1, unix.SIGTERM)
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if !anyChildren() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = unix.Kill(-1, unix.SIGKILL)

	unix.Sync()

	// RESTART rather than POWER_OFF, and on x86_64 that is the difference
	// between the VMM exiting and not (P6-18).
	//
	// Firecracker has no firmware to hand control back to, so "reboot" and
	// "power off" are the same act here: the end of the machine. But they are
	// not the same to the VMM. Firecracker does not virtualise power
	// management on x86_64 — there is no ACPI — so a guest `poweroff` stops the
	// guest and leaves the Firecracker process running with nothing inside it.
	// What it does emulate is the i8042 controller, and a reset on that line is
	// what it takes as "this machine is finished". That is why `reboot=k` is on
	// the kernel command line (config.go): it tells Linux to reset through the
	// keyboard controller, which is the one signal Firecracker is listening for.
	// On aarch64 either call works, because KVM emulates PSCI and tells the VMM
	// about the power-state change, which is why this went unnoticed — the
	// development machines are arm64.
	//
	// Found by `kelyfos pause` failing on an x86_64 runner with "guest
	// acknowledged shutdown but the microVM is still running": the guest had
	// powered itself off exactly as asked, and the VM it was inside had no way
	// to know.
	//
	// POWER_OFF is kept as the fallback rather than dropped, because it is the
	// correct call on any platform that does virtualise power management, and
	// HALT after it — if the reboot call somehow returns, falling through would
	// make PID 1 exit, which is a kernel panic and a far worse way to end a
	// session.
	if err := unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART); err != nil {
		logf("restart failed (%v), powering off", err)
		if err := unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
			logf("power off failed (%v), halting", err)
			_ = unix.Reboot(unix.LINUX_REBOOT_CMD_HALT)
		}
	}
	select {}
}

func anyChildren() bool {
	var ws unix.WaitStatus
	pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
	// ECHILD means there is nothing left to wait for.
	if errors.Is(err, unix.ECHILD) {
		return false
	}
	return pid >= 0
}

package sandbox

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/hostile"
	"github.com/ikapa-dev/kelyfos/internal/proto"
)

// The hostile corpus for the control channel (P6-22).
//
// The fixture the audit's list asked for here was a stub answering OK:false to
// OpTrust, on the premise that the host proceeds anyway. It does not:
// InstallTrustAnchor refuses on !OK and all six callers propagate, and the read
// is bounded by a ten-second deadline. That half is not a defect at HEAD, so
// there is no fixture for it — a fixture for a defect that does not exist is a
// test that will one day be "fixed" by somebody who cannot find the bug.
//
// Building the stub found a different one, which is why the fixture is here at
// all. The guest's refusal message is printed to the operator's terminal
// verbatim. It is bytes the untrusted side chose, and this project already has
// the function for that case — proto.SafeText, which quotes a string carrying
// control characters — applied on other paths and not on this one.
//
// A guest that answers with "\x1b[1A\x1b[2K\r" moves the cursor up a line and
// erases it. What it erases is whatever the host printed immediately before,
// which on this path is the line saying the sandbox is ready and which walls
// were around it. The guest gets to choose what the operator sees about the
// guest.
//
// No image, no mke2fs, no KVM: a Unix socket answering four tokens is the whole
// of the guest here.

// stubControl is the control channel with no VM behind it. It speaks the vsock
// handshake, reads one request, and answers whatever it was told to.
func stubControl(t *testing.T, answer proto.ControlResponse) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kelyfos-hostile-ctl-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "v.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ln.Close()
		os.RemoveAll(dir)
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := readLineByte(conn); err != nil { // "CONNECT 10003"
					return
				}
				fmt.Fprint(conn, "OK 65535\n")
				var req proto.ControlRequest
				if err := proto.NewReader(conn).Read(&req); err != nil {
					return
				}
				_ = proto.NewWriter(conn).Write(answer)
			}()
		}
	}()
	return path
}

// The guest chooses the bytes; the operator's terminal must not obey them.
func TestHostileGuestCannotWriteOnTheOperatorsTerminal(t *testing.T) {
	for _, tc := range []struct {
		name, kind, message string
	}{
		{"cursor-control", "internal", "\x1b[1A\x1b[2K\rsandbox ready in 41 ms (jailer on, landlock on)"},
		{"carriage-return", "internal", "denied\rallowed"},
		{"newline-injection", "internal", "no\nkelyfos: everything is fine"},
		{"in-the-kind", "\x1b[31mfatal\x1b[0m", "refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uds := stubControl(t, proto.ControlResponse{
				V: proto.Version, ID: "trust", OK: false,
				Error: &proto.Error{Kind: tc.kind, Message: tc.message},
			})
			sb := &Sandbox{State: State{UDSPath: uds}}

			err := sb.InstallTrustAnchor([]byte("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"))
			if err == nil {
				t.Fatal("the host accepted a refusal, which is a different and worse finding")
			}

			// The test asks what a terminal would do with it, not what it says.
			// A control byte anywhere in the message the host prints is the
			// defect, whatever the surrounding words are.
			problem := ""
			if got := err.Error(); hasControlBytes(got) {
				problem = fmt.Sprintf("the error the host prints carries control bytes the guest chose: %s",
					strconv.Quote(got))
			}
			hostile.Holds(t, "control/guest-controls-the-terminal", problem)
		})
	}
}

// And the refusal itself still has to be a refusal. This holds today and is here
// because it is the half that would be easy to lose while fixing the other half:
// a fix that quoted the message and then dropped the error would be worse than
// the defect.
func TestHostileRefusedTrustAnchorIsStillRefused(t *testing.T) {
	uds := stubControl(t, proto.ControlResponse{
		V: proto.Version, ID: "trust", OK: false,
		Error: &proto.Error{Kind: "internal", Message: "no room in the trust store"},
	})
	sb := &Sandbox{State: State{UDSPath: uds}}

	problem := ""
	err := sb.InstallTrustAnchor([]byte("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"))
	switch {
	case err == nil:
		problem = "a guest that refused the trust anchor was treated as having accepted it"
	case !strings.Contains(err.Error(), "no room in the trust store"):
		problem = fmt.Sprintf("the refusal does not say what the guest said: %v", err)
	}
	hostile.Holds(t, "control/refusal-is-refused", problem)
}

func hasControlBytes(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

package vsock

import (
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// F3 (security review of 2026-08-28) — the guest's listeners never check who is
// connecting.
//
// The supervisor binds exec, MCP, control, shell and forward on VMADDR_CID_ANY,
// and Accept read the peer's CID into a remote address and then never looked at
// it. Any peer that can reach the socket was treated as the host, and the host
// is the one party allowed to run commands in this guest.
//
// Nothing inside the guest can be that peer today, because the loopback
// transport is compiled out — measured on a booted guest rather than assumed:
//
//	grep -c vsock_loopback /proc/kallsyms   -> 0
//	socket(AF_VSOCK, SOCK_STREAM, 0)        -> succeeds
//	connect((VMADDR_CID_LOCAL, 10002))      -> ETIMEDOUT
//
// The middle line is the point. `socket` is not on the seccomp refusal list and
// will not be — a denylist that refuses socket() refuses the network — so the
// only thing between a confined process and the supervisor's own control channel
// is one kernel config symbol. That symbol is `default y` upstream
// (net/vmw_vsock/Kconfig, checked in 6.12.105 and 6.19.14), which is to say the
// base config turns it *off* against the default, and check-kernel.sh verifies
// only the two KelyfOS fragments — not the base. An olddefconfig over a kernel
// bump would turn it back on and nothing would notice.
//
// So: the fragment now pins it, and Accept refuses a peer that is not the host,
// which is the half that does not depend on a build staying correct.

// hostPort picks a port unlikely to collide with the supervisor's own map
// (10001–10003, 10100–10101, docs/protocol.md §1.4) or with a parallel run.
func hostPort(t *testing.T) uint32 {
	t.Helper()
	return uint32(41000 + (os.Getpid()+int(time.Now().UnixNano()))%2000)
}

// loopbackOrSkip reports whether this machine can speak vsock to itself.
//
// A skip rather than a failure, and loud about why: the KelyfOS guest kernel
// deliberately has no loopback transport — that is F3's first layer — so a
// fixture that drives the real Listen/Accept can only run where one exists.
//
// **CI loads the module, and it did not until v1.1.** Ubuntu builds
// vsock_loopback as a module and does not load it, so on a stock runner this
// and TestF3_ARefusedPeerIsReported both SKIPPED and the only F3 test that
// executed was TestF3_OnlyTheHostIsServed — the decision table, which is real
// coverage of `fromHost` and does not touch Accept. A green run meant the table
// passed and these two were not run, which is a skipped fixture reading like a
// passing one: the failure mode this whole review round is about. The `checks`
// job now runs `sudo modprobe vsock_loopback` before the unit tests, and
// dev/ci-local.sh does the same (P7-17/C).
//
// The skip below stays, and stays loud, because the module is still not on
// every machine: a container with no vsock, a runner image that drops it, a
// developer's Mac. What changed is that the ordinary path now runs the fixture
// rather than passing over it.
func loopbackOrSkip(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no AF_VSOCK on this machine (%v); this fixture needs the loopback transport", err)
	}
	unix.Close(fd)
	if _, err := os.Stat("/sys/module/vsock_loopback"); err != nil {
		t.Skip("vsock_loopback is not loaded; `sudo modprobe vsock_loopback` to run this fixture")
	}
}

func TestF3_ListenerRefusesAPeerThatIsNotTheHost(t *testing.T) {
	loopbackOrSkip(t)

	port := hostPort(t)
	ln, err := Listen(port)
	if err != nil {
		t.Skipf("could not bind vsock port %d: %v", port, err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	failed := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			failed <- err
			return
		}
		accepted <- c
	}()

	// VMADDR_CID_LOCAL is the loopback CID: a peer inside this machine, which is
	// exactly what a guest process would be if the transport were built in. It
	// is not the host, and the host is the only party these channels serve.
	dialed := make(chan error, 1)
	go func() {
		c, err := Dial(unix.VMADDR_CID_LOCAL, port)
		if err == nil {
			defer c.Close()
			// Write something, so a listener that accepted and then read would
			// have real bytes to be fooled by rather than an empty connection.
			_, _ = c.Write([]byte("{\"v\":1,\"id\":\"f3\",\"cmd\":[\"L2Jpbi9zaA==\"]}\n"))
			time.Sleep(500 * time.Millisecond)
		}
		dialed <- err
	}()

	select {
	case c := <-accepted:
		c.Close()
		t.Fatalf("Accept returned a connection from %s — a peer inside this machine, not the host.\n"+
			"  Every channel the supervisor binds serves the host and nothing else: exec runs commands,\n"+
			"  control stops the machine, MCP is the whole tool surface. A guest process that reached\n"+
			"  one of them would be talking to its own supervisor as if it were the operator.",
			c.RemoteAddr())
	case err := <-failed:
		t.Fatalf("Accept failed for a reason other than refusing the peer: %v", err)
	case <-time.After(2 * time.Second):
		// Nothing was accepted, which is the point. Closing the listener is what
		// releases the Accept goroutine.
	}

	if err := <-dialed; err != nil {
		t.Logf("the non-host peer could not even connect: %v", err)
	}
	ln.Close()
	select {
	case err := <-failed:
		if !errors.Is(err, os.ErrClosed) && err != nil {
			t.Logf("Accept returned after Close with: %v", err)
		}
	case c := <-accepted:
		c.Close()
		t.Errorf("Accept handed back the non-host connection after the listener was closed")
	case <-time.After(2 * time.Second):
		t.Logf("Accept was still waiting for a host peer when the test ended, which is correct")
	}
}

// The decision on its own, so that a machine without the loopback transport —
// which is every KelyfOS guest, by design — still tests it.
//
// The CID values are the kernel's own: 0 hypervisor, 1 local/loopback, 2 host,
// and 3 and up are guests. Only one of them is the operator.
func TestF3_OnlyTheHostIsServed(t *testing.T) {
	for _, tc := range []struct {
		name string
		sa   unix.Sockaddr
		want bool
	}{
		{"the host", &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: 1024}, true},
		{"the hypervisor", &unix.SockaddrVM{CID: unix.VMADDR_CID_HYPERVISOR, Port: 1024}, false},
		{"loopback, which is a process in this guest", &unix.SockaddrVM{CID: unix.VMADDR_CID_LOCAL, Port: 1024}, false},
		{"this guest by its own CID", &unix.SockaddrVM{CID: 3, Port: 1024}, false},
		{"another guest", &unix.SockaddrVM{CID: 42, Port: 1024}, false},
		{"the wildcard, which is not an address anything connects from", &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: 1024}, false},
		{"a sockaddr that is not a vsock one", &unix.SockaddrInet4{Port: 1024}, false},
		{"no sockaddr at all", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fromHost(tc.sa); got != tc.want {
				verb := map[bool]string{true: "served", false: "refused"}
				t.Errorf("a peer that is %s was %s; it must be %s", tc.name, verb[got], verb[tc.want])
			}
		})
	}
}

// The refusal has to be audible. A channel that quietly drops connections is
// indistinguishable, from the guest's console, from one nobody is knocking on —
// and being able to see the knock is most of why this check is worth having,
// given the transport is compiled out.
func TestF3_ARefusedPeerIsReported(t *testing.T) {
	loopbackOrSkip(t)

	saved := OnRefusedPeer
	t.Cleanup(func() { OnRefusedPeer = saved })
	type refusal struct{ cid, peerPort, localPort uint32 }
	seen := make(chan refusal, 4)
	OnRefusedPeer = func(cid, peerPort, localPort uint32) {
		select {
		case seen <- refusal{cid, peerPort, localPort}:
		default:
		}
	}

	port := hostPort(t)
	ln, err := Listen(port)
	if err != nil {
		t.Skipf("could not bind vsock port %d: %v", port, err)
	}
	defer ln.Close()
	go ln.Accept()

	c, err := Dial(unix.VMADDR_CID_LOCAL, port)
	if err != nil {
		t.Skipf("the loopback peer could not connect: %v", err)
	}
	defer c.Close()

	select {
	case r := <-seen:
		if r.cid != unix.VMADDR_CID_LOCAL {
			t.Errorf("the refusal named CID %d, not the %d that connected", r.cid, unix.VMADDR_CID_LOCAL)
		}
		if r.localPort != port {
			t.Errorf("the refusal named port %d, not the %d that was bound", r.localPort, port)
		}
	case <-time.After(3 * time.Second):
		t.Error("a peer that was not the host was turned away without a word about it")
	}
}

// The refusal log is rate-limited, and the count is not. A peer that can connect
// at all can connect in a loop — that is the same scenario the check exists for
// — so a line per connection would hand a guest process the operator's console.
func TestF3_TheRefusalLogIsRateLimitedButCounted(t *testing.T) {
	loopbackOrSkip(t)

	saved := OnRefusedPeer
	t.Cleanup(func() { OnRefusedPeer = saved })
	var lines atomic.Uint64
	OnRefusedPeer = func(cid, peerPort, localPort uint32) { lines.Add(1) }

	port := hostPort(t)
	ln, err := Listen(port)
	if err != nil {
		t.Skipf("could not bind vsock port %d: %v", port, err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	const knocks = 40
	for i := 0; i < knocks; i++ {
		c, err := Dial(unix.VMADDR_CID_LOCAL, port)
		if err != nil {
			t.Skipf("the loopback peer could not connect: %v", err)
		}
		c.Close()
	}

	l := ln.(*listener)
	deadline := time.Now().Add(5 * time.Second)
	for l.Refusals() < knocks && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	if got := l.Refusals(); got != knocks {
		t.Errorf("the listener counted %d refusals, not the %d peers that knocked", got, knocks)
	}
	if got := lines.Load(); got != 1 {
		t.Errorf("%d connections from a non-host peer produced %d log lines; one per listener is the bound, "+
			"or a guest that can reach the port can write the operator's console without limit", knocks, got)
	}
}

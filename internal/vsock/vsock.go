// Package vsock provides the guest side of the KelyfOS transport: AF_VSOCK
// sockets presented as ordinary net.Conn and net.Listener values.
//
// Only the guest speaks AF_VSOCK. The host never does — Firecracker's hybrid
// vsock terminates every channel on a Unix domain socket on the host side, so
// there is deliberately no host-side counterpart to this package
// (docs/protocol.md §1).
//
// The wrapping is done by hand rather than with net.FileConn, which rejects
// AF_VSOCK outright ("address family not supported by protocol"): Go's net
// package only knows how to parse AF_INET, AF_INET6 and AF_UNIX addresses. What
// it does give us is the runtime poller, and os.NewFile will register any
// non-blocking pollable descriptor with it — so a *os.File over a vsock socket
// gets real deadlines and goroutine-friendly blocking, and the only pieces
// missing from net.Conn are the two address methods.
package vsock

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// listenBacklog bounds how many connections may be waiting to be accepted.
const listenBacklog = 128

// Addr is a vsock endpoint: a context ID and a port.
type Addr struct {
	CID  uint32
	Port uint32
}

func (a *Addr) Network() string { return "vsock" }
func (a *Addr) String() string  { return fmt.Sprintf("vsock:%d:%d", a.CID, a.Port) }

// Dial opens a connection to a host-side listener: the guest connects to CID 2
// on the given port and Firecracker forwards it to the Unix socket the host is
// listening on at "<uds_path>_<port>" (docs/protocol.md §1.2). There is no
// handshake in this direction — the connection carries channel bytes from the
// first byte.
func Dial(cid, port uint32) (net.Conn, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock: socket: %w", err)
	}
	// Connect while still blocking: it completes immediately over virtio and
	// dodges the EINPROGRESS dance. Non-blocking comes after, for the poller.
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: port}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock: connect cid=%d port=%d: %w", cid, port, err)
	}
	return newConn(fd, &Addr{CID: cid, Port: port})
}

// Listen binds a port for host-initiated channels. The host reaches it by
// opening the vsock UDS and sending "CONNECT <port>\n"; Firecracker delivers the
// connection here (docs/protocol.md §1.1).
//
// The socket binds VMADDR_CID_ANY rather than the guest's own CID: after a
// snapshot restore the guest's CID can change, and a listener pinned to the old
// value would quietly stop accepting.
func Listen(port uint32) (net.Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock: socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock: bind port=%d: %w", port, err)
	}
	// The backlog is generous on purpose. An agent driving this sandbox can
	// fire many tool calls at once, and each one is a separate connection; when
	// the backlog overflows, Firecracker cannot complete the CONNECT handshake
	// and the host sees the socket close with no "OK" — indistinguishable, from
	// the outside, from a supervisor that is not running.
	if err := unix.Listen(fd, listenBacklog); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock: listen port=%d: %w", port, err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock: set nonblocking: %w", err)
	}
	return &listener{
		f:    os.NewFile(uintptr(fd), fmt.Sprintf("vsock:listen:%d", port)),
		addr: &Addr{CID: unix.VMADDR_CID_ANY, Port: port},
	}, nil
}

type listener struct {
	f    *os.File
	addr *Addr
}

func (l *listener) Addr() net.Addr { return l.addr }
func (l *listener) Close() error   { return l.f.Close() }

// OnRefusedPeer is called when Accept turns a connection away. It is a package
// variable because this package cannot see the supervisor's console logger and
// must not grow a dependency on it; the supervisor points it at logf.
//
// The default is not a no-op, deliberately. The whole value of the refusal below
// is that a kernel which regains the loopback transport is *noticed*, and a
// refusal nobody is wired up to hear is the silent regression it exists to
// prevent. Stderr in the guest is the console.
var OnRefusedPeer = func(cid, peerPort, localPort uint32) {
	fmt.Fprintf(os.Stderr, "vsock: refused a connection on port %d from CID %d:%d — only the host (CID %d) may connect\n",
		localPort, cid, peerPort, unix.VMADDR_CID_HOST)
}

// Accept returns the next connection from the host, and only from the host.
//
// Every channel bound by this package serves the host: exec runs commands,
// control stops the machine, MCP is the whole tool surface. Accept used to read
// the peer's CID into a remote address and never look at it, so any peer that
// could reach the socket was served as if it were the operator (F3, security
// review of 2026-08-28).
//
// Nothing inside the guest can reach it today, because the loopback transport is
// compiled out of the guest kernel — but `socket` is not on the seccomp refusal
// list and cannot be, so that kernel line was the only thing in the way, and it
// is a symbol upstream marks `default y`. The fragment now pins it off and this
// refuses the peer, which is the half that does not depend on a build staying
// correct. A refused connection is closed and accepting continues: one peer
// knocking is not a reason to stop serving the one that matters.
func (l *listener) Accept() (net.Conn, error) {
	for {
		nfd, sa, err := l.accept1()
		if err != nil {
			return nil, err
		}
		if !fromHost(sa) {
			unix.Close(nfd)
			if OnRefusedPeer != nil {
				OnRefusedPeer(peerCID(sa), peerPort(sa), l.addr.Port)
			}
			continue
		}
		vm := sa.(*unix.SockaddrVM)
		return newConn(nfd, &Addr{CID: vm.CID, Port: vm.Port})
	}
}

// accept1 is one accept(2), parked on the runtime poller until the listening
// socket is readable.
func (l *listener) accept1() (int, unix.Sockaddr, error) {
	rc, err := l.f.SyscallConn()
	if err != nil {
		return -1, nil, fmt.Errorf("vsock: accept: %w", err)
	}
	var (
		nfd  int
		sa   unix.Sockaddr
		serr error
	)
	// rc.Read parks the goroutine on the runtime poller until the listening
	// socket is readable, then calls back; returning false means "not ready
	// yet, wait again", which is how a spurious wakeup is handled.
	if err := rc.Read(func(fd uintptr) bool {
		nfd, sa, serr = unix.Accept4(int(fd), unix.SOCK_CLOEXEC)
		// EAGAIN and EWOULDBLOCK are the same value on Linux.
		switch serr {
		case unix.EAGAIN, unix.ECONNABORTED, unix.EINTR:
			return false
		}
		return true
	}); err != nil {
		return -1, nil, fmt.Errorf("vsock: accept: %w", err)
	}
	if serr != nil {
		return -1, nil, fmt.Errorf("vsock: accept: %w", serr)
	}
	return nfd, sa, nil
}

// fromHost reports whether a peer may be served: the host, and nothing else.
//
// Fail closed on both counts. A sockaddr that is not a vsock one cannot happen
// on an AF_VSOCK listener, which is exactly why it is refused rather than
// defaulted to CID 0 the way the old code did — a case that "cannot happen" and
// is handled by assuming the safest-looking value is a case nobody has thought
// about. CID 2 is VMADDR_CID_HOST and is what Firecracker's hybrid vsock
// actually delivers; that was measured on a booted guest, not assumed, because a
// check on the wrong constant would refuse every channel this machine has.
func fromHost(sa unix.Sockaddr) bool {
	vm, ok := sa.(*unix.SockaddrVM)
	return ok && vm.CID == unix.VMADDR_CID_HOST
}

// peerCID and peerPort report what a refused peer said it was, for the log only.
// A sockaddr of the wrong type has no CID to report and gets VMADDR_CID_ANY,
// which is not a CID anything can connect from and so cannot be mistaken for one.
func peerCID(sa unix.Sockaddr) uint32 {
	if vm, ok := sa.(*unix.SockaddrVM); ok {
		return vm.CID
	}
	return unix.VMADDR_CID_ANY
}

func peerPort(sa unix.Sockaddr) uint32 {
	if vm, ok := sa.(*unix.SockaddrVM); ok {
		return vm.Port
	}
	return 0
}

// conn is a net.Conn over a vsock descriptor. Everything except the addresses
// comes from *os.File, including working deadlines.
type conn struct {
	*os.File
	remote *Addr
}

func (c *conn) LocalAddr() net.Addr                { return &Addr{CID: unix.VMADDR_CID_ANY, Port: c.remote.Port} }
func (c *conn) RemoteAddr() net.Addr               { return c.remote }
func (c *conn) SetDeadline(t time.Time) error      { return c.File.SetDeadline(t) }
func (c *conn) SetReadDeadline(t time.Time) error  { return c.File.SetReadDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.File.SetWriteDeadline(t) }

func newConn(fd int, remote *Addr) (net.Conn, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock: set nonblocking: %w", err)
	}
	return &conn{File: os.NewFile(uintptr(fd), remote.String()), remote: remote}, nil
}

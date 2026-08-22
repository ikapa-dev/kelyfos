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

func (l *listener) Accept() (net.Conn, error) {
	rc, err := l.f.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("vsock: accept: %w", err)
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
		return nil, fmt.Errorf("vsock: accept: %w", err)
	}
	if serr != nil {
		return nil, fmt.Errorf("vsock: accept: %w", serr)
	}
	remote := &Addr{Port: l.addr.Port}
	if vm, ok := sa.(*unix.SockaddrVM); ok {
		remote = &Addr{CID: vm.CID, Port: vm.Port}
	}
	return newConn(nfd, remote)
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

//go:build linux

package sandbox

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// peerIsThisUser reports whether the far side of an accepted unix-socket
// connection runs as the same user this process does, read with SO_PEERCRED.
//
// This is the belt to the channel credential's braces (audit 2026-09-01, A2):
// the credential is what actually gates the guest's channels, because the
// threat it answers includes a process running as this very user, which no uid
// check can refuse. What a uid check adds is a second, independent refusal for
// a peer from a *different* account that reached the socket anyway — a group
// or ACL accident, a container sharing the socket path — and it refuses that
// peer before a frame of it is read.
//
// said is false when the kernel would not say — which on Linux it does for
// every unix socket — and is not itself a refusal: the credential is the
// control either way. err is a real failure to ask.
func peerIsThisUser(conn *net.UnixConn) (ok, said bool, err error) {
	var uid uint32
	rc, err := conn.SyscallConn()
	if err != nil {
		return false, false, err
	}
	var serr error
	if cerr := rc.Control(func(fd uintptr) {
		ucred, uerr := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if uerr != nil {
			serr = uerr
			return
		}
		uid = ucred.Uid
	}); cerr != nil {
		return false, false, cerr
	}
	if serr != nil {
		return false, false, serr
	}
	return uid == uint32(os.Getuid()), true, nil
}

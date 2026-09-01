//go:build !linux

package sandbox

import "net"

// peerIsThisUser is the non-Linux stub: there is no SO_PEERCRED to ask, so the
// kernel never says. Nothing boots a sandbox off Linux — this answers the
// compiler, and keeps the gate's only real control on the channel credential
// itself (peercred_linux.go has the reasoning).
func peerIsThisUser(conn *net.UnixConn) (ok, said bool, err error) {
	return false, false, nil
}

// The channel credential, guest side (audit 2026-09-01, A2/A3).
//
// The host hands this supervisor a per-session secret over the control
// channel — the one direction a process inside the guest cannot reach,
// because a guest vsock listener serves the host's CID alone — and this
// process presents it as the first frame of every connection it dials to the
// host's 101xx listeners. The host refuses the connection without it.
//
// Why the credential lives only here, in memory: everything running in this
// guest is root, so file permissions cannot separate the supervisor from the
// code it runs; the environment and the kernel command line are readable by
// every process through /proc; and the supervisor's own memory is the one
// place the audit's probes could not go (ptrace and process_vm were refused
// at the kernel ACL, and PR_SET_DUMPABLE 0 — this audit's A17b — is set in the
// boot path so that safety does not rest on the ACL alone). A credential in a
// file, an env var or argv would gate nothing.
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"sync"

	"github.com/ikapa-dev/kelyfos/internal/proto"
)

// credentialHexLen is the credential as the host sends it: 32 bytes of
// entropy, hex-encoded.
const credentialHexLen = 64

var (
	credentialMu sync.RWMutex
	// channelCredential is the per-session secret above. Empty until the
	// host's first auth op lands, and replaced — never merged — on every
	// later one, because a restore hands this supervisor a fresh value and
	// the frozen one belonged to a session that is over.
	channelCredential string
)

// setChannelCredential stores what the host sent. A malformed token is
// refused rather than stored: the host is the only legitimate sender, so a
// malformed one is a bug or an attack, and storing neither is the safe half
// of both.
func setChannelCredential(token string) error {
	if len(token) != credentialHexLen {
		return fmt.Errorf("a channel credential is %d hex characters, this one is %d",
			credentialHexLen, len(token))
	}
	if _, err := hex.DecodeString(token); err != nil {
		return fmt.Errorf("a channel credential is hex: %v", err)
	}
	credentialMu.Lock()
	channelCredential = token
	credentialMu.Unlock()
	return nil
}

// currentChannelCredential is what to present on the next dial. It can be
// empty — the pumps dial the instant they start, and the host's auth op
// arrives over control some time into the boot — and the host's answer to an
// empty one is a refused connection, which the pumps' existing retry
// discipline absorbs. Nobody waits on a lock here: the credential arriving is
// not something to block PID 1's boot on, it is something to be ready for.
func currentChannelCredential() string {
	credentialMu.RLock()
	defer credentialMu.RUnlock()
	return channelCredential
}

// credentialHello is the first frame on every guest-initiated connection.
type credentialHello struct {
	V    int    `json:"v"`
	Auth string `json:"auth"`
}

// presentCredential writes the hello: the first frame on the connection, before
// any channel traffic. The host reads it with the connection's first-frame
// deadline and closes the connection if it does not carry this session's
// credential — which, for a supervisor still waiting on the host's auth op,
// is the ordinary way the first dials of a boot end, and the reason every
// caller treats a presentation failure exactly like any other failed dial.
func presentCredential(conn net.Conn) error {
	w := proto.NewWriter(conn)
	return w.Write(credentialHello{V: proto.Version, Auth: currentChannelCredential()})
}

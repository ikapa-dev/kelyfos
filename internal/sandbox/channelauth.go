// The guest-initiated channels' credential (audit 2026-09-01, A2/A3).
//
// Before this, the host's side of the ready, events and team channels was a
// plain unix socket in a 0700 run directory, and the guest reached it by
// dialling CID 2. Both directions accepted whoever arrived: any same-uid
// process on the host could connect to the socket and hand the flight
// recorder a forged guest event, and any process inside the guest — all of
// them root, none of them distinguishable from the supervisor by anything the
// kernel tracks — could dial the port and do the same. The hash chain then
// verified, faithfully, over content nobody legitimate wrote.
//
// The fix is one credential per machine, minted by the host and held in the
// guest supervisor's memory:
//
//   - the host mints it in New and again in Restore (the restoring process
//     did not boot the machine, and the snapshot's frozen copy belongs to a
//     session that is over), and pushes it over the control channel — the one
//     direction a guest process cannot reach, because a guest vsock listener
//     serves the host's CID alone;
//   - the supervisor presents it as the first frame of every connection it
//     dials to 10100, 10101 and 10102;
//   - the host refuses — before one frame of the rest of the connection is
//     read — any connection whose first frame does not carry it, compared in
//     constant time.
//
// What the credential is not is ever as deliberate as what it is: not an
// environment variable or a command-line argument, which every process in the
// guest reads from /proc; not a file, whose permissions cannot separate the
// supervisor from the agents it runs, because they are all root; not derived
// from anything the guest already knows, because then it would gate nothing.
// Memory is the one place the guest's own code does not reach — the kernel's
// ACL on /proc/<pid>/mem held under every probe the audit threw at it, and
// PR_SET_DUMPABLE 0 on the supervisor (the same audit's A17) hardens it
// further.
package sandbox

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/proto"
)

// channelCredentialBytes is the credential's entropy: 32 bytes, hex-encoded
// on the wire as 64 characters.
const channelCredentialBytes = 32

// newChannelCredential mints one. A failure is a boot failure: a machine
// whose channels could not be credentialled is a machine whose record can be
// forged, which is not a machine this package starts.
func newChannelCredential() (string, error) {
	b := make([]byte, channelCredentialBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// the credential hello is the first frame on every guest-initiated connection:
//
//	{"v":1,"auth":"<64 hex characters>"}
type channelHello struct {
	V    int    `json:"v"`
	Auth string `json:"auth"`
}

// errAuthUnsupported is set on the Sandbox when the guest answers the auth op
// with bad_request — an image whose supervisor predates the credential. The
// machine is then unusable by construction (every channel the guest dials is
// refused), and the boot fails with the named refusal instead of a bare
// timeout that would leave somebody reading Firecracker logs for the cause.
var errAuthUnsupported = errors.New("this image's supervisor does not accept a channel credential " +
	"— it predates the authentication handshake the running CLI requires\n" +
	"    rebuild the guest image for this CLI:  make image FLAVOR=dev   (or FLAVOR=base)")

// authenticate gates one accepted connection on a guest-initiated channel.
//
// The first frame is read through the same reader the channel's frames will
// use — a second reader would swallow what the first buffered — and must
// carry the credential, compared in constant time because the value it guards
// is the audit record's authenticity. On any failure the connection is
// refused: the caller closes it, and nothing the peer sent beyond the first
// frame is read.
//
// r must already have the connection's first-frame deadline behind it, which
// is what bounds a connection that opens and says nothing (F5's
// guestFirstFrameTimeout).
func (s *Sandbox) authenticate(r *proto.Reader, conn net.Conn, port uint32) bool {
	if s.channelAuth == "" {
		// Unreachable on every path that builds a machine — New and Restore
		// mint before anything listens — and fail-closed for the fixtures
		// that drive a bare Sandbox: an empty expected credential would
		// otherwise accept an empty one.
		return s.refuseChannel(conn, port, "no credential was minted for this session")
	}
	var hello channelHello
	if err := r.Read(&hello); err != nil {
		return s.refuseChannel(conn, port, "no credential was presented")
	}
	if subtle.ConstantTimeCompare([]byte(hello.Auth), []byte(s.channelAuth)) != 1 {
		return s.refuseChannel(conn, port, "the credential presented is not this session's")
	}
	// The belt to the credential's braces: a peer the kernel says is from
	// another account is refused before anything else about it matters. The
	// credential already refuses every same-uid peer — which is the threat —
	// so this is the second, independent refusal for a peer from a different
	// one, and it is skipped where the kernel cannot say (peercred_other.go).
	if u, ok := conn.(*net.UnixConn); ok {
		if same, said, err := peerIsThisUser(u); err == nil && said && !same {
			return s.refuseChannel(conn, port, "the peer is not this user")
		}
	}
	return true
}

// refuseChannel reports one refused connection and says so, once per port per
// machine on the console — the volume a knock loop would otherwise drive is
// the reason vsock's own refused-peer log keeps the same discipline — and on
// every refusal to the caller's OnChannelRefused, because the record should
// hold every attempt to forge it.
func (s *Sandbox) refuseChannel(conn net.Conn, port uint32, reason string) bool {
	if v, loaded := s.refusedLogged.LoadOrStore(port, new(atomic.Bool)); !loaded {
		if b := v.(*atomic.Bool); b.CompareAndSwap(false, true) {
			warnf("refused a connection on port %d: %s — the credential minted for this session "+
				"is required; every refusal is in the session record", port, reason)
		}
	}
	if s.opts.OnChannelRefused != nil {
		s.opts.OnChannelRefused(port, reason)
	}
	_ = conn.Close()
	return false
}

// pushChannelCredential hands the guest its credential over the control
// channel, retrying until the guest answers, the machine dies, the guest
// reveals it is too old to take one, or the timeout passes.
//
// The retries are the boot path: control binds some seconds into the guest's
// boot, and before that every connect fails with a reset the way any
// too-early host→guest connect does (docs/protocol.md §1.1). A fresh boot
// runs this on its own goroutine and lets WaitReady gate on the outcome; a
// restore runs it inline, because a restored machine's outbound channels come
// back the moment it resumes and every one of them is refused until the fresh
// credential lands.
func (s *Sandbox) pushChannelCredential(timeout time.Duration) error {
	giveUp := time.After(timeout)
	backoff := 25 * time.Millisecond
	for {
		err := s.tryPushCredential()
		if err == nil {
			return nil
		}
		if errors.Is(err, errAuthUnsupported) {
			s.authMu.Lock()
			s.authUnsupported = err
			s.authMu.Unlock()
			return err
		}
		select {
		case <-s.done:
			return fmt.Errorf("the machine ended before it took its channel credential: %w", s.waitErr)
		case <-giveUp:
			return fmt.Errorf("the guest did not take its channel credential in time: %w", err)
		case <-time.After(backoff):
		}
		if backoff < time.Second {
			backoff *= 2
		}
	}
}

// tryPushCredential is one control-channel round trip.
func (s *Sandbox) tryPushCredential() error {
	conn, err := Connect(s.State.UDSPath, proto.PortControl, 2*time.Second)
	if err != nil {
		// The guest is not answering yet, which during a boot is ordinary.
		return err
	}
	defer conn.Close()
	if err := proto.NewWriter(conn).Write(proto.ControlRequest{
		V: proto.Version, ID: "auth", Op: proto.OpAuth, Token: s.channelAuth,
	}); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp proto.ControlResponse
	if err := proto.NewReader(conn).Read(&resp); err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error != nil && resp.Error.Kind == proto.ErrBadRequest {
			// Unknown op is answered bad_request by every supervisor that
			// predates the handshake (control.go's default case). Nothing
			// later in this boot can succeed: the guest cannot present what
			// it was never given, so name it now rather than at the timeout.
			return errAuthUnsupported
		}
		return fmt.Errorf("the guest refused its channel credential: %v", resp.Error)
	}
	return nil
}

// authUnsupported returns why the guest cannot take a credential, when it
// said so.
func (s *Sandbox) authUnsupportedReason() error {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	return s.authUnsupported
}

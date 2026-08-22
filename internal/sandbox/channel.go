package sandbox

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Connect opens a host-initiated channel to the guest (docs/protocol.md §1.1):
// dial the vsock Unix socket, send "CONNECT <port>\n", and consume the
// "OK <assigned_hostside_port>\n" acknowledgement. What comes back afterwards is
// the channel itself.
//
// Firecracker answers a CONNECT it cannot complete by closing the connection,
// and it cannot complete one when nothing is listening yet *or* when the guest's
// accept backlog is momentarily full. Both are transient, so a closed handshake
// is retried until the caller's timeout runs out rather than reported
// immediately — which is what makes `kelyfos exec` usable the instant a sandbox
// reports ready, and what keeps a burst of concurrent tool calls from failing
// some of its members.
func Connect(udsPath string, port uint32, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	backoff := 2 * time.Millisecond
	for {
		conn, err := connectOnce(udsPath, port, timeout)
		if err == nil {
			return conn, nil
		}
		if !errors.Is(err, errHandshakeClosed) || time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(backoff)
		if backoff < 50*time.Millisecond {
			backoff *= 2
		}
	}
}

// errHandshakeClosed marks the retryable case: Firecracker closed the
// connection instead of acknowledging.
var errHandshakeClosed = errors.New("vsock handshake closed without acknowledgement")

// connectOnce is one attempt.
//
// The acknowledgement is read one byte at a time on purpose. A buffered reader
// would happily pull the following 4 KiB into its own buffer, swallowing the
// first bytes of channel data on any channel where the guest speaks first — a
// bug that only shows up under timing you cannot reproduce.
func connectOnce(udsPath string, port uint32, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("unix", udsPath, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial vsock socket %s: %w", udsPath, err)
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", port); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send CONNECT %d: %w", port, err)
	}

	ack, err := readLineByte(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("no acknowledgement for CONNECT %d: %w", port, errHandshakeClosed)
	}
	if !strings.HasPrefix(ack, "OK ") {
		conn.Close()
		return nil, fmt.Errorf("unexpected handshake response %q", ack)
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Time{})
	}
	return conn, nil
}

func readLineByte(conn net.Conn) (string, error) {
	var b strings.Builder
	buf := make([]byte, 1)
	for b.Len() < 128 {
		n, err := conn.Read(buf)
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}
		if buf[0] == '\n' {
			return strings.TrimRight(b.String(), "\r"), nil
		}
		b.WriteByte(buf[0])
	}
	return "", fmt.Errorf("handshake response too long")
}

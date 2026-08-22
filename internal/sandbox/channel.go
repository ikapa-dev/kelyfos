package sandbox

import (
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
// The acknowledgement is read one byte at a time on purpose. A buffered reader
// would happily pull the following 4 KiB into its own buffer, swallowing the
// first bytes of channel data on any channel where the guest speaks first — a
// bug that only shows up under timing you cannot reproduce.
func Connect(udsPath string, port uint32, timeout time.Duration) (net.Conn, error) {
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
		// Firecracker closes the connection instead of acknowledging when
		// nothing in the guest is listening on that port.
		return nil, fmt.Errorf("no acknowledgement for CONNECT %d — is the supervisor listening?: %w", port, err)
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

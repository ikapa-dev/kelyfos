package proto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// The shell channel (E5-3, docs/qol.md §3).
//
// Two kinds of frame share one connection, and the asymmetry is deliberate.
// A terminal stream is binary, high-rate and latency-sensitive, so data frames
// carry raw bytes: base64 inside a JSON envelope would cost a third of the
// bandwidth and a copy per keystroke for nothing. Everything that is not the
// stream — the opening request, a window resize, the exit status — is a JSON
// control frame, because those are structured and rare.
//
// The framing is one byte of kind, four bytes of length, then the payload. It
// is written down in docs/protocol.md rather than discovered from this file.

// Frame kinds.
const (
	ShellData    byte = 1
	ShellControl byte = 2
)

// MaxShellFrame bounds one frame. A terminal writes in small bursts and a
// paste is the largest thing it sends; a megabyte is far more than either and
// still bounds what a compromised guest can make the host buffer.
const MaxShellFrame = 1 << 20

// ShellOpen is the first control frame the host sends, and the only one that
// starts anything.
type ShellOpen struct {
	Op string `json:"op"` // "open"
	// Cmd is the shell to run. Empty means the guest's own default, which is
	// what the flavor ships — the host does not get to name a binary that has
	// to exist inside a machine it did not build.
	Cmd  string   `json:"cmd,omitempty"`
	Args []string `json:"args,omitempty"`
	Cwd  string   `json:"cwd,omitempty"`
	Cols uint16   `json:"cols"`
	Rows uint16   `json:"rows"`
}

// ShellResize is a window-size change. It is a control frame rather than an
// escape sequence in the stream because it is something the *kernel* is told —
// TIOCSWINSZ on the pty — and not something the shell reads.
type ShellResize struct {
	Op   string `json:"op"` // "resize"
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// ShellExit is the guest's last word: what the shell exited with. A closed
// connection with no exit frame is a supervisor that died, which is a different
// thing from a shell that ended.
type ShellExit struct {
	Op     string `json:"op"` // "exit"
	Code   int    `json:"code"`
	Signal string `json:"signal,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Sanitize is Sanitizer for the shell channel's last word, which the host
// decodes off a channel the guest writes to (host/shell.go:203).
//
// Error was already cleaned at that call site; Signal was not, and it goes
// straight into the flight recorder beside it (host/shell.go:112). That is the
// shape this whole finding is: one field somebody remembered and one nobody
// did. The rule belongs to the frame, so there is one thing to remember rather
// than four (P7-17/F20, second review round).
//
// The LENGTH bound on Error stays at the call site: SafeText has no length
// policy, and clipping is a decision about how much of a guest's sentence the
// host keeps, not about which characters it may contain.
func (e *ShellExit) Sanitize() {
	e.Op, e.Signal, e.Error = SafeText(e.Op), SafeText(e.Signal), SafeText(e.Error)
}

// ShellOp reads just the op out of a control frame, so a reader can tell which
// shape to unmarshal into.
type ShellOp struct {
	Op string `json:"op"`
}

// Sanitize is Sanitizer for the one-field peek. Op is only ever compared
// against a constant, so a clean value is unchanged and a hostile one simply
// stops matching — but it implements the interface because every guest->host
// frame does, and "this one's string does not matter" is the reasoning that
// left ExecResponse.ID and the whole of TeamRequest unsanitised.
func (o *ShellOp) Sanitize() { o.Op = SafeText(o.Op) }

// WriteShellFrame writes one frame.
func WriteShellFrame(w io.Writer, kind byte, payload []byte) error {
	if len(payload) > MaxShellFrame {
		return fmt.Errorf("proto: shell frame of %d bytes exceeds %d", len(payload), MaxShellFrame)
	}
	head := make([]byte, 5)
	head[0] = kind
	binary.BigEndian.PutUint32(head[1:], uint32(len(payload)))
	if _, err := w.Write(head); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// WriteShellControl marshals and writes a control frame.
func WriteShellControl(w io.Writer, v any) error {
	blob, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return WriteShellFrame(w, ShellControl, blob)
}

// ReadShellFrame reads one frame. The returned slice is freshly allocated, so a
// caller may hold it.
func ReadShellFrame(r io.Reader) (kind byte, payload []byte, err error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n > MaxShellFrame {
		// Fatal for the connection: there is no way to resynchronise a stream
		// whose length prefix cannot be trusted.
		return 0, nil, fmt.Errorf("proto: shell frame claims %d bytes, over the %d limit",
			n, MaxShellFrame)
	}
	if head[0] != ShellData && head[0] != ShellControl {
		return 0, nil, errors.New("proto: unknown shell frame kind")
	}
	if n == 0 {
		return head[0], nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return head[0], buf, nil
}

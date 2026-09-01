package sandbox

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/proto"
)

// ExecResult is one completed command.
type ExecResult struct {
	Stdout []byte
	Stderr []byte
	Code   int
	Err    *proto.Error
}

// MaxExecOutput bounds what Exec will hold in memory for one command.
//
// Exec buffers, unlike `kelyfos exec`, which streams to a terminal and is
// bounded by the terminal. Its callers are the two long-lived server doors —
// `serve-mcp` and the E2B shim — so a guest that streams output for ever grows
// a host process that is serving other people. The guest chooses how much it
// sends and the host was choosing to keep all of it.
//
// Sixteen MiB because that is already the ceiling downstream: an MCP frame is
// bounded at proto.MaxMCPLine and the result is base64 inside it, so output
// past this point could not be delivered anyway. Refusing here makes the limit
// a stated one with a clear error rather than a frame failure further along.
const MaxExecOutput = 16 << 20

// execGrace is how long past a command's own budget the host keeps reading.
//
// The guest is asked to stop at timeout_ms and is given this much longer to say
// what happened. Past it the host stops listening, because a guest that has
// neither finished nor reported is a guest this call cannot wait on — and the
// caller may be a server holding the goroutine for everybody else.
const execGrace = 10 * time.Second

// maxExecFrames bounds a conversation that carries no bytes.
//
// MaxExecOutput counts what a command produced; this counts how many times it
// said anything at all. A guest sending empty frames advances the first not at
// all and this one every time, which is the whole of the difference between a
// ceiling that holds and one that reads as if it does.
const maxExecFrames = 1 << 20

// MaxExecTimeout bounds the timeout a command may be given, and is exported so
// the doors that take one from a client can refuse above it before the
// arithmetic lies (audit 2026-09-01, A15): a timeout_ms near the largest
// signed integer multiplied out to a negative Duration, which the grace path
// below absorbed into a silent ten-second kill. Clamped here as well, so the
// deadline arithmetic this function does can never wrap whatever a caller
// passes.
const MaxExecTimeout = 24 * time.Hour

// Exec runs one command in a sandbox and collects its output.
//
// It is the programmatic form of `kelyfos exec`, for callers that need the
// result rather than a terminal — the E2B shim, and anything else that has to
// act on what a command produced.
func Exec(udsPath string, argv []string, stdin []byte, timeout time.Duration) (*ExecResult, error) {
	if timeout > MaxExecTimeout {
		// Clamped, not refused: the door that took the ask from a person
		// refuses above this ceiling; the library's job is that no caller,
		// however wrong its number, turns the deadline arithmetic into a
		// wrap (audit 2026-09-01, A15).
		timeout = MaxExecTimeout
	}
	conn, err := Connect(udsPath, proto.PortExec, 15*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// A deadline on the host's side of the channel (P6-24/P6-25, finding M-9).
	//
	// The timeout in this function's signature was, until now, a number mailed
	// to the untrusted party: it travels in the request as timeout_ms and asks
	// the guest to please stop. Connect clears the deadline it dialled with, so
	// nothing here ever stopped reading. A guest that answered with frames
	// carrying no bytes, or with a stream name no case matched, or with blank
	// lines, kept this call inside its loop for as long as the process lived —
	// and the caller is `sandbox_exec` on a long-lived server, so the goroutine,
	// the connection and its buffer were held for good.
	//
	// The grace above the command's own budget is what lets a guest that is
	// obeying the timeout report the result of doing so. Every other guest→host
	// channel in this package sets a deadline; this was the one that did not.
	deadline := timeout + execGrace
	if timeout <= 0 {
		deadline = execGrace
	}
	if err := conn.SetDeadline(time.Now().Add(deadline)); err != nil {
		return nil, err
	}

	req := proto.ExecRequest{
		V: proto.Version, ID: fmt.Sprintf("x%d", time.Now().UnixNano()),
		Cmd: proto.EncodeCmd(argv), TimeoutMS: timeout.Milliseconds(),
	}
	if len(stdin) > 0 {
		req.Stdin = base64.StdEncoding.EncodeToString(stdin)
	}
	if err := proto.NewWriter(conn).Write(req); err != nil {
		return nil, err
	}

	out := &ExecResult{Code: -1}
	frames := 0
	r := proto.NewReader(conn)
	for {
		var resp proto.ExecResponse
		if err := r.Read(&resp); err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("the supervisor closed the connection without an exit frame")
			}
			return nil, err
		}
		switch resp.Stream {
		case proto.StreamStdout, proto.StreamStderr:
			data, err := base64.StdEncoding.DecodeString(resp.Data)
			if err != nil {
				return nil, fmt.Errorf("guest sent invalid base64 on %s: %w", resp.Stream, err)
			}
			if len(out.Stdout)+len(out.Stderr)+len(data) > MaxExecOutput {
				return nil, fmt.Errorf("the command produced more than %d MiB of output, "+
					"which is more than one result can carry; redirect it to a file in /work "+
					"and read that instead", MaxExecOutput>>20)
			}
			if resp.Stream == proto.StreamStdout {
				out.Stdout = append(out.Stdout, data...)
			} else {
				out.Stderr = append(out.Stderr, data...)
			}
		case proto.StreamExit:
			if resp.Code != nil {
				out.Code = *resp.Code
			}
			out.Err = resp.Error
			return out, nil
		default:
			// The switch had no default, so a stream name nothing matched fell
			// out of it and the loop went round again — forever, at no cost to
			// the sender. `kelyfos exec`'s own copy of this loop has always had
			// this case; the library the servers use did not, which made the
			// CLI stricter than the thing serving other people.
			return nil, fmt.Errorf("guest sent an unknown stream %q", proto.SafeText(resp.Stream))
		}

		// Frames that carry nothing still cost something to receive. The output
		// ceiling counts bytes, so a stream of empty frames never reaches it —
		// this is the same ceiling expressed in the other currency.
		frames++
		if frames > maxExecFrames {
			return nil, fmt.Errorf("guest sent more than %d frames without finishing; "+
				"a command that produces this much has more to say than one result can carry",
				maxExecFrames)
		}
	}
}

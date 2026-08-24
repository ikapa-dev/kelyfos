package sandbox

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
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

// Exec runs one command in a sandbox and collects its output.
//
// It is the programmatic form of `kelyfos exec`, for callers that need the
// result rather than a terminal — the E2B shim, and anything else that has to
// act on what a command produced.
func Exec(udsPath string, argv []string, stdin []byte, timeout time.Duration) (*ExecResult, error) {
	conn, err := Connect(udsPath, proto.PortExec, 15*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := proto.ExecRequest{
		V: proto.Version, ID: fmt.Sprintf("x%d", time.Now().UnixNano()),
		Cmd: argv, TimeoutMS: timeout.Milliseconds(),
	}
	if len(stdin) > 0 {
		req.Stdin = base64.StdEncoding.EncodeToString(stdin)
	}
	if err := proto.NewWriter(conn).Write(req); err != nil {
		return nil, err
	}

	out := &ExecResult{Code: -1}
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
		}
	}
}

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

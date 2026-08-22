package main

import (
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
)

// defaultEnv is the environment a command gets when the request does not carry
// one. It is a fixed set, not the supervisor's own environment: a sandbox that
// silently hands its process environment to guest commands is one leak away
// from handing over whatever the host put there.
var defaultEnv = []string{
	"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	"HOME=/root",
	"TERM=dumb",
}

// serveExecConn runs one command for one connection and answers with the frames
// docs/protocol.md §5.2 requires: any number of stdout/stderr chunks, then
// exactly one exit frame — including on every error path. A caller that gets a
// valid exit frame knows what happened; a caller that gets a closed socket
// cannot tell a finished command from a crashed supervisor.
func serveExecConn(conn net.Conn) {
	defer conn.Close()

	w := &syncWriter{w: proto.NewWriter(conn)}

	var req proto.ExecRequest
	if err := proto.NewReader(conn).Read(&req); err != nil {
		if !errors.Is(err, io.EOF) {
			w.exit(req.ID, -1, "", &proto.Error{
				Kind: proto.ErrBadRequest, Message: "unreadable request: " + err.Error(),
			})
		}
		return
	}
	if req.V != proto.Version {
		w.exit(req.ID, -1, "", &proto.Error{
			Kind: proto.ErrBadRequest, Message: "unsupported protocol version",
		})
		return
	}
	if len(req.Cmd) == 0 {
		w.exit(req.ID, -1, "", &proto.Error{
			Kind: proto.ErrBadRequest, Message: "cmd must not be empty",
		})
		return
	}

	var stdin []byte
	if req.Stdin != "" {
		var err error
		stdin, err = base64.StdEncoding.DecodeString(req.Stdin)
		if err != nil {
			w.exit(req.ID, -1, "", &proto.Error{
				Kind: proto.ErrBadRequest, Message: "stdin is not valid base64",
			})
			return
		}
	}

	cmd := exec.Command(req.Cmd[0], req.Cmd[1:]...)
	cmd.Dir = "/"
	if req.Cwd != "" {
		cmd.Dir = req.Cwd
	}
	cmd.Env = defaultEnv
	if req.Env != nil {
		cmd.Env = cmd.Env[:0]
		for k, v := range req.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	// Its own process group, so a timeout kills the whole tree rather than just
	// the shell that spawned it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		w.exit(req.ID, -1, "", &proto.Error{Kind: proto.ErrInternal, Message: err.Error()})
		return
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		w.exit(req.ID, -1, "", &proto.Error{Kind: proto.ErrInternal, Message: err.Error()})
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		w.exit(req.ID, -1, "", &proto.Error{Kind: proto.ErrInternal, Message: err.Error()})
		return
	}

	if err := cmd.Start(); err != nil {
		kind := proto.ErrInternal
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound) {
			kind = proto.ErrNotFound
		} else if errors.Is(err, os.ErrPermission) {
			kind = proto.ErrDenied
		}
		w.exit(req.ID, -1, "", &proto.Error{Kind: kind, Message: err.Error()})
		return
	}

	// stdin is written and closed regardless: a command reading to EOF must see
	// one, and an empty or absent stdin means an immediately-closed pipe.
	go func() {
		if len(stdin) > 0 {
			_, _ = stdinPipe.Write(stdin)
		}
		_ = stdinPipe.Close()
	}()

	var pump sync.WaitGroup
	pump.Add(2)
	go func() { defer pump.Done(); w.stream(req.ID, proto.StreamStdout, stdoutPipe) }()
	go func() { defer pump.Done(); w.stream(req.ID, proto.StreamStderr, stderrPipe) }()

	// Set by the timer goroutine, read here after the wait — hence atomic.
	var timedOut atomic.Bool
	var timer *time.Timer
	if req.TimeoutMS > 0 {
		timer = time.AfterFunc(time.Duration(req.TimeoutMS)*time.Millisecond, func() {
			timedOut.Store(true)
			killGroup(cmd)
		})
	}

	// Drain both streams to EOF before reaping. Reaping first would race the
	// pumps and could truncate the tail of a command's output.
	pump.Wait()
	waitErr := cmd.Wait()
	if timer != nil {
		timer.Stop()
	}

	code, signal := exitStatus(cmd, waitErr)
	var perr *proto.Error
	switch {
	case timedOut.Load():
		perr = &proto.Error{Kind: proto.ErrTimeout, Message: "command exceeded timeout_ms"}
		code = -1
	case waitErr != nil && code < 0:
		perr = &proto.Error{Kind: proto.ErrInternal, Message: waitErr.Error()}
	}
	w.exit(req.ID, code, signal, perr)
}

func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	// Negative pid targets the whole process group (see Setpgid above). Fall
	// back to the single process if the group is gone.
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}

// exitStatus maps a finished command onto the protocol's code/signal pair: the
// exit status normally, and 128+N with the signal named when a signal killed it.
func exitStatus(cmd *exec.Cmd, waitErr error) (int, string) {
	if cmd.ProcessState == nil {
		return -1, ""
	}
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		return cmd.ProcessState.ExitCode(), ""
	}
	if ws.Signaled() {
		return 128 + int(ws.Signal()), ws.Signal().String()
	}
	return ws.ExitStatus(), ""
}

// syncWriter serialises the frames produced by the two output pumps and the
// terminating exit frame. Interleaving is allowed across streams; a torn JSON
// line is not.
type syncWriter struct {
	mu sync.Mutex
	w  *proto.Writer
}

func (s *syncWriter) stream(id, name string, r io.Reader) {
	buf := make([]byte, proto.MaxChunk)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			s.mu.Lock()
			werr := s.w.Write(proto.ExecResponse{
				V: proto.Version, ID: id, Stream: name,
				Data: base64.StdEncoding.EncodeToString(buf[:n]),
			})
			s.mu.Unlock()
			if werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *syncWriter) exit(id string, code int, signal string, perr *proto.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.w.Write(proto.ExecResponse{
		V: proto.Version, ID: id, Stream: proto.StreamExit,
		Code: &code, Signal: signal, Error: perr,
	})
}

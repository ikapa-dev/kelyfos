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
func serveExecConn(conn net.Conn, rp *reaper) {
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
	switch {
	case req.V != proto.Version:
		w.exit(req.ID, -1, "", &proto.Error{Kind: proto.ErrBadRequest, Message: "unsupported protocol version"})
		return
	case len(req.Cmd) == 0:
		w.exit(req.ID, -1, "", &proto.Error{Kind: proto.ErrBadRequest, Message: "cmd must not be empty"})
		return
	}

	var stdin []byte
	if req.Stdin != "" {
		var err error
		if stdin, err = base64.StdEncoding.DecodeString(req.Stdin); err != nil {
			w.exit(req.ID, -1, "", &proto.Error{Kind: proto.ErrBadRequest, Message: "stdin is not valid base64"})
			return
		}
	}

	// Pipes are built by hand rather than with StdoutPipe/StderrPipe, because
	// those are wired to Cmd.Wait — and in PID 1 the reaper owns every wait
	// (see reaper.go). Owning the pipes means owning when they close.
	inR, inW, err := os.Pipe()
	if err != nil {
		w.exit(req.ID, -1, "", &proto.Error{Kind: proto.ErrInternal, Message: err.Error()})
		return
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		w.exit(req.ID, -1, "", &proto.Error{Kind: proto.ErrInternal, Message: err.Error()})
		return
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		w.exit(req.ID, -1, "", &proto.Error{Kind: proto.ErrInternal, Message: err.Error()})
		return
	}

	cmd := exec.Command(req.Cmd[0], req.Cmd[1:]...)
	cmd.Dir = "/"
	if req.Cwd != "" {
		cmd.Dir = req.Cwd
	}
	cmd.Env = defaultEnv
	if req.Env != nil {
		cmd.Env = make([]string, 0, len(req.Env))
		for k, v := range req.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	// Its own process group, so a timeout kills the whole tree rather than just
	// the shell that spawned it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		for _, f := range []*os.File{inR, inW, outR, outW, errR, errW} {
			f.Close()
		}
		kind := proto.ErrInternal
		switch {
		case errors.Is(err, exec.ErrNotFound), errors.Is(err, os.ErrNotExist):
			kind = proto.ErrNotFound
		case errors.Is(err, os.ErrPermission):
			kind = proto.ErrDenied
		}
		w.exit(req.ID, -1, "", &proto.Error{Kind: kind, Message: err.Error()})
		return
	}
	status := rp.register(cmd.Process.Pid)
	defer rp.forget(cmd.Process.Pid)

	// The child holds its own copies now; ours would otherwise keep the pipes
	// from ever reaching EOF.
	inR.Close()
	outW.Close()
	errW.Close()

	go func() {
		if len(stdin) > 0 {
			_, _ = inW.Write(stdin)
		}
		_ = inW.Close()
	}()

	var pump sync.WaitGroup
	pump.Add(2)
	go func() { defer pump.Done(); defer outR.Close(); w.stream(req.ID, proto.StreamStdout, outR) }()
	go func() { defer pump.Done(); defer errR.Close(); w.stream(req.ID, proto.StreamStderr, errR) }()

	var timedOut atomic.Bool
	var timer *time.Timer
	if req.TimeoutMS > 0 {
		timer = time.AfterFunc(time.Duration(req.TimeoutMS)*time.Millisecond, func() {
			timedOut.Store(true)
			killGroup(cmd.Process.Pid)
		})
	}

	// Drain both streams to EOF before taking the status. Taking it first would
	// race the pumps and could truncate the tail of a command's output.
	pump.Wait()
	ws := <-status
	if timer != nil {
		timer.Stop()
	}

	code, signal := exitStatus(ws)
	var perr *proto.Error
	if timedOut.Load() {
		perr = &proto.Error{Kind: proto.ErrTimeout, Message: "command exceeded timeout_ms"}
		code = -1
	}
	w.exit(req.ID, code, signal, perr)
}

// killGroup targets the whole process group (negative pid), falling back to the
// single process if the group is already gone.
func killGroup(pid int) {
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// exitStatus maps a wait status onto the protocol's code/signal pair: the exit
// status normally, and 128+N with the signal named when a signal killed it.
func exitStatus(ws syscall.WaitStatus) (int, string) {
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

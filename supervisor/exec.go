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

	"github.com/ikapa-dev/kelyfos/internal/proto"
)

// maxExecTimeoutMS is the ceiling on a command's timeout, matching the host
// doors' 24-hour bound (audit 2026-09-01, A15). It exists so the multiply into
// time.Duration below cannot wrap negative; a caller wanting no timeout passes
// zero, not a number near the top of int64.
const maxExecTimeoutMS = 24 * 60 * 60 * 1000

// defaultEnv is the environment a command gets when the request does not carry
// one. It is a fixed set, not the supervisor's own environment: a sandbox that
// silently hands its process environment to guest commands is one leak away
// from handing over whatever the host put there.
var defaultEnv = []string{
	"PATH=" + defaultPath,
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
	if req.V != proto.Version {
		w.exit(req.ID, -1, "", &proto.Error{Kind: proto.ErrBadRequest, Message: "unsupported protocol version"})
		return
	}

	res := runCommand(req, rp,
		func(b []byte) { w.chunk(req.ID, proto.StreamStdout, b) },
		func(b []byte) { w.chunk(req.ID, proto.StreamStderr, b) },
	)
	w.exit(req.ID, res.Code, res.Signal, res.Err)
}

// Result is what running one command produced, beyond its output.
type Result struct {
	Code   int
	Signal string
	Err    *proto.Error
}

// runCommand executes one request and hands output to the callbacks as it
// arrives. It is the single implementation of "run a thing in this guest",
// shared by the raw exec channel and the MCP exec tool, so the two cannot drift
// in how they handle environments, timeouts or exit statuses.
//
// Output callbacks are invoked from two goroutines; callers serialise if they
// need to.
func runCommand(req proto.ExecRequest, rp *reaper, onStdout, onStderr func([]byte)) Result {
	if len(req.Cmd) == 0 {
		return Result{Code: -1, Err: &proto.Error{Kind: proto.ErrBadRequest, Message: "cmd must not be empty"}}
	}
	argv, err := proto.DecodeCmd(req.Cmd)
	if err != nil {
		return Result{Code: -1, Err: &proto.Error{Kind: proto.ErrBadRequest, Message: err.Error()}}
	}

	var stdin []byte
	if req.Stdin != "" {
		var err error
		if stdin, err = base64.StdEncoding.DecodeString(req.Stdin); err != nil {
			return Result{Code: -1, Err: &proto.Error{Kind: proto.ErrBadRequest, Message: "stdin is not valid base64"}}
		}
	}

	// Pipes are built by hand rather than with StdoutPipe/StderrPipe, because
	// those are wired to Cmd.Wait — and in PID 1 the reaper owns every wait
	// (see reaper.go). Owning the pipes means owning when they close.
	inR, inW, err := os.Pipe()
	if err != nil {
		return internalErr(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return internalErr(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return internalErr(err)
	}

	cmd := exec.Command(argv[0], argv[1:]...)
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

	status, err := rp.startAndRegister(cmd)
	if err != nil {
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
		return Result{Code: -1, Err: &proto.Error{Kind: kind, Message: err.Error()}}
	}
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
	go func() { defer pump.Done(); defer outR.Close(); drain(outR, onStdout) }()
	go func() { defer pump.Done(); defer errR.Close(); drain(errR, onStderr) }()

	var timedOut atomic.Bool
	var timer *time.Timer
	if req.TimeoutMS > 0 {
		// Clamp before the multiply, or a timeout_ms near the top of int64
		// overflows time.Duration to a negative and fires the kill at once
		// (audit 2026-09-01, A15). The host doors already refuse absurd values;
		// this is the same guard at the source, for the in-guest MCP exec tool
		// that reaches this path directly (adversarial review 2026-09-01).
		ms := req.TimeoutMS
		if ms > maxExecTimeoutMS {
			ms = maxExecTimeoutMS
		}
		timer = time.AfterFunc(time.Duration(ms)*time.Millisecond, func() {
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
	if timedOut.Load() {
		return Result{Code: -1, Signal: signal, Err: &proto.Error{
			Kind: proto.ErrTimeout, Message: "command exceeded timeout_ms",
		}}
	}
	return Result{Code: code, Signal: signal}
}

func internalErr(err error) Result {
	return Result{Code: -1, Err: &proto.Error{Kind: proto.ErrInternal, Message: err.Error()}}
}

func drain(r io.Reader, sink func([]byte)) {
	buf := make([]byte, proto.MaxChunk)
	for {
		n, err := r.Read(buf)
		if n > 0 && sink != nil {
			sink(buf[:n])
		}
		if err != nil {
			return
		}
	}
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

func (s *syncWriter) chunk(id, name string, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.w.Write(proto.ExecResponse{
		V: proto.Version, ID: id, Stream: name,
		Data: base64.StdEncoding.EncodeToString(b),
	})
}

func (s *syncWriter) exit(id string, code int, signal string, perr *proto.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.w.Write(proto.ExecResponse{
		V: proto.Version, ID: id, Stream: proto.StreamExit,
		Code: &code, Signal: signal, Error: perr,
	})
}

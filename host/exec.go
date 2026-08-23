package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/exitcode"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// exitError carries a guest exit status out to main so the CLI can exit with it.
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("command exited with status %d", e.code) }

func execCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos exec", flag.ExitOnError)
	var (
		id      = fs.String("sandbox", "", "sandbox id (default: the only running one)")
		cwd     = fs.String("cwd", "", "working directory inside the guest (default /)")
		timeout = fs.Duration("timeout", 0, "kill the command after this long (0 = no limit)")
		shell   = fs.Bool("shell", true, "run a single argument through /bin/sh -c")
		useIn   = fs.Bool("stdin", false, "forward this process's stdin to the command")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos exec [flags] <command>
       kelyfos exec [flags] -- <argv>...

A single argument is a shell command line, run as /bin/sh -c "<argument>".
Several arguments are an argv, executed directly with no shell involved.

Standard input is only forwarded when --stdin is given, the same way docker exec
requires -i. Reading it automatically would hang whenever kelyfos runs from a
script or a CI job, where stdin is an inherited pipe that nobody is ever going
to close.

    printf 'data' | kelyfos exec --stdin "cat"

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	args := fs.Args()
	if len(args) == 0 {
		fs.Usage()
		return errors.New("no command given")
	}

	// Shell wrapping is done here, in the open, rather than in the guest: the
	// audit log should show that a shell was involved, because it changes what
	// the command can do (docs/protocol.md §5.2).
	cmd := args
	if len(args) == 1 && *shell {
		cmd = []string{"/bin/sh", "-c", args[0]}
	}

	st, err := sandbox.Load(*id)
	if err != nil {
		return err
	}

	var stdin string
	if *useIn {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		stdin = base64.StdEncoding.EncodeToString(data)
	}

	conn, err := sandbox.Connect(st.UDSPath, proto.PortExec, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	reqID := fmt.Sprintf("e%d", time.Now().UnixNano())

	// Every command goes into the flight recorder, including the shell wrapper
	// if one was added, because that changes what the command can do.
	rec, err := recorder.Open(sandbox.Root(), st.RecordSession())
	if err != nil {
		return err
	}
	defer rec.Close()
	started := time.Now()
	_ = rec.Append(recorder.Event{
		Type: recorder.TypeCommandStart, Call: reqID, Cmd: cmd, Cwd: *cwd, Via: "exec",
		Agent: st.Agent,
	})
	out := &outputRecorder{rec: rec, call: reqID, agent: st.Agent}
	defer out.flush()
	if err := proto.NewWriter(conn).Write(proto.ExecRequest{
		V:         proto.Version,
		ID:        reqID,
		Cmd:       cmd,
		Cwd:       *cwd,
		Stdin:     stdin,
		TimeoutMS: timeout.Milliseconds(),
	}); err != nil {
		return fmt.Errorf("send exec request: %w", err)
	}

	r := proto.NewReader(conn)
	for {
		var resp proto.ExecResponse
		if err := r.Read(&resp); err != nil {
			if errors.Is(err, io.EOF) {
				// §5.2: exactly one exit frame per request. A closed connection
				// without one is a supervisor crash, and inventing an exit code
				// here would hide it.
				return errors.New("the supervisor closed the connection without an exit frame")
			}
			return fmt.Errorf("read exec response: %w", err)
		}
		switch resp.Stream {
		case proto.StreamStdout, proto.StreamStderr:
			data, err := base64.StdEncoding.DecodeString(resp.Data)
			if err != nil {
				return fmt.Errorf("guest sent invalid base64 on %s: %w", resp.Stream, err)
			}
			out.add(resp.Stream, data)
			out := os.Stdout
			if resp.Stream == proto.StreamStderr {
				out = os.Stderr
			}
			if _, err := out.Write(data); err != nil {
				return err
			}
		case proto.StreamExit:
			out.flush()
			ev := recorder.Event{
				Type: recorder.TypeCommandExit, Call: reqID, Code: resp.Code,
				Signal: resp.Signal, DurationMS: time.Since(started).Milliseconds(),
				Agent: st.Agent,
			}
			if resp.Error != nil {
				ev.Error = &recorder.EvError{Kind: resp.Error.Kind, Message: resp.Error.Message}
			}
			_ = rec.Append(ev)

			if resp.Error != nil {
				fmt.Fprintf(os.Stderr, "kelyfos: %s: %s\n", resp.Error.Kind, resp.Error.Message)
				return &exitError{code: exitCodeFor(resp.Error.Kind)}
			}
			code := -1
			if resp.Code != nil {
				code = *resp.Code
			}
			if code == 0 {
				return nil
			}
			return &exitError{code: code}
		default:
			return fmt.Errorf("guest sent unknown stream %q", resp.Stream)
		}
	}
}

// exitCodeFor maps a protocol error onto the exit status the CLI reports. The
// values follow long-standing shell convention so that scripts wrapping kelyfos
// can branch on them the way they already branch on timeout(1) and a missing
// binary, rather than learning a private numbering.
func exitCodeFor(kind string) int {
	switch kind {
	case proto.ErrTimeout:
		return exitcode.TimedOut
	case proto.ErrDenied:
		return exitcode.NotExecutable
	case proto.ErrNotFound:
		return exitcode.NotFound
	default:
		return exitcode.Fail
	}
}

// outputRecorder coalesces command output before it reaches the flight
// recorder.
//
// A pipe read returns whatever is available, which for an unbuffered writer like
// curl's progress output is often a single byte. Recording one event per read
// turned "curl: (7) CONNECT tunnel failed" into twenty-eight events, one per
// character — a log that is unreadable, needlessly long, and whose hash chain is
// mostly noise. Coalescing here rather than on the wire keeps output streaming
// to the terminal immediately, which is what a person watching a command wants,
// while the record stays legible.
type outputRecorder struct {
	rec    *recorder.Recorder
	call   string
	agent  string
	stream string
	buf    []byte
}

const outputFlushAt = 8 << 10

func (o *outputRecorder) add(stream string, data []byte) {
	if stream != o.stream {
		o.flush()
		o.stream = stream
	}
	o.buf = append(o.buf, data...)
	if len(o.buf) >= outputFlushAt {
		o.flush()
	}
}

func (o *outputRecorder) flush() {
	if len(o.buf) == 0 {
		return
	}
	_ = o.rec.Append(recorder.Event{
		Type: recorder.TypeCommandOutput, Call: o.call, Stream: o.stream,
		Data: base64.StdEncoding.EncodeToString(o.buf), Bytes: len(o.buf),
		Agent: o.agent,
	})
	o.buf = o.buf[:0]
}

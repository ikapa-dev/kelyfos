package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
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
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos exec [flags] <command>
       kelyfos exec [flags] -- <argv>...

A single argument is a shell command line, run as /bin/sh -c "<argument>".
Several arguments are an argv, executed directly with no shell involved.
Piped stdin is forwarded to the command.

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
	if data, err := readPipedStdin(); err != nil {
		return err
	} else if len(data) > 0 {
		stdin = base64.StdEncoding.EncodeToString(data)
	}

	conn, err := sandbox.Connect(st.UDSPath, proto.PortExec, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	reqID := fmt.Sprintf("e%d", time.Now().UnixNano())
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
			out := os.Stdout
			if resp.Stream == proto.StreamStderr {
				out = os.Stderr
			}
			if _, err := out.Write(data); err != nil {
				return err
			}
		case proto.StreamExit:
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

// readPipedStdin returns stdin only when it is piped or redirected. Reading an
// interactive terminal here would hang waiting for a Ctrl-D nobody expects.
func readPipedStdin() ([]byte, error) {
	info, err := os.Stdin.Stat()
	if err != nil {
		return nil, nil
	}
	if info.Mode()&os.ModeCharDevice != 0 {
		return nil, nil
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	return data, nil
}

// exitCodeFor maps a protocol error onto the exit status the CLI reports. The
// values follow long-standing shell convention so that scripts wrapping kelyfos
// can branch on them the way they already branch on timeout(1) and a missing
// binary, rather than learning a private numbering.
func exitCodeFor(kind string) int {
	switch kind {
	case proto.ErrTimeout:
		return 124 // same as timeout(1)
	case proto.ErrDenied:
		return 126 // found but not executable
	case proto.ErrNotFound:
		return 127 // not found
	default:
		return 1
	}
}

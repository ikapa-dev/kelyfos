package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// kelyfos shell — an interactive terminal inside a running sandbox (E5-3,
// docs/qol.md §3).
//
// The host's job is small and exacting: put this terminal in raw mode so every
// keystroke reaches the guest unprocessed, copy bytes both ways, forward window
// resizes, and put the terminal back however this ends. A tool that leaves your
// terminal unusable after it crashes is a tool people stop running, so the
// restore is on every path out including a panic.

func shellCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos shell", flag.ExitOnError)
	var (
		id         = fs.String("sandbox", "", "sandbox id (default: the only running one)")
		cwd        = fs.String("cwd", "", "working directory inside the guest")
		transcript = fs.Bool("transcript", false, "record everything the terminal shows, beside the session log")
		timeout    = fs.Duration("timeout", 15*time.Second, "how long to wait for the sandbox channel")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos shell [flags]

An interactive shell inside a running sandbox. A real terminal: job control,
line editing, and full-screen programs all work, and resizing this window
resizes the one in there.

What is recorded, and what is not. The session log always says a shell was
opened, for how long, and how it ended. It does not record what was typed or
shown unless you ask with --transcript, which writes the terminal stream to a
file beside the log. The default is off deliberately: a shell is where somebody
pastes a token to test something, and recording that by default would make the
honest thing the risky thing.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if !onATerminal(os.Stdin) {
		return errors.New("kelyfos shell needs a terminal — it is the interactive one.\n" +
			"    for a command, use:  kelyfos exec \"<command>\"")
	}

	st, err := sandbox.Load(*id)
	if err != nil {
		return err
	}
	conn, err := sandbox.Connect(st.UDSPath, proto.PortShell, *timeout)
	if err != nil {
		return fmt.Errorf("attach to sandbox %s: %w\n"+
			"    a sandbox booted by an older kelyfos has no shell channel", st.ID, err)
	}
	defer conn.Close()

	cols, rows := terminalSize(os.Stdin)
	if err := proto.WriteShellControl(conn, proto.ShellOpen{
		Op: "open", Cwd: *cwd, Cols: cols, Rows: rows,
	}); err != nil {
		return err
	}

	// The record. Always the fact of the shell; the contents only if asked.
	rec, _ := recorder.Open(sandbox.Root(), st.RecordSession())
	var tape *os.File
	if *transcript {
		path := filepath.Join(filepath.Dir(recorder.Path(sandbox.Root(), st.RecordSession())),
			fmt.Sprintf("shell-%d.stream", time.Now().Unix()))
		if tape, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err != nil {
			return fmt.Errorf("open the transcript: %w", err)
		}
		defer tape.Close()
		fmt.Fprintf(os.Stderr, "kelyfos: recording this terminal to %s\n", path)
	}
	started := time.Now()
	if rec != nil {
		_ = rec.Append(recorder.Event{Type: recorder.TypeShellStart, Agent: st.Agent,
			Path: transcriptPath(tape)})
	}

	restore, err := rawMode(os.Stdin)
	if err != nil {
		return fmt.Errorf("put this terminal in raw mode: %w", err)
	}
	// Every path out, including a panic: the terminal goes back to how it was.
	defer restore()

	exit := pumpShell(conn, tape)

	restore()
	if rec != nil {
		_ = rec.Append(recorder.Event{Type: recorder.TypeShellEnd, Agent: st.Agent,
			Code: &exit.Code, Signal: exit.Signal, Reason: exit.Error,
			DurationMS: time.Since(started).Milliseconds()})
		_ = rec.Close()
	}
	if exit.Error != "" {
		return errors.New(exit.Error)
	}
	fmt.Printf("\nshell exited %d after %s\n", exit.Code,
		time.Since(started).Truncate(time.Second))
	if exit.Code != 0 {
		return &exitError{exit.Code}
	}
	return nil
}

// pumpShell copies both directions until the guest sends its exit frame or the
// connection ends.
func pumpShell(conn io.ReadWriter, tape *os.File) proto.ShellExit {
	var wmu sync.Mutex
	send := func(kind byte, b []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return proto.WriteShellFrame(conn, kind, b)
	}

	// Window resizes, forwarded as control frames. SIGWINCH is the only way the
	// host learns its terminal changed, and the guest's kernel is the thing
	// that has to be told.
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, unix.SIGWINCH)
	defer signal.Stop(winch)
	go func() {
		for range winch {
			cols, rows := terminalSize(os.Stdin)
			wmu.Lock()
			_ = proto.WriteShellControl(conn, proto.ShellResize{Op: "resize", Cols: cols, Rows: rows})
			wmu.Unlock()
		}
	}()

	// Keystrokes in. This goroutine outlives the function when the terminal has
	// nothing to say — a read on a terminal blocks until somebody types — which
	// is why the exit comes from the guest's frame rather than from here.
	go func() {
		buf := make([]byte, 8<<10)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				if err := send(proto.ShellData, buf[:n]); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	for {
		kind, payload, err := proto.ReadShellFrame(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return proto.ShellExit{Code: 0}
			}
			return proto.ShellExit{Code: 1, Error: err.Error()}
		}
		switch kind {
		case proto.ShellData:
			_, _ = os.Stdout.Write(payload)
			if tape != nil {
				_, _ = tape.Write(payload)
			}
		case proto.ShellControl:
			var op proto.ShellOp
			if json.Unmarshal(payload, &op) != nil || op.Op != "exit" {
				continue
			}
			var exit proto.ShellExit
			_ = json.Unmarshal(payload, &exit)
			return exit
		}
	}
}

func transcriptPath(tape *os.File) string {
	if tape == nil {
		return ""
	}
	return tape.Name()
}

// rawMode puts this terminal in the state an interactive program needs: no line
// buffering, no echo, no signal generation — every byte reaches the guest, and
// Ctrl-C is the guest's to handle.
//
// Written against the termios syscalls directly rather than through a
// dependency, because this is the whole of what such a dependency would do.
func rawMode(f *os.File) (restore func(), err error) {
	fd := int(f.Fd())
	before, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	saved := *before

	raw := *before
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, &saved) })
	}, nil
}

// terminalSize asks this terminal how big it is. A terminal that will not say
// gets a reasonable answer rather than a zero, because a guest told its window
// is 0x0 renders nothing at all.
func terminalSize(f *os.File) (cols, rows uint16) {
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws.Col == 0 || ws.Row == 0 {
		return 80, 24
	}
	return ws.Col, ws.Row
}

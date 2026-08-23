package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
)

// The interactive shell, from inside the guest (E5-3, docs/qol.md §3).
//
// One connection is one shell. The supervisor allocates a pty, spawns the
// shell as a session leader with that pty as its controlling terminal, and
// copies bytes both ways until one end stops.
//
// A pty and not a pipe, because the difference is the whole feature: a shell on
// a pipe has no job control, no line editing and no idea how wide the terminal
// is, and every program it runs decides it is not interactive.

// defaultShells are tried in order. The host does not name one: it has no way
// to know what a flavor ships, and a host that could name an arbitrary binary
// would be choosing what runs inside a machine it did not build.
var defaultShells = []string{"/bin/sh", "/bin/ash", "/bin/bash"}

func serveShell(ln net.Listener, rp *reaper) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			logf("shell accept: %v", err)
			return
		}
		go func() {
			defer conn.Close()
			if err := runShell(conn, rp); err != nil {
				logf("shell: %v", err)
			}
		}()
	}
}

func runShell(conn net.Conn, rp *reaper) error {
	// The first frame must be the open. Anything else is a client that does not
	// speak this channel, and answering it would be guessing.
	kind, payload, err := proto.ReadShellFrame(conn)
	if err != nil {
		return err
	}
	if kind != proto.ShellControl {
		return fmt.Errorf("the first shell frame was data, not an open")
	}
	var open proto.ShellOpen
	if err := json.Unmarshal(payload, &open); err != nil || open.Op != "open" {
		return fmt.Errorf("the first shell frame is not an open request")
	}

	ptmx, ptsName, err := openPTY()
	if err != nil {
		return sendShellError(conn, "allocate a terminal: "+err.Error())
	}
	defer ptmx.Close()
	if open.Cols > 0 && open.Rows > 0 {
		setWinsize(ptmx, open.Cols, open.Rows)
	}

	pts, err := os.OpenFile(ptsName, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return sendShellError(conn, "open the terminal: "+err.Error())
	}

	name, args := shellCommand(open)
	cmd := exec.Command(name, args...)
	cmd.Dir = open.Cwd
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	// The same environment every command in this sandbox gets, plus the one
	// thing an interactive terminal needs and a batch command does not.
	cmd.Env = append(append([]string{}, defaultEnv...), "TERM=xterm-256color")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pts, pts, pts
	// Its own session with the pty as the controlling terminal, which is what
	// makes job control work: without Setsid and Setctty a Ctrl-C reaches
	// nothing and every program decides it is not interactive.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}

	status, err := rp.startAndRegister(cmd)
	if err != nil {
		pts.Close()
		return sendShellError(conn, "start "+name+": "+err.Error())
	}
	// The child holds the slave now. Keeping it open here would mean the master
	// never sees EOF when the shell exits.
	pts.Close()

	var wmu sync.Mutex
	write := func(kind byte, b []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return proto.WriteShellFrame(conn, kind, b)
	}

	// The terminal's output, to the host.
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32<<10)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				if err := write(proto.ShellData, buf[:n]); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// The host's keystrokes and control frames, to the terminal.
	go func() {
		for {
			kind, payload, err := proto.ReadShellFrame(conn)
			if err != nil {
				// The host hung up. Ending the shell's session is what closes
				// the terminal on its side; a shell left running on a pty
				// nobody is reading is a process that never ends.
				_ = cmd.Process.Signal(syscall.SIGHUP)
				return
			}
			switch kind {
			case proto.ShellData:
				if _, err := ptmx.Write(payload); err != nil {
					return
				}
			case proto.ShellControl:
				var op proto.ShellOp
				if json.Unmarshal(payload, &op) == nil && op.Op == "resize" {
					var r proto.ShellResize
					if json.Unmarshal(payload, &r) == nil {
						setWinsize(ptmx, r.Cols, r.Rows)
					}
				}
			}
		}
	}()

	ws := <-status
	rp.forget(cmd.Process.Pid)
	// The reader is given a moment to drain what the shell wrote before it
	// exited; without it the last line of output races the exit frame.
	ptmx.Close()
	<-done

	exit := proto.ShellExit{Op: "exit", Code: ws.ExitStatus()}
	if ws.Signaled() {
		exit.Code = 128 + int(ws.Signal())
		exit.Signal = unix.SignalName(ws.Signal())
	}
	wmu.Lock()
	defer wmu.Unlock()
	return proto.WriteShellControl(conn, exit)
}

// shellCommand decides what to run. The host may ask for a command, and asking
// for one that is not there is answered by the shell that is.
func shellCommand(open proto.ShellOpen) (string, []string) {
	if open.Cmd != "" {
		return open.Cmd, open.Args
	}
	for _, candidate := range defaultShells {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, []string{"-i"}
		}
	}
	return "/bin/sh", []string{"-i"}
}

func sendShellError(conn net.Conn, msg string) error {
	_ = proto.WriteShellControl(conn, proto.ShellExit{Op: "exit", Code: 1, Error: msg})
	return fmt.Errorf("%s", msg)
}

// openPTY allocates a pseudo-terminal pair the way the kernel documents it:
// open the multiplexer, unlock the slave, ask for its number.
func openPTY() (*os.File, string, error) {
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, "", err
	}
	var unlock int
	if err := unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, unlock); err != nil {
		ptmx.Close()
		return nil, "", fmt.Errorf("unlock the terminal: %w", err)
	}
	n, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		ptmx.Close()
		return nil, "", fmt.Errorf("ask the terminal its number: %w", err)
	}
	return ptmx, fmt.Sprintf("/dev/pts/%d", n), nil
}

// setWinsize tells the kernel how big the terminal is, which is what makes a
// full-screen program redraw correctly after the host's window changes.
func setWinsize(f *os.File, cols, rows uint16) {
	w := struct{ Row, Col, Xpixel, Ypixel uint16 }{rows, cols, 0, 0}
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(),
		uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(&w)))
}

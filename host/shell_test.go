package main

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/proto"
)

// shellConn is a shell channel whose guest side is a canned script of frames
// and whose host side goes nowhere. What pumpShell writes is keystrokes and
// resizes, and in a test there is nobody typing; the lock is there because the
// keystroke goroutine may still be writing when the read side has finished.
type shellConn struct {
	r  io.Reader
	mu sync.Mutex
}

func (c *shellConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *shellConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(p), nil
}

// A shell that ended says so with an exit frame (docs/protocol.md §5.7). A
// connection that simply stops is the supervisor dying with the terminal still
// open, and the two must not look alike to whoever asked: a script that branches
// on `kelyfos shell`'s status cannot tell a clean exit from a dead sandbox if a
// missing exit frame is reported as zero.
func TestADeadSupervisorIsNotAShellThatExitedCleanly(t *testing.T) {
	exit := pumpShell(&shellConn{r: strings.NewReader("")}, nil)

	if exit.Error == "" {
		t.Fatalf("a connection that ended with no exit frame was reported as %+v, "+
			"with nothing to say the supervisor died", exit)
	}
	if exit.Code == 0 {
		t.Errorf("a dead supervisor reported code 0, which a script reads as success")
	}
}

// The other half of the same rule: an exit frame is believed, including the
// zero. The fix above must not turn every ended shell into a failure.
func TestAnExitFrameIsTheShellsOwnStatus(t *testing.T) {
	var script bytes.Buffer
	if err := proto.WriteShellControl(&script, proto.ShellExit{Op: "exit", Code: 0}); err != nil {
		t.Fatal(err)
	}
	if exit := pumpShell(&shellConn{r: &script}, nil); exit.Code != 0 || exit.Error != "" {
		t.Errorf("a shell that exited 0 was reported as %+v", exit)
	}

	script.Reset()
	if err := proto.WriteShellControl(&script, proto.ShellExit{
		Op: "exit", Code: 137, Signal: "SIGKILL"}); err != nil {
		t.Fatal(err)
	}
	exit := pumpShell(&shellConn{r: &script}, nil)
	if exit.Code != 137 || exit.Signal != "SIGKILL" || exit.Error != "" {
		t.Errorf("a killed shell was reported as %+v", exit)
	}
}

// The same rule one step further in: the op check reads a single string, so a
// frame that says "exit" and then carries a code of the wrong shape gets past
// it with the typed fields still at zero. Believing that is the same invented
// success as believing a closed connection — "shell exited 0", status 0, and a
// script wrapping this command told the session was fine. Only a compromised or
// non-conforming guest sends such a frame, which is exactly who this has to
// hold against.
func TestAnExitFrameThisHostCannotReadIsNotASuccess(t *testing.T) {
	for _, frame := range []string{
		`{"op":"exit","code":"7"}`,        // a code that is not a number
		`{"op":"exit","code":{"n":7}}`,    // nor an object
		`{"op":"exit","signal":["kill"]}`, // a signal that is not a string
	} {
		var script bytes.Buffer
		if err := proto.WriteShellFrame(&script, proto.ShellControl, []byte(frame)); err != nil {
			t.Fatal(err)
		}
		exit := pumpShell(&shellConn{r: &script}, nil)
		if exit.Code == 0 {
			t.Errorf("the unreadable exit frame %s was reported as %+v, which the CLI prints "+
				"as \"shell exited 0\"", frame, exit)
		}
		if exit.Error == "" {
			t.Errorf("the unreadable exit frame %s was reported as %+v, with nothing to say "+
				"the guest's last word could not be read", frame, exit)
		}
	}
}

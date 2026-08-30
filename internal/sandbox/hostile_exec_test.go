package sandbox

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/hostile"
	"github.com/ikapa-dev/kelyfos/internal/proto"
)

// The hostile corpus for the exec channel (P6-22, finding M-9 as D46 corrected
// it).
//
// M-9 as the audit worded it — "no total-output ceiling" — is not a defect at
// HEAD. ac8968f added one in P6-3, after the audit read babec8f, and a fixture
// for it would be a fixture for something that no longer exists. What survives
// is the rest of that finding's own sentence: *without ever sending
// StreamExit*.
//
// The ceiling counts bytes, and a guest can send frames that carry none. There
// is no host-side deadline on this channel either: connectOnce clears the
// deadline it dialled with, and the `timeout` in Exec's signature becomes a
// `timeout_ms` field in a JSON message — a number mailed to the untrusted party
// asking it to please stop. Every other guest→host channel sets a read deadline.
// This is the one that does not.
//
// Four ways to make the call never return, and they are not variations on one
// bug: bytes that never reach the ceiling, empty frames that never advance it,
// a stream name no case matches and no default catches, and blank lines that
// keep proto.Reader.Read spinning inside a single call. The last sits *below*
// Exec and belongs to every channel built on proto.NewReader.
//
// These need no mke2fs and no image, so unlike the workspace cases they run
// everywhere.

// hostileGuest is the exec channel with no VM behind it.
func hostileGuest(t *testing.T, behave func(c net.Conn)) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kelyfos-hostile-exec-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "v.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	t.Cleanup(func() {
		ln.Close()
		for _, c := range conns {
			c.Close()
		}
		os.RemoveAll(dir)
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
			go func() {
				br := bufio.NewReader(c)
				if line, err := br.ReadString('\n'); err != nil || !strings.HasPrefix(line, "CONNECT ") {
					c.Close()
					return
				}
				fmt.Fprint(c, "OK 1\n")
				if _, err := br.ReadString('\n'); err != nil { // the ExecRequest
					c.Close()
					return
				}
				behave(c)
			}()
		}
	}()
	return path
}

// answers reports how Exec finished, or "" if it had not finished in time.
func answers(uds string, budget time.Duration) (string, bool) {
	type outcome struct {
		res *ExecResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := Exec(uds, []string{"/bin/true"}, nil, 1*time.Second)
		done <- outcome{res, err}
	}()
	select {
	case o := <-done:
		if o.err != nil {
			return o.err.Error(), true
		}
		return fmt.Sprintf("exit %d", o.res.Code), true
	case <-time.After(budget):
		return "", false
	}
}

func TestHostileExecStreamCannotRunForever(t *testing.T) {
	// Taken from the product's own constant rather than guessed. The host now
	// stops reading at the command's budget plus execGrace, so a case that
	// holds returns by then and a case that does not never returns at all —
	// and a budget below execGrace would report a working deadline as a hang.
	//
	// It costs nothing for the cases that return quickly: this is how long the
	// test is willing to wait, not how long it waits.
	budget := execGrace + 3*time.Second
	oneMiB := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A", 600<<10)))

	cases := []struct {
		key   string
		speak func(c net.Conn)
	}{
		// This one holds, and is here as the guard on what ac8968f bought:
		// the 16 MiB ceiling ends the read even though the guest never sends
		// an exit frame. It is the only one of the five that does.
		{"exec/flood-with-bytes", func(c net.Conn) {
			w := proto.NewWriter(c)
			for w.Write(proto.ExecResponse{V: proto.Version, ID: "x",
				Stream: proto.StreamStdout, Data: oneMiB}) == nil {
			}
		}},
		{"exec/flood-empty-frames", func(c net.Conn) {
			w := proto.NewWriter(c)
			for w.Write(proto.ExecResponse{V: proto.Version, ID: "x",
				Stream: proto.StreamStdout}) == nil {
			}
		}},
		{"exec/flood-unknown-stream", func(c net.Conn) {
			w := proto.NewWriter(c)
			for w.Write(proto.ExecResponse{V: proto.Version, ID: "x", Stream: "keepalive"}) == nil {
			}
		}},
		{"exec/flood-blank-lines", func(c net.Conn) {
			for {
				if _, err := c.Write([]byte("\n")); err != nil {
					return
				}
			}
		}},
		{"exec/never-answers", func(c net.Conn) { select {} }},
	}

	for _, tc := range cases {
		t.Run(strings.TrimPrefix(tc.key, "exec/"), func(t *testing.T) {
			uds := hostileGuest(t, tc.speak)
			how, finished := answers(uds, budget)
			problem := ""
			if !finished {
				problem = fmt.Sprintf("Exec was still reading after %s and no exit frame was ever sent; "+
					"the call never returns and the goroutine, the connection and its buffer are held for good", budget)
			} else {
				t.Logf("refused with: %s", how)
			}
			hostile.Holds(t, tc.key, problem)
		})
	}
}

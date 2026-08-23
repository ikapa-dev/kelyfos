// Package notify sends a desktop notification when a run wants a person back
// (E5-7).
//
// The case it exists for is the one this product creates: a sandbox you started
// and stopped watching. A run that finishes in four minutes, a domain that was
// blocked thirty seconds in, a budget that expired, a review prompt waiting for
// a yes — all of them are things you find out about by looking, and looking is
// the thing you stopped doing.
//
// Three rules shape everything here.
//
//   - **A notification must never fail a run.** Every send is best effort, with
//     a short timeout, and its error is discarded. A tool that fell over
//     because a notification daemon was not running would be worse than one
//     that never notified.
//   - **The message is data, never script.** On macOS this means passing the
//     text as arguments to osascript and reading them back with `item 1 of
//     argv`, rather than building an AppleScript string: a command name or a
//     domain can contain a quote, and a notification is not a place to have an
//     injection bug.
//   - **Off unless asked.** A tool that starts sending desktop notifications
//     because you upgraded it is a tool people learn to distrust.
package notify

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// sendTimeout bounds one notification. Anything slower is a daemon in trouble,
// and waiting for it would hold up a teardown.
const sendTimeout = 5 * time.Second

// Kind is how notifications get out on this machine.
type Kind string

const (
	// None means notifications were not asked for.
	None Kind = "off"
	// NotifySend is the freedesktop.org command, on Linux.
	NotifySend Kind = "notify-send"
	// OSAScript is macOS's, driven with the text as arguments rather than as
	// script.
	OSAScript Kind = "osascript"
	// Bell is the fallback: the terminal's own, which every terminal has and
	// which needs nothing installed. Written only when stderr is a terminal,
	// because a BEL in a log file is a stray byte nobody asked for.
	Bell Kind = "bell"
)

// Notifier sends notifications, or does nothing.
type Notifier struct {
	kind Kind
	bin  string
	out  *os.File
}

// New picks how this machine notifies, once. Returning a Notifier rather than
// nil when disabled means callers never have to check.
func New(enabled bool) *Notifier {
	if !enabled {
		return &Notifier{kind: None}
	}
	return newWith(exec.LookPath, runtime.GOOS, os.Stderr)
}

// newWith is New with its two facts about the world injected, so the choice can
// be tested on a machine that is not the one being described.
func newWith(look func(string) (string, error), goos string, out *os.File) *Notifier {
	order := []string{"notify-send", "osascript"}
	if goos == "darwin" {
		order = []string{"osascript", "notify-send"}
	}
	for _, name := range order {
		if path, err := look(name); err == nil {
			kind := NotifySend
			if name == "osascript" {
				kind = OSAScript
			}
			return &Notifier{kind: kind, bin: path, out: out}
		}
	}
	return &Notifier{kind: Bell, out: out}
}

// Kind reports how this notifier gets a message out, so a caller can say so
// once rather than leaving somebody wondering whether it worked.
func (n *Notifier) Kind() Kind { return n.kind }

// Enabled reports whether anything will be sent.
func (n *Notifier) Enabled() bool { return n.kind != None }

// Send delivers one notification. It never returns an error, because there is
// no caller for whom a failed notification is worth changing course over.
func (n *Notifier) Send(title, body string) {
	if n == nil || n.kind == None {
		return
	}
	if n.kind == Bell {
		// Only into a terminal. A run whose output is being collected should
		// not have a control character spliced into it.
		if n.out != nil && isTerminal(n.out) {
			_, _ = n.out.WriteString("\a")
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, n.bin, n.args(title, body)...)
	_ = cmd.Run()
}

// args builds the command line for one notification.
//
// The osascript form is the whole reason this is a separate function worth
// testing: the text travels as arguments and is read back inside the script
// with `item N of argv`, so a title containing a quote is a title containing a
// quote rather than the end of a string literal.
func (n *Notifier) args(title, body string) []string {
	if n.kind == OSAScript {
		return []string{
			"-e", "on run argv",
			"-e", "display notification (item 1 of argv) with title (item 2 of argv)",
			"-e", "end run",
			"--", body, title,
		}
	}
	// notify-send takes them positionally, and takes them as data: there is no
	// shell between here and it.
	return []string{"--app-name=kelyfos", title, body}
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

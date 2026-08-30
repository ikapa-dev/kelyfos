package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/digest"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// P7-17/C — two render paths F20's sweep did not reach.
//
// F20 made all three renderers call safeEvent once per event, reflectively, so
// a field added to Event later is covered without anyone adding a line. Two
// places sit outside that by construction:
//
//   - `kelyfos log`'s default arm prints the RAW JSON line rather than the
//     decoded event, for an event type this build has no case for. It works
//     from bytes, so the sweep over the decoded struct never touches it — and
//     replaying a newer chain with an older binary is a thing docs/events.md §3
//     says you may do.
//   - `kelyfos watch`'s two headers read EndReason, Image and Arch off the
//     digest and printed them raw, where host/view.go sanitises the same three
//     rendering the same header. One renderer cleaned and the next one not is
//     the exact shape F20 is about.

// hostile carries a bidi override, a CSI erase-display, a bare CR and an OSC
// introducer — the four things a terminal acts on rather than shows.
const cHostile = "‮pwned\x1b[2J\rlooking\x1b]0;title\a"

// captureStdout runs f with os.Stdout redirected, and returns what it wrote.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				b.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- b.String()
	}()
	f()
	os.Stdout = saved
	w.Close()
	out := <-done
	r.Close()
	return out
}

// The default arm: an event type this build has no case for.
func TestC_TheLogsUnknownEventArmIsSanitised(t *testing.T) {
	ev := recorder.Event{
		Type: "some.type.this.build.does.not.know",
		Cmd:  []string{cHostile},
	}
	line, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() { printEvent(line, false) })

	if out == "" {
		t.Fatal("nothing was printed; this fixture is measuring the wrong thing")
	}
	for _, bad := range []struct{ name, s string }{
		{"a bidi override", "‮"},
		{"an ESC", "\x1b"},
		{"a bare carriage return", "\r"},
		{"a BEL", "\a"},
	} {
		if strings.Contains(out, bad.s) {
			t.Errorf("%s reached the terminal through the unknown-event arm:\n%q", bad.name, out)
		}
	}
	// The line is still there to read, quoted rather than dropped: an event
	// nobody has a renderer for is exactly the one somebody needs the bytes of.
	if !strings.Contains(out, "pwned") {
		t.Errorf("the line's content was dropped rather than quoted:\n%q", out)
	}
}

// A type this build DOES know still renders through its own case, so the arm
// above is the fallback and not a new behaviour for everything.
func TestC_AKnownEventStillRendersThroughItsOwnCase(t *testing.T) {
	ev := recorder.Event{Type: recorder.TypeCommandStart, Cmd: []string{"echo", "hello"}}
	line, _ := json.Marshal(ev)
	out := captureStdout(t, func() { printEvent(line, false) })
	if strings.Contains(out, `"type"`) {
		t.Errorf("a known event fell through to the raw-line arm:\n%s", out)
	}
	if !strings.Contains(out, "echo hello") {
		t.Errorf("the command did not render:\n%s", out)
	}
}

// watch's headers, both of them.
func TestC_WatchsHeadersSanitiseWhatTheyReadOffTheChain(t *testing.T) {
	for _, tc := range []struct {
		name string
		team bool
	}{{"sandbox", false}, {"team", true}} {
		t.Run(tc.name, func(t *testing.T) {
			d := *digest.New()
			d.EndReason = cHostile
			d.Image = cHostile
			d.Arch = cHostile
			m := &watchModel{d: d, session: cHostile, width: 120, height: 40}
			if tc.team {
				// A team view needs a lane per name in order; teamView reads
				// m.lanes[name] and laneBlock dereferences it.
				m.order = []string{"one"}
				m.lanes = map[string]*lane{"one": {name: "one"}}
			}
			// ALL FOUR panes, not the one render() happens to dispatch to
			// (P7-17/C, review round). The first version called render() alone,
			// which reaches the activity pane and never the map or the sheet —
			// and those two were still printing the session id raw, which is
			// the same "one renderer cleaned and the next one not" shape this
			// whole item is about. A test that walks one of four is how the
			// other three stay unfixed.
			panes := map[string]string{"activity": m.render()}
			for name, p := range map[string]pane{"map": paneMap, "sheet": paneSheet} {
				m.pane = p
				panes[name] = m.render()
			}
			m.pane = paneActivity
			for pane, out := range panes {
				for _, bad := range []struct{ name, s string }{
					{"a bidi override", "‮"},
					{"an ESC introducing something other than SGR", "\x1b]"},
					{"a bare carriage return", "\r"},
					{"a BEL", "\a"},
				} {
					if strings.Contains(out, bad.s) {
						t.Errorf("%s reached the %s pane's header:\n%q", bad.name, pane, out)
					}
				}
			}
		})
	}
}

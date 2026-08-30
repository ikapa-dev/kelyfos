package main

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/proto"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// P7-17/F20 — guest strings reach the terminal without SafeText.
//
// The edge fix (internal/proto) sanitises what a running guest sends before it
// is either recorded or shown. It cannot cover a chain that is already on disk:
// `kelyfos log`, `kelyfos watch` and `kelyfos view` all replay a file, which may
// have been written by an older build, hand-edited, or torn by a crash. Those
// three renderers therefore still have to defend themselves, and this file is
// what says so — the test host/view.go already had, applied to the other three
// readers, as the review asked.
//
// f20Hostile is the reviewer's own proof of concept: ED-2 plus ED-3 clears the
// screen and the scrollback, and what it clears is the boot line saying which
// walls were around the sandbox.
const f20Hostile = "\x1b[2J\x1b[3Jpwned\rlooking"

// f20Unsafe reports whether a rendered line still carries a byte a terminal
// would act on. A newline is a line separator here, not content. Used on the
// surfaces that emit no colour of their own — `kelyfos log`'s identity-like
// fields and `kelyfos view`'s lines — where an ESC can only have come from the
// record.
func f20Unsafe(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// f20UnsafeStyled is the same question for a surface that legitimately carries
// colour: `kelyfos watch` styles every line through lipgloss, and command
// output is legitimately coloured on replay. SGR (ESC [ … m) is allowed
// through; every other C0 byte, DEL, and ESC followed by anything else — OSC
// title and hyperlink injection, the CSI screen controls J and H, a bare
// carriage return over a fixed prefix — is not.
//
// Written out here rather than delegating to proto.SafeBody on purpose: a test
// that asks the function under test whether its own output is safe cannot fail.
func f20UnsafeStyled(s string) bool {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == '\n' || c == '\t' {
			continue
		}
		if c == 0x1b {
			// ESC [ <params> <final>: safe only when the final byte is 'm'.
			if i+1 < len(b) && b[i+1] == '[' {
				j := i + 2
				for j < len(b) && b[j] >= 0x30 && b[j] <= 0x3f {
					j++
				}
				for j < len(b) && b[j] >= 0x20 && b[j] <= 0x2f {
					j++
				}
				if j < len(b) && b[j] == 'm' {
					i = j
					continue
				}
			}
			return true
		}
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// The three fields `kelyfos log`'s own switch still printed raw while the
// branches on either side of them routed through proto.SafeText — the sharpest
// illustration in the whole finding, because :793 and :795 sanitise and :790
// and :802 do not, inside one switch statement.
func TestF20_TheReplayEscapesTheGuestFieldsItStillPrintedRaw(t *testing.T) {
	overlay := true
	code := 0
	cases := []struct {
		name string
		e    recorder.Event
	}{
		{"session.ready kernel", recorder.Event{Type: recorder.TypeSessionReady,
			BootMS: 700, Kernel: f20Hostile, Supervisor: "v0.9.1", Overlay: &overlay}},
		{"session.ready supervisor", recorder.Event{Type: recorder.TypeSessionReady,
			BootMS: 700, Kernel: "6.18.45", Supervisor: f20Hostile, Overlay: &overlay}},
		{"command.exit error kind", recorder.Event{Type: recorder.TypeCommandExit,
			Code: &code, Error: &recorder.EvError{Kind: f20Hostile, Message: "denied"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.e.TS = "2026-08-28T10:00:00.000Z"
			line := renderEvent(t, c.e)
			if f20Unsafe(line) {
				t.Errorf("a raw control byte reached the replay:\n  %q", line)
			}
		})
	}
	t.Run("command.output data", func(t *testing.T) {
		line := renderEvent(t, recorder.Event{
			TS: "2026-08-28T10:00:00.000Z", Type: recorder.TypeCommandOutput,
			Stream: "stdout", Data: base64.StdEncoding.EncodeToString([]byte(f20Hostile)),
		})
		if f20UnsafeStyled(line) {
			t.Errorf("a raw control byte reached the replay:\n  %q", line)
		}
	})
}

// Command output is the one field that is legitimately multi-line and
// legitimately coloured, so the replay must keep it readable rather than quote
// the whole blob — and must still refuse OSC and the screen controls.
func TestF20_TheReplayKeepsColouredOutputButRefusesOSC(t *testing.T) {
	out := func(s string) string {
		return renderEvent(t, recorder.Event{
			TS: "2026-08-28T10:00:00.000Z", Type: recorder.TypeCommandOutput,
			Stream: "stdout", Data: base64.StdEncoding.EncodeToString([]byte(s)),
		})
	}

	coloured := out("\x1b[31mFAIL\x1b[0m three tests\nline two\n")
	if !strings.Contains(coloured, "\x1b[31m") {
		t.Errorf("SGR colour did not survive the replay:\n  %q", coloured)
	}
	if !strings.Contains(coloured, "line two") {
		t.Errorf("the second line of output was lost:\n  %q", coloured)
	}

	for _, bad := range []string{"\x1b]0;pwned\x07", "\x1b[2J\x1b[1;1H", "\x1b]8;;http://evil\x1b\\"} {
		got := out(bad)
		if strings.Contains(got, bad) {
			t.Errorf("the replay passed %q through verbatim:\n  %q", bad, got)
		}
	}
}

// f20WatchLines is everything one watchModel would draw, gathered from every
// buffer absorb writes into.
func f20WatchLines(m *watchModel) string {
	var b strings.Builder
	for _, l := range m.lines {
		b.WriteString(l + "\n")
	}
	for _, l := range m.flow {
		b.WriteString(l + "\n")
	}
	// Through laneBlock, which is what actually draws a lane: the heading is
	// an agent name off the chain and is as much a rendered field as the lines
	// under it. The width is far wider than anything this corpus produces, so
	// fit cannot truncate a control byte out of view and turn a real failure
	// into a pass.
	for _, name := range m.order {
		for _, l := range m.laneBlock(m.lanes[name], 200, 12) {
			b.WriteString(l + "\n")
		}
	}
	for _, l := range m.refusals {
		b.WriteString(l + "\n")
	}
	return b.String()
}

// watch.go routes none of its fields through SafeText and bubbletea emits what
// it is given; fitStyled trims runes and is not a sanitiser. Every field absorb
// reads is a field a guest, a teammate or a tampered chain chose.
func TestF20_WatchEscapesEveryGuestFieldItDraws(t *testing.T) {
	code := 1
	cases := []struct {
		name string
		e    recorder.Event
	}{
		{"session.start image", recorder.Event{Type: recorder.TypeSessionStart, Image: f20Hostile, Arch: "aarch64"}},
		{"session.start arch", recorder.Event{Type: recorder.TypeSessionStart, Image: "base", Arch: f20Hostile}},
		{"session.ready kernel", recorder.Event{Type: recorder.TypeSessionReady, BootMS: 7, Kernel: f20Hostile}},
		{"session.end reason", recorder.Event{Type: recorder.TypeSessionEnd, Reason: f20Hostile}},
		{"command.start argv", recorder.Event{Type: recorder.TypeCommandStart, Cmd: []string{f20Hostile}}},
		{"command.output data", recorder.Event{Type: recorder.TypeCommandOutput, Stream: "stdout",
			Data: base64.StdEncoding.EncodeToString([]byte(f20Hostile))}},
		{"file.write path", recorder.Event{Type: recorder.TypeFileWrite, Path: f20Hostile, Bytes: 3}},
		{"egress.attempt host", recorder.Event{Type: recorder.TypeEgressAttempt, Host: f20Hostile, Port: 443, Mode: "connect"}},
		{"egress.attempt mode", recorder.Event{Type: recorder.TypeEgressAttempt, Host: "a.example", Port: 443, Mode: f20Hostile}},
		{"egress.attempt reason", recorder.Event{Type: recorder.TypeEgressAttempt, Host: "a.example", Port: 443, Reason: f20Hostile}},
		{"egress.attempt peer", recorder.Event{Type: recorder.TypeEgressAttempt, Reason: "foreign_peer", Peer: f20Hostile}},
		{"secret.use name", recorder.Event{Type: recorder.TypeSecretUse, Name: f20Hostile, Host: "a.example"}},
		{"secret.use host", recorder.Event{Type: recorder.TypeSecretUse, Name: "TOKEN", Host: f20Hostile}},
		{"team.message agent", recorder.Event{Type: recorder.TypeTeamMessage, Agent: f20Hostile, Peer: "w", Kind: "send"}},
		{"team.message peer", recorder.Event{Type: recorder.TypeTeamMessage, Agent: "m", Peer: f20Hostile, Kind: "send"}},
		{"team.refused reason", recorder.Event{Type: recorder.TypeTeamRefused, Agent: "m", Peer: "w", Kind: "send", Reason: f20Hostile}},
		{"team.store peer", recorder.Event{Type: recorder.TypeTeamStore, Agent: "m", Peer: f20Hostile, Kind: "get", Outcome: "ok"}},
		{"team.store reason", recorder.Event{Type: recorder.TypeTeamStore, Agent: "m", Peer: "k", Kind: "get", Outcome: "refused", Reason: f20Hostile}},
		{"team.spawn peer", recorder.Event{Type: recorder.TypeTeamSpawn, Agent: "m", Peer: f20Hostile, Kind: "spawn", Outcome: "ok"}},
		{"team.spawn reason", recorder.Event{Type: recorder.TypeTeamSpawn, Agent: "m", Kind: "spawn", Outcome: "refused", Reason: f20Hostile}},
		{"resource.oom comm", recorder.Event{Type: recorder.TypeResourceOOM, Comm: f20Hostile, PID: 9}},
		{"command.exit code", recorder.Event{Type: recorder.TypeCommandExit, Code: &code, Agent: f20Hostile}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.e.TS = "2026-08-28T10:00:00.000Z"
			m := &watchModel{session: "s1"}
			m.absorb(c.e)
			got := f20WatchLines(m)
			if f20UnsafeStyled(got) {
				t.Errorf("a raw control byte reached the watch TUI:\n  %q", got)
			}
		})
	}
}

// The same corpus through `kelyfos view`'s own line renderer. view.go is the
// model the rest of this fix follows, so what this pins is the fields it did
// not yet read at all rather than fields it read raw.
func TestF20_ViewEscapesEveryGuestFieldItDraws(t *testing.T) {
	for _, e := range []recorder.Event{
		{Type: recorder.TypeSessionEnd, Reason: f20Hostile},
		{Type: recorder.TypeEgressAttempt, Host: f20Hostile, Port: 443},
		{Type: recorder.TypeEgressAttempt, Reason: f20Hostile, Port: 0},
		{Type: recorder.TypeEgressAttempt, Reason: "foreign_peer", Peer: f20Hostile},
		{Type: recorder.TypeResourceOOM, Comm: f20Hostile},
	} {
		e.TS = "2026-08-28T10:00:00.000Z"
		if got := viewLogLine(e); f20Unsafe(got) {
			t.Errorf("a raw control byte reached kelyfos view:\n  %q", got)
		}
	}
}

// The two riders the F9 review left for this finding. F9 records who knocked on
// the proxy in Event.Peer and nothing renders it, so an `egress.attempt` with
// reason=foreign_peer and peer=127.0.0.1:54321 prints as `egress BLOCKED :0` —
// indistinguishable from an ordinary blocked egress with an empty host, in the
// two surfaces an operator actually watches a live run through.
func TestF20_AForeignPeerRefusalSaysWhoKnockedAndWhy(t *testing.T) {
	blocked := false
	e := recorder.Event{
		TS: "2026-08-28T10:00:00.000Z", Type: recorder.TypeEgressAttempt,
		Allowed: &blocked, Reason: "foreign_peer", Peer: "127.0.0.1:54321",
	}

	t.Run("kelyfos log", func(t *testing.T) {
		got := renderEvent(t, e)
		if !strings.Contains(got, "127.0.0.1:54321") {
			t.Errorf("the replay does not say who connected:\n  %s", got)
		}
		if !strings.Contains(got, "foreign_peer") {
			t.Errorf("the replay does not say why it was refused:\n  %s", got)
		}
	})

	t.Run("kelyfos view", func(t *testing.T) {
		got := viewLogLine(e)
		if !strings.Contains(got, "127.0.0.1:54321") {
			t.Errorf("kelyfos view does not say who connected:\n  %s", got)
		}
		if !strings.Contains(got, "foreign_peer") {
			t.Errorf("kelyfos view does not say why it was refused:\n  %s", got)
		}
	})

	t.Run("kelyfos watch", func(t *testing.T) {
		m := &watchModel{session: "s1"}
		m.absorb(e)
		got := f20WatchLines(m)
		if !strings.Contains(got, "127.0.0.1:54321") {
			t.Errorf("the watch TUI does not say who connected:\n  %s", got)
		}
	})
}

// P7-17/F20, rider 2 (from the record workstream's review). host/exec.go
// copied resp.Error.Message straight into the chain, and that string is the
// guest supervisor's own prose carrying agent-chosen content — an argv, a path
// — which is F12's shape: guest text in a record field, unbounded and not
// enumerated. The chain keeps Kind, which is an enumeration now, and nothing
// else from the guest's error.
func TestF20_TheExecRecordKeepsTheErrorKindAndNotTheGuestsProse(t *testing.T) {
	resp := proto.ExecResponse{
		Stream: proto.StreamExit,
		Error: &proto.Error{
			Kind:    proto.ErrNotFound,
			Message: `exec: "/tmp/\x00../../etc/shadow": executable file not found in $PATH`,
		},
	}
	ev := execExitEvent("e1", "master", resp, 42*time.Millisecond)
	if ev.Error == nil {
		t.Fatal("the exit event carries no error at all")
	}
	if ev.Error.Kind != proto.ErrNotFound {
		t.Errorf("the kind was not carried: %q", ev.Error.Kind)
	}
	if ev.Error.Message != "" {
		t.Errorf("the guest's message reached the chain: %q", ev.Error.Message)
	}
	// Everything else the event is for is still there.
	if ev.Call != "e1" || ev.Agent != "master" || ev.DurationMS != 42 {
		t.Errorf("the exit event lost a field it is supposed to carry: %+v", ev)
	}
	// And an exit with no error carries none.
	if ev := execExitEvent("e2", "", proto.ExecResponse{Stream: proto.StreamExit}, 0); ev.Error != nil {
		t.Errorf("a clean exit grew an error: %+v", ev.Error)
	}
}

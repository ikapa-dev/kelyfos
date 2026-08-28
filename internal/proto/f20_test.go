package proto

import (
	"bytes"
	"strings"
	"testing"
)

// P7-17/F20 — guest strings reach the terminal without SafeText.
//
// The defence this pins is the one the review asked for by name: sanitise at
// the edge, where guest bytes become host strings, rather than at each print.
// Reader.Read is that edge. Every frame the HOST reads off a channel a guest
// writes to arrives through it, and the host has eight print sites and one
// recorder append that read those strings afterwards — a per-print fix leaves
// whichever of them the next change forgets, and leaves the escape sequence in
// the audit record besides (host/run.go records ev.Comm raw).
//
// hostile is the reviewer's own proof of concept: ED-2 clears the screen and
// the scrollback, and what it clears is the boot line that says which walls
// were around the sandbox.
const hostile = "\x1b[2J\x1b[3Jpwned\rlooking"

// hasRawControl reports whether s still carries a byte a terminal would act on
// rather than display. \t and \n are excluded because a body legitimately
// carries them; no field checked here is a body.
func hasRawControl(s string) bool {
	for _, r := range s {
		if r == '\t' || r == '\n' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// readOne frames v as the guest would and reads it back through the host's
// own reader, which is the only way this defence is reachable.
func readOne(t *testing.T, line string, v any) {
	t.Helper()
	if err := NewReader(strings.NewReader(line + "\n")).Read(v); err != nil {
		t.Fatalf("Read(%q): %v", line, err)
	}
}

func TestF20_ReadSanitisesEveryGuestChosenStringAtTheEdge(t *testing.T) {
	q := func(s string) string {
		b, _ := marshalString(s)
		return b
	}

	t.Run("GuestEvent", func(t *testing.T) {
		var ev GuestEvent
		readOne(t, `{"v":1,"type":`+q(hostile)+`,"comm":`+q(hostile)+`,"name":`+q(hostile)+
			`,"tool":`+q(hostile)+`,"outcome":`+q(hostile)+`,"message":`+q(hostile)+
			`,"args":`+q(hostile)+`}`, &ev)
		for name, got := range map[string]string{
			"Type": ev.Type, "Comm": ev.Comm, "Name": ev.Name,
			"Tool": ev.Tool, "Outcome": ev.Outcome, "Message": ev.Message, "Args": ev.Args,
		} {
			if hasRawControl(got) {
				t.Errorf("GuestEvent.%s came back with a raw control byte: %q", name, got)
			}
		}
	})

	t.Run("Ready", func(t *testing.T) {
		var r Ready
		readOne(t, `{"v":1,"type":"ready","boot_id":`+q(hostile)+`,"arch":`+q(hostile)+
			`,"kernel":`+q(hostile)+`,"supervisor":`+q(hostile)+`,"profile":`+q(hostile)+
			`,"profile_error":`+q(hostile)+`}`, &r)
		for name, got := range map[string]string{
			"BootID": r.BootID, "Arch": r.Arch, "Kernel": r.Kernel,
			"Supervisor": r.Supervisor, "Profile": r.Profile, "ProfileError": r.ProfileError,
		} {
			if hasRawControl(got) {
				t.Errorf("Ready.%s came back with a raw control byte: %q", name, got)
			}
		}
		// A ready frame reaches the host inside an anonymous struct that
		// embeds Ready (internal/sandbox/sandbox.go's serveReady). Method
		// promotion has to carry the sanitiser through that embedding, or the
		// one reader that actually decodes a ready frame is the one reader
		// this does not protect.
		var msg struct {
			Ready
			UptimeMS int64 `json:"uptime_ms"`
		}
		readOne(t, `{"v":1,"type":"ready","kernel":`+q(hostile)+`,"uptime_ms":5}`, &msg)
		if hasRawControl(msg.Kernel) {
			t.Errorf("an embedded Ready was not sanitised: %q", msg.Kernel)
		}
	})

	t.Run("Error inside ExecResponse", func(t *testing.T) {
		var resp ExecResponse
		readOne(t, `{"v":1,"id":"x","stream":"exit","error":{"kind":`+q(hostile)+
			`,"message":`+q(hostile)+`}}`, &resp)
		if resp.Error == nil {
			t.Fatal("no error frame decoded")
		}
		if hasRawControl(resp.Error.Kind) || hasRawControl(resp.Error.Message) {
			t.Errorf("ExecResponse.Error reached the host raw: %q / %q",
				resp.Error.Kind, resp.Error.Message)
		}
	})

	t.Run("Error inside ControlResponse", func(t *testing.T) {
		var resp ControlResponse
		readOne(t, `{"v":1,"id":"x","ok":false,"error":{"kind":`+q(hostile)+
			`,"message":`+q(hostile)+`},"profile":`+q(hostile)+`,"profile_error":`+q(hostile)+`}`, &resp)
		if resp.Error == nil {
			t.Fatal("no error frame decoded")
		}
		if hasRawControl(resp.Error.Kind) || hasRawControl(resp.Error.Message) ||
			hasRawControl(resp.Profile) || hasRawControl(resp.ProfileError) {
			t.Errorf("ControlResponse reached the host raw: %q / %q / %q / %q",
				resp.Error.Kind, resp.Error.Message, resp.Profile, resp.ProfileError)
		}
	})

	t.Run("a clean frame is untouched", func(t *testing.T) {
		var r Ready
		readOne(t, `{"v":1,"type":"ready","kernel":"6.18.45","supervisor":"v0.9.1","arch":"aarch64"}`, &r)
		if r.Kernel != "6.18.45" || r.Supervisor != "v0.9.1" || r.Arch != "aarch64" || r.Type != "ready" {
			t.Fatalf("an ordinary ready frame was altered: %+v", r)
		}
	})
}

// marshalString is json.Marshal for one string, used to build the hostile
// frames above without hand-escaping them.
func marshalString(s string) (string, error) {
	var buf bytes.Buffer
	if err := NewWriter(&buf).Write(s); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

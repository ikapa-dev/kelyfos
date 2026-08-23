package notify

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func looker(available ...string) func(string) (string, error) {
	have := map[string]bool{}
	for _, a := range available {
		have[a] = true
	}
	return func(name string) (string, error) {
		if have[name] {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
}

// Each platform's own first, and the terminal bell when neither is there — a
// fallback that needs nothing installed is the point of having one.
func TestItPicksWhatTheMachineHas(t *testing.T) {
	for _, tc := range []struct {
		name string
		goos string
		have []string
		want Kind
	}{
		{"linux with notify-send", "linux", []string{"notify-send"}, NotifySend},
		{"macos with osascript", "darwin", []string{"osascript"}, OSAScript},
		{"macos prefers its own", "darwin", []string{"osascript", "notify-send"}, OSAScript},
		{"linux prefers its own", "linux", []string{"osascript", "notify-send"}, NotifySend},
		{"a linux box with osascript somehow", "linux", []string{"osascript"}, OSAScript},
		{"nothing at all", "linux", nil, Bell},
	} {
		got := newWith(looker(tc.have...), tc.goos, os.Stderr).Kind()
		if got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestDisabledSendsNothing(t *testing.T) {
	n := New(false)
	if n.Enabled() || n.Kind() != None {
		t.Errorf("a notifier nobody asked for is %s", n.Kind())
	}
	n.Send("title", "body") // must not panic, must not run anything
	var nilN *Notifier
	nilN.Send("title", "body")
}

// The message is data. A title with a quote in it is a title with a quote in
// it, and never the end of a string literal in a script.
func TestTextTravelsAsArgumentsNotAsScript(t *testing.T) {
	mac := &Notifier{kind: OSAScript, bin: "/usr/bin/osascript"}
	nasty := `"; display dialog "pwned`
	args := mac.args("kelyfos: run finished", nasty)

	joined := strings.Join(args, "\x00")
	if !strings.Contains(joined, nasty) {
		t.Fatalf("the body was mangled instead of passed through: %q", args)
	}
	// Every -e fragment is a fixed string with no interpolation in it at all.
	for i, a := range args {
		if i > 0 && args[i-1] == "-e" {
			if strings.Contains(a, "kelyfos") || strings.Contains(a, "pwned") {
				t.Errorf("script fragment %q carries caller text", a)
			}
		}
	}
	if args[len(args)-2] != nasty || args[len(args)-1] != "kelyfos: run finished" {
		t.Errorf("body and title are not the last two arguments: %q", args)
	}

	linux := &Notifier{kind: NotifySend, bin: "/usr/bin/notify-send"}
	got := linux.args("kelyfos: blocked", nasty)
	if got[1] != "kelyfos: blocked" || got[2] != nasty {
		t.Errorf("notify-send args = %q", got)
	}
	if got[0] != "--app-name=kelyfos" {
		t.Errorf("the notification does not say who it is from: %q", got)
	}
}

package egress

import (
	"io"
	"os"
	"strings"
	"testing"
)

// The audit of 2026-09-01's A4: the minScrub carve-out means a credential
// shorter than 8 bytes is never scrubbed from responses — by design, but
// silently. ParseSecret now says so at parse time, where the user can still
// choose a longer credential.
func TestParseSecretWarnsOnShortValues(t *testing.T) {
	t.Setenv("KELYFOS_SHORT_TOKEN", "abc")
	t.Setenv("KELYFOS_LONG_TOKEN", "longenoughvalue")

	capture := func(spec string) string {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		saved := os.Stderr
		os.Stderr = w
		_, _ = ParseSecret(spec)
		os.Stderr = saved
		_ = w.Close()
		out, _ := io.ReadAll(r)
		return string(out)
	}

	short := capture("KELYFOS_SHORT_TOKEN@api.example.com")
	if !strings.Contains(short, "3 bytes") || !strings.Contains(short, "never scrubbed") {
		t.Errorf("a short credential did not get the parse-time warning:\n%s", short)
	}
	if strings.Contains(short, "KELYFOS_LONG_TOKEN") {
		t.Errorf("the warning leaked between parses:\n%s", short)
	}

	long := capture("KELYFOS_LONG_TOKEN@api.example.com")
	if strings.Contains(long, "never scrubbed") {
		t.Errorf("a credential above the floor was warned about:\n%s", long)
	}
}

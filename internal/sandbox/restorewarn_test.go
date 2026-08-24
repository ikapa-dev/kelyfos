package sandbox

import (
	"strings"
	"testing"
)

// The three states a restored machine can be in, and what each is told.
//
// The middle one is why this is a function rather than four lines inside
// Restore: staging a guest that predates guest confinement means building an
// image from before the feature existed, and a warning nobody can test is a
// warning that will be wrong the first time it matters.
func TestARestoreSaysWhatItBroughtBack(t *testing.T) {
	cases := []struct {
		name         string
		profile      string
		profileError string
		want         []string
		silent       bool
	}{
		{
			name:    "a current machine says nothing",
			profile: "landlock abi 6 · dev · write /work /tmp /run /root · 26 syscalls refused",
			silent:  true,
		},
		{
			name:    "a snapshot older than confinement names the fix that fixes it",
			profile: "",
			want:    []string{"predates guest confinement", "host walls are unchanged", "snapshot save"},
		},
		{
			name:         "a kernel that cannot confine says so, and it is not the same thing",
			profileError: "landlock is not available in this kernel (function not implemented)",
			want:         []string{"cannot confine what it runs", "refused", "CONFIG_LSM"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := restoreWarning(tc.profile, tc.profileError)
			if tc.silent {
				if got != "" {
					t.Fatalf("a confined machine warned about itself:\n%s", got)
				}
				return
			}
			if got == "" {
				t.Fatal("said nothing about a machine that is not confined")
			}
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("the warning does not mention %q:\n%s", want, got)
				}
			}
		})
	}
}

// An error and an absent profile are different conditions and must not collapse
// into one message: one is a machine that will refuse everything, the other is a
// machine that will run everything unconfined. Telling somebody the wrong one
// sends them to fix the wrong thing.
func TestTheTwoUnconfinedStatesAreNotTheSameMessage(t *testing.T) {
	old := restoreWarning("", "")
	broken := restoreWarning("", "landlock is not available in this kernel")
	if old == broken {
		t.Fatal("a pre-confinement snapshot and a kernel without Landlock got the same warning")
	}
	if strings.Contains(old, "are refused") {
		t.Error("the old-snapshot warning claims commands are refused; they are not")
	}
}

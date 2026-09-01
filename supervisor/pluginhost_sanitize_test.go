package main

import (
	"os"
	"strings"
	"testing"
)

// The audit of 2026-09-01's A18: a plugin's stderr reaches the operator's
// console, and it did so unsanitised — a plugin could write escape sequences,
// or a line that reads as the supervisor's own, onto the terminal a person is
// reading. The sanitiser runs at that boundary now.

func TestA18_PluginStderrIsSanitisedAtTheConsole(t *testing.T) {
	// The escape sequence is quoted whole — the diagnostic survives, the
	// escape does not — and a clean line is left exactly as it was.
	hostile := "\x1b]0;pwned\x07\x1b[31mtainted"
	got := sanitizeConsoleLine(hostile)
	if got == hostile {
		t.Errorf("an escape sequence reached the console verbatim: %q", got)
	}
	if !strings.Contains(got, "pwned") || !strings.Contains(got, "tainted") {
		t.Errorf("the quoted line lost the diagnostic: %q", got)
	}
	clean := "compiling foo.c"
	if got := sanitizeConsoleLine(clean); got != clean {
		t.Errorf("a clean line was rewritten: %q", got)
	}
}

// The sanitiser runs where the plugin's words meet the console, not somewhere
// upstream that a refactor could bypass. Reading the source is the check, the
// same shape TestEveryToolCallPassesTheAudit uses on the host side.
func TestA18_PrefixedLogSanitises(t *testing.T) {
	src, err := os.ReadFile("pluginhost.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "sanitizeConsoleLine(sc.Text())") {
		t.Error("prefixedLog no longer sanitises plugin stderr at the console boundary")
	}
}

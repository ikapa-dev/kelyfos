package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
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

	// A raw 0x9b byte is C1 CSI on an 8-bit terminal, and on its own it is
	// invalid UTF-8 — so a U+FFFD-decoding sanitiser would let the byte
	// through printable. SafeText quotes the whole line instead, so the raw
	// control byte never reaches the terminal (adversarial cross-check,
	// 2026-09-01).
	raw := "before\x9bafter"
	got = sanitizeConsoleLine(raw)
	if strings.ContainsRune(got, 0x9b) {
		t.Errorf("a raw C1 CSI byte reached the console verbatim: %q", got)
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Errorf("the quoted line lost the diagnostic: %q", got)
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

// The audit of 2026-09-01's L10: a plugin stderr line over the scanner's limit
// used to end the scanner (bufio.ErrTooLong is terminal) without draining the
// pipe, so the plugin's next stderr Write blocked forever and the plugin
// wedged. prefixedLog now notes the overlong line, skips its tail and keeps
// reading — so a later line still reaches the console and the plugin never
// blocks.
func TestL10_AnOverlongStderrLineDoesNotWedgeThePlugin(t *testing.T) {
	// logf writes straight to os.Stderr, so the console is captured by swapping
	// a pipe in. The swap is restored only once the needle has arrived:
	// restoring earlier would let a later logf from the reader goroutine land
	// on the real stderr, or race the goroutine mid-write.
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = wr

	sink := prefixedLog("plugin overlong")

	// One line well past maxPluginStderrLine, then a line that must still get
	// through. If the pipe wedges, the second Fprintln never returns and the
	// needle never reaches the console.
	overlong := strings.Repeat("A", 70<<10)
	go func() {
		fmt.Fprintln(sink, overlong)
		fmt.Fprintln(sink, "still here")
	}()

	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(rd)
		sc.Buffer(make([]byte, 0, 4<<10), 1<<20)
		var saw []string
		for sc.Scan() {
			saw = append(saw, sc.Text())
			if strings.Contains(sc.Text(), "still here") {
				break
			}
		}
		found <- strings.Join(saw, "\n")
	}()

	select {
	case got := <-found:
		os.Stderr = saved
		if c, ok := sink.(io.Closer); ok {
			_ = c.Close()
		}
		_ = wr.Close()
		if !strings.Contains(got, "still here") {
			t.Fatalf("the line after the overlong one never reached the console:\n%s", got)
		}
		if !strings.Contains(got, "longer than") {
			t.Errorf("the drop of the overlong line was not noted on the console:\n%s", got)
		}
	case <-time.After(10 * time.Second):
		os.Stderr = saved
		if c, ok := sink.(io.Closer); ok {
			_ = c.Close()
		}
		_ = wr.Close()
		t.Fatal("the plugin wedged: 'still here' never reached the console within 10s")
	}
}

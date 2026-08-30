package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/mcp"
)

// A client is entitled to prefer structuredContent over the text block, and one
// that does — Claude Code does — sees nothing at all from a tool whose whole
// payload lives only in the text. That is not a theoretical preference: it is
// how sandbox_read_file was found to return nothing usable in a live session at
// the E4 exit, after passing every test and every recipe here.
//
// So the rule is now a test: whatever a caller asked a tool for must be
// reachable from structuredContent alone. Reading the text block must never be
// necessary.

func mustJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatalf("structuredContent is not an object: %v", err)
	}
	return m
}

func TestEveryToolThatReturnsDataPutsItInStructuredContent(t *testing.T) {
	dir := t.TempDir()
	text := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(text, []byte("the payload\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(binary, []byte{0xff, 0xfe, 0x00, 0x01}, 0o644); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		res  *mcp.CallToolResult
		// want is the key that must carry what the caller asked for, and the
		// value it must have.
		key, value string
	}{
		{"read_file", toolReadFile(json.RawMessage(`{"path":"` + text + `"}`)),
			"content", "the payload\n"},
		{"read_file on bytes", toolReadFile(json.RawMessage(`{"path":"` + binary + `"}`)),
			"content", "//4AAQ=="},
		{"download", toolDownload(json.RawMessage(`{"path":"` + binary + `"}`)),
			"data", "//4AAQ=="},
	} {
		if tc.res.IsError {
			t.Errorf("%s: %s", tc.name, tc.res.Content[0].Text)
			continue
		}
		m := mustJSON(t, tc.res.StructuredContent)
		got, ok := m[tc.key].(string)
		if !ok {
			t.Errorf("%s: structuredContent has no %q; a client that reads only "+
				"structuredContent gets nothing. Keys: %v", tc.name, tc.key, keysOf(m))
			continue
		}
		if got != tc.value {
			t.Errorf("%s: %s = %q, want %q", tc.name, tc.key, got, tc.value)
		}
	}
}

// Bytes that are not text are base64 and say so, rather than being put in a
// JSON string where Go replaces every invalid sequence with U+FFFD and the
// caller receives a quietly corrupted file.
func TestReadFileSaysHowItEncodedWhatItReturned(t *testing.T) {
	dir := t.TempDir()
	text := filepath.Join(dir, "a.txt")
	binary := filepath.Join(dir, "b.bin")
	if err := os.WriteFile(text, []byte("plain"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte{0xff, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}

	m := mustJSON(t, toolReadFile(json.RawMessage(`{"path":"`+text+`"}`)).StructuredContent)
	if m["encoding"] != "utf-8" {
		t.Errorf("text was encoded as %v, want utf-8", m["encoding"])
	}
	res := toolReadFile(json.RawMessage(`{"path":"` + binary + `"}`))
	m = mustJSON(t, res.StructuredContent)
	if m["encoding"] != "base64" {
		t.Errorf("bytes were encoded as %v, want base64", m["encoding"])
	}
	// And the text block says what happened rather than carrying a mangled copy.
	if strings.Contains(res.Content[0].Text, "�") {
		t.Error("the text block carries a corrupted copy of the bytes")
	}
	if !strings.Contains(res.Content[0].Text, "base64") {
		t.Errorf("the text block does not say how to read the result: %s", res.Content[0].Text)
	}
}

// A write is checkable without reading it back, and by the same digest the
// flight recorder stores for it.
func TestAWriteReturnsItsDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.txt")
	m := mustJSON(t, toolWriteFile(json.RawMessage(
		`{"path":"`+path+`","content":"abc"}`)).StructuredContent)
	// sha256("abc")
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if m["sha256"] != want {
		t.Errorf("sha256 = %v, want %s", m["sha256"], want)
	}
	if m["bytes"] != float64(3) {
		t.Errorf("bytes = %v, want 3", m["bytes"])
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

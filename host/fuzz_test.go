package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Fuzz target for the outward MCP audit summariser (P6-3).
//
// The arguments of a tool call arrive from an MCP client — `serve-mcp` is a
// door in the wall, and what comes through it is not this project's code. They
// are then written into the flight recorder, which is the one artifact this
// product asks people to trust.
//
// So the property worth fuzzing here is not "does not panic". It is the
// redaction guarantee itself: an argument that carries content is recorded by
// its size and never by its value. A summariser that can be made to pass the
// content through has not crashed — it has quietly written the thing it exists
// to withhold into a file somebody may forward to a stranger.

func FuzzSummariseArgsNeverEchoesContent(f *testing.F) {
	f.Add("content", "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldA==")
	f.Add("stdin", "the quick brown fox jumps over the lazy dog")
	f.Add("data", "0123456789abcdef0123456789abcdef")
	f.Add("path", "/work/notes.txt")
	f.Add("content", strings.Repeat("A", 4096))
	f.Add("content", "{\"nested\": \"json inside a string\"}")

	f.Fuzz(func(t *testing.T, key, payload string) {
		// Sixteen characters is comfortably past anything the summariser prints
		// incidentally — a byte count, a truncation marker, a key name — so a
		// verbatim appearance is a leak rather than a coincidence.
		if len(payload) < 16 {
			t.Skip()
		}
		if !contentKeys[key] {
			t.Skip()
		}
		raw, err := json.Marshal(map[string]any{key: payload, "other": 1})
		if err != nil {
			t.Skip()
		}

		out := summariseArgs(raw)
		if strings.Contains(out, payload) {
			t.Fatalf("summariseArgs wrote a %d-byte %q argument into the record verbatim:\n%s",
				len(payload), key, out)
		}
	})
}

// FuzzSummariseArgs drives the same function with arbitrary bytes, for the
// ordinary question: a client can send anything, and a malformed argument
// object must produce a line rather than a panic.
func FuzzSummariseArgs(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"cmd":"ls","content":"abc"}`))
	f.Add([]byte(`{"a":[1,2,{"b":null}],"c":{"d":"e"}}`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(`{"content":12345}`))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, raw []byte) {
		out := summariseArgs(json.RawMessage(raw))
		// A record line is a line. A summariser that emits a newline would let
		// a caller forge an extra entry in anything that reads the transcript
		// by line.
		if strings.ContainsAny(out, "\n\r") {
			t.Fatalf("summariseArgs produced a multi-line summary from %q:\n%q", raw, out)
		}
	})
}

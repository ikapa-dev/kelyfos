package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/hostile"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// The hostile corpus for the MCP exec-output bridge (S1, door B).
//
// mcpobserve.go's fromGuest used to base64-encode a whole command's stdout or
// stderr into a single command.output event with no chunking at all.
// supervisor/tools.go builds stdout/stderr into unbounded strings and carries
// the same content twice in the tool result (Content and StructuredContent);
// guest output near the ~16 MiB MCP frame cap (proto.MaxMCPLine), expanded 4/3
// by base64, produced a single recorder line past every reader's
// recorder.MaxLine — durable, guest-triggered destruction of every event
// after it, because the chain is a chain.
func TestHostileGuestExecOutputCannotBreakTheChain(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "s1")
	if err != nil {
		t.Fatal(err)
	}
	obs := newObserver(rec, "")

	// Comfortably past MaxLine once base64-expanded, and past what a single,
	// unchunked command.output event used to survive as.
	want := strings.Repeat("A", 10<<20)

	obs.fromClient([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call",` +
		`"params":{"name":"exec","arguments":{"command":"cat huge.bin"}}}`))
	resp, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"content": []map[string]any{{"type": "text", "text": "ok"}},
			"structuredContent": map[string]any{
				"exit_code": 0,
				"stdout":    want,
				"stderr":    "",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	obs.fromGuest(resp)
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	blob, err := os.ReadFile(recorder.Path(root, "s1"))
	if err != nil {
		t.Fatal(err)
	}

	problem := ""
	for i, line := range bytes.Split(bytes.TrimRight(blob, "\n"), []byte("\n")) {
		if len(line) > recorder.MaxLine {
			problem = fmt.Sprintf("line %d is %d bytes, over recorder.MaxLine (%d)", i+1, len(line), recorder.MaxLine)
			break
		}
	}
	if problem == "" {
		if _, _, verr := recorder.Verify(bytes.NewReader(blob)); verr != nil {
			problem = fmt.Sprintf("the chain does not verify: %v", verr)
		}
	}
	if problem == "" {
		events, rerr := recorder.Read(bytes.NewReader(blob))
		if rerr != nil {
			t.Fatal(rerr)
		}
		var got strings.Builder
		chunks := 0
		for _, e := range events {
			if e.Type != recorder.TypeCommandOutput || e.Stream != "stdout" {
				continue
			}
			chunks++
			data, derr := base64.StdEncoding.DecodeString(e.Data)
			if derr != nil {
				problem = fmt.Sprintf("a command.output chunk did not decode as base64: %v", derr)
				break
			}
			got.Write(data)
		}
		if problem == "" && got.String() != want {
			problem = fmt.Sprintf("reassembled stdout is %d bytes across %d chunks, want %d bytes", got.Len(), chunks, len(want))
		}
		if problem == "" && chunks < 2 {
			problem = fmt.Sprintf("stdout arrived as %d command.output event(s) — chunking did not run", chunks)
		}
	}
	hostile.Holds(t, "mcp/oversized-exec-output", problem)
}

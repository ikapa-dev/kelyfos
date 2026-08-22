package sandbox_test

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMCPBridge drives `kelyfos mcp` the way an MCP client does: launch it as a
// subprocess and speak newline-delimited JSON-RPC over its standard streams.
//
// The sharpest thing it checks is stdout purity. The specification says the
// server "MUST NOT write anything to its stdout that is not a valid MCP
// message", and the bridge has exactly one chance to break that: Firecracker's
// "OK <port>" handshake acknowledgement, which arrives on the same connection
// just before the MCP traffic. Every line here is parsed as JSON, so a leaked
// acknowledgement fails the test rather than confusing a client months later.
func TestMCPBridge(t *testing.T) {
	sb := bootOne(t)

	bin, err := filepath.Abs(filepath.Join("..", "..", "bin", "kelyfos"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("no built CLI at %s — run `make cli` first", bin)
	}

	cmd := exec.Command(bin, "mcp", "--sandbox", sb.State.ID)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bridge: %v", err)
	}
	defer func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	lines := bufio.NewScanner(stdout)
	lines.Buffer(make([]byte, 0, 64<<10), 1<<20)

	send := func(v any) {
		t.Helper()
		blob, _ := json.Marshal(v)
		if _, err := stdin.Write(append(blob, '\n')); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	// readResponse returns the response with the given id, failing on any line
	// that is not valid JSON — which is the stdout-purity check.
	readResponse := func(id float64) map[string]any {
		t.Helper()
		for lines.Scan() {
			line := lines.Text()
			var msg map[string]any
			if err := json.Unmarshal([]byte(line), &msg); err != nil {
				t.Fatalf("bridge wrote a non-MCP line to stdout: %q", line)
			}
			if got, ok := msg["id"].(float64); ok && got == id {
				return msg
			}
		}
		t.Fatalf("bridge closed before answering id %v (stderr: %s)", id, stderr.String())
		return nil
	}

	send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": "2025-11-25",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "bridge-test", "version": "0"},
	}})
	init := readResponse(1)
	result, _ := init["result"].(map[string]any)
	if result == nil || result["serverInfo"] == nil {
		t.Fatalf("initialize returned %v", init)
	}

	send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	list, _ := readResponse(2)["result"].(map[string]any)
	tools, _ := list["tools"].([]any)
	if len(tools) != 6 {
		t.Errorf("got %d tools through the bridge, want 6", len(tools))
	}

	send(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{
		"name": "exec", "arguments": map[string]any{"command": "echo through-the-bridge"},
	}})
	call, _ := readResponse(3)["result"].(map[string]any)
	content, _ := call["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("exec returned no content: %v", call)
	}
	first, _ := content[0].(map[string]any)
	if text, _ := first["text"].(string); !strings.Contains(text, "through-the-bridge") {
		t.Errorf("exec through the bridge returned %q", text)
	}

	// Closing stdin means "no more requests"; the bridge must exit rather than
	// hang on a peer that will never speak again.
	_ = stdin.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("bridge exited with %v (stderr: %s)", err, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Error("bridge did not exit after stdin was closed")
	}
}

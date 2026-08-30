package sandbox_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/mcp"
	"github.com/ikapa-dev/kelyfos/internal/proto"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// mcpClient is a minimal MCP client speaking the same newline-delimited
// JSON-RPC the guest serves, over a vsock channel.
type mcpClient struct {
	w  *proto.Writer
	r  *proto.Reader
	id int
}

func dialMCP(t *testing.T, uds string) *mcpClient {
	t.Helper()
	conn, err := sandbox.Connect(uds, proto.PortMCP, 15*time.Second)
	if err != nil {
		t.Fatalf("connect to the MCP channel: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &mcpClient{w: proto.NewWriter(conn), r: proto.NewReader(conn)}
}

// call sends a request and returns the response, skipping any notifications
// that arrive first — progress notifications are interleaved with responses by
// design.
func (c *mcpClient) call(t *testing.T, method string, params any) *mcp.Response {
	t.Helper()
	c.id++
	id, _ := json.Marshal(c.id)
	req := map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method}
	if params != nil {
		req["params"] = params
	}
	if err := c.w.Write(req); err != nil {
		t.Fatalf("%s: write: %v", method, err)
	}
	for {
		var raw json.RawMessage
		if err := c.r.Read(&raw); err != nil {
			t.Fatalf("%s: read: %v", method, err)
		}
		var probe struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(raw, &probe)
		if probe.Method != "" && len(probe.ID) == 0 {
			continue // a notification
		}
		if string(probe.ID) != string(id) {
			continue
		}
		var resp mcp.Response
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("%s: decode: %v", method, err)
		}
		return &resp
	}
}

func (c *mcpClient) notify(t *testing.T, method string) {
	t.Helper()
	if err := c.w.Write(map[string]any{"jsonrpc": "2.0", "method": method}); err != nil {
		t.Fatalf("notify %s: %v", method, err)
	}
}

func (c *mcpClient) callTool(t *testing.T, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	resp := c.call(t, "tools/call", map[string]any{"name": name, "arguments": args})
	if resp.Error != nil {
		t.Fatalf("tools/call %s: protocol error %d: %s", name, resp.Error.Code, resp.Error.Message)
	}
	blob, _ := json.Marshal(resp.Result)
	var out mcp.CallToolResult
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("tools/call %s: decode result: %v", name, err)
	}
	return &out
}

func firstText(r *mcp.CallToolResult) string {
	for _, c := range r.Content {
		if c.Type == "text" {
			return c.Text
		}
	}
	return ""
}

// TestMCPSession walks a full MCP session against a real guest: initialize,
// tools/list, then every tool the plan promises.
func TestMCPSession(t *testing.T) {
	sb := bootOne(t)
	c := dialMCP(t, sb.State.UDSPath)

	// --- initialize ---
	resp := c.call(t, "initialize", map[string]any{
		"protocolVersion": mcp.ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "kelyfos-test", "version": "0"},
	})
	if resp.Error != nil {
		t.Fatalf("initialize: %v", resp.Error)
	}
	blob, _ := json.Marshal(resp.Result)
	var init mcp.InitializeResult
	if err := json.Unmarshal(blob, &init); err != nil {
		t.Fatalf("initialize result: %v", err)
	}
	if init.ProtocolVersion != mcp.ProtocolVersion {
		t.Errorf("protocolVersion = %q, want %q", init.ProtocolVersion, mcp.ProtocolVersion)
	}
	if init.ServerInfo.Name != "kelyfos" {
		t.Errorf("serverInfo.name = %q, want kelyfos", init.ServerInfo.Name)
	}
	if init.Capabilities.Tools == nil {
		t.Error("server did not advertise the tools capability")
	}
	c.notify(t, "notifications/initialized")

	// --- ping ---
	if r := c.call(t, "ping", nil); r.Error != nil {
		t.Errorf("ping: %v", r.Error)
	}

	// --- tools/list: the six tools the plan promises ---
	resp = c.call(t, "tools/list", nil)
	if resp.Error != nil {
		t.Fatalf("tools/list: %v", resp.Error)
	}
	blob, _ = json.Marshal(resp.Result)
	var list mcp.ToolsListResult
	_ = json.Unmarshal(blob, &list)
	got := map[string]bool{}
	for _, tool := range list.Tools {
		got[tool.Name] = true
		if tool.Description == "" || tool.InputSchema.Type != "object" {
			t.Errorf("tool %q has an unusable definition: %+v", tool.Name, tool)
		}
	}
	for _, want := range []string{"exec", "read_file", "write_file", "list_dir", "upload", "download"} {
		if !got[want] {
			t.Errorf("tools/list is missing %q", want)
		}
	}
	if len(list.Tools) != 6 {
		t.Errorf("got %d tools, want 6", len(list.Tools))
	}

	// --- exec ---
	r := c.callTool(t, "exec", map[string]any{"command": "echo hello-from-mcp"})
	if r.IsError {
		t.Errorf("exec reported an error: %s", firstText(r))
	}
	if !strings.Contains(firstText(r), "hello-from-mcp") {
		t.Errorf("exec output = %q", firstText(r))
	}

	// A non-zero exit is a tool error, not a protocol error, and must carry the
	// exit status through structuredContent.
	r = c.callTool(t, "exec", map[string]any{"command": "exit 7"})
	if !r.IsError {
		t.Error("a command exiting 7 should be reported as a tool error")
	}
	if sc, ok := r.StructuredContent.(map[string]any); !ok {
		t.Error("exec did not return structuredContent")
	} else if code, _ := sc["exit_code"].(float64); code != 7 {
		t.Errorf("structuredContent.exit_code = %v, want 7", sc["exit_code"])
	}

	// --- write_file / read_file ---
	const path, body = "/tmp/mcp-test.txt", "written through MCP\n"
	if r := c.callTool(t, "write_file", map[string]any{"path": path, "content": body}); r.IsError {
		t.Fatalf("write_file: %s", firstText(r))
	}
	if r := c.callTool(t, "read_file", map[string]any{"path": path}); r.IsError {
		t.Fatalf("read_file: %s", firstText(r))
	} else if firstText(r) != body {
		t.Errorf("read_file returned %q, want %q", firstText(r), body)
	}

	// --- list_dir ---
	if r := c.callTool(t, "list_dir", map[string]any{"path": "/tmp"}); r.IsError {
		t.Fatalf("list_dir: %s", firstText(r))
	} else if !strings.Contains(firstText(r), "mcp-test.txt") {
		t.Errorf("list_dir did not show the file it should: %q", firstText(r))
	}

	// --- upload / download round trip, with bytes that are not valid UTF-8 ---
	binary := []byte{0x00, 0x01, 0xff, 0xfe, 'k', 'e', 'l', 'y', 0x80}
	if r := c.callTool(t, "upload", map[string]any{
		"path": "/tmp/mcp-test.bin",
		"data": base64.StdEncoding.EncodeToString(binary),
	}); r.IsError {
		t.Fatalf("upload: %s", firstText(r))
	}
	r = c.callTool(t, "download", map[string]any{"path": "/tmp/mcp-test.bin"})
	if r.IsError {
		t.Fatalf("download: %s", firstText(r))
	}
	back, err := base64.StdEncoding.DecodeString(firstText(r))
	if err != nil {
		t.Fatalf("download did not return base64: %v", err)
	}
	if string(back) != string(binary) {
		t.Errorf("binary round trip corrupted the data: got %x, want %x", back, binary)
	}

	// --- errors are tool errors, not protocol errors ---
	if r := c.callTool(t, "read_file", map[string]any{"path": "/nope/missing"}); !r.IsError {
		t.Error("reading a missing file should be a tool error")
	}
	if r := c.callTool(t, "no_such_tool", map[string]any{}); !r.IsError {
		t.Error("an unknown tool should be a tool error")
	}
	if r := c.call(t, "no/such/method", nil); r.Error == nil || r.Error.Code != mcp.CodeMethodNotFound {
		t.Errorf("an unknown method should be a JSON-RPC method-not-found, got %+v", r.Error)
	}
}

// TestMCPExecStreams checks that exec really streams rather than only returning
// output at the end. MCP's own mechanism is used: when the caller supplies a
// progress token, each chunk of output becomes a notifications/progress, so
// nothing KelyfOS-specific had to be invented.
func TestMCPExecStreams(t *testing.T) {
	sb := bootOne(t)
	c := dialMCP(t, sb.State.UDSPath)

	if r := c.call(t, "initialize", map[string]any{
		"protocolVersion": mcp.ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "kelyfos-test", "version": "0"},
	}); r.Error != nil {
		t.Fatalf("initialize: %v", r.Error)
	}
	c.notify(t, "notifications/initialized")

	c.id++
	reqID := c.id
	if err := c.w.Write(map[string]any{
		"jsonrpc": "2.0", "id": reqID, "method": "tools/call",
		"params": map[string]any{
			"name": "exec",
			"arguments": map[string]any{
				// Three chunks, spaced out, so anything that only returns at
				// the end cannot pass by accident.
				"command": "echo one; sleep 0.3; echo two; sleep 0.3; echo three",
			},
			"_meta": map[string]any{"progressToken": "tok-1"},
		},
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	var progress []string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var raw json.RawMessage
		if err := c.r.Read(&raw); err != nil {
			t.Fatalf("read: %v", err)
		}
		var probe struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				ProgressToken json.RawMessage `json:"progressToken"`
				Message       string          `json:"message"`
			} `json:"params"`
		}
		_ = json.Unmarshal(raw, &probe)
		if probe.Method == "notifications/progress" {
			if string(probe.Params.ProgressToken) != `"tok-1"` {
				t.Errorf("progress carried token %s, want \"tok-1\"", probe.Params.ProgressToken)
			}
			progress = append(progress, probe.Params.Message)
			continue
		}
		if len(probe.ID) > 0 {
			break // the final response
		}
	}

	if len(progress) < 2 {
		t.Fatalf("got %d progress notifications, want at least 2 — output was not streamed: %q", len(progress), progress)
	}
	joined := strings.Join(progress, "")
	for _, want := range []string{"one", "two", "three"} {
		if !strings.Contains(joined, want) {
			t.Errorf("streamed output is missing %q: %q", want, joined)
		}
	}
}

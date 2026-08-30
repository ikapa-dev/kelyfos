package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/mcp"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// sandbox_read_file and sandbox_write_file (E4-2).
//
// Both are the guest's own file tools with a sandbox id in front, called over
// the guest's MCP channel rather than reimplemented out here (host/guestmcp.go
// says why). What this layer adds is the two things the guest cannot do: pick
// the right machine, and write the audit record — because the recorder lives on
// the host, and a write that arrived through this door is a write like any
// other (F-D33).

// guestFileTimeout bounds one file call. Generous next to a local read and
// short next to a wedged guest.
const guestFileTimeout = 60 * time.Second

func (s *hostServer) toolReadFile(raw json.RawMessage) *mcp.CallToolResult {
	var a struct {
		Sandbox string `json:"sandbox"`
		Path    string `json:"path"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return mcp.Errorf("sandbox_read_file: %v", err)
	}
	b, err := s.box(a.Sandbox)
	if err != nil {
		return mcp.Errorf("%v", err)
	}
	if a.Path == "" {
		return mcp.Errorf("sandbox_read_file needs a `path`")
	}
	res, err := callGuestTool(b.sb.State.UDSPath, "read_file",
		map[string]any{"path": a.Path}, guestFileTimeout)
	if err != nil {
		return mcp.Errorf("sandbox_read_file: %v", err)
	}
	return res
}

func (s *hostServer) toolWriteFile(raw json.RawMessage) *mcp.CallToolResult {
	var a struct {
		Sandbox string `json:"sandbox"`
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return mcp.Errorf("sandbox_write_file: %v", err)
	}
	b, err := s.box(a.Sandbox)
	if err != nil {
		return mcp.Errorf("%v", err)
	}
	if a.Path == "" {
		return mcp.Errorf("sandbox_write_file needs a `path`")
	}
	res, err := callGuestTool(b.sb.State.UDSPath, "write_file",
		map[string]any{"path": a.Path, "content": a.Content}, guestFileTimeout)
	if err != nil {
		return mcp.Errorf("sandbox_write_file: %v", err)
	}
	if res.IsError {
		// A refused write is not a write, and recording one would put a line in
		// the log for a file that does not exist.
		return res
	}
	// Recorded by path, size and digest, never by content (docs/events.md §4).
	sum := sha256.Sum256([]byte(a.Content))
	_ = b.rec.Append(recorder.Event{
		Type: recorder.TypeFileWrite, Path: a.Path, Bytes: len(a.Content),
		SHA256: hex.EncodeToString(sum[:]), Via: "serve-mcp",
	})
	return res
}

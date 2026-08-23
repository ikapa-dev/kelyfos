package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/p4r4n0rm4l/KelyfOS/internal/mcp"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
)

// maxToolBytes bounds what a single file tool will move in one call. It is not
// a security boundary — the sandbox is the security boundary — but a tool that
// will happily read a 10 GB file into a JSON string is a way to kill the guest
// by accident, and an agent that hits this limit gets a clear message instead
// of a dead sandbox.
const maxToolBytes = 8 << 20 // 8 MiB

func toolDefinitions() []mcp.Tool {
	str := func(desc string) mcp.Property { return mcp.Property{Type: "string", Description: desc} }
	return []mcp.Tool{
		{
			Name:  "exec",
			Title: "Run a command",
			Description: "Run a command inside the sandbox and return its output and exit code. " +
				"Give `command` for a shell command line (run with /bin/sh -c), or `argv` to run a " +
				"program directly with no shell involved. Output is streamed as progress " +
				"notifications when the caller supplies a progress token.",
			InputSchema: mcp.Schema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"command":    str("Shell command line, run as /bin/sh -c \"<command>\"."),
					"argv":       {Type: "array", Description: "Argument vector, executed directly without a shell.", Items: &mcp.Property{Type: "string"}},
					"cwd":        str("Working directory. Defaults to /."),
					"stdin":      str("Text written to the command's standard input."),
					"timeout_ms": {Type: "integer", Description: "Kill the command after this many milliseconds. 0 means no limit."},
				},
			},
		},
		{
			Name:  "read_file",
			Title: "Read a text file",
			Description: "Read a file from the sandbox filesystem. The contents come back both as " +
				"text and in structuredContent as `content`, with `encoding` saying whether that " +
				"is utf-8 or base64 — a file that is not valid UTF-8 is base64 rather than " +
				"silently mangled. `download` is the tool built for binary files.",
			InputSchema: mcp.Schema{
				Type:       "object",
				Properties: map[string]mcp.Property{"path": str("Absolute path inside the sandbox.")},
				Required:   []string{"path"},
			},
		},
		{
			Name:        "write_file",
			Title:       "Write a text file",
			Description: "Write UTF-8 text to a file in the sandbox, creating parent directories as needed. Replaces any existing contents.",
			InputSchema: mcp.Schema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"path":    str("Absolute path inside the sandbox."),
					"content": str("Text to write."),
				},
				Required: []string{"path", "content"},
			},
		},
		{
			Name:        "list_dir",
			Title:       "List a directory",
			Description: "List the entries of a directory in the sandbox, with type and size.",
			InputSchema: mcp.Schema{
				Type:       "object",
				Properties: map[string]mcp.Property{"path": str("Absolute path inside the sandbox.")},
				Required:   []string{"path"},
			},
		},
		{
			Name:        "upload",
			Title:       "Upload a file into the sandbox",
			Description: "Write base64-encoded bytes to a path in the sandbox. The binary counterpart of write_file.",
			InputSchema: mcp.Schema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"path": str("Absolute path inside the sandbox."),
					"data": str("Base64-encoded file contents."),
					"mode": {Type: "integer", Description: "File mode, e.g. 493 for 0755. Defaults to 420 (0644)."},
				},
				Required: []string{"path", "data"},
			},
		},
		{
			Name:        "download",
			Title:       "Download a file from the sandbox",
			Description: "Read a file from the sandbox and return it base64-encoded. The binary counterpart of read_file.",
			InputSchema: mcp.Schema{
				Type:       "object",
				Properties: map[string]mcp.Property{"path": str("Absolute path inside the sandbox.")},
				Required:   []string{"path"},
			},
		},
	}
}

// --- exec ---

type execArgs struct {
	Command   string   `json:"command"`
	Argv      []string `json:"argv"`
	Cwd       string   `json:"cwd"`
	Stdin     string   `json:"stdin"`
	TimeoutMS int64    `json:"timeout_ms"`
}

func (s *mcpSession) toolExec(raw json.RawMessage, meta *mcp.CallMeta) *mcp.CallToolResult {
	var a execArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return mcp.Errorf("invalid arguments: %v", err)
	}
	argv := a.Argv
	if len(argv) == 0 {
		if strings.TrimSpace(a.Command) == "" {
			return mcp.Errorf("give either `command` or `argv`")
		}
		// The shell is chosen here, in the open, so the audit log shows that one
		// was involved — it changes what the command can do.
		argv = []string{"/bin/sh", "-c", a.Command}
	}

	var out, errOut strings.Builder
	var bufMu sync.Mutex
	var progress float64

	// Streaming, done the way MCP already provides for: if the caller supplied
	// a progress token, each chunk of output becomes a progress notification.
	// No KelyfOS-specific streaming mechanism is invented.
	emit := func(stream string, b []byte) {
		bufMu.Lock()
		if stream == proto.StreamStdout {
			out.Write(b)
		} else {
			errOut.Write(b)
		}
		progress += float64(len(b))
		p := progress
		bufMu.Unlock()
		if meta == nil || len(meta.ProgressToken) == 0 {
			return
		}
		_ = s.send(mcp.Notification{
			JSONRPC: "2.0",
			Method:  "notifications/progress",
			Params: mcp.ProgressParams{
				ProgressToken: meta.ProgressToken,
				Progress:      p,
				Message:       stream + ": " + string(b),
			},
		})
	}

	res := runCommand(proto.ExecRequest{
		V: proto.Version, ID: "mcp", Cmd: argv, Cwd: a.Cwd,
		Stdin: base64.StdEncoding.EncodeToString([]byte(a.Stdin)), TimeoutMS: a.TimeoutMS,
	}, s.rp,
		func(b []byte) { emit(proto.StreamStdout, b) },
		func(b []byte) { emit(proto.StreamStderr, b) },
	)

	if res.Err != nil {
		return mcp.Errorf("%s: %s", res.Err.Kind, res.Err.Message)
	}

	var text strings.Builder
	if out.Len() > 0 {
		text.WriteString(out.String())
	}
	if errOut.Len() > 0 {
		if text.Len() > 0 && !strings.HasSuffix(text.String(), "\n") {
			text.WriteString("\n")
		}
		text.WriteString("[stderr]\n")
		text.WriteString(errOut.String())
	}
	if res.Code != 0 {
		fmt.Fprintf(&text, "\n[exit status %d]", res.Code)
	}
	if text.Len() == 0 {
		text.WriteString("[no output, exit status 0]")
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.Text(text.String())},
		// A non-zero exit is reported as a tool error, not a protocol error:
		// the spec reserves isError for "actionable feedback that language
		// models can use to self-correct", and a failing command is exactly
		// that.
		IsError: res.Code != 0,
		StructuredContent: map[string]any{
			"exit_code": res.Code,
			"stdout":    out.String(),
			"stderr":    errOut.String(),
			"signal":    res.Signal,
		},
	}
}

// --- files ---

type pathArg struct {
	Path string `json:"path"`
}

func toolReadFile(raw json.RawMessage) *mcp.CallToolResult {
	var a pathArg
	if err := json.Unmarshal(raw, &a); err != nil || a.Path == "" {
		return mcp.Errorf("`path` is required")
	}
	b, res := readCapped(a.Path)
	if res != nil {
		return res
	}
	// The contents go in structuredContent as well as in the text block.
	//
	// Not redundancy: a client is entitled to prefer one or the other, and
	// Claude Code prefers structuredContent — so a tool whose entire payload
	// lived only in the text block returned, to that client, nothing at all.
	// The rule this establishes for every tool here: whatever a caller asked
	// for must be reachable from structuredContent alone (E4-8).
	out := map[string]any{"path": a.Path, "bytes": len(b)}
	if utf8.Valid(b) {
		out["content"], out["encoding"] = string(b), "utf-8"
		return &mcp.CallToolResult{
			Content: []mcp.Content{mcp.Text(string(b))}, StructuredContent: out,
		}
	}
	// Bytes that are not text would be mangled by being put in a JSON string —
	// Go replaces every invalid sequence with U+FFFD — so they are base64 here
	// and the encoding says so. The text block says what happened rather than
	// carrying a corrupted copy of it.
	out["content"], out["encoding"] = base64.StdEncoding.EncodeToString(b), "base64"
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.Text(fmt.Sprintf(
			"%s is %d bytes and is not valid UTF-8, so `content` is base64 "+
				"(`encoding` says which). `download` is the tool for binary files.",
			a.Path, len(b)))},
		StructuredContent: out,
	}
}

func toolWriteFile(raw json.RawMessage) *mcp.CallToolResult {
	var a struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || a.Path == "" {
		return mcp.Errorf("`path` and `content` are required")
	}
	if res := writeFile(a.Path, []byte(a.Content), 0o644); res != nil {
		return res
	}
	// The digest is here so a caller can check what landed without reading it
	// back, and it is the same digest the flight recorder stores for the write.
	sum := sha256.Sum256([]byte(a.Content))
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.Text(fmt.Sprintf("wrote %d bytes to %s", len(a.Content), a.Path))},
		StructuredContent: map[string]any{
			"path": a.Path, "bytes": len(a.Content), "sha256": hex.EncodeToString(sum[:]),
		},
	}
}

func toolListDir(raw json.RawMessage) *mcp.CallToolResult {
	var a pathArg
	if err := json.Unmarshal(raw, &a); err != nil || a.Path == "" {
		return mcp.Errorf("`path` is required")
	}
	entries, err := os.ReadDir(a.Path)
	if err != nil {
		return mcp.Errorf("%v", err)
	}
	type row struct {
		Name string `json:"name"`
		Type string `json:"type"`
		Size int64  `json:"size"`
	}
	rows := make([]row, 0, len(entries))
	for _, e := range entries {
		r := row{Name: e.Name(), Type: "file"}
		switch {
		case e.IsDir():
			r.Type = "dir"
		case e.Type()&os.ModeSymlink != 0:
			r.Type = "symlink"
		}
		if info, err := e.Info(); err == nil && r.Type == "file" {
			r.Size = info.Size()
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })

	var text strings.Builder
	for _, r := range rows {
		if r.Type == "file" {
			fmt.Fprintf(&text, "%-8s %9d  %s\n", r.Type, r.Size, r.Name)
		} else {
			fmt.Fprintf(&text, "%-8s %9s  %s\n", r.Type, "-", r.Name)
		}
	}
	if len(rows) == 0 {
		text.WriteString("(empty)\n")
	}
	return &mcp.CallToolResult{
		Content:           []mcp.Content{mcp.Text(text.String())},
		StructuredContent: map[string]any{"path": a.Path, "entries": rows},
	}
}

func toolUpload(raw json.RawMessage) *mcp.CallToolResult {
	var a struct {
		Path string `json:"path"`
		Data string `json:"data"`
		Mode uint32 `json:"mode"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || a.Path == "" {
		return mcp.Errorf("`path` and `data` are required")
	}
	b, err := base64.StdEncoding.DecodeString(a.Data)
	if err != nil {
		return mcp.Errorf("`data` is not valid base64: %v", err)
	}
	if len(b) > maxToolBytes {
		return mcp.Errorf("upload is %d bytes, over the %d byte per-call limit", len(b), maxToolBytes)
	}
	mode := os.FileMode(0o644)
	if a.Mode != 0 {
		mode = os.FileMode(a.Mode)
	}
	if res := writeFile(a.Path, b, mode); res != nil {
		return res
	}
	sum := sha256.Sum256(b)
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.Text(fmt.Sprintf("uploaded %d bytes to %s", len(b), a.Path))},
		StructuredContent: map[string]any{
			"path": a.Path, "bytes": len(b), "mode": uint32(mode.Perm()),
			"sha256": hex.EncodeToString(sum[:]),
		},
	}
}

func toolDownload(raw json.RawMessage) *mcp.CallToolResult {
	var a pathArg
	if err := json.Unmarshal(raw, &a); err != nil || a.Path == "" {
		return mcp.Errorf("`path` is required")
	}
	b, res := readCapped(a.Path)
	if res != nil {
		return res
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{{
			Type:     "text",
			Text:     base64.StdEncoding.EncodeToString(b),
			MIMEType: "application/octet-stream",
		}},
		StructuredContent: map[string]any{
			"path": a.Path, "bytes": len(b),
			"data": base64.StdEncoding.EncodeToString(b),
		},
	}
}

func readCapped(path string) ([]byte, *mcp.CallToolResult) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, mcp.Errorf("%v", err)
	}
	if info.IsDir() {
		return nil, mcp.Errorf("%s is a directory — use list_dir", path)
	}
	if info.Size() > maxToolBytes {
		return nil, mcp.Errorf("%s is %d bytes, over the %d byte per-call limit", path, info.Size(), maxToolBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, mcp.Errorf("%v", err)
	}
	return b, nil
}

func writeFile(path string, data []byte, mode os.FileMode) *mcp.CallToolResult {
	if len(data) > maxToolBytes {
		return mcp.Errorf("content is %d bytes, over the %d byte per-call limit", len(data), maxToolBytes)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return mcp.Errorf("%v", err)
		}
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return mcp.Errorf("%v", err)
	}
	return nil
}

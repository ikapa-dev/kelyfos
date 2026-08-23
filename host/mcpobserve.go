package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/p4r4n0rm4l/KelyfOS/internal/mcp"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// observer watches the MCP traffic crossing the bridge and turns it into flight
// recorder events.
//
// It never modifies, delays or reorders anything. The bridge copies bytes
// through unchanged and hands a *copy* of each direction to this, which is what
// keeps `kelyfos mcp` a pass-through while still producing an audit trail
// (docs/protocol.md §6.1).
type observer struct {
	rec *recorder.Recorder
	// agent names the team member these calls were made against, so a team's
	// one chain says which machine did the work (E2-7). Empty outside a team.
	agent string

	mu    sync.Mutex
	calls map[string]*pendingCall // by JSON-RPC id
}

type pendingCall struct {
	tool string
	call string
	args map[string]any
}

func newObserver(rec *recorder.Recorder, agent string) *observer {
	return &observer{rec: rec, agent: agent, calls: map[string]*pendingCall{}}
}

// outstanding lists the tool calls the client asked for and never got an answer
// to, newest last. It exists so the bridge can answer them itself rather than
// leaving a caller waiting on a channel that has already gone (F-D33).
func (o *observer) outstanding() []pendingID {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]pendingID, 0, len(o.calls))
	for id, c := range o.calls {
		out = append(out, pendingID{ID: id, Tool: c.tool})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// pendingID is one unanswered call: the JSON-RPC id to answer against, and the
// tool it was for, so the error can say which.
type pendingID struct {
	ID   string
	Tool string
}

// tee returns a reader that yields exactly what it was given, while feeding a
// copy to sink. Nothing downstream can tell it is there.
func tee(r io.Reader, sink func([]byte)) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		sc := bufio.NewScanner(io.TeeReader(r, pw))
		sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
		for sc.Scan() {
			line := append([]byte(nil), sc.Bytes()...)
			sink(line)
		}
		pw.CloseWithError(sc.Err())
	}()
	return pr
}

// fromClient records tool calls as they are requested.
func (o *observer) fromClient(line []byte) {
	var req mcp.Request
	if err := json.Unmarshal(line, &req); err != nil || req.Method != "tools/call" {
		return
	}
	var p mcp.CallToolParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return
	}
	var args map[string]any
	_ = json.Unmarshal(p.Arguments, &args)

	id := string(req.ID)
	call := "m" + strings.Trim(id, `"`)

	o.mu.Lock()
	o.calls[id] = &pendingCall{tool: p.Name, call: call, args: args}
	o.mu.Unlock()

	switch p.Name {
	case "exec":
		_ = o.rec.Append(recorder.Event{
			Type: recorder.TypeCommandStart, Call: call,
			Cmd: execArgv(args), Cwd: str(args["cwd"]), Via: "mcp", Agent: o.agent,
		})
	case "write_file":
		content := str(args["content"])
		sum := sha256.Sum256([]byte(content))
		_ = o.rec.Append(recorder.Event{
			Type: recorder.TypeFileWrite, Path: str(args["path"]),
			Bytes: len(content), SHA256: hex.EncodeToString(sum[:]), Via: "write_file", Agent: o.agent,
		})
	case "upload":
		raw, _ := base64.StdEncoding.DecodeString(str(args["data"]))
		sum := sha256.Sum256(raw)
		_ = o.rec.Append(recorder.Event{
			Type: recorder.TypeFileWrite, Path: str(args["path"]),
			Bytes: len(raw), SHA256: hex.EncodeToString(sum[:]), Via: "upload", Agent: o.agent,
		})
	}
}

// fromGuest records results as they come back.
func (o *observer) fromGuest(line []byte) {
	var resp struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(line, &resp); err != nil || len(resp.ID) == 0 || len(resp.Result) == 0 {
		return
	}
	o.mu.Lock()
	pc, ok := o.calls[string(resp.ID)]
	if ok {
		delete(o.calls, string(resp.ID))
	}
	o.mu.Unlock()
	if !ok || pc.tool != "exec" {
		return
	}

	var out mcp.CallToolResult
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		return
	}
	code := 0
	if sc, ok := out.StructuredContent.(map[string]any); ok {
		if f, ok := sc["exit_code"].(float64); ok {
			code = int(f)
		}
		for _, k := range []string{"stdout", "stderr"} {
			if text := str(sc[k]); text != "" {
				_ = o.rec.Append(recorder.Event{
					Type: recorder.TypeCommandOutput, Call: pc.call, Stream: k,
					Data: base64.StdEncoding.EncodeToString([]byte(text)), Bytes: len(text),
					Agent: o.agent,
				})
			}
		}
	} else if out.IsError {
		code = -1
	}
	_ = o.rec.Append(recorder.Event{Type: recorder.TypeCommandExit, Call: pc.call, Code: &code,
		Agent: o.agent})
}

// execArgv reconstructs the argv the guest will actually run, so the record
// shows the shell wrapper when there is one.
func execArgv(args map[string]any) []string {
	if raw, ok := args["argv"].([]any); ok && len(raw) > 0 {
		argv := make([]string, 0, len(raw))
		for _, v := range raw {
			argv = append(argv, str(v))
		}
		return argv
	}
	if cmd := str(args["command"]); cmd != "" {
		return []string{"/bin/sh", "-c", cmd}
	}
	return nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

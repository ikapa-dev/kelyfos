package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/ikapa-dev/kelyfos/internal/mcp"
	"github.com/ikapa-dev/kelyfos/internal/proto"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
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
	// write is the file.write this call will produce *if the guest accepts it*,
	// and nil for a tool that writes nothing. It is built from the request,
	// because that is where the content is, and held until the answer comes
	// back, because that is when we learn whether the write happened at all.
	//
	// The guest refuses writes: a path outside the profile's writable trees
	// (supervisor's writableFor) and a body over the per-call limit both come
	// back as errors. A refused write is not a write, and a record of one is a
	// claim about a file that does not exist — the worst thing this chain can
	// say. The other two doors already record after the fact for exactly this
	// reason (host/servemcpfiles.go, shim/shim.go).
	write *recorder.Event
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
// copy to sink. Nothing downstream can tell it is there — with one line this
// scanner cannot buffer as a token, which used to be the one case where
// downstream could tell, and worse: everything after it too.
//
// A line over proto.MaxMCPLine makes sc.Scan below give up (bufio.ErrTooLong),
// and the loop that only ran while Scan kept returning true stopped right
// there — closing pw with that error, which ends this reader for good and, one
// level up, io.Copy(conn, tee(...)): the whole client->guest or guest->client
// relay this tee sits in. Nothing sent after that oversized line, on the same
// connection, from either side, was ever getting through, no matter how the
// far end handled it — the observer meant to be a tee, watching a copy of the
// traffic, had become a filter that could stop the traffic itself. Sending an
// oversized frame at the MCP door used to end the bridge silently before the
// guest's own answer to it — the fix in supervisor/mcp.go — was ever reached.
func tee(r io.Reader, sink func([]byte)) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		for {
			sc := bufio.NewScanner(io.TeeReader(r, pw))
			sc.Buffer(make([]byte, 0, 64<<10), proto.MaxMCPLine)
			for sc.Scan() {
				line := append([]byte(nil), sc.Bytes()...)
				sink(line)
			}
			err := sc.Err()
			if err == nil {
				pw.CloseWithError(nil) // true EOF: nothing left to relay
				return
			}
			if !errors.Is(err, bufio.ErrTooLong) {
				pw.CloseWithError(err) // r itself failed; no line to resync to
				return
			}
			// The scanner has already mirrored the first proto.MaxMCPLine
			// bytes of the oversized line into pw via the TeeReader above —
			// that part already reached the connection. What has not is the
			// rest of that same line, up to its real newline: relay it raw,
			// with nothing asked to parse it as a token, then loop and build
			// a fresh scanner (bufio.Scanner does not resume after an error;
			// see internal/proto's resetScanner for the same fact on the
			// guest side of this channel) so observation of whatever comes
			// after resumes rather than staying degraded for the rest of the
			// session over one oversized message.
			//
			// relayRestOfLine reads in chunks, not byte by byte, so a single
			// Read can return bytes from *past* that newline too — the start
			// of whatever comes next, already off the wire and out of r for
			// good. Those come back as leftover rather than being dropped,
			// and go in front of r for the next round: a scanner reading r
			// after that sees exactly the stream it would have seen were the
			// chunking not there, just reassembled from two pieces instead of
			// one.
			leftover, relayErr := relayRestOfLine(pw, r)
			if relayErr != nil {
				pw.CloseWithError(relayErr)
				return
			}
			if len(leftover) > 0 {
				r = io.MultiReader(bytes.NewReader(leftover), r)
			}
		}
	}()
	return pr
}

// maxTeeOverlongRelay bounds how far relayRestOfLine reads past the frame
// limit looking for the newline that ends an oversized line, so a peer that
// never sends one cannot hold this goroutine — and the pipe it feeds — open
// forever. A small multiple of proto.MaxMCPLine, the same margin
// proto.Reader.DrainOverlongLine gives the guest side of this same problem.
const maxTeeOverlongRelay = 4 * proto.MaxMCPLine

// relayRestOfLine copies r to w, unparsed, until it writes a newline or r
// ends, then reports whatever it read past that newline in the same chunk —
// bytes belonging to the frame after it, already consumed from r and not yet
// written to w. It exists only for the oversized-line recovery in tee above:
// the bytes up to the newline are relayed exactly as read, because by the
// time this runs they have already failed to fit in a token this
// connection's own reader would accept either (proto.MaxMCPLine on both ends
// of the MCP channel, docs/protocol.md §3) — there is nothing left to gain by
// holding them for a parse that was always going to fail, and holding them is
// what silently dropped them before.
func relayRestOfLine(w io.Writer, r io.Reader) (leftover []byte, err error) {
	buf := make([]byte, 32<<10)
	var total int
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if i := bytes.IndexByte(chunk, '\n'); i >= 0 {
				if _, werr := w.Write(chunk[:i+1]); werr != nil {
					return nil, werr
				}
				if i+1 < n {
					return append([]byte(nil), chunk[i+1:]...), nil
				}
				return nil, nil
			}
			if _, werr := w.Write(chunk); werr != nil {
				return nil, werr
			}
			total += n
			if total > maxTeeOverlongRelay {
				return nil, proto.ErrLineTooLong
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil, nil
			}
			return nil, rerr
		}
	}
}

// fromClient records tool calls as they are requested: a command starts here,
// and a write is only prepared here, to be recorded when the guest answers.
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
	o.calls[id] = &pendingCall{tool: p.Name, call: call, args: args, write: o.writeEvent(p.Name, args)}
	o.mu.Unlock()

	// A command is recorded the moment it is asked for, because a command that
	// was started is a fact whatever it does next, and command.exit says how it
	// ended. A write has no second event to correct it, so it waits for the
	// answer (see pendingCall.write).
	if p.Name == "exec" {
		_ = o.rec.Append(recorder.Event{
			Type: recorder.TypeCommandStart, Call: call,
			Cmd: execArgv(args), Cwd: str(args["cwd"]), Via: "mcp", Agent: o.agent,
		})
	}
}

// writeEvent builds the file.write a write_file or upload call would produce,
// or nil for any other tool. Recorded by path, size and digest, never by
// content (docs/events.md §4).
func (o *observer) writeEvent(tool string, args map[string]any) *recorder.Event {
	var data []byte
	switch tool {
	case "write_file":
		data = []byte(str(args["content"]))
	case "upload":
		// A body that is not valid base64 is refused by the guest, so this
		// event is never appended; what it must not do is invent a size for
		// bytes nobody could decode.
		data, _ = base64.StdEncoding.DecodeString(str(args["data"]))
	default:
		return nil
	}
	sum := sha256.Sum256(data)
	// The tool's name is the door's name: `write_file` and `upload` are the two
	// `via` values docs/events.md lists for a guest MCP tool.
	return &recorder.Event{
		Type: recorder.TypeFileWrite, Path: str(args["path"]), Bytes: len(data),
		SHA256: hex.EncodeToString(sum[:]), Via: tool, Agent: o.agent,
	}
}

// fromGuest records results as they come back: how a command ended, and the
// writes the guest actually accepted.
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
	if !ok {
		return
	}

	var out mcp.CallToolResult
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		// An answer nobody can read is not an answer that the write landed. A
		// call the guest never answered at all keeps its pending write for the
		// same reason: it is dropped, not appended.
		return
	}
	if pc.write != nil {
		if !out.IsError {
			_ = o.rec.Append(*pc.write)
		}
		return
	}
	if pc.tool != "exec" {
		return
	}
	code := 0
	if sc, ok := out.StructuredContent.(map[string]any); ok {
		if f, ok := sc["exit_code"].(float64); ok {
			code = int(f)
		}
		for _, k := range []string{"stdout", "stderr"} {
			o.appendCommandOutput(pc.call, k, str(sc[k]))
		}
	} else if out.IsError {
		code = -1
	}
	_ = o.rec.Append(recorder.Event{Type: recorder.TypeCommandExit, Call: pc.call, Code: &code,
		Agent: o.agent})
}

// appendCommandOutput records one stream's text in outputFlushAt-sized
// chunks, base64-encoding and appending each on its own — the same shape
// host/exec.go's outputRecorder uses for `kelyfos exec`, and for the same
// reason: a guest's stdout or stderr is unbounded, and the whole point of
// coalescing is many small events instead of one giant one, never truncation.
//
// Before this chunked, a single command's output went into one event with no
// size check at all. Guest output near the ~16 MiB MCP frame cap
// (proto.MaxMCPLine), carried twice in the tool result (Content and
// StructuredContent — supervisor/tools.go) and then expanded 4/3 by base64,
// produced a line past every reader's recorder.MaxLine — durable,
// guest-triggered destruction of the chain from there on, because the chain
// is a chain (S1). recorder.Append now also guards this unconditionally, but
// chunking here is the fix that keeps a legible log rather than one giant
// line that merely survives.
func (o *observer) appendCommandOutput(call, stream, text string) {
	data := []byte(text)
	for len(data) > 0 {
		n := outputFlushAt
		if n > len(data) {
			n = len(data)
		}
		chunk := data[:n]
		data = data[n:]
		_ = o.rec.Append(recorder.Event{
			Type: recorder.TypeCommandOutput, Call: call, Stream: stream,
			Data: base64.StdEncoding.EncodeToString(chunk), Bytes: len(chunk),
			Agent: o.agent,
		})
	}
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

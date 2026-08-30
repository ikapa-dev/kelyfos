package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/ikapa-dev/kelyfos/internal/mcp"
	"github.com/ikapa-dev/kelyfos/internal/proto"
)

// serveMCP answers the MCP channel. Unlike exec, a session is long-lived: one
// connection carries initialization and every subsequent tool call.
func serveMCP(ln net.Listener, rp *reaper) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			logf("mcp accept: %v", err)
			return
		}
		go func() {
			defer conn.Close()
			(&mcpSession{w: proto.NewWriterLimit(conn, proto.MaxMCPLine), rp: rp}).serve(conn)
		}()
	}
}

// mcpSession is one MCP connection. The mutex matters because progress
// notifications are emitted from a running tool's output goroutines while the
// main loop may be writing a response: interleaved messages are fine, a torn
// JSON line is not.
type mcpSession struct {
	mu sync.Mutex
	w  *proto.Writer
	rp *reaper
}

func (s *mcpSession) send(v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(v)
}

func (s *mcpSession) serve(conn net.Conn) {
	r := proto.NewReaderLimit(conn, proto.MaxMCPLine)
	for {
		var req mcp.Request
		if err := r.Read(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}

			// A frame we cannot parse is a protocol error. There is no id to
			// answer with, so JSON-RPC says report it against a null id.
			//
			// Two shapes of that are worth surviving rather than treated as a
			// dead connection, because both leave the stream on a clean frame
			// boundary once handled:
			//
			//   - ErrLineTooLong, once DrainOverlongLine has read past the
			//     rest of that same line. Answering without draining first
			//     used to race whatever the peer was still sending on it: a
			//     close right after this reply could interleave with, or be
			//     cut short by, those unread bytes, and the reply — the one
			//     thing a caller had left to receive — was not guaranteed to
			//     arrive. A peer whose oversized line never ends is not left
			//     drained forever either; DrainOverlongLine gives up past its
			//     own bound and this falls through to the close below.
			//   - a *proto.MalformedFrame, e.g. a request whose JSON carries a
			//     literal (unescaped) newline: the scanner had already found
			//     and consumed a complete, newline-terminated line before
			//     json.Unmarshal rejected it, so the next Read starts clean
			//     regardless of what this one send did.
			//
			// A single bad frame from a client otherwise behaving normally
			// used to take the whole session down with it — every call still
			// in flight on the connection lost along with it, and nothing to
			// show afterward but an EOF the caller could not explain. This is
			// the same precedent the oversized-*answer* path already set
			// (tooLongToSend, below): the channel refusing one frame is not
			// the channel dying (F6).
			var overlong = errors.Is(err, proto.ErrLineTooLong)
			var malformed *proto.MalformedFrame
			recoverable := errors.As(err, &malformed)
			if overlong {
				if drainErr := r.DrainOverlongLine(); drainErr != nil {
					_ = s.send(mcp.NewError(nil, mcp.CodeParseError, err.Error()))
					logf("mcp session: closing after an oversized frame could not be drained: %v", drainErr)
					return
				}
				recoverable = true
			}

			if sendErr := s.send(mcp.NewError(nil, mcp.CodeParseError, err.Error())); sendErr != nil {
				return
			}
			if recoverable {
				continue
			}
			// Neither of the above: a genuine I/O failure on the connection
			// itself (reset, timeout, closed pipe). There is no frame
			// boundary to resync to, so unlike the two cases above this one
			// really does end the session — logged so a session that ends
			// this way leaves a trace instead of looking like an ordinary
			// close.
			logf("mcp session: closing after a read error: %v", err)
			return
		}
		if resp := s.dispatch(&req); resp != nil {
			if err := s.send(resp); err != nil {
				if !errors.Is(err, proto.ErrLineTooLong) {
					return
				}
				// An answer too large for the channel is the one send failure
				// that is not a dead connection. proto.Writer checks the
				// length before it writes anything, so none of the oversized
				// frame reached the wire and the stream is still sitting on a
				// frame boundary — a refusal can be written in its place.
				//
				// Closing here is what made a read_file near the 8 MiB
				// per-call cap arrive as an unexplained EOF: the file is under
				// the limit the tool names, the frame is over the limit the
				// channel has, and the caller was told neither. Everything
				// else in this project refuses with a reason, and the size of
				// an answer is a reason a caller can act on.
				if err := s.send(tooLongToSend(&req, resp)); err != nil {
					return
				}
			}
		}
	}
}

// tooLongToSend is the bounded refusal that stands in for an answer the channel
// will not carry.
//
// For a tools/call it is a tool error rather than a JSON-RPC error, because
// that is where the spec draws the line: a JSON-RPC error means the request was
// malformed, and this request was not — the tool ran, and what it produced is
// too big to send back. It is also the shape the neighbouring refusal already
// has. A file over the 8 MiB per-call limit comes back from readCapped as
// mcp.Errorf naming the limit in bytes (supervisor/tools.go), and a file under
// that limit whose frame is over this one should not reach the caller as
// something else entirely.
//
// The message carries both numbers because neither alone explains it: since the
// structuredContent rule of E4-8 a read_file result carries the file twice, so
// a file comfortably inside the tool's own cap can still marshal to more than a
// frame, and a caller told only "too long" has no way to know by how much. It
// names a way to get the bytes anyway, because read_file has no offset argument
// and exec does have head -c: a refusal that leaves the caller with nothing to
// try next teaches a model to stop asking rather than to ask differently.
func tooLongToSend(req *mcp.Request, resp *mcp.Response) *mcp.Response {
	size := encodedSize(resp)

	// Nothing peer-controlled goes into either message. The id has to be echoed
	// back — JSON-RPC has no other way to say which request this answers — and
	// an id so large that even the refusal will not fit is the one case where
	// this connection still closes without a word. A peer that sends one has
	// broken the framing on purpose.
	if req.Method == "tools/call" {
		return mcp.NewResponse(req.ID, mcp.Errorf(
			"the result of this call is %d bytes, over the %d byte frame limit on the MCP "+
				"channel, so it cannot be sent whole. A read_file result carries the file twice "+
				"— once as text and once as `content` — so a file well inside the 8 MiB per-call "+
				"limit can still land over this, and a command's output is not capped at all. "+
				"Ask for less of it: `head -c`, `tail -c` or `dd` through `exec` returns a large "+
				"result in pieces.",
			size, proto.MaxMCPLine))
	}
	return mcp.NewError(req.ID, mcp.CodeInternalError, fmt.Sprintf(
		"the answer to this request is %d bytes, over the %d byte frame limit on the MCP channel",
		size, proto.MaxMCPLine))
}

// encodedSize is the length of the frame the writer refused, delimiting newline
// included, measured without holding a second copy of it.
//
// The number cannot come from the refusal: proto.ErrLineTooLong is a bare
// sentinel value and the writer that knows the length is in another package
// (internal/proto/proto.go). Marshalling the response a second time and taking
// len() of the result is the obvious way to get it and the wrong one, because
// json.Marshal returns a freshly allocated []byte on every call: measuring a
// 16 MiB answer that way allocated at least another 16 MiB, every time, in a
// guest whose whole machine is 512 MiB by default and smaller than that in a
// team ([resources] mem, internal/config/schema.go), and where an
// out-of-memory kill of this process takes the sandbox with it. The cost is no
// longer paid once per session either — this refusal leaves the connection
// open, so a caller may ask for the same oversized result in a loop.
//
// An encoder writing into a counter produces the same bytes and keeps none of
// them, and its scratch buffer comes from encoding/json's own pool and goes
// straight back, so repeated measurements reuse one buffer instead of
// allocating a copy per call. On the pinned toolchain (go 1.27.0) the second
// json.Marshal allocated 16 MiB or more for a 16 MiB answer on every call,
// against nothing at all for the counted encode once the pool is warm.
//
// It counts what the writer counts. Encoder.Encode appends the delimiting
// newline that Writer.Write adds to its own length check, and escapes exactly
// what json.Marshal escapes, the <, > and & included — so this is that
// len(b)+1 to the byte, not an estimate of it.
//
// The encode error is dropped because there is none to have: Writer.Write
// returns a marshal failure as itself and only reaches the length check after
// marshalling succeeded, so an answer that came back ErrLineTooLong has already
// been through encoding/json without complaint, a moment ago.
func encodedSize(resp *mcp.Response) int {
	var n byteCounter
	_ = json.NewEncoder(&n).Encode(resp)
	return int(n)
}

// byteCounter is an io.Writer that keeps the length and throws the bytes away.
type byteCounter int

func (c *byteCounter) Write(p []byte) (int, error) {
	*c += byteCounter(len(p))
	return len(p), nil
}

// dispatch returns the response to send, or nil for a notification — JSON-RPC
// forbids answering those, and a client that receives an answer to one will
// treat the stream as broken.
func (s *mcpSession) dispatch(req *mcp.Request) *mcp.Response {
	switch req.Method {
	case "initialize":
		return mcp.NewResponse(req.ID, mcp.InitializeResult{
			ProtocolVersion: mcp.ProtocolVersion,
			Capabilities:    mcp.Capabilities{Tools: &mcp.ToolsCapability{}},
			ServerInfo: mcp.Info{
				Name:    "kelyfos",
				Title:   "KelyfOS sandbox",
				Version: Version,
			},
			Instructions: "This is a KelyfOS microVM sandbox. The machine is exposed as tools " +
				"rather than as a shell: there is no login, no SSH and no terminal. Files written " +
				"outside /work live in a tmpfs overlay and vanish when the sandbox stops.",
		})

	case "notifications/initialized", "notifications/cancelled":
		return nil

	case "ping":
		return mcp.NewResponse(req.ID, struct{}{})

	case "tools/list":
		// The team tools are listed only for a sandbox that is in a team. A
		// tool that is always advertised and always fails teaches a model to
		// ignore failures, which is the last habit this project wants to teach.
		tools := toolDefinitions()
		if theTeam != nil {
			tools = append(tools, teamToolDefinitions(theTeam.maySpawn)...)
		}
		// The plugins' tools come last and namespaced, so a plugin can never
		// shadow a built-in one: <plugin>_<tool> cannot collide with exec or
		// read_file, because a plugin name may not contain an underscore
		// (docs/mcp-surface.md §3.2).
		tools = append(tools, pluginTools()...)
		return mcp.NewResponse(req.ID, mcp.ToolsListResult{Tools: tools})

	case "tools/call":
		if req.IsNotification() {
			return nil
		}
		var p mcp.CallToolParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return mcp.NewError(req.ID, mcp.CodeInvalidParams, err.Error())
		}
		return mcp.NewResponse(req.ID, s.callTool(&p))

	default:
		if req.IsNotification() {
			return nil
		}
		return mcp.NewError(req.ID, mcp.CodeMethodNotFound, "unknown method "+req.Method)
	}
}

func (s *mcpSession) callTool(p *mcp.CallToolParams) *mcp.CallToolResult {
	args := p.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	switch p.Name {
	case "exec":
		return s.toolExec(args, p.Meta)
	case "read_file":
		return toolReadFile(args)
	case "write_file":
		return toolWriteFile(args)
	case "list_dir":
		return toolListDir(args)
	case "upload":
		return toolUpload(args)
	case "download":
		return toolDownload(args)
	default:
		if isTeamTool(p.Name) {
			return callTeamTool(theTeam, p.Name, args)
		}
		if plug, tool, ok := findPluginTool(p.Name); ok {
			return callPluginTool(plug, tool, args, reportGuestEvent)
		}
		return mcp.Errorf("unknown tool %q", p.Name)
	}
}

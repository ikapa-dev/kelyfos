package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/p4r4n0rm4l/KelyfOS/internal/mcp"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
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
			_ = s.send(mcp.NewError(nil, mcp.CodeParseError, err.Error()))
			return
		}
		if resp := s.dispatch(&req); resp != nil {
			if err := s.send(resp); err != nil {
				return
			}
		}
	}
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

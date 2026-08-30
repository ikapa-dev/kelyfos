package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/mcp"
	"github.com/ikapa-dev/kelyfos/internal/proto"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// A small MCP client for a guest's own tool surface (E4-2).
//
// `serve-mcp`'s file tools are the supervisor's file tools with a sandbox id in
// front (docs/mcp-surface.md §2.2), and that is meant literally: the host asks
// the guest over the same protocol every other client uses, rather than
// shelling out to `base64` and growing a second idea of what the per-call limit
// is, whether a parent directory is created, and how a failure reads. One
// implementation, one behaviour — the same reason `internal/proto` exists.
//
// The frame limit on this channel is proto.MaxMCPLine, not proto.MaxLine: one
// tool result can carry a whole file, and the constant says why.

type guestConn struct {
	c    net.Conn
	s    *bufio.Scanner
	enc  *json.Encoder
	next int
}

func dialGuest(uds string, timeout time.Duration) (*guestConn, error) {
	c, err := sandbox.Connect(uds, proto.PortMCP, timeout)
	if err != nil {
		return nil, err
	}
	// One deadline for the whole exchange: a bounded tool call is the only
	// thing this connection is for, and a guest that stops answering must not
	// hold a serve-mcp goroutine open for ever.
	_ = c.SetDeadline(time.Now().Add(timeout))
	s := bufio.NewScanner(c)
	s.Buffer(make([]byte, 0, 64<<10), proto.MaxMCPLine)
	return &guestConn{c: c, s: s, enc: json.NewEncoder(c)}, nil
}

func (g *guestConn) close() { _ = g.c.Close() }

// notify sends a message with no id, which JSON-RPC forbids answering.
func (g *guestConn) notify(method string) error {
	return g.enc.Encode(mcp.Notification{JSONRPC: "2.0", Method: method})
}

// call sends one request and returns its answer, skipping anything that is not
// it: a notification, or progress belonging to some other call. json.Encoder
// ends every value with a newline, which is exactly this transport's framing.
func (g *guestConn) call(method string, params any, result any) error {
	g.next++
	id := json.RawMessage(fmt.Sprintf("%d", g.next))
	if err := g.enc.Encode(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  any             `json:"params,omitempty"`
	}{"2.0", id, method, params}); err != nil {
		return err
	}
	for {
		if !g.s.Scan() {
			if err := g.s.Err(); err != nil {
				if errors.Is(err, bufio.ErrTooLong) {
					return fmt.Errorf("the guest answered %s with more than %d bytes on one line, "+
						"which is more than this side will buffer", method, proto.MaxMCPLine)
				}
				return err
			}
			return io.EOF
		}
		line := bytes.TrimRight(g.s.Bytes(), "\r")
		if len(line) == 0 {
			continue
		}
		var resp struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *mcp.Error      `json:"error"`
		}
		if err := json.Unmarshal(line, &resp); err != nil {
			return err
		}
		if string(resp.ID) != string(id) {
			continue
		}
		if resp.Error != nil {
			return fmt.Errorf("%s: %s", method, resp.Error.Message)
		}
		if result == nil {
			return nil
		}
		return json.Unmarshal(resp.Result, result)
	}
}

// callGuestTool runs one of the guest's own MCP tools and hands back its result
// unchanged — including isError, which belongs to the caller to read.
//
// A fresh connection per call rather than one held per sandbox: the supervisor
// gives every connection its own session, a vsock dial costs microseconds
// beside the work, and a cached connection is a thing that can be quietly stale
// in a place where a file write must not be.
func callGuestTool(uds, tool string, args any, timeout time.Duration) (*mcp.CallToolResult, error) {
	g, err := dialGuest(uds, timeout)
	if err != nil {
		return nil, err
	}
	defer g.close()

	// Initialize properly rather than firing a tool call at a server that has
	// not been introduced to anyone. The guest would answer either way; a
	// conforming client is what §5 of docs/mcp-surface.md claims this is.
	if err := g.call("initialize", map[string]any{
		"protocolVersion": mcp.ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "kelyfos-serve-mcp", "version": Version},
	}, nil); err != nil {
		return nil, err
	}
	if err := g.notify("notifications/initialized"); err != nil {
		return nil, err
	}

	blob, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	var res mcp.CallToolResult
	if err := g.call("tools/call", mcp.CallToolParams{Name: tool, Arguments: blob}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

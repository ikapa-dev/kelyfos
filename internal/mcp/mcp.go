// Package mcp implements the Model Context Protocol envelope KelyfOS speaks
// over vsock: JSON-RPC 2.0, one message per line.
//
// The framing is the MCP stdio transport's framing unchanged — "messages are
// delimited by newlines, and MUST NOT contain embedded newlines" — which the
// 2026-07-28 revision states explicitly works "over Unix domain sockets, TCP
// connections, or any similar channel". A vsock stream is exactly such a
// channel, so KelyfOS is a conforming custom transport rather than a dialect
// (docs/protocol.md §6).
package mcp

import (
	"encoding/json"
	"fmt"
)

// ProtocolVersion is the revision this server implements and offers during
// initialization.
const ProtocolVersion = "2025-11-25"

// Request is a JSON-RPC request or, when ID is absent, a notification.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether no response may be sent. JSON-RPC forbids
// answering a notification, and a client that receives one will treat the
// stream as broken.
func (r *Request) IsNotification() bool { return len(r.ID) == 0 || string(r.ID) == "null" }

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Notification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// JSON-RPC 2.0 error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

func NewResponse(id json.RawMessage, result any) *Response {
	return &Response{JSONRPC: "2.0", ID: id, Result: result}
}

func NewError(id json.RawMessage, code int, msg string) *Response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return &Response{JSONRPC: "2.0", ID: id, Error: &Error{Code: code, Message: msg}}
}

// --- initialization ---

type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      Info         `json:"serverInfo"`
	Instructions    string       `json:"instructions,omitempty"`
}

type Capabilities struct {
	Tools *ToolsCapability `json:"tools,omitempty"`
}

type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type Info struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version"`
}

// --- tools ---

type Tool struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description"`
	InputSchema Schema `json:"inputSchema"`
}

type Schema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties,omitempty"`
	Required   []string            `json:"required,omitempty"`
}

type Property struct {
	Type        string    `json:"type"`
	Description string    `json:"description,omitempty"`
	Items       *Property `json:"items,omitempty"`
	Default     any       `json:"default,omitempty"`
}

type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Meta      *CallMeta       `json:"_meta,omitempty"`
}

// CallMeta carries the progress token a client supplies when it wants
// incremental updates, which is how a long-running exec streams its output
// without inventing a KelyfOS-specific mechanism.
type CallMeta struct {
	ProgressToken json.RawMessage `json:"progressToken,omitempty"`
}

// Content is one item of a tool result. Text is the common case; Data carries
// base64 for binary payloads.
type Content struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MIMEType string `json:"mimeType,omitempty"`
}

func Text(s string) Content { return Content{Type: "text", Text: s} }

// CallToolResult is what a tool returns.
//
// A tool that fails sets IsError and describes the failure in Content — it does
// not return a JSON-RPC error. The spec draws that line deliberately: protocol
// errors mean the request was malformed, while tool errors are "actionable
// feedback that language models can use to self-correct". A command exiting
// non-zero is information for the agent, not a broken request.
type CallToolResult struct {
	Content           []Content `json:"content"`
	IsError           bool      `json:"isError,omitempty"`
	StructuredContent any       `json:"structuredContent,omitempty"`
}

func Errorf(format string, args ...any) *CallToolResult {
	return &CallToolResult{Content: []Content{Text(fmt.Sprintf(format, args...))}, IsError: true}
}

// ProgressParams is the payload of notifications/progress.
type ProgressParams struct {
	ProgressToken json.RawMessage `json:"progressToken"`
	Progress      float64         `json:"progress"`
	Message       string          `json:"message,omitempty"`
}

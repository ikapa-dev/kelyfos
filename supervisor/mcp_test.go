package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/mcp"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
)

var digits = regexp.MustCompile(`\d+`)

// mcpTestSession runs one real session over an in-memory pipe, wired exactly as
// serveMCP wires the one on the vsock: the same writer, the same limit, the
// same reader. What is under test here is the seam between the two, so a
// session built by hand with a convenient limit would be testing something
// else.
func mcpTestSession(t *testing.T) (net.Conn, *bufio.Reader) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	s := &mcpSession{w: proto.NewWriterLimit(server, proto.MaxMCPLine)}
	go func() {
		defer server.Close()
		s.serve(server)
	}()
	return client, bufio.NewReaderSize(client, 64<<10)
}

// mcpAnswer sends one request and returns the next frame, decoded far enough to
// tell a result from an error.
func mcpAnswer(t *testing.T, conn net.Conn, br *bufio.Reader, req string) (json.RawMessage, *mcp.CallToolResult, *mcp.Error) {
	t.Helper()
	if _, err := io.WriteString(conn, req+"\n"); err != nil {
		t.Fatalf("sending the request: %v", err)
	}
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("the session closed instead of answering: %v", err)
	}
	var resp struct {
		ID     json.RawMessage     `json:"id"`
		Result *mcp.CallToolResult `json:"result"`
		Error  *mcp.Error          `json:"error"`
	}
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("the answer is not JSON: %v (%q)", err, line)
	}
	return resp.ID, resp.Result, resp.Error
}

// A file at the tool's own 8 MiB cap is refused by the transport, not by the
// tool: the structuredContent rule of E4-8 puts the contents in the text block
// *and* in `content`, so the frame is about twice the file and lands over
// proto.MaxMCPLine before a single character is escaped.
//
// The session used to return on that send error and the connection closed, so
// what reached the caller was an unexplained EOF — the one refusal in this
// project that did not say why. The two things this asserts are that the caller
// is told, in bytes, and that the session is still there afterwards: the answer
// did not fit, but nothing was written and the connection is not broken.
func TestAnAnswerTooLargeForTheChannelIsRefusedRatherThanClosingTheSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "at-the-cap")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxToolBytes)), 0o644); err != nil {
		t.Fatal(err)
	}

	conn, br := mcpTestSession(t)

	id, result, rpcErr := mcpAnswer(t, conn, br, fmt.Sprintf(
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":%q}}}`, path))
	if string(id) != "7" {
		t.Errorf("the refusal answers id %s, not the request's own", id)
	}
	if rpcErr != nil {
		t.Fatalf("a tool whose result will not fit is a tool error, not a protocol error: %+v", rpcErr)
	}
	if result == nil || !result.IsError || len(result.Content) == 0 {
		t.Fatalf("expected a tool error naming the limit, got %+v", result)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, strconv.Itoa(proto.MaxMCPLine)) {
		t.Errorf("the refusal does not name the frame limit: %q", text)
	}
	// The first number in the message is the size of the answer that could not
	// be sent, and it has to be a real measurement: a refusal that named the
	// limit without naming the overrun would leave a caller with no idea how
	// much less to ask for.
	nums := digits.FindAllString(text, -1)
	if len(nums) == 0 {
		t.Fatalf("the refusal says no numbers at all: %q", text)
	}
	if n, err := strconv.Atoi(nums[0]); err != nil || n <= proto.MaxMCPLine {
		t.Errorf("the stated size %q is not over the limit: %q", nums[0], text)
	}

	// The session survived. This is the half that matters most: the writer
	// rejects an oversized frame before it writes any of it, so the stream is
	// still on a frame boundary and the next call is answered normally.
	id, _, rpcErr = mcpAnswer(t, conn, br, `{"jsonrpc":"2.0","id":8,"method":"ping"}`)
	if rpcErr != nil || string(id) != "8" {
		t.Errorf("the session did not survive the oversized answer: id=%s err=%+v", id, rpcErr)
	}
}

// Everything that is not a tools/call is refused as a JSON-RPC error, because
// there is no tool result to put an isError on. Exercised directly: no answer
// to initialize, ping or tools/list can be made to exceed 16 MiB from outside.
func TestAnOversizedAnswerToSomethingOtherThanAToolCallIsAProtocolError(t *testing.T) {
	req := &mcp.Request{JSONRPC: "2.0", ID: json.RawMessage("3"), Method: "tools/list"}
	resp := tooLongToSend(req, mcp.NewResponse(req.ID, strings.Repeat("y", 32)))
	if resp.Error == nil {
		t.Fatalf("expected a JSON-RPC error, got %+v", resp)
	}
	if resp.Error.Code != mcp.CodeInternalError {
		t.Errorf("code = %d, want %d", resp.Error.Code, mcp.CodeInternalError)
	}
	if string(resp.ID) != "3" {
		t.Errorf("the refusal answers id %s, not the request's own", resp.ID)
	}
	if !strings.Contains(resp.Error.Message, strconv.Itoa(proto.MaxMCPLine)) {
		t.Errorf("the refusal does not name the frame limit: %q", resp.Error.Message)
	}
}

// The refusal names the size of the answer that would not fit, and the way it
// learns that size must not be to build the answer a second time.
//
// The first version of this path called json.Marshal again purely to take len()
// of the result. json.Marshal allocates a fresh []byte every call, so measuring
// a 16 MiB answer allocated another 16 MiB inside a guest that has 512 MiB for
// the whole machine by default — and because this refusal leaves the connection
// open where the old behaviour closed it, a caller can ask for the same
// oversized result over and over.
//
// Both halves are asserted here: the number is the true length of the frame,
// delimiting newline included, and getting it costs nothing like another copy
// of the frame. Allocation is measured as the best of several runs, because
// what is being ruled out is a copy per call — a measurement that allocates the
// answer every time cannot have a cheap run among them.
func TestMeasuringAnAnswerThatWillNotFitDoesNotBuildItAgain(t *testing.T) {
	const size = 4 << 20
	req := &mcp.Request{JSONRPC: "2.0", ID: json.RawMessage("11"), Method: "tools/list"}
	resp := mcp.NewResponse(req.ID, strings.Repeat("z", size))

	frame, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	want := len(frame) + 1 // proto.Writer counts the newline it appends

	refusal := tooLongToSend(req, resp)
	if refusal.Error == nil {
		t.Fatalf("expected a JSON-RPC error, got %+v", refusal)
	}
	nums := digits.FindAllString(refusal.Error.Message, -1)
	if len(nums) == 0 || nums[0] != strconv.Itoa(want) {
		t.Errorf("the refusal says %q bytes, the frame is %d: %q", nums, want, refusal.Error.Message)
	}

	var best uint64
	for i := 0; i < 8; i++ {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		out := tooLongToSend(req, resp)
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(out)
		if used := after.TotalAlloc - before.TotalAlloc; i == 0 || used < best {
			best = used
		}
	}
	if best > size/4 {
		t.Errorf("measuring a %d byte answer allocated %d bytes, which is another copy of it", size, best)
	}
}

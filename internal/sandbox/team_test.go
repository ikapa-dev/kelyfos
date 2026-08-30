package sandbox

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/proto"
	"github.com/ikapa-dev/kelyfos/internal/team"
)

// teamChannel binds a team channel and dials it the way a guest does, so these
// tests exercise the real accept loop rather than a stand-in for it.
func teamChannel(t *testing.T, answer func(proto.TeamRequest) proto.TeamResponse) (*proto.Writer, *proto.Reader) {
	t.Helper()
	dir := t.TempDir()
	s := &Sandbox{
		State: State{UDSPath: filepath.Join(dir, "v.sock")},
		opts:  Options{OnTeamRequest: answer},
	}
	if err := s.listenTeam(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.teamLn.Close() })

	conn, err := net.Dial("unix", fmt.Sprintf("%s_%d", s.State.UDSPath, proto.PortTeam))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return proto.NewWriter(conn), proto.NewReader(conn)
}

// A message an agent can send has to be a message the host can deliver. It was
// not: the frame that delivers one carries `from` where the send carried `to`,
// plus `ok`, plus the correlate tag a reply quotes back, so there was a band of
// payload sizes that went out fine, that the broker accepted and recorded as
// delivered, and that could then never be written to the agent they were for.
// Broker.Recv takes the message off the mailbox before the frame is built, so
// the failed write destroyed it — and the write failure was read as a dead
// connection, so the recipient got an unexplained EOF for a message it never
// saw (M-8).
//
// Refused to the sender, at the door, naming the size and the limit: the only
// place where nothing has been consumed yet and the agent that chose the size
// is the one being told about it.
func TestATeamMessageTooLargeToDeliverIsRefusedToItsSender(t *testing.T) {
	reached := make(chan proto.TeamRequest, 4)
	w, r := teamChannel(t, func(req proto.TeamRequest) proto.TeamResponse {
		reached <- req
		return proto.TeamResponse{OK: true}
	})

	oversize := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), proto.MaxTeamBody+1))
	if err := w.Write(proto.TeamRequest{
		V: proto.Version, ID: "1", Op: proto.OpTeamSend, To: "bob", Body: oversize,
	}); err != nil {
		t.Fatalf("the sending frame does not even fit, so this tests nothing: %v", err)
	}

	var resp proto.TeamResponse
	if err := r.Read(&resp); err != nil {
		t.Fatalf("no answer to an oversized message, which is the drop itself: %v", err)
	}
	if resp.Error == nil || resp.Error.Kind != proto.ErrBadRequest {
		t.Fatalf("an undeliverable message was accepted instead of refused: %+v", resp)
	}
	if !strings.Contains(resp.Error.Message, strconv.Itoa(proto.MaxTeamBody)) ||
		!strings.Contains(resp.Error.Message, strconv.Itoa(proto.MaxTeamBody+1)) {
		t.Errorf("the refusal names neither the limit nor the size: %q", resp.Error.Message)
	}
	if resp.ID != "1" {
		t.Errorf("the refusal answers under id %q rather than the one asked with", resp.ID)
	}
	select {
	case req := <-reached:
		t.Fatalf("the broker was asked to carry it anyway: op %q, %d bytes of body", req.Op, len(req.Body))
	default:
	}

	// And the channel is still there. A refusal that costs the connection is
	// the failure this replaces wearing a different hat.
	if err := w.Write(proto.TeamRequest{V: proto.Version, ID: "2", Op: proto.OpTeamRecv}); err != nil {
		t.Fatal(err)
	}
	var next proto.TeamResponse
	if err := r.Read(&next); err != nil {
		t.Fatalf("the channel did not survive the refusal: %v", err)
	}
	if !next.OK || next.ID != "2" {
		t.Fatalf("the next request was answered wrongly: %+v", next)
	}
}

// The backstop, which the check above makes unreachable for a body an agent
// sent — and which is worth having anyway, because it is what keeps a field
// added to the envelope later from quietly bringing the destroyed message and
// the unexplained EOF back. A body can reach the broker without crossing that
// door: the host can put one in the store or a message in a mailbox itself, and
// internal/team's own value limit is larger than any frame can carry back.
//
// proto.Writer measures the whole frame before it writes any of it, so nothing
// of the refused answer reached the wire and the stream is still on a frame
// boundary — the same recovery the guest's MCP session makes (supervisor/mcp.go).
func TestAnAnswerTooLargeForTheChannelIsARefusalAndNotAnEOF(t *testing.T) {
	w, r := teamChannel(t, func(req proto.TeamRequest) proto.TeamResponse {
		if req.Op == proto.OpTeamRecv {
			return proto.TeamResponse{OK: true, From: "planner",
				Body:      base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), proto.MaxLine)),
				Correlate: "0123456789abcdef"}
		}
		return proto.TeamResponse{OK: true}
	})

	if err := w.Write(proto.TeamRequest{V: proto.Version, ID: "1", Op: proto.OpTeamRecv}); err != nil {
		t.Fatal(err)
	}
	var resp proto.TeamResponse
	if err := r.Read(&resp); err != nil {
		t.Fatalf("the channel closed on an answer it could not write, which is the EOF agents saw: %v", err)
	}
	if resp.Error == nil {
		t.Fatalf("an answer that cannot be written came back as a success: %+v", resp)
	}
	if !strings.Contains(resp.Error.Message, strconv.Itoa(proto.MaxLine)) {
		t.Errorf("the refusal does not name the frame limit: %q", resp.Error.Message)
	}
	if resp.ID != "1" {
		t.Errorf("the refusal answers under id %q rather than the one asked with", resp.ID)
	}

	// One whole frame and nothing glued to it: the next request is answered,
	// which it would not be if a fragment of the refused answer had gone out.
	if err := w.Write(proto.TeamRequest{V: proto.Version, ID: "2", Op: proto.OpTeamPeers}); err != nil {
		t.Fatal(err)
	}
	var next proto.TeamResponse
	if err := r.Read(&next); err != nil {
		t.Fatalf("the stream is no longer on a frame boundary: %v", err)
	}
	if !next.OK || next.ID != "2" {
		t.Fatalf("the next request was answered wrongly: %+v", next)
	}
}

// The id is the guest's own choice and the host echoes it onto the answer, so
// an unbounded id is an unbounded answer — which would leave the body limit
// above provable only for guests that are reasonable about their ids, and the
// guest is the untrusted side. A guest reaches this only by bypassing its own
// supervisor, which numbers requests from a counter; that it can is the point.
func TestAnOversizedRequestIDIsRefusedRatherThanEchoed(t *testing.T) {
	reached := make(chan proto.TeamRequest, 4)
	w, r := teamChannel(t, func(req proto.TeamRequest) proto.TeamResponse {
		reached <- req
		return proto.TeamResponse{OK: true}
	})

	id := strings.Repeat("9", proto.MaxTeamID+1)
	if err := w.Write(proto.TeamRequest{V: proto.Version, ID: id, Op: proto.OpTeamPeers}); err != nil {
		t.Fatal(err)
	}
	var resp proto.TeamResponse
	if err := r.Read(&resp); err != nil {
		t.Fatalf("no answer to an oversized id: %v", err)
	}
	if resp.Error == nil || resp.Error.Kind != proto.ErrBadRequest {
		t.Fatalf("an unbounded id was echoed rather than refused: %+v", resp)
	}
	if len(resp.ID) > proto.MaxTeamID {
		t.Errorf("the refusal echoed %d bytes of id, which is the thing being refused", len(resp.ID))
	}
	select {
	case <-reached:
		t.Fatal("the request was served under an id the host cannot answer with")
	default:
	}
}

// The store key rides the same envelope (proto.TeamRequest.Key) for store_get
// and store_put, and internal/team already bounds it — MaxKeyBytes — but
// nothing here enforced that bound before OnTeamRequest, and therefore
// internal/team's own Store, ever saw the request. Same shape as the id and
// body checks above, and the same reason: the guest is the side that chose
// the size, so it is the side refused with it (S5b).
func TestAnOversizedKeyIsRefusedRatherThanReachingTheStore(t *testing.T) {
	reached := make(chan proto.TeamRequest, 4)
	w, r := teamChannel(t, func(req proto.TeamRequest) proto.TeamResponse {
		reached <- req
		return proto.TeamResponse{OK: true}
	})

	key := strings.Repeat("k", team.MaxKeyBytes+1)
	if err := w.Write(proto.TeamRequest{
		V: proto.Version, ID: "1", Op: proto.OpTeamStoreGet, Key: key,
	}); err != nil {
		t.Fatal(err)
	}
	var resp proto.TeamResponse
	if err := r.Read(&resp); err != nil {
		t.Fatalf("no answer to an oversized key: %v", err)
	}
	if resp.Error == nil || resp.Error.Kind != proto.ErrBadRequest {
		t.Fatalf("an oversized key was accepted instead of refused: %+v", resp)
	}
	if !strings.Contains(resp.Error.Message, strconv.Itoa(team.MaxKeyBytes)) {
		t.Errorf("the refusal does not name the limit: %q", resp.Error.Message)
	}
	if resp.ID != "1" {
		t.Errorf("the refusal answers under id %q rather than the one asked with", resp.ID)
	}
	select {
	case req := <-reached:
		t.Fatalf("the broker was asked to carry an oversized key anyway: op %q, %d-byte key", req.Op, len(req.Key))
	default:
	}
}

// serveTeam's accept loop had no connection cap and no read deadline: any
// process inside the guest can dial the team channel directly over vsock,
// without going through the supervisor's own well-behaved client, and one
// that connects and never writes a byte used to pin a goroutine forever.
// Enough of them and no connection — including the supervisor's real one —
// could ever be served again (F5). This proves both halves of the fix at
// once: maxConcurrentGuestConnections bounds how many silent connections can
// occupy a slot, and guestFirstFrameTimeout is what gets a slot back from one
// that never speaks, so a legitimate connection queued behind the cap is
// eventually served rather than stuck for good.
func TestSilentTeamConnectionsAreCappedAndReclaimed(t *testing.T) {
	dir := t.TempDir()
	served := make(chan struct{}, 1)
	s := &Sandbox{
		State: State{UDSPath: filepath.Join(dir, "v.sock")},
		opts: Options{OnTeamRequest: func(proto.TeamRequest) proto.TeamResponse {
			served <- struct{}{}
			return proto.TeamResponse{OK: true}
		}},
	}
	if err := s.listenTeam(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.teamLn.Close() })
	addr := fmt.Sprintf("%s_%d", s.State.UDSPath, proto.PortTeam)

	// Saturate every slot with connections that dial in and never write
	// anything — exactly what a guest process reaching this listener
	// directly, rather than through teamClient, can do.
	for i := 0; i < maxConcurrentGuestConnections; i++ {
		c, err := net.Dial("unix", addr)
		if err != nil {
			t.Fatalf("silent connection %d: %v", i, err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}
	// Accept happens asynchronously to Dial returning, so give the loop a
	// moment to actually pull all of them in and fill the semaphore.
	deadline := time.Now().Add(2 * time.Second)
	for len(s.teamSem) < maxConcurrentGuestConnections && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(s.teamSem); n != maxConcurrentGuestConnections {
		t.Fatalf("only %d of %d silent connections filled the cap", n, maxConcurrentGuestConnections)
	}

	// One legitimate connection on top of the cap: with every slot held by a
	// connection that will never free it on its own, this must not reach the
	// broker yet — that is the bound actually doing something.
	conn, err := net.Dial("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(guestFirstFrameTimeout + 20*time.Second)); err != nil {
		t.Fatal(err)
	}
	w, r := proto.NewWriter(conn), proto.NewReader(conn)
	if err := w.Write(proto.TeamRequest{V: proto.Version, ID: "1", Op: proto.OpTeamPeers}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-served:
		t.Fatal("a connection past the cap reached the broker while every slot was held by a silent one")
	case <-time.After(500 * time.Millisecond):
	}

	// guestFirstFrameTimeout is what gets those slots back: once it passes,
	// every silent connection is closed from the host side, freeing the cap,
	// and the legitimate connection above is finally accepted and answered —
	// proof that a guest holding the cap in connections it never finishes
	// costs those connections and nothing more, not the channel for good.
	var resp proto.TeamResponse
	if err := r.Read(&resp); err != nil {
		t.Fatalf("the legitimate connection was never served once the silent ones' deadline passed: %v", err)
	}
	if !resp.OK || resp.ID != "1" {
		t.Fatalf("served with the wrong answer: %+v", resp)
	}
	select {
	case <-served:
	default:
		t.Fatal("a response came back but OnTeamRequest was never actually called")
	}
}

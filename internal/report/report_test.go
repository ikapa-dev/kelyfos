package report

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

func ev(t string, agent string) recorder.Event {
	return recorder.Event{Type: t, Agent: agent, TS: "2026-08-23T10:00:00.000Z"}
}

func render(t *testing.T, events []recorder.Event) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, "s1", events, nil); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// A single sandbox has no lanes and its report is exactly the report it was
// before teams existed. The lane view is an addition, not a replacement.
func TestLanesAreAbsentForASingleSandbox(t *testing.T) {
	lanes, rows := buildLanes([]recorder.Event{
		ev(recorder.TypeSessionStart, ""),
		ev(recorder.TypeCommandStart, ""),
		ev(recorder.TypeSessionEnd, ""),
	})
	if lanes != nil || rows != nil {
		t.Fatalf("a single-sandbox session grew lanes: %v", lanes)
	}
	if html := render(t, []recorder.Event{ev(recorder.TypeSessionStart, "")}); strings.Contains(html, `class="lanes"`) {
		t.Error("the lane section rendered for a session with no agents")
	}
}

// Lane order is first-appearance order, which for a team is boot order — so the
// columns read like the file the user wrote.
func TestLaneOrderIsBootOrder(t *testing.T) {
	lanes, _ := buildLanes([]recorder.Event{
		ev(recorder.TypeCommandStart, "master"),
		ev(recorder.TypeCommandStart, "worker-1"),
		ev(recorder.TypeCommandStart, "worker-2"),
		ev(recorder.TypeCommandStart, "master"),
	})
	if got := strings.Join(lanes, " "); got != "master worker-1 worker-2" {
		t.Errorf("lanes = %q", got)
	}
}

// A peer that never acted still needs a column, or a message to it would have
// nowhere to point.
func TestAPeerThatNeverActedStillGetsALane(t *testing.T) {
	e := ev(recorder.TypeTeamMessage, "master")
	e.Peer, e.Kind = "quiet-worker", "send"
	lanes, rows := buildLanes([]recorder.Event{e})
	if len(lanes) != 2 || lanes[1] != "quiet-worker" {
		t.Fatalf("lanes = %v", lanes)
	}
	if !rows[0].Flow {
		t.Error("a message between two agents was not drawn as a flow")
	}
	if got := string(rows[0].Place); got != "grid-column:2/4" {
		t.Errorf("the message does not span its two lanes: %q", got)
	}
}

// A store key is not an agent. This is the assertion that catches a regression
// in the pre-pass that mints lanes from peers.
func TestAStoreKeyDoesNotMintALane(t *testing.T) {
	e := ev(recorder.TypeTeamStore, "master")
	e.Peer, e.Kind, e.Outcome = "findings/a", "put", "delivered"
	lanes, rows := buildLanes([]recorder.Event{e})
	if len(lanes) != 1 || lanes[0] != "master" {
		t.Fatalf("a store key became a lane: %v", lanes)
	}
	// Inline in the acting agent's lane: a store access is something one agent
	// did, not a message between two.
	if rows[0].Flow {
		t.Error("a store access was drawn as a flow between lanes")
	}
	if got := string(rows[0].Place); got != "grid-column:2" {
		t.Errorf("the store access is not in the acting agent's lane: %q", got)
	}
}

// A reply travels the return path, and the view says so.
func TestAReplyPointsBackwards(t *testing.T) {
	ask := ev(recorder.TypeTeamMessage, "master")
	ask.Peer, ask.Kind = "worker-1", "ask"
	reply := ev(recorder.TypeTeamMessage, "worker-1")
	reply.Peer, reply.Kind = "master", "reply"
	_, rows := buildLanes([]recorder.Event{ask, reply})
	if !strings.Contains(rows[0].Title, "→") {
		t.Errorf("an ask does not point forwards: %q", rows[0].Title)
	}
	if !strings.Contains(rows[1].Title, "←") {
		t.Errorf("a reply does not point backwards: %q", rows[1].Title)
	}
}

// Acceptance line 8 asks for the refused events to be in the export. A refusal
// is a flow like any other message — that is the point, it shows what was
// attempted — and it is flagged.
func TestARefusedMessageSpansItsLanesAndIsFlagged(t *testing.T) {
	e := ev(recorder.TypeTeamRefused, "worker-1")
	e.Peer, e.Kind, e.Reason = "worker-2", "send", "no_edge"
	_, rows := buildLanes([]recorder.Event{
		ev(recorder.TypeCommandStart, "master"), e,
	})
	r := rows[len(rows)-1]
	if !r.Flow || !r.IsError || r.Kind != "team-refused" {
		t.Fatalf("a refused message was not flagged as one: %+v", r)
	}
	if !strings.Contains(r.Title, "REFUSED") {
		t.Errorf("the refusal does not say so: %q", r.Title)
	}
	html := render(t, []recorder.Event{ev(recorder.TypeCommandStart, "master"), e})
	if !strings.Contains(html, `class="flow team-refused err"`) {
		t.Error("the refused message is not rendered as a flagged flow")
	}
	if !strings.Contains(html, "no_edge") {
		t.Error("the reason the message was refused is not in the report")
	}
}

// A refused spawn has no peer to point at, so it is a cell in the asker's lane
// rather than a flow to nowhere.
func TestARefusedSpawnIsACellNotAFlow(t *testing.T) {
	e := ev(recorder.TypeTeamSpawn, "master")
	e.Outcome, e.Reason = "refused", "budget_exhausted"
	lanes, rows := buildLanes([]recorder.Event{e})
	if len(lanes) != 1 {
		t.Fatalf("a refused spawn minted a phantom lane: %v", lanes)
	}
	if rows[0].Flow {
		t.Error("a refused spawn was drawn as a flow")
	}
	if got := string(rows[0].Place); got != "grid-column:2" {
		t.Errorf("place = %q", got)
	}
}

// Output belongs to the command it came from. A transcript where output floats
// away from its command is not a transcript.
func TestCommandOutputAttachesToItsCommandInTheLanes(t *testing.T) {
	start := ev(recorder.TypeCommandStart, "worker-1")
	start.Call, start.Cmd, start.Via = "c1", []string{"echo", "hi"}, "exec"
	out := ev(recorder.TypeCommandOutput, "worker-1")
	out.Call, out.Stream = "c1", "stdout"
	out.Data = base64.StdEncoding.EncodeToString([]byte("hi\n"))
	code := 0
	exit := ev(recorder.TypeCommandExit, "worker-1")
	exit.Call, exit.Code = "c1", &code

	_, rows := buildLanes([]recorder.Event{start, out, exit})
	if len(rows) != 1 {
		t.Fatalf("expected one row for one command, got %d", len(rows))
	}
	if rows[0].Output != "hi\n" {
		t.Errorf("output = %q", rows[0].Output)
	}
	if !strings.HasSuffix(rows[0].Detail, "exit 0") {
		t.Errorf("detail = %q", rows[0].Detail)
	}
}

// An event that names no agent must not be attributed to whichever agent
// happens to be first. In a record whose whole purpose is saying who did what,
// that is the worst failure available.
func TestAnAgentlessEventDoesNotLandInTheFirstLane(t *testing.T) {
	e := ev(recorder.TypeResourceTimeout, "")
	e.Budget = "max_runtime"
	_, rows := buildLanes([]recorder.Event{
		ev(recorder.TypeCommandStart, "master"),
		ev(recorder.TypeCommandStart, "worker-1"),
		e,
	})
	last := rows[len(rows)-1]
	if got := string(last.Place); got == "grid-column:2" {
		t.Errorf("an agentless event was attributed to %q's lane", "master")
	} else if got != "grid-column:2/4" {
		t.Errorf("an agentless event is not spanning the team: %q", got)
	}
}

// A team writes one receipt per agent into the same chain. The header's single
// receipt must not become whichever machine stopped last.
func TestPerAgentReceiptsDoNotBecomeTheSessionsReceipt(t *testing.T) {
	var events []recorder.Event
	for _, a := range []string{"master", "worker-1", "worker-2"} {
		e := ev(recorder.TypeResourceSummary, a)
		e.CPUSeconds, e.PeakRSSKiB = 1.5, 40960
		events = append(events, e)
	}
	var buf bytes.Buffer
	if err := Render(&buf, "s1", events, nil); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if strings.Contains(html, "usage receipt</td>") {
		t.Error("a team's per-agent receipts were rendered as the session's single receipt")
	}
	for _, a := range []string{"master", "worker-1", "worker-2"} {
		if !strings.Contains(html, "usage receipt · "+a) {
			t.Errorf("no receipt row for %s", a)
		}
	}
}

// The report is one file. A compliance artefact that needs a CDN to render is
// not one, and a lane view is exactly where a chart library would creep in.
func TestTheReportIsSelfContained(t *testing.T) {
	html := render(t, []recorder.Event{
		ev(recorder.TypeCommandStart, "master"),
		ev(recorder.TypeCommandStart, "worker-1"),
	})
	for _, forbidden := range []string{"<script", "http://", "https://", "src="} {
		if strings.Contains(html, forbidden) {
			t.Errorf("the report reaches outside itself: found %q", forbidden)
		}
	}
}

// The gutter's column is explicit and load-bearing: grid's sparse
// auto-placement would otherwise scatter the timestamps into the lanes. A
// string assertion is a weak proxy for measuring it in a browser, and it is the
// assertion available here — so it locks the declaration in place.
func TestTheTimeGutterIsPinnedToColumnOne(t *testing.T) {
	html := render(t, []recorder.Event{ev(recorder.TypeCommandStart, "master")})
	if !strings.Contains(html, ".lanes .t{grid-column:1") {
		t.Error("the lane view's time gutter is not pinned to column 1")
	}
}

package digest

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// teamEvents mirrors host/watch_test.go's fixture of the same name, so this
// package's own expectations and the two consumers' can be read side by side.
func teamEvents() []recorder.Event {
	code0, code3 := 0, 3
	return []recorder.Event{
		{Type: recorder.TypeSessionStart, TS: "2026-08-23T10:00:00.000Z", Arch: "aarch64"},
		{Type: recorder.TypeCommandStart, TS: "2026-08-23T10:00:01.000Z", Agent: "master",
			Cmd: []string{"echo", "assembling"}, Call: "c1", Via: "exec"},
		{Type: recorder.TypeCommandExit, TS: "2026-08-23T10:00:01.100Z", Agent: "master",
			Call: "c1", Code: &code0},
		{Type: recorder.TypeCommandStart, TS: "2026-08-23T10:00:02.000Z", Agent: "worker-1",
			Cmd: []string{"scan"}, Call: "c2", Via: "exec"},
		{Type: recorder.TypeCommandExit, TS: "2026-08-23T10:00:02.100Z", Agent: "worker-1",
			Call: "c2", Code: &code3},
		{Type: recorder.TypeTeamMessage, TS: "2026-08-23T10:00:03.000Z", Agent: "master",
			Peer: "worker-1", Kind: "send", Bytes: 10},
		{Type: recorder.TypeTeamRefused, TS: "2026-08-23T10:00:04.000Z", Agent: "worker-1",
			Peer: "worker-2", Kind: "send", Bytes: 4, Reason: "no_edge"},
		{Type: recorder.TypeTeamStore, TS: "2026-08-23T10:00:05.000Z", Agent: "worker-1",
			Peer: "findings/a", Kind: "get", Outcome: "refused", Reason: "denied"},
	}
}

// A session that carries agents is a team, and lane order is boot order — no
// flag, no asking, the same rule both existing folds used.
func TestATeamIsDetectedAndOrderedByFirstAppearance(t *testing.T) {
	d := Walk(teamEvents())
	if !d.Team {
		t.Fatal("a chain naming agents was not recognised as a team")
	}
	if got := d.AgentOrder; len(got) != 2 || got[0] != "master" || got[1] != "worker-1" {
		t.Errorf("agent order = %v, want [master worker-1]", got)
	}
}

// Per-agent counters land in the right bucket, and stay out of the others'.
func TestPerAgentCounters(t *testing.T) {
	d := Walk(teamEvents())
	if d.Agents["master"].Commands != 1 {
		t.Errorf("master.Commands = %d, want 1", d.Agents["master"].Commands)
	}
	if d.Agents["worker-1"].Commands != 1 || d.Agents["worker-1"].Failed != 1 {
		t.Errorf("worker-1 = %+v, want Commands=1 Failed=1", d.Agents["worker-1"].Counters)
	}
	if d.Agents["master"].Failed != 0 {
		t.Errorf("master.Failed = %d, want 0 (its command exited 0)", d.Agents["master"].Failed)
	}
	// A session.start names no agent, so it must not land in either lane —
	// the exact failure a record whose whole purpose is "who did what" must
	// not make.
	if d.Session.Commands != 0 {
		t.Errorf("session.Commands = %d, want 0 (both commands were an agent's)", d.Session.Commands)
	}
}

// Totals is every event's contribution regardless of bucket — what
// internal/report has always shown. AgentTotals leaves the session's own
// agentless bucket out — what kelyfos watch's team status line has always
// shown. The two differ exactly when an agentless event occurs in a team
// session, which this fixture does not have, so here they agree; the point of
// having both is that a caller does not have to choose which to trust.
func TestTotalsAndAgentTotalsAgreeWhenNothingIsAgentless(t *testing.T) {
	d := Walk(teamEvents())
	tot, agentTot := d.Totals(), d.AgentTotals()
	if tot.Commands != 2 || tot.Failed != 1 {
		t.Errorf("Totals = %+v, want Commands=2 Failed=1", tot)
	}
	if agentTot != tot {
		t.Errorf("AgentTotals = %+v, want it to equal Totals (nothing agentless here): %+v", agentTot, tot)
	}

	// Now with one agentless command added: Totals sees it, AgentTotals does
	// not — reproducing the exact place the two existing folds diverge.
	events := append(teamEvents(), recorder.Event{
		Type: recorder.TypeCommandStart, TS: "2026-08-23T10:00:06.000Z", Call: "c3",
	})
	d2 := Walk(events)
	if got := d2.Totals().Commands; got != 3 {
		t.Errorf("Totals().Commands = %d, want 3", got)
	}
	if got := d2.AgentTotals().Commands; got != 2 {
		t.Errorf("AgentTotals().Commands = %d, want 2 (the agentless command excluded)", got)
	}
}

// The two existing folds have never agreed about what "refused" means for a
// team: report's Summary.TeamRefused counts a team.refused message and a
// refused spawn; kelyfos watch's status line adds a denied team.store on top.
// TeamRefused and AllRefusals reproduce each exactly, from the same counts,
// so neither consumer has to recompute — or re-diverge.
func TestTeamRefusedAndAllRefusalsDisagreeExactlyOnStoreDenials(t *testing.T) {
	d := Walk(teamEvents())
	if d.MessagesRefused != 1 {
		t.Errorf("MessagesRefused = %d, want 1", d.MessagesRefused)
	}
	if d.StoreRefused != 1 {
		t.Errorf("StoreRefused = %d, want 1", d.StoreRefused)
	}
	if got := d.TeamRefused(); got != 1 {
		t.Errorf("TeamRefused() = %d, want 1 (report's definition excludes the store denial)", got)
	}
	if got := d.AllRefusals(); got != 2 {
		t.Errorf("AllRefusals() = %d, want 2 (watch's definition includes it)", got)
	}
}

// Messages counts only delivered team.message events.
func TestMessagesCountsOnlyDelivered(t *testing.T) {
	d := Walk(teamEvents())
	if d.Messages != 1 {
		t.Errorf("Messages = %d, want 1", d.Messages)
	}
}

// Per-pair counts are directional and keyed on exactly who sent to whom.
func TestPerPairMessageCounts(t *testing.T) {
	d := Walk(teamEvents())
	sent := d.Pairs[Pair{"master", "worker-1"}]
	if sent == nil || sent.Messages != 1 || sent.Bytes != 10 {
		t.Errorf("master->worker-1 = %+v, want Messages=1 Bytes=10", sent)
	}
	refused := d.Pairs[Pair{"worker-1", "worker-2"}]
	if refused == nil || refused.Refused != 1 {
		t.Errorf("worker-1->worker-2 = %+v, want Refused=1", refused)
	}
	// The reverse direction was never sent, and must not exist.
	if _, ok := d.Pairs[Pair{"worker-1", "master"}]; ok {
		t.Error("a pair that never happened (worker-1 -> master) was recorded")
	}
}

// A peer that never generated its own event still needs a lane in a grid
// view — report's buildLanes has always minted one for the peer of a
// message, refusal or spawn. worker-2 here never acted, only received a
// refused send.
func TestAPeerThatNeverActedIsRecordedSeparatelyFromAgents(t *testing.T) {
	d := Walk(teamEvents())
	if len(d.PeerOnly) != 1 || d.PeerOnly[0] != "worker-2" {
		t.Errorf("PeerOnly = %v, want [worker-2]", d.PeerOnly)
	}
	// And a store key is not a peer worth a lane: findings/a is a key, not
	// an agent, and must never appear here.
	for _, p := range d.PeerOnly {
		if p == "findings/a" {
			t.Error("a store key was minted as a peer lane")
		}
	}
}

// A peer that later becomes a real agent must not also sit in PeerOnly — an
// agent is not a peer-only name.
func TestAPeerThatLaterActsIsNotDoubleListed(t *testing.T) {
	events := []recorder.Event{
		{Type: recorder.TypeTeamMessage, Agent: "master", Peer: "worker-1", Kind: "send"},
		{Type: recorder.TypeCommandStart, Agent: "worker-1", Call: "c1"},
	}
	d := Walk(events)
	if len(d.PeerOnly) != 0 {
		t.Errorf("PeerOnly = %v, want none: worker-1 went on to act", d.PeerOnly)
	}
	if len(d.AgentOrder) != 2 || d.AgentOrder[1] != "worker-1" {
		t.Errorf("AgentOrder = %v, want [master worker-1]", d.AgentOrder)
	}
}

// Store activity is bucketed by key, not by agent, with denials counted
// separately from the operations that went through.
func TestStoreActivityByKey(t *testing.T) {
	events := []recorder.Event{
		{Type: recorder.TypeTeamStore, Agent: "master", Peer: "findings/a", Kind: "put",
			Outcome: "delivered", Bytes: 100},
		{Type: recorder.TypeTeamStore, Agent: "worker-1", Peer: "findings/a", Kind: "get",
			Outcome: "delivered", Bytes: 100},
		{Type: recorder.TypeTeamStore, Agent: "worker-2", Peer: "findings/a", Kind: "delete",
			Outcome: "refused", Reason: "denied"},
	}
	d := Walk(events)
	sk := d.Store["findings/a"]
	if sk == nil {
		t.Fatal("no store activity recorded for findings/a")
	}
	if sk.Puts != 1 || sk.Gets != 1 || sk.Deletes != 1 || sk.Denied != 1 {
		t.Errorf("findings/a = %+v, want Puts=1 Gets=1 Deletes=1 Denied=1", sk)
	}
	if sk.Bytes != 200 {
		t.Errorf("findings/a.Bytes = %d, want 200 (the delivered ops only)", sk.Bytes)
	}
}

// Egress is bucketed per domain: allowed and blocked attempts, terminated
// connections, and the bytes each attempt reports.
func TestPerDomainEgress(t *testing.T) {
	allowed, blocked := true, false
	events := []recorder.Event{
		{Type: recorder.TypeEgressAttempt, Host: "api.example.com", Port: 443,
			Allowed: &allowed, Mode: "terminated", BytesIn: 500, BytesOut: 100},
		{Type: recorder.TypeEgressAttempt, Host: "api.example.com", Port: 443,
			Allowed: &allowed, Mode: "tunnelled", BytesIn: 10, BytesOut: 10},
		{Type: recorder.TypeEgressAttempt, Host: "evil.example.com", Port: 443,
			Allowed: &blocked, Reason: "not_in_allowlist"},
	}
	d := Walk(events)
	if got := d.DomainOrder; len(got) != 2 || got[0] != "api.example.com" || got[1] != "evil.example.com" {
		t.Errorf("DomainOrder = %v", got)
	}
	api := d.Domains["api.example.com"]
	if api.Allowed != 2 || api.Terminated != 1 {
		t.Errorf("api.example.com = %+v, want Allowed=2 Terminated=1", api)
	}
	if api.BytesIn != 510 || api.BytesOut != 110 {
		t.Errorf("api.example.com bytes = in %d out %d, want in 510 out 110", api.BytesIn, api.BytesOut)
	}
	evil := d.Domains["evil.example.com"]
	if evil.Blocked != 1 || evil.Allowed != 0 {
		t.Errorf("evil.example.com = %+v, want Blocked=1", evil)
	}
	if d.Terminated != 1 {
		t.Errorf("Digest.Terminated = %d, want 1", d.Terminated)
	}
	// A blocked attempt with no reachable host (bad_request can leave Host
	// empty per docs/events.md) must not mint a domain bucket for "".
	blockedNoHost := Walk([]recorder.Event{{Type: recorder.TypeEgressAttempt, Allowed: &blocked, Reason: "bad_request"}})
	if len(blockedNoHost.Domains) != 0 {
		t.Errorf("an egress attempt with no host minted a domain: %v", blockedNoHost.Domains)
	}
}

// Secrets are de-duplicated by name and host, in first-seen order, and never
// carry a value — only what secret.use itself already writes.
func TestSecretsAreDeduplicatedAndNeverCarryAValue(t *testing.T) {
	events := []recorder.Event{
		{Type: recorder.TypeSecretUse, Agent: "master", Name: "api-key", Host: "api.example.com"},
		{Type: recorder.TypeSecretUse, Agent: "master", Name: "api-key", Host: "api.example.com"},
		{Type: recorder.TypeSecretUse, Agent: "worker-1", Name: "db-pass", Host: "db.example.com"},
	}
	d := Walk(events)
	if len(d.Secrets) != 2 {
		t.Fatalf("Secrets = %v, want 2 de-duplicated entries", d.Secrets)
	}
	if d.Secrets[0] != (SecretRef{"api-key", "api.example.com"}) {
		t.Errorf("Secrets[0] = %+v", d.Secrets[0])
	}
	if d.Agents["master"].Secrets != 2 {
		t.Errorf("master.Secrets = %d, want 2 (the counter is not deduplicated, unlike the list)", d.Agents["master"].Secrets)
	}
}

// A command's output is decoded once here and accumulated onto the command's
// own timeline entry, stream-prefixed exactly as internal/report has always
// prefixed it — so a static view sees one entry per command, not one per
// output chunk.
func TestCommandOutputAccumulatesOntoItsCommand(t *testing.T) {
	code := 0
	events := []recorder.Event{
		{Type: recorder.TypeCommandStart, Agent: "worker-1", Call: "c1", Cmd: []string{"echo", "hi"}},
		{Type: recorder.TypeCommandOutput, Agent: "worker-1", Call: "c1", Stream: "stdout",
			Data: base64.StdEncoding.EncodeToString([]byte("hi\n"))},
		{Type: recorder.TypeCommandOutput, Agent: "worker-1", Call: "c1", Stream: "stderr",
			Data: base64.StdEncoding.EncodeToString([]byte("warning\n"))},
		{Type: recorder.TypeCommandExit, Agent: "worker-1", Call: "c1", Code: &code, DurationMS: 42},
	}
	d := Walk(events)
	if len(d.Timeline) != 1 {
		t.Fatalf("Timeline has %d entries, want 1 (command.output/exit fold into command.start)", len(d.Timeline))
	}
	entry := d.Timeline[0]
	want := "hi\nstderr: warning\n"
	if entry.Output != want {
		t.Errorf("Output = %q, want %q", entry.Output, want)
	}
	if entry.Code == nil || *entry.Code != 0 {
		t.Errorf("Code = %v, want 0", entry.Code)
	}
	if entry.DurationMS != 42 {
		t.Errorf("DurationMS = %d, want 42", entry.DurationMS)
	}
	if entry.Refused {
		t.Error("a command that exited 0 was marked Refused")
	}
}

// Absorb, called directly rather than through Walk, returns a transient entry
// for command.output and command.exit — what a live view needs to render the
// occurrence immediately, without waiting for or re-scanning the timeline.
func TestAbsorbReturnsATransientEntryForOutputAndExit(t *testing.T) {
	d := New()
	d.Absorb(recorder.Event{Type: recorder.TypeCommandStart, Agent: "a", Call: "c1"})

	out := d.Absorb(recorder.Event{Type: recorder.TypeCommandOutput, Agent: "a", Call: "c1",
		Data: base64.StdEncoding.EncodeToString([]byte("chunk"))})
	if out.Category != "command-output" || out.Text != "chunk" {
		t.Errorf("output entry = %+v", out)
	}

	code := 7
	exit := d.Absorb(recorder.Event{Type: recorder.TypeCommandExit, Agent: "a", Call: "c1", Code: &code})
	if exit.Category != "command-exit" || !exit.Refused {
		t.Errorf("exit entry = %+v, want Refused=true for a non-zero exit", exit)
	}
	// Neither transient entry was appended to the timeline — only the
	// command.start entry they belong to is there.
	if len(d.Timeline) != 1 {
		t.Errorf("Timeline has %d entries, want 1", len(d.Timeline))
	}
	if d.Agents["a"].Failed != 1 {
		t.Errorf("a.Failed = %d, want 1", d.Agents["a"].Failed)
	}
}

// Failed increments even when the exit names a call no command.start ever
// opened — both existing folds bumped their failure counter unconditionally
// on a non-zero exit, never gated on finding the owning command.
func TestFailedCountsEvenWithoutAMatchingCommandStart(t *testing.T) {
	code := 1
	d := New()
	entry := d.Absorb(recorder.Event{Type: recorder.TypeCommandExit, Agent: "a", Call: "ghost", Code: &code})
	if !entry.Refused {
		t.Error("an unmatched exit was not marked Refused")
	}
	if d.Agents["a"].Failed != 1 {
		t.Errorf("a.Failed = %d, want 1 even with no matching command.start", d.Agents["a"].Failed)
	}
}

// A delivered spawn is a flow between two lanes; a refused one is a cell in
// the asker's own lane, whether or not it names a peer — internal/report's
// buildLanes has always drawn it this way.
func TestSpawnFlowVersusCell(t *testing.T) {
	delivered := Walk([]recorder.Event{{Type: recorder.TypeTeamSpawn, Agent: "master",
		Peer: "master-spawn-1", Kind: "spawn", Outcome: "delivered"}})
	if !delivered.Timeline[0].Flow || delivered.Timeline[0].Refused {
		t.Errorf("delivered spawn = %+v, want Flow=true Refused=false", delivered.Timeline[0])
	}

	refused := Walk([]recorder.Event{{Type: recorder.TypeTeamSpawn, Agent: "master",
		Outcome: "refused", Reason: "budget_exhausted"}})
	if refused.Timeline[0].Flow || !refused.Timeline[0].Refused {
		t.Errorf("refused spawn = %+v, want Flow=false Refused=true", refused.Timeline[0])
	}
	if len(refused.PeerOnly) != 0 {
		t.Errorf("a refused spawn with no peer minted one: %v", refused.PeerOnly)
	}

	// A refusal that does name a peer (name_taken, not_a_spawned_worker per
	// docs/events.md) still mints that peer's lane, even though the row
	// itself is a cell rather than a flow.
	namedRefusal := Walk([]recorder.Event{{Type: recorder.TypeTeamSpawn, Agent: "master",
		Peer: "master-spawn-1", Outcome: "refused", Reason: "name_taken"}})
	if len(namedRefusal.PeerOnly) != 1 || namedRefusal.PeerOnly[0] != "master-spawn-1" {
		t.Errorf("PeerOnly = %v, want [master-spawn-1]", namedRefusal.PeerOnly)
	}
}

// Session-header fields come only from agentless events — a team's per-agent
// session.ready must not overwrite the session's single set of boot figures.
func TestSessionHeaderIgnoresPerAgentEvents(t *testing.T) {
	events := []recorder.Event{
		{Type: recorder.TypeSessionReady, BootMS: 1283, Kernel: "6.18.45"},
		{Type: recorder.TypeSessionReady, Agent: "worker-1", BootMS: 411},
	}
	d := Walk(events)
	if d.BootMS != 1283 || d.Kernel != "6.18.45" {
		t.Errorf("session header = boot %d kernel %q, want 1283 and 6.18.45", d.BootMS, d.Kernel)
	}
}

// A serve-mcp session is marked Served, from session.start's reason — but
// only when it also carries no single image, matching the fallback text this
// exists for (F-D33): a session.start that somehow named both an image and
// the serve-mcp reason should show that image, not override it.
func TestServedSessionIsMarked(t *testing.T) {
	d := Walk([]recorder.Event{{Type: recorder.TypeSessionStart, Reason: recorder.ReasonServeMCP}})
	if !d.Served {
		t.Error("a serve-mcp session.start did not mark Served")
	}

	named := Walk([]recorder.Event{{Type: recorder.TypeSessionStart, Reason: recorder.ReasonServeMCP, Image: "base"}})
	if named.Served {
		t.Error("Served was set even though the session.start named an image")
	}
}

// A receipt lands on the session when agentless, and on the agent when not —
// never both, and a team's per-agent receipts must never become the
// session's.
func TestReceiptGoesToTheRightBucket(t *testing.T) {
	d := Walk([]recorder.Event{
		{Type: recorder.TypeResourceSummary, Agent: "master", CPUSeconds: 1.5},
		{Type: recorder.TypeResourceSummary, CPUSeconds: 9.9},
	})
	if d.Receipt == nil || d.Receipt.CPUSeconds != 9.9 {
		t.Errorf("session receipt = %v, want CPUSeconds=9.9", d.Receipt)
	}
	if d.Agents["master"].Receipt == nil || d.Agents["master"].Receipt.CPUSeconds != 1.5 {
		t.Errorf("master's receipt = %v, want CPUSeconds=1.5", d.Agents["master"].Receipt)
	}
}

// An event type this package's switch does not classify still lands in the
// timeline, tagged "other" rather than silently dropped — the extension
// point session.policy and team.topology (P7-2, P7-3) will use.
func TestAnUnclassifiedTypeStillReachesTheTimeline(t *testing.T) {
	d := Walk([]recorder.Event{{Type: "session.policy"}})
	if len(d.Timeline) != 1 {
		t.Fatalf("Timeline has %d entries, want 1", len(d.Timeline))
	}
	if d.Timeline[0].Category != "other" {
		t.Errorf("Category = %q, want %q", d.Timeline[0].Category, "other")
	}
}

// Every event type this package's schema knows about must be classified into
// something other than "other" — a future field added to recorder.Event
// without a matching case here would otherwise pass silently. This mirrors
// the intent of TestSchemaCoversEveryType in internal/recorder: read the
// package's own type list rather than trust a hand-kept copy of it.
func TestEveryKnownEventTypeIsClassified(t *testing.T) {
	knownUnclassified := map[string]bool{
		// Written by hosts this project has, but not yet drawn by either
		// consumer this package folds for — recorded here so a reviewer
		// finds a deliberate list, not a silent gap.
		recorder.TypeSecretWithheld: true,
		recorder.TypeSecretScrubbed: true,
		recorder.TypeSessionPause:   true,
		recorder.TypeSessionResume:  true,
		recorder.TypeRunReview:      true,
		recorder.TypeShellStart:     true,
		recorder.TypeShellEnd:       true,
		recorder.TypeForwardAccept:  true,
	}
	for _, typ := range allEventTypes {
		d := Walk([]recorder.Event{{Type: typ}})
		got := d.Timeline[0].Category
		if got == "other" && !knownUnclassified[typ] {
			t.Errorf("%s classified as %q with no entry in knownUnclassified — "+
				"either give it a category or add it to the list deliberately", typ, got)
		}
	}
}

// A zero-value Digest — kelyfos watch's own choice, absorbing live from a
// session with no natural end — does not retain Timeline: nothing accumulates
// per event beyond the aggregates, which is what keeps a long-running watch's
// memory flat instead of growing with session length. New's Digest, and
// Walk's, do retain it — internal/report needs the whole thing.
func TestKeepTimelineControlsRetention(t *testing.T) {
	var live Digest // watch's shape: zero value, no New()
	for i := 0; i < 500; i++ {
		live.Absorb(recorder.Event{Type: recorder.TypeFileWrite, Path: "/x", Bytes: 1})
	}
	if len(live.Timeline) != 0 {
		t.Errorf("a zero-value Digest retained %d Timeline entries, want 0", len(live.Timeline))
	}
	// The aggregate is unaffected — only the per-event history is dropped.
	if live.Session.Files != 500 {
		t.Errorf("Session.Files = %d, want 500 even with Timeline unkept", live.Session.Files)
	}

	kept := New()
	for i := 0; i < 500; i++ {
		kept.Absorb(recorder.Event{Type: recorder.TypeFileWrite, Path: "/x", Bytes: 1})
	}
	if len(kept.Timeline) != 500 {
		t.Errorf("New()'s Digest kept %d Timeline entries, want 500", len(kept.Timeline))
	}
}

// Command output still accumulates onto its command, and Failed still counts
// a non-zero exit, even when Timeline itself is not retained — a live view
// needs the transient per-chunk text and the refusal flag Absorb returns, not
// the retained history.
func TestOutputAndExitStillFoldWithoutKeepingTimeline(t *testing.T) {
	var live Digest
	live.Absorb(recorder.Event{Type: recorder.TypeCommandStart, Agent: "a", Call: "c1"})
	out := live.Absorb(recorder.Event{Type: recorder.TypeCommandOutput, Agent: "a", Call: "c1",
		Data: base64.StdEncoding.EncodeToString([]byte("hi"))})
	if out.Text != "hi" {
		t.Errorf("output entry Text = %q, want %q", out.Text, "hi")
	}
	code := 3
	exit := live.Absorb(recorder.Event{Type: recorder.TypeCommandExit, Agent: "a", Call: "c1", Code: &code})
	if !exit.Refused {
		t.Error("a non-zero exit was not flagged Refused even without KeepTimeline")
	}
	if live.Agents["a"].Failed != 1 {
		t.Errorf("a.Failed = %d, want 1", live.Agents["a"].Failed)
	}
	if len(live.Timeline) != 0 {
		t.Errorf("Timeline has %d entries, want 0 (KeepTimeline unset)", len(live.Timeline))
	}
}

// openCommands is bounded by commands still running, not by how many have
// ever run: it is freed the moment a command's exit is absorbed, win or lose.
func TestOpenCommandsIsFreedOnExit(t *testing.T) {
	var d Digest
	for i := 0; i < 200; i++ {
		call := fmt.Sprintf("c%d", i)
		d.Absorb(recorder.Event{Type: recorder.TypeCommandStart, Agent: "a", Call: call})
		code := 0
		d.Absorb(recorder.Event{Type: recorder.TypeCommandExit, Agent: "a", Call: call, Code: &code})
	}
	if len(d.openCommands) != 0 {
		t.Errorf("openCommands has %d entries after every command exited, want 0", len(d.openCommands))
	}
	// One still running: exactly one left open.
	d.Absorb(recorder.Event{Type: recorder.TypeCommandStart, Agent: "a", Call: "still-running"})
	if len(d.openCommands) != 1 {
		t.Errorf("openCommands has %d entries with one command still running, want 1", len(d.openCommands))
	}
}

// A zero-value Digest — no call to New — is safe to Absorb into directly.
// kelyfos watch relies on this: a *watchModel built by a bare struct literal
// in a test, with its Digest field left at its zero value, must be able to
// absorb an event without a nil-map panic.
func TestAZeroValueDigestIsSafeToAbsorbInto(t *testing.T) {
	var d Digest
	entry := d.Absorb(recorder.Event{Type: recorder.TypeCommandStart, Agent: "a", Call: "c1"})
	if entry.Category != "command" {
		t.Fatalf("Absorb on a zero-value Digest produced %+v", entry)
	}
	if d.Agents["a"] == nil || d.Agents["a"].Commands != 1 {
		t.Errorf("a zero-value Digest did not fold the event: %+v", d.Agents["a"])
	}
	// Reading a field before ever absorbing anything must not panic either.
	var empty Digest
	if empty.AgentOrder != nil || len(empty.Agents) != 0 {
		t.Errorf("an untouched zero-value Digest is not empty: %+v", empty)
	}
}

var allEventTypes = []string{
	recorder.TypeSessionStart, recorder.TypeSessionReady, recorder.TypeSessionEnd,
	recorder.TypeCommandStart, recorder.TypeFileWrite, recorder.TypeEgressAttempt,
	recorder.TypeSecretUse, recorder.TypeSecretWithheld, recorder.TypeSecretScrubbed,
	recorder.TypeResourceOOM, recorder.TypeResourceTimeout, recorder.TypeResourceSummary,
	recorder.TypeTeamMessage, recorder.TypeTeamRefused, recorder.TypeTeamStore, recorder.TypeTeamSpawn,
	recorder.TypeMCPHostCall, recorder.TypeMCPHostResult, recorder.TypePluginCall, recorder.TypePluginCrash,
	recorder.TypeSessionPause, recorder.TypeSessionResume, recorder.TypeRunReview,
	recorder.TypeShellStart, recorder.TypeShellEnd, recorder.TypeForwardAccept,
}

// FuzzAbsorbNeverPanics is this package's hostile-input target: every string
// field on Event this package reads (Cmd joined, Path, Host, Name, Reason,
// Data, Kind, Outcome) is, in the product this feeds, a value a compromised
// or merely malformed guest, agent or store key could have produced —
// digest.Absorb sits between the flight recorder and two renderers, and both
// of those renderers now trust it to have already looked at the shape of
// this data once. Absorbing the same fuzzed event twice, once through a
// kept-Timeline Digest and once through a live one, exercises both of
// KeepTimeline's paths (P7-1) with one corpus.
func FuzzAbsorbNeverPanics(f *testing.F) {
	for _, typ := range allEventTypes {
		f.Add(typ, "agent-1", "peer-1", "call-1", "cmd one\x00cmd two", "example.com",
			"/etc/passwd", "api-key", "denied", "get", "delivered", "\x1b[2Jhi", 3, true)
	}
	f.Add("command.start", "", "", "", "", "", "", "", "", "", "", "", 0, false)
	f.Add("team.store", "a", "<script>alert(1)</script>", "c1", "", "", "", "",
		"", "delete", "refused", "", 0, false)

	f.Fuzz(func(t *testing.T, typ, agent, peer, call, cmd, host, path, name,
		reason, kind, outcome, data string, code int, allowed bool) {
		e := recorder.Event{
			Type: typ, Agent: agent, Peer: peer, Call: call,
			Cmd: strings.Split(cmd, "\x00"), Host: host, Path: path, Name: name,
			Reason: reason, Kind: kind, Outcome: outcome, Data: data,
			Code: &code, Allowed: &allowed, Mode: "terminated", Bytes: len(data),
		}

		kept := New()
		entry := kept.Absorb(e)
		if entry == nil {
			t.Fatal("Absorb returned a nil entry")
		}
		if entry.Category == "" {
			t.Errorf("entry for type %q has an empty Category", typ)
		}

		var live Digest
		live.Absorb(e)
		if len(live.Timeline) != 0 {
			t.Errorf("a zero-value Digest retained a Timeline entry for type %q", typ)
		}
	})
}

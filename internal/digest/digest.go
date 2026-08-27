// Package digest is the one fold over a session's flight recorder that every
// view builds on.
//
// Before this package existed there were two: host/watch.go's absorb() and
// internal/report's own three loops, each independently deciding what a
// command.exit means, which counter an egress.attempt bumps, and whether a
// team.store denial counts as a refusal — the same interpretation, written
// twice, with no guarantee the two copies agreed (they did not: see Refused
// and TeamRefused below). P7-1 replaces both with this package: Absorb walks
// one event and updates the aggregate every reader of the chain needs — the
// per-agent counters, the per-pair message counts, the per-domain egress, the
// store activity and the timeline — and Walk is Absorb run once per event over
// a whole chain. kelyfos watch calls Absorb live, as each event arrives from
// the tail of a running session; internal/report calls Walk once, over a
// chain it already holds in full. Both read the same struct afterwards.
//
// What this package deliberately does not do is decide how anything looks.
// Colour, CSS class names and column widths stay in the two packages that
// draw them, because a terminal and an HTML page are different artefacts with
// different constraints — the fold is what both need to agree on before
// either starts drawing.
//
// session.policy and team.topology (P7-2, P7-3) are not folded here yet:
// neither event type exists in today's schema. Absorb already forwards every
// event it does not recognise into Digest.Timeline unrecognised, so the two
// event types can be added to this file's switch the day they land, without
// either consumer changing again.
package digest

import (
	"encoding/base64"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// MaxDistinctKeys bounds how many distinct domains, store keys and message
// pairs a Digest will ever mint a map entry for.
//
// Every one of these is keyed on a value at least partly under a guest's
// choice: the host an egress.attempt names, the key a team.store access
// requests, the peer named in a team.message — every one recorded whether it
// was allowed or refused. kelyfos watch absorbs from a session this project's
// own threat model treats as hostile for as long as it keeps running, so
// `for i in $(seq 1 200000); do wget http://$i.evil/; done` must not be able
// to grow the *watcher's* own heap by one map entry per distinct hostname,
// without bound, for as long as the loop runs. Past the cap, a key already
// being tracked keeps accumulating normally; a genuinely new key sets the
// matching Truncated flag instead of minting another entry — the aggregate
// stays bounded, and says so, rather than silently stopping being accurate
// (the RENDER checklist's own "output bounded, and saying so when it
// truncates"). Applied unconditionally, not only when KeepTimeline is unset:
// internal/report reads a chain already large enough to have hit this is a
// chain a view should say so about too, not only a live one.
const MaxDistinctKeys = 4096

// Counters is one bucket's tally: a session's own, or one agent's. The two
// views disagree about which bucket an event lands in — watch keeps a team's
// agentless events and its agents' events apart; report sums both into one
// number — and Totals and AgentTotals below exist so each view can ask for
// the combination it wants without recomputing it.
type Counters struct {
	Commands, Failed, Files, EgressOK, EgressBlocked, Secrets int
}

// Add returns the elementwise sum of two Counters.
func (c Counters) Add(o Counters) Counters {
	return Counters{
		Commands:      c.Commands + o.Commands,
		Failed:        c.Failed + o.Failed,
		Files:         c.Files + o.Files,
		EgressOK:      c.EgressOK + o.EgressOK,
		EgressBlocked: c.EgressBlocked + o.EgressBlocked,
		Secrets:       c.Secrets + o.Secrets,
	}
}

// Agent is one team member's slice of the fold: its own counters, plus its
// usage receipt once resource.summary has been written for it.
type Agent struct {
	Name string
	Counters
	Receipt *recorder.Event
}

// SecretRef is one secret bound during the session, named but never valued —
// what secret.use already writes, folded into a de-duplicated, first-seen
// list the way internal/report's Summary.Secrets has always been built.
type SecretRef struct {
	Name, Host string
}

// Pair is a directional agent-to-peer relationship: who a message was sent
// from and to. Kept directional rather than unordered because an ask and its
// reply are different pairs, and a reach view (P7-7) wants to draw the
// direction, not just the fact that two agents talk.
type Pair struct {
	From, To string
}

// PairCounts is what happened between one directional pair.
type PairCounts struct {
	Messages, Refused int
	Bytes             int64
}

// Domain is one egress destination's activity — every attempt this session
// made against one host, allowed or not.
type Domain struct {
	Host                         string
	Allowed, Blocked, Terminated int
	BytesIn, BytesOut            int64
}

// StoreKey is one team-store key's activity across the session.
type StoreKey struct {
	Key                         string
	Gets, Puts, Deletes, Denied int
	Bytes                       int64
}

// Entry is one event, annotated with the three facts every view needs to
// decide how to draw it, without re-deriving them from the raw fields:
// Category is a view-neutral tag for what kind of thing this is (never a CSS
// class — the two views spell the same category differently, e.g. report's
// flat timeline calls a team.store denial "team-refused" while its lane view
// calls the same event "store"), Refused is whether this represents a denial,
// error or non-zero exit, and Flow is whether the event belongs to a
// relationship between two agents rather than to one agent's own lane.
//
// Entry embeds the recorder.Event it was built from, so every original field
// — Cmd, Path, Host, Reason, and the rest — is available under its own name
// for a view to format as it sees fit.
type Entry struct {
	recorder.Event
	Category string
	Refused  bool
	Flow     bool

	// Exited is set on a command.start entry once its command.exit has been
	// absorbed — distinct from Code being non-nil, which it is not: a
	// command can exit with no numeric code at all (a supervisor crash mid-
	// exec, docs/events.md's `error` case) and still need its Error shown. A
	// view must not use "Code != nil" as a proxy for "this command finished"
	// — that was P7-1's own regression, caught by review rather than by the
	// fold's own tests: it silently dropped the exit line and the error
	// detail together on exactly the event shape where the diagnostic
	// matters most.
	Exited bool

	// Output is filled in only on the command.start entry: the decoded,
	// stream-prefixed text of every command.output event that named the same
	// Call, accumulated here so a static view (the report) can show a
	// command's whole transcript as one block. A live view does not need
	// this — it renders each command.output event as it arrives, using the
	// transient entry Absorb returns for that event, whose Text field below
	// carries just that one chunk.
	Output string

	// Text is set only on the transient entry Absorb returns for a
	// command.output event: the base64 payload, decoded once here so neither
	// consumer decodes it again.
	Text string
}

// Digest is the aggregate a whole chain folds down to.
type Digest struct {
	Events int

	// Session header fields, taken only from agentless events — a team
	// writes one session.ready/session.end per member, and those must not
	// overwrite the session's own single set of boot figures (E2-9).
	Image, Arch, Kelyfos, Kernel, Supervisor string
	BootMS                                   int64
	Started, Ended, EndReason                string
	// SawSessionStart is whether an agentless session.start was ever
	// absorbed — distinct from Image being non-empty, which it is not: a
	// team or a server session.start legitimately carries no single image
	// and still happened. A view asking "what should I show for the image"
	// needs to tell "this chain has no single flavour" (fall back to a
	// label) apart from "this chain never told me" (show nothing) — a
	// malformed or partial chain with no session.start at all should not
	// have a view assert "per agent" about a fact it never received.
	SawSessionStart bool
	// Served marks a serve-mcp session, whose lanes are sandboxes rather
	// than agents (E4-4).
	Served bool

	TimedOut   string
	OOMKills   int
	Terminated int // egress.attempt allowed with mode "terminated"

	// Session is every agentless event's contribution. Totals is Session
	// plus every agent's — the number report has always shown, because its
	// counters increment once per event regardless of which bucket it also
	// lands in.
	Session Counters
	// Receipt is the agentless resource.summary, nil until the session ends
	// (or for a team, which writes one per agent instead — see Agents).
	Receipt *recorder.Event

	Secrets []SecretRef // de-duplicated by name+host, first-seen order
	// SecretsTruncated is set once a distinct name+host past MaxDistinctKeys
	// was seen and not added to Secrets. See MaxDistinctKeys.
	SecretsTruncated bool

	// Team is true the moment any event names an agent — no flag, no
	// asking, the same rule watch and report have always used.
	Team       bool
	AgentOrder []string
	Agents     map[string]*Agent
	// PeerOnly is a peer named only as the other end of a message or spawn,
	// who never generated an event of their own — still needs a lane in a
	// grid view, or a message to them has nowhere to point (report's
	// buildLanes has always minted these; watch never has).
	PeerOnly []string

	// Messages and MessagesRefused count team.message and team.refused.
	// SpawnRefused and StoreRefused are kept apart because the two existing
	// views disagree about which belong in "refused": report's
	// Summary.TeamRefused is Messages refused plus spawns refused; watch's
	// status line adds store denials on top. TeamRefused and AllRefusals
	// below are that difference, made explicit instead of silently
	// re-diverging in a third place.
	Messages, MessagesRefused, SpawnRefused, StoreRefused int

	PairOrder []Pair
	Pairs     map[Pair]*PairCounts
	// PairsTruncated is set once a distinct (From, To) past MaxDistinctKeys
	// was seen and not added to Pairs. See MaxDistinctKeys.
	PairsTruncated bool

	DomainOrder []string
	Domains     map[string]*Domain
	// DomainsTruncated is set once a distinct host past MaxDistinctKeys was
	// seen and not added to Domains. See MaxDistinctKeys.
	DomainsTruncated bool

	StoreOrder []string
	Store      map[string]*StoreKey
	// StoreTruncated is set once a distinct key past MaxDistinctKeys was
	// seen and not added to Store. See MaxDistinctKeys.
	StoreTruncated bool

	// KeepTimeline controls whether Absorb retains Timeline. A batch caller
	// that already holds a whole chain in memory — internal/report, via Walk,
	// which sets this — wants every entry retained for its lane and flat
	// views. A live, open-ended caller does not: kelyfos watch absorbs one
	// event at a time from a session with no natural end and never reads
	// Timeline back out, so retaining it anyway would be exactly the
	// unbounded growth host/watch.go's own bound() helper exists to refuse —
	// a long session's command.start entries, each accumulating its whole
	// command.output text, kept forever. The zero value is the safe default;
	// New and Walk are where a caller that wants the timeline opts in.
	KeepTimeline bool

	// Timeline is every event, in order, each annotated once, present only
	// when KeepTimeline is set. command.output and command.exit do not add
	// their own entry — they fold into the command.start entry they belong
	// to (Output, Code, DurationMS, Error), tracked via openCommands below —
	// so a static view sees one entry per command, matching what has always
	// been true of internal/report's Rows.
	Timeline []*Entry

	// openCommands holds the in-flight command.start entry for each open
	// Call, regardless of KeepTimeline: a live caller still needs
	// command.output and command.exit to find and update the command they
	// belong to, even though it is not keeping Timeline. An entry is removed
	// the moment its command.exit is absorbed, so this stays bounded by how
	// many commands are genuinely still running — not by how many have ever
	// run.
	openCommands map[string]*Entry
	seenSecret   map[string]bool // name+"@"+host, for Secrets' de-duplication
}

// New returns an empty Digest with KeepTimeline set, ready for a caller that
// wants the full record: internal/report's Walk uses this. Calling New is
// never required to Absorb safely — every map Absorb needs initialises
// itself lazily, so a plain &digest.Digest{}, or a zero-value Digest embedded
// by value in another struct (as host/watch.go's watchModel does, so a
// *watchModel built by a bare struct literal in a test is already safe to
// absorb into), works too. What differs is KeepTimeline: New's Digest keeps
// one, a zero-value Digest does not — the safe default for a live caller with
// no natural end to how many events it will ever absorb.
func New() *Digest {
	return &Digest{KeepTimeline: true}
}

// Walk folds a whole chain in one pass. Callers that already hold every event
// — internal/report, chiefly — use this; kelyfos watch calls Absorb directly,
// once per event, as its tail of the running session delivers them.
func Walk(events []recorder.Event) *Digest {
	d := New()
	for _, e := range events {
		d.Absorb(e)
	}
	return d
}

// Totals is every agentless event plus every agent's, added together — the
// number internal/report has always shown as a session's command/file/egress
// counts, because its loop incremented once per event regardless of which
// bucket (agent or session) that event also updated.
func (d *Digest) Totals() Counters {
	t := d.Session
	for _, a := range d.Agents {
		t = t.Add(a.Counters)
	}
	return t
}

// AgentTotals sums every agent's own counters, with the session's agentless
// bucket left out — what kelyfos watch's team status line has always shown
// (teamCommands, teamFailed, and so on), which is not Totals: an agentless
// event in a team session would count toward Totals but not AgentTotals.
func (d *Digest) AgentTotals() Counters {
	var t Counters
	for _, a := range d.Agents {
		t = t.Add(a.Counters)
	}
	return t
}

// TeamRefused is internal/report's definition of a team's refusals: a
// team.refused message plus a refused team.spawn. It does not count a denied
// team.store access — report's Summary.TeamRefused never has.
func (d *Digest) TeamRefused() int { return d.MessagesRefused + d.SpawnRefused }

// AllRefusals is kelyfos watch's definition: TeamRefused plus every denied
// team.store access, which the live view has always folded into its one
// "refused" counter on the status line.
func (d *Digest) AllRefusals() int { return d.TeamRefused() + d.StoreRefused }

func (d *Digest) agent(name string) *Agent {
	a, ok := d.Agents[name]
	if !ok {
		a = &Agent{Name: name}
		if d.Agents == nil {
			d.Agents = map[string]*Agent{}
		}
		d.Agents[name] = a
		d.AgentOrder = append(d.AgentOrder, name)
		d.Team = true
		// A name already carried in PeerOnly — addressed before it ever
		// acted, which the chain's own order does not guarantee will happen
		// the other way round — is a real agent now, not a peer-only one.
		// report's buildLanes reaches the same end state by making two full
		// passes over every event before deciding; a single streaming pass
		// reaches it by fixing the list up the moment the truth changes.
		for i, p := range d.PeerOnly {
			if p == name {
				d.PeerOnly = append(d.PeerOnly[:i], d.PeerOnly[i+1:]...)
				break
			}
		}
	}
	return a
}

// peer registers a name as needing a lane even though it may never generate
// an event of its own — the same rule internal/report's buildLanes has always
// applied to the peer of a team.message, team.refused or team.spawn.
func (d *Digest) peer(name string) {
	if name == "" {
		return
	}
	if _, ok := d.Agents[name]; ok {
		return
	}
	for _, p := range d.PeerOnly {
		if p == name {
			return
		}
	}
	d.PeerOnly = append(d.PeerOnly, name)
}

// pair returns p's counters, minting them the first time p is seen — unless
// MaxDistinctKeys distinct pairs already exist, in which case it returns nil
// and sets PairsTruncated rather than let a session naming an unbounded
// number of distinct peers grow this map without bound (see MaxDistinctKeys).
// A nil return means "do not update anything for this pair", not an error.
func (d *Digest) pair(p Pair) *PairCounts {
	pc, ok := d.Pairs[p]
	if ok {
		return pc
	}
	if len(d.Pairs) >= MaxDistinctKeys {
		d.PairsTruncated = true
		return nil
	}
	pc = &PairCounts{}
	if d.Pairs == nil {
		d.Pairs = map[Pair]*PairCounts{}
	}
	d.Pairs[p] = pc
	d.PairOrder = append(d.PairOrder, p)
	return pc
}

// domain is pair's counterpart for egress hosts. See pair and MaxDistinctKeys.
func (d *Digest) domain(host string) *Domain {
	dm, ok := d.Domains[host]
	if ok {
		return dm
	}
	if len(d.Domains) >= MaxDistinctKeys {
		d.DomainsTruncated = true
		return nil
	}
	dm = &Domain{Host: host}
	if d.Domains == nil {
		d.Domains = map[string]*Domain{}
	}
	d.Domains[host] = dm
	d.DomainOrder = append(d.DomainOrder, host)
	return dm
}

// store is pair's counterpart for store keys. See pair and MaxDistinctKeys.
func (d *Digest) store(key string) *StoreKey {
	sk, ok := d.Store[key]
	if ok {
		return sk
	}
	if len(d.Store) >= MaxDistinctKeys {
		d.StoreTruncated = true
		return nil
	}
	sk = &StoreKey{Key: key}
	if d.Store == nil {
		d.Store = map[string]*StoreKey{}
	}
	d.Store[key] = sk
	d.StoreOrder = append(d.StoreOrder, key)
	return sk
}

// count applies fn to the agent's counters when this event named one, and to
// the session's shared bucket otherwise — the one rule both existing folds
// used to bump a counter, made a single function instead of being repeated at
// every call site.
func count(agent *Agent, session *Counters, fn func(*Counters)) {
	if agent != nil {
		fn(&agent.Counters)
		return
	}
	fn(session)
}

// Absorb folds one event into the digest and returns the entry it produced —
// the annotated event for most types, or (for command.output and
// command.exit, which have no entry of their own) a transient entry
// describing just this occurrence, for a live view to render immediately.
// Absorb always mutates the Digest; the returned Entry is never nil.
func (d *Digest) Absorb(e recorder.Event) *Entry {
	d.Events++

	var agent *Agent
	if e.Agent != "" {
		agent = d.agent(e.Agent)
	}

	switch e.Type {
	case recorder.TypeCommandOutput:
		return d.absorbOutput(e)
	case recorder.TypeCommandExit:
		return d.absorbExit(e, agent)
	}

	entry := &Entry{Event: e}

	switch e.Type {
	case recorder.TypeSessionStart:
		entry.Category = "session"
		if e.Agent == "" {
			d.SawSessionStart = true
			d.Image, d.Arch, d.Kelyfos = e.Image, e.Arch, e.Kelyfos
			d.Started = e.TS
			// Served only when Image is blank too, matching the fallback it
			// exists for (F-D33): a session.start that somehow carried both
			// an image and the serve-mcp reason should show its image, not
			// override it.
			if e.Image == "" && e.Reason == recorder.ReasonServeMCP {
				d.Served = true
			}
		}

	case recorder.TypeSessionReady:
		entry.Category = "session"
		if e.Agent == "" {
			d.BootMS, d.Kernel, d.Supervisor = e.BootMS, e.Kernel, e.Supervisor
		}

	case recorder.TypeSessionEnd:
		entry.Category = "session"
		if e.Agent == "" {
			d.Ended, d.EndReason = e.TS, e.Reason
		}

	case recorder.TypeCommandStart:
		entry.Category = "command"
		count(agent, &d.Session, func(c *Counters) { c.Commands++ })

	case recorder.TypeFileWrite:
		entry.Category = "file"
		count(agent, &d.Session, func(c *Counters) { c.Files++ })

	case recorder.TypeEgressAttempt:
		entry.Category = "egress"
		allowed := e.Allowed != nil && *e.Allowed
		entry.Refused = !allowed
		count(agent, &d.Session, func(c *Counters) {
			if allowed {
				c.EgressOK++
			} else {
				c.EgressBlocked++
			}
		})
		terminated := allowed && e.Mode == "terminated"
		if terminated {
			d.Terminated++
		}
		if e.Host != "" {
			if dm := d.domain(e.Host); dm != nil {
				if allowed {
					dm.Allowed++
				} else {
					dm.Blocked++
				}
				if terminated {
					dm.Terminated++
				}
				dm.BytesIn += e.BytesIn
				dm.BytesOut += e.BytesOut
			}
		}

	case recorder.TypeSecretUse:
		entry.Category = "secret"
		count(agent, &d.Session, func(c *Counters) { c.Secrets++ })
		key := e.Name + "@" + e.Host
		if !d.seenSecret[key] {
			if len(d.Secrets) >= MaxDistinctKeys {
				d.SecretsTruncated = true
			} else {
				if d.seenSecret == nil {
					d.seenSecret = map[string]bool{}
				}
				d.seenSecret[key] = true
				d.Secrets = append(d.Secrets, SecretRef{e.Name, e.Host})
			}
		}

	case recorder.TypeTeamMessage, recorder.TypeTeamRefused:
		entry.Category = "team-message"
		entry.Flow = true
		refused := e.Type == recorder.TypeTeamRefused
		entry.Refused = refused
		if refused {
			d.MessagesRefused++
		} else {
			d.Messages++
		}
		d.peer(e.Peer)
		if pc := d.pair(Pair{e.Agent, e.Peer}); pc != nil {
			if refused {
				pc.Refused++
			} else {
				pc.Messages++
				pc.Bytes += int64(e.Bytes)
			}
		}

	case recorder.TypeTeamStore:
		entry.Category = "team-store"
		refused := e.Outcome != "delivered"
		entry.Refused = refused
		if refused {
			d.StoreRefused++
		}
		if sk := d.store(e.Peer); sk != nil {
			switch e.Kind {
			case "get":
				sk.Gets++
			case "put":
				sk.Puts++
			case "delete":
				sk.Deletes++
			}
			if refused {
				sk.Denied++
			} else {
				sk.Bytes += int64(e.Bytes)
			}
		}

	case recorder.TypeTeamSpawn:
		entry.Category = "team-spawn"
		delivered := e.Outcome == "delivered"
		entry.Refused = !delivered
		entry.Flow = delivered
		if !delivered {
			d.SpawnRefused++
		}
		d.peer(e.Peer)

	case recorder.TypeResourceOOM:
		entry.Category = "oom"
		entry.Refused = true
		d.OOMKills++

	case recorder.TypeResourceTimeout:
		entry.Category = "oom"
		entry.Refused = true
		d.TimedOut = e.Budget

	case recorder.TypeResourceSummary:
		entry.Category = "session"
		ev := e
		if agent != nil {
			agent.Receipt = &ev
		} else {
			d.Receipt = &ev
		}

	case recorder.TypePluginCall:
		entry.Category = "plugin"
		entry.Refused = e.Outcome != "ok"

	case recorder.TypePluginCrash:
		entry.Category = "plugin"
		entry.Refused = true

	case recorder.TypeMCPHostCall:
		entry.Category = "client"

	case recorder.TypeMCPHostResult:
		entry.Category = "client"
		entry.Refused = e.Outcome != "ok"

	default:
		// session.policy and team.topology (P7-2, P7-3) land here until
		// those event types exist, and any future type does the same: the
		// entry is still recorded, still visible in Timeline, and this
		// package's own tests catch a category that never gets classified
		// once the switch above is extended to it.
		entry.Category = "other"
	}

	if d.KeepTimeline {
		d.Timeline = append(d.Timeline, entry)
	}
	if e.Type == recorder.TypeCommandStart {
		// Tracked regardless of KeepTimeline: command.output and
		// command.exit still need to find this entry to fold into, even for
		// a caller that is not retaining Timeline.
		if d.openCommands == nil {
			d.openCommands = map[string]*Entry{}
		}
		d.openCommands[e.Call] = entry
	}
	return entry
}

// absorbOutput decodes one command.output event once — instead of once per
// consumer, which is what host/watch.go and internal/report each did before
// this package existed — accumulates it onto the command.start entry it
// belongs to, and returns a transient entry carrying just this chunk for a
// live view to render immediately.
//
// The accumulation itself is gated on KeepTimeline, not just its presence in
// Timeline: openCommands tracks the owning entry regardless of KeepTimeline
// (Code/DurationMS/Error/Refused all need it), but Output is the one field on
// that entry that grows with the command's own output volume rather than
// with the chain's event count — a still-running command watched live can
// print without bound, and appending to a Go string on every chunk is
// O(n^2) over its lifetime on top of that. A live caller (KeepTimeline
// false) never reads Output back — it renders each chunk's own Text as it
// arrives — so there is nothing to accumulate for; only a caller that opted
// into keeping Timeline (internal/report, building one block of output per
// command) needs it, and pays for it. This is the same defect class
// KeepTimeline itself was added to close, in the one place it was left
// half-open: tracking the owner unconditionally was correct, growing an
// unbounded field on it regardless of KeepTimeline was not.
func (d *Digest) absorbOutput(e recorder.Event) *Entry {
	data, _ := base64.StdEncoding.DecodeString(e.Data)
	text := string(data)
	if d.KeepTimeline {
		if owner, ok := d.openCommands[e.Call]; ok {
			prefix := ""
			if e.Stream == "stderr" {
				prefix = "stderr: "
			}
			owner.Output += prefix + text
		}
	}
	return &Entry{Event: e, Category: "command-output", Text: text}
}

// absorbExit folds a command's exit into the command.start entry it belongs
// to — Code, DurationMS, Error and whether it counts as a failure — and bumps
// Failed regardless of whether the owning entry was found, matching both
// existing folds: report's Summary.Failed and watch's failed counters have
// always incremented unconditionally on a non-zero exit.
//
// The command is removed from openCommands here, win or lose: nothing after
// its own exit event can still be attributed to it, so there is no reason to
// keep it reachable by Call — which is what bounds openCommands to commands
// that are genuinely still running, for a caller like kelyfos watch that
// absorbs from a session with no natural end.
func (d *Digest) absorbExit(e recorder.Event, agent *Agent) *Entry {
	code := -1
	if e.Code != nil {
		code = *e.Code
	}
	refused := code != 0
	if owner, ok := d.openCommands[e.Call]; ok {
		owner.Code = e.Code
		owner.DurationMS = e.DurationMS
		owner.Error = e.Error
		owner.Refused = refused
		owner.Exited = true
		delete(d.openCommands, e.Call)
	}
	if refused {
		count(agent, &d.Session, func(c *Counters) { c.Failed++ })
	}
	return &Entry{Event: e, Category: "command-exit", Refused: refused}
}

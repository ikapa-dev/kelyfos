// Package report renders a session's flight recorder as a single self-contained
// HTML file.
//
// It is the answer to "what did the agent do?" in a form someone can open, read
// and forward without installing anything — no server, no JavaScript
// dependencies, no network. Everything comes from the JSONL in docs/events.md;
// this is a view, and the schema is the product.
package report

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/digest"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// View is what the template renders.
type View struct {
	SessionID string
	Generated string
	Events    int
	// ChainHead is the digest the record ends on, printed as text so a reader
	// holding two reports of the same session can tell whether they hold the
	// same record. Empty when the chain does not verify: a head read off a line
	// nobody could check is a number a reader would quote.
	ChainHead string
	// Chain is the record itself, base64 of the file as the host wrote it. It
	// is why this page is evidence rather than a claim about one, and it is
	// template.HTML for a reason chain.go states at length: the escaper rewrites
	// `+`, which is an ordinary base64 character.
	Chain      template.HTML
	ChainBytes int
	// SelfCheck is what the exporter's own verification said, and it is
	// rendered only when it said the chain is broken. A page that certifies
	// itself is worth nothing; a page that reports a problem with itself is
	// worth reading, and dropping the failure to avoid the appearance of a
	// verdict would be hiding the one sentence a reader needs.
	SelfCheck string
	// Signed is what the page says about who exported it, empty when nobody
	// signed. An unsigned report is an ordinary report: the signature is
	// optional by construction, and the page never renders "unsigned" as a
	// finding (P6-7).
	Signed      Signature
	Fingerprint string
	Summary     Summary
	Rows        []Row
	// Lanes is the team view: one column per agent, in boot order. Empty for a
	// session with one machine in it, and the whole lane section then does not
	// render at all (E2-7).
	Lanes     []string
	LaneRows  []LaneRow
	LaneWidth template.CSS
	// Served marks a serve-mcp session, whose lanes are sandboxes rather than
	// agents. The drawing is identical; the words around it are not, and a page
	// that called six sandboxes a team would be wrong on the one point the lane
	// view exists to make (E4-4).
	Served bool
}

// LaneRow is one entry in the team view. It is the same information the
// timeline carries, placed in a column instead of a list — because "who told
// what to whom" is a question about position, and a single ordered list makes
// the reader reconstruct the positions in their head.
type LaneRow struct {
	Time    string
	Kind    string
	Title   string
	Detail  string
	Output  string
	IsError bool
	// Place is the CSS grid placement, computed in Go because a template
	// cannot do arithmetic and a lane view is entirely arithmetic.
	Place template.CSS
	// Flow marks a message between two lanes, drawn as a bar spanning them
	// rather than as a cell inside one.
	Flow bool
}

// Summary is the at-a-glance answer, so a reader does not have to scroll a
// hundred command outputs to learn whether anything left the box.
type Summary struct {
	Image        string
	Arch         string
	Kelyfos      string
	Kernel       string
	Supervisor   string
	BootMS       int64
	Started      string
	Ended        string
	EndReason    string
	Commands     int
	Failed       int
	FilesWritten int
	EgressOK     int
	EgressBlock  int
	Terminated   int
	OOMKills     int
	TeamMessages int
	TeamRefused  int
	TimedOut     string
	Secrets      []string
	// Usage is the receipt: what the sandbox actually consumed, and what it was
	// allowed to. Nil for a session that ended before one was written.
	Usage *Usage
}

// Usage is the rendered form of the resource.summary event.
type Usage struct {
	CPUSeconds float64
	CPUQuota   int
	Vcpus      int
	PeakRSS    string
	MemMiB     int
	NetIn      string
	NetOut     string
	DiskRead   string
	DiskWrite  string
}

// Row is one line of the timeline.
type Row struct {
	Time    string
	Kind    string // css class
	Title   string
	Detail  string
	Output  string
	IsError bool
}

// Render writes the report from a session's flight recorder.
//
// It takes the record's bytes rather than its parsed events, and that is the
// whole design: the page and the record embedded in it are made from one blob
// by one call, so a report whose visible timeline was drawn from different
// events than it carries cannot be produced. It also means the embedded record
// is the file the host wrote, byte for byte, which is what verification needs
// (chain.go).
//
// It returns the number of events it rendered, so the caller's summary and the
// page cannot disagree about what is in the file they describe.
// Render writes an unsigned report. Most callers want this.
func Render(w io.Writer, sessionID string, chain []byte) (events int, err error) {
	return RenderSigned(w, sessionID, chain, nil)
}

// RenderSigned writes a report, signed when a key is given (P6-7).
//
// The key is the caller's, never one this package makes: a signature by a key
// nobody has seen proves that one process made both halves, which the chain
// already proves, and it invites a reader to stop asking.
func RenderSigned(w io.Writer, sessionID string, chain []byte, key ed25519.PrivateKey) (events int, err error) {
	parsed, err := recorder.Read(bytes.NewReader(chain))
	if err != nil {
		return 0, err
	}
	_, head, verifyErr := recorder.Verify(bytes.NewReader(chain))
	v := View{
		SessionID:  sessionID,
		Generated:  time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Events:     len(parsed),
		ChainHead:  head,
		Chain:      embedChain(chain),
		ChainBytes: len(chain),
	}
	if verifyErr != nil {
		v.SelfCheck = verifyErr.Error()
	}
	if key != nil {
		// A broken chain has no head, and signing one would put a signature
		// over an empty string — a statement about nothing that still reads as
		// a statement.
		if verifyErr != nil {
			return 0, fmt.Errorf("this record does not verify, so there is nothing worth signing: %w", verifyErr)
		}
		sig, err := SignChain(chain, head, key)
		if err != nil {
			return 0, err
		}
		v.Signed, v.Fingerprint = sig, sig.Fingerprint()
	}

	// The fold. This used to be three loops — this one, and buildLanes'
	// two — each independently deciding what a command.exit means and
	// whether a team.store denial counts as a refusal. Now the chain is
	// walked once (internal/digest), and the summary, the flat timeline and
	// the lane view are three cheap translations of that one result rather
	// than three re-interpretations of the raw events (P7-1).
	d := digest.Walk(parsed)
	fillSummary(&v, d)
	v.Rows = timelineRows(d)
	v.Lanes, v.LaneRows = buildLanes(d)
	if n := len(v.Lanes); n > 0 {
		v.LaneWidth = template.CSS(fmt.Sprintf("grid-template-columns:88px repeat(%d,minmax(0,1fr))", n))
	}
	if err := tmpl.Execute(w, v); err != nil {
		return 0, err
	}
	// The count the page shows, returned rather than recomputed by the caller.
	// The CLI used to print recorder.Verify's own count here, which is the
	// length of the verified *prefix* and not the number of events in the file
	// — so a broken chain made the command's summary disagree with the page it
	// had just written, about the page.
	return len(parsed), nil
}

// shownImage is what the header and the session-start row both say the
// image was: the recorded flavor, or — when a team or a server left it blank
// because no single flavor covers every machine — a fallback that names which
// kind of hole this is rather than rendering an empty one (F-D33).
func shownImage(d *digest.Digest) string {
	if d.Image != "" {
		return d.Image
	}
	if d.Served {
		return "per sandbox"
	}
	return "per agent"
}

// fillSummary is the at-a-glance header, built from the fold rather than by
// re-walking the chain: every field here was already computed once by
// digest.Walk.
func fillSummary(v *View, d *digest.Digest) {
	v.Served = d.Served
	tot := d.Totals()
	v.Summary = Summary{
		Image: shownImage(d), Arch: d.Arch, Kelyfos: d.Kelyfos,
		Kernel: d.Kernel, Supervisor: d.Supervisor, BootMS: d.BootMS,
		Started: d.Started, Ended: d.Ended, EndReason: d.EndReason,
		// Totals, not Session: the header has always counted every command,
		// file write and egress attempt regardless of which agent (or none)
		// made it — see digest.Digest.Totals.
		Commands: tot.Commands, Failed: tot.Failed, FilesWritten: tot.Files,
		EgressOK: tot.EgressOK, EgressBlock: tot.EgressBlocked,
		Terminated: d.Terminated, OOMKills: d.OOMKills,
		// TeamRefused, not AllRefusals: the header has never counted a
		// denied store access as a "team refused", only a refused message or
		// spawn (digest.Digest.TeamRefused documents the split).
		TeamMessages: d.Messages, TeamRefused: d.TeamRefused(),
		TimedOut: d.TimedOut,
	}
	for _, s := range d.Secrets {
		v.Summary.Secrets = append(v.Summary.Secrets, s.Name+" → "+s.Host)
	}
	if d.Receipt != nil {
		e := d.Receipt
		v.Summary.Usage = &Usage{
			CPUSeconds: e.CPUSeconds, CPUQuota: e.CPUQuota, Vcpus: e.VcpuCount,
			PeakRSS: HumanKiB(e.PeakRSSKiB), MemMiB: e.MemMiB,
			NetIn: HumanBytes(e.NetInBytes), NetOut: HumanBytes(e.NetOutBytes),
			DiskRead: HumanBytes(e.DiskReadBytes), DiskWrite: HumanBytes(e.DiskWriteBytes),
		}
	}
}

// shortTS is the clock the flat timeline and the lane view have always
// shown: HH:MM:SS.mmm, trimmed out of the full RFC 3339 timestamp.
func shortTS(ts string) string {
	if len(ts) > 23 {
		return ts[11:23]
	}
	return ts
}

// timelineRows turns the fold's timeline into the flat view — the report
// exactly as it read before teams existed, and as it still reads for a
// session with no agents in it.
//
// Output is attached to the command it belongs to already: digest.Absorb
// accumulated every command.output onto its command.start entry as the chain
// was walked, so there is nothing left to correlate here — a transcript
// where output floats away from its command is not a transcript, and now
// that rule lives in one place rather than in this loop and buildLanes'.
func timelineRows(d *digest.Digest) []Row {
	var rows []Row
	for _, en := range d.Timeline {
		ts := shortTS(en.TS)
		switch en.Type {
		case recorder.TypeSessionStart:
			detail := fmt.Sprintf("image %s · arch %s · kelyfos %s", shownImage(d), en.Arch, en.Kelyfos)
			// A restored or forked machine says what it came from here, and a
			// cold boot records no reason at all, so this adds nothing to the
			// common case and everything to the one that needs it.
			if en.Reason != "" {
				detail += " · " + en.Reason
			}
			rows = append(rows, Row{ts, "session", "session start", detail, "", false})
		case recorder.TypeSessionReady:
			// A team writes one of these per member, so the header's single set
			// of boot figures would end up being whichever agent was last —
			// with the kernel and supervisor blank, because the team's copy
			// records how the machine started rather than what booted (E2-9).
			if en.Agent != "" {
				rows = append(rows, Row{ts, "session", en.Agent + " ready",
					fmt.Sprintf("%d ms · %s · image %s", en.BootMS, bootPath(en.Via), en.Image), "", false})
				break
			}
			overlay := "overlay unknown"
			if en.Overlay != nil {
				overlay = fmt.Sprintf("overlay %t", *en.Overlay)
			}
			rows = append(rows, Row{ts, "session", "ready",
				fmt.Sprintf("%d ms · kernel %s · supervisor %s · %s", en.BootMS, en.Kernel, en.Supervisor, overlay), "", false})
		case recorder.TypeSessionEnd:
			rows = append(rows, Row{ts, "session", "session end",
				fmt.Sprintf("%s after %d ms", en.Reason, en.DurationMS), "", false})
		case recorder.TypeCommandStart:
			detail := "via " + en.Via
			if en.Code != nil {
				detail += fmt.Sprintf(" · exit %d · %d ms", *en.Code, en.DurationMS)
				if en.Error != nil {
					detail += fmt.Sprintf(" · %s: %s", en.Error.Kind, en.Error.Message)
				}
			}
			rows = append(rows, Row{ts, "command", strings.Join(en.Cmd, " "), detail, en.Output, en.Refused})
		case recorder.TypeFileWrite:
			rows = append(rows, Row{ts, "file", "write " + en.Path,
				fmt.Sprintf("%d bytes · sha256 %s · via %s", en.Bytes, short(en.SHA256), en.Via), "", false})
		case recorder.TypeEgressAttempt:
			kind, title := "egress-blocked", "BLOCKED "+en.Host
			if !en.Refused {
				kind, title = "egress", "egress "+en.Host
			}
			detail := fmt.Sprintf("port %d", en.Port)
			if en.Mode != "" {
				detail += " · " + en.Mode
			}
			if en.Reason != "" {
				detail += " · " + en.Reason
			}
			if en.BytesIn > 0 || en.BytesOut > 0 {
				detail += fmt.Sprintf(" · %d in / %d out", en.BytesIn, en.BytesOut)
			}
			rows = append(rows, Row{ts, kind, title, detail, "", en.Refused})
		case recorder.TypePluginCall:
			detail := fmt.Sprintf("%s · %d ms", en.Outcome, en.DurationMS)
			if en.Args != "" {
				detail = en.Args + " · " + detail
			}
			rows = append(rows, Row{ts, "plugin", en.Name + "_" + en.Tool, detail, "", en.Refused})
		case recorder.TypePluginCrash:
			rows = append(rows, Row{ts, "plugin", "plugin " + en.Name + " stopped", en.Reason, "", true})
		case recorder.TypeSecretUse:
			rows = append(rows, Row{ts, "secret", "secret " + en.Name,
				"sent to " + en.Host + " · the value is not recorded anywhere", "", false})
		case recorder.TypeTeamMessage, recorder.TypeTeamRefused:
			// The same arrow the lane view draws. A reply points back, because
			// it travels the return path of the ask that provoked it — and the
			// two views rendering one event in opposite directions is worse
			// than either being wrong on its own (F-D33).
			arrow := "→"
			if en.Kind == "reply" {
				arrow = "←"
			}
			kind, title := "team", fmt.Sprintf("%s %s %s", en.Agent, arrow, en.Peer)
			if en.Refused {
				kind, title = "team-refused", fmt.Sprintf("REFUSED %s %s %s", en.Agent, arrow, en.Peer)
			}
			detail := fmt.Sprintf("%s · %d bytes · sha256 %s", en.Kind, en.Bytes, short(en.SHA256))
			if en.Reason != "" {
				detail += " · " + en.Reason
			}
			rows = append(rows, Row{ts, kind, title, detail, en.Data, en.Refused})
		case recorder.TypeTeamSpawn:
			if en.Refused {
				rows = append(rows, Row{ts, "team-refused", "REFUSED spawn by " + en.Agent, en.Reason, "", true})
				break
			}
			rows = append(rows, Row{ts, "team", fmt.Sprintf("%s %s", en.Kind, en.Peer), "requested by " + en.Agent, "", false})
		case recorder.TypeTeamStore:
			detail := en.Outcome
			if en.Reason != "" {
				detail += " · " + en.Reason
			}
			if en.Bytes > 0 {
				detail += fmt.Sprintf(" · %d bytes", en.Bytes)
			}
			kind := "team"
			if en.Refused {
				kind = "team-refused"
			}
			rows = append(rows, Row{ts, kind, fmt.Sprintf("%s %s %s", en.Agent, en.Kind, en.Peer), detail, "", en.Refused})
		case recorder.TypeResourceSummary:
			// A team writes one receipt per agent into the same chain, so the
			// header's single receipt would show whichever machine stopped
			// last and call it the session's. Those become timeline rows
			// instead, and the header keeps the receipt only when there is
			// exactly one machine to have one (E1-7, E2-7).
			if en.Agent != "" {
				rows = append(rows, Row{ts, "session", "usage receipt · " + en.Agent,
					fmt.Sprintf("%.2f CPU-seconds%s · peak RSS %s · net %s in / %s out · disk %s written",
						en.CPUSeconds, quotaNote(en.Event), HumanKiB(en.PeakRSSKiB),
						HumanBytes(en.NetInBytes), HumanBytes(en.NetOutBytes),
						HumanBytes(en.DiskWriteBytes)), "", false})
			}
		case recorder.TypeResourceTimeout:
			rows = append(rows, Row{ts, "oom", "timed out on " + en.Budget,
				fmt.Sprintf("budget %s · ran %s",
					time.Duration(en.BudgetMS)*time.Millisecond,
					(time.Duration(en.ElapsedMS) * time.Millisecond).Round(time.Second)), "", true})
		case recorder.TypeResourceOOM:
			// Flagged the way a blocked egress attempt is: this is a limit
			// firing, and a reader skimming the transcript should not have to
			// hunt for it.
			detail := fmt.Sprintf("pid %d · %s resident", en.PID, HumanKiB(en.RSSKiB))
			if en.MemMiB > 0 {
				detail += fmt.Sprintf(" · the machine had %d MiB", en.MemMiB)
			}
			rows = append(rows, Row{ts, "oom", "OOM-killed " + en.Comm, detail, "", true})
		}
	}
	return rows
}

// buildLanes turns the fold's timeline into a per-agent view.
//
// Lane order is first-appearance order, which for a team is boot order, so the
// columns read like the file the user wrote. An event with no agent belongs to
// the team rather than to any member and spans every lane; a message between
// two agents spans exactly the columns it connects, which is the whole point of
// drawing it this way instead of listing it (E2-7).
func buildLanes(d *digest.Digest) ([]string, []LaneRow) {
	if len(d.AgentOrder) == 0 {
		return nil, nil
	}
	// AgentOrder first, then PeerOnly: an agent who acted gets a column from
	// its own events; a peer who was only ever addressed — the other end of
	// a message, refusal or spawn, never generating an event of its own —
	// still needs one, or a message to them has nowhere to point.
	lanes := append(append([]string{}, d.AgentOrder...), d.PeerOnly...)
	col := make(map[string]int, len(lanes))
	for i, name := range lanes {
		col[name] = i
	}

	// grid-column is 1-based and column 1 is the time gutter, so a lane at
	// index i starts at i+2.
	wide := template.CSS(fmt.Sprintf("grid-column:2/%d", len(lanes)+2))
	// laneOf places an event in its agent's column — or across all of them when
	// it names no agent. Looking the name up in the map and using the zero
	// value would put an agentless event in the *first* agent's lane and
	// attribute it to a machine that had nothing to do with it, which in a
	// record whose whole purpose is saying who did what is the worst available
	// failure.
	laneOf := func(agent string) template.CSS {
		i, ok := col[agent]
		if !ok {
			return wide
		}
		return template.CSS(fmt.Sprintf("grid-column:%d", i+2))
	}
	span := func(a, b int) template.CSS {
		if a > b {
			a, b = b, a
		}
		return template.CSS(fmt.Sprintf("grid-column:%d/%d", a+2, b+3))
	}

	// Output is already attached to its command — digest.Absorb accumulated
	// every command.output onto the command.start entry as the chain was
	// walked — so there is no byCall bookkeeping left to do here either.
	var rows []LaneRow
	for _, en := range d.Timeline {
		ts := shortTS(en.TS)
		add := func(r LaneRow) { rows = append(rows, r) }

		switch en.Type {
		case recorder.TypeTeamMessage, recorder.TypeTeamRefused:
			from, to := col[en.Agent], col[en.Peer]
			arrow := "→"
			if en.Kind == "reply" {
				arrow = "←"
			}
			kind, title := "team", fmt.Sprintf("%s %s %s", en.Agent, arrow, en.Peer)
			if en.Refused {
				kind = "team-refused"
				title = "REFUSED " + title
			}
			detail := fmt.Sprintf("%s · %d bytes · sha256 %s", en.Kind, en.Bytes, short(en.SHA256))
			if en.Reason != "" {
				detail += " · " + en.Reason
			}
			add(LaneRow{ts, kind, title, detail, en.Data, en.Refused, span(from, to), true})

		case recorder.TypeTeamStore:
			// Inline in the acting agent's lane, because a store access is
			// something one agent did, not a message between two.
			kind := "store"
			if en.Refused {
				kind = "team-refused"
			}
			detail := en.Outcome
			if en.Reason != "" {
				detail += " · " + en.Reason
			}
			if en.Bytes > 0 {
				detail += fmt.Sprintf(" · %d bytes", en.Bytes)
			}
			add(LaneRow{ts, kind, fmt.Sprintf("store %s %s", en.Kind, en.Peer), detail, "",
				en.Refused, laneOf(en.Agent), false})

		case recorder.TypeTeamSpawn:
			if en.Refused {
				add(LaneRow{ts, "team-refused", "REFUSED spawn", en.Reason, "",
					true, laneOf(en.Agent), false})
				break
			}
			add(LaneRow{ts, "team", en.Kind + " " + en.Peer, "requested by " + en.Agent, "",
				false, span(col[en.Agent], col[en.Peer]), true})

		case recorder.TypeCommandStart:
			detail := "via " + en.Via
			if en.Code != nil {
				detail += fmt.Sprintf(" · exit %d", *en.Code)
			}
			add(LaneRow{ts, "command", strings.Join(en.Cmd, " "), detail, en.Output, en.Refused, laneOf(en.Agent), false})
		case recorder.TypeFileWrite:
			add(LaneRow{ts, "file", "write " + en.Path,
				fmt.Sprintf("%d bytes · %s", en.Bytes, short(en.SHA256)), "",
				false, laneOf(en.Agent), false})
		case recorder.TypeEgressAttempt:
			kind, title := "egress-blocked", "BLOCKED "+en.Host
			if !en.Refused {
				kind, title = "egress", "egress "+en.Host
			}
			detail := en.Mode
			if en.Reason != "" {
				detail += " " + en.Reason
			}
			add(LaneRow{ts, kind, title, detail, "", en.Refused, laneOf(en.Agent), false})
		case recorder.TypeSecretUse:
			add(LaneRow{ts, "secret", "secret " + en.Name, "sent to " + en.Host, "",
				false, laneOf(en.Agent), false})
		case recorder.TypeResourceOOM:
			add(LaneRow{ts, "oom", "OOM-killed " + en.Comm,
				fmt.Sprintf("pid %d · %s resident", en.PID, HumanKiB(en.RSSKiB)), "",
				true, laneOf(en.Agent), false})
		case recorder.TypeResourceTimeout:
			add(LaneRow{ts, "oom", "timed out on " + en.Budget,
				fmt.Sprintf("budget %s", time.Duration(en.BudgetMS)*time.Millisecond), "",
				true, laneOf(en.Agent), false})
		case recorder.TypeResourceSummary:
			if en.Agent == "" {
				break
			}
			add(LaneRow{ts, "session", "usage receipt",
				fmt.Sprintf("%.2f CPU-seconds · peak RSS %s", en.CPUSeconds, HumanKiB(en.PeakRSSKiB)),
				"", false, laneOf(en.Agent), false})
		case recorder.TypePluginCall:
			kind := "plugin"
			if en.Refused {
				kind = "team-refused"
			}
			detail := fmt.Sprintf("%s · %d ms", en.Outcome, en.DurationMS)
			if en.Args != "" {
				detail = en.Args + " · " + detail
			}
			add(LaneRow{ts, kind, en.Name + "_" + en.Tool, detail, "",
				en.Refused, laneOf(en.Agent), false})
		case recorder.TypePluginCrash:
			add(LaneRow{ts, "team-refused", "plugin " + en.Name + " stopped", en.Reason, "",
				true, laneOf(en.Agent), false})
		case recorder.TypeMCPHostCall:
			add(LaneRow{ts, "client", "client called " + en.Name, en.Args, "",
				false, laneOf(en.Agent), false})
		case recorder.TypeMCPHostResult:
			// A refused call is drawn like a refused message, because it is the
			// same thing: the wall saying no, where a reader can see it.
			if en.Refused {
				detail := fmt.Sprintf("%d ms", en.DurationMS)
				if en.Error != nil {
					detail = en.Error.Message
				}
				add(LaneRow{ts, "team-refused", "REFUSED " + en.Name, detail, "",
					true, laneOf(en.Agent), false})
				break
			}
			add(LaneRow{ts, "client", en.Name + " ok", fmt.Sprintf("%d ms", en.DurationMS), "",
				false, laneOf(en.Agent), false})
		case recorder.TypeSessionReady:
			// The one row that says how this machine came to exist. F-D19 asks
			// for the two boot paths to be visible rather than inferred, and a
			// transcript that does not carry it is where it would go missing.
			add(LaneRow{ts, "session", "ready in " + fmt.Sprintf("%d ms", en.BootMS),
				bootPath(en.Via), "", false, laneOf(en.Agent), false})
		case recorder.TypeSessionStart:
			add(LaneRow{ts, "session", "team session start",
				fmt.Sprintf("arch %s · kelyfos %s", en.Arch, en.Kelyfos), "", false, wide, false})
		case recorder.TypeSessionEnd:
			add(LaneRow{ts, "session", "team session end",
				fmt.Sprintf("%s after %d ms", en.Reason, en.DurationMS), "", false, wide, false})
		}
	}
	return lanes, rows
}

// HumanBytes renders a byte count the way a person reads it.
func HumanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n>>10)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// HumanKiB renders a kernel-reported size the way a person reads it. Exported
// because the CLI's own renderers want the same words for the same number, and
// two copies of a formatter is two ways for the same event to read differently.
func HumanKiB(kib int64) string {
	switch {
	case kib >= 1<<20:
		return fmt.Sprintf("%.1f GiB", float64(kib)/(1<<20))
	case kib >= 1<<10:
		return fmt.Sprintf("%d MiB", kib>>10)
	default:
		return fmt.Sprintf("%d KiB", kib)
	}
}

// bootPath spells out how a machine started, for a reader who should not have
// to know what "via" means.
func bootPath(via string) string {
	switch via {
	case "fork":
		return "forked from a shared template"
	case "cold":
		return "cold boot"
	case "":
		return ""
	}
	return via
}

// quotaNote says what a receipt's CPU number was measured against, when there
// was something to measure it against.
func quotaNote(e recorder.Event) string {
	switch {
	case e.CPUQuota > 0:
		return fmt.Sprintf(" (quota %d%% of one core)", e.CPUQuota)
	case e.VcpuCount > 0:
		return fmt.Sprintf(" across %d core(s), no quota", e.VcpuCount)
	}
	return ""
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

var tmpl = template.Must(template.New("report").Parse(reportHTML))

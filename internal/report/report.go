// Package report renders a session's flight recorder as a single self-contained
// HTML file.
//
// It is the answer to "what did the agent do?" in a form someone can open, read
// and forward without installing anything — no server, no JavaScript
// dependencies, no network. Everything comes from the JSONL in docs/events.md;
// this is a view, and the schema is the product.
package report

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// View is what the template renders.
type View struct {
	SessionID  string
	Generated  string
	Verified   bool
	VerifyNote string
	Events     int
	Summary    Summary
	Rows       []Row
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

// Render writes the report.
func Render(w io.Writer, sessionID string, events []recorder.Event, verifyErr error) error {
	v := View{
		SessionID: sessionID,
		Generated: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Verified:  verifyErr == nil,
		Events:    len(events),
	}
	if verifyErr != nil {
		v.VerifyNote = verifyErr.Error()
	}

	seenSecret := map[string]bool{}
	// Output is attached to the command it belongs to rather than listed
	// separately, because a transcript where output floats away from its
	// command is not a transcript.
	byCall := map[string]int{}

	for _, e := range events {
		ts := e.TS
		if len(ts) > 23 {
			ts = ts[11:23]
		}
		switch e.Type {
		case recorder.TypeSessionStart:
			v.Summary.Image, v.Summary.Arch, v.Summary.Kelyfos = e.Image, e.Arch, e.Kelyfos
			v.Summary.Started = e.TS
			// A team has no single flavor — each agent has its own, and each
			// says so in its own session.ready. Saying that beats rendering a
			// hole where a value should be (F-D33).
			shown := e.Image
			if shown == "" {
				// A server's session has no single flavor either, and its
				// machines are sandboxes rather than agents. Saying which
				// beats rendering a hole (F-D33).
				shown = "per agent"
				if e.Reason == recorder.ReasonServeMCP {
					shown, v.Served = "per sandbox", true
				}
				v.Summary.Image = shown
			}
			detail := fmt.Sprintf("image %s · arch %s · kelyfos %s", shown, e.Arch, e.Kelyfos)
			// A restored or forked machine says what it came from here, and a
			// cold boot records no reason at all, so this adds nothing to the
			// common case and everything to the one that needs it.
			if e.Reason != "" {
				detail += " · " + e.Reason
			}
			v.Rows = append(v.Rows, Row{ts, "session", "session start", detail, "", false})
		case recorder.TypeSessionReady:
			// A team writes one of these per member, so the header's single set
			// of boot figures would end up being whichever agent was last —
			// with the kernel and supervisor blank, because the team's copy
			// records how the machine started rather than what booted (E2-9).
			if e.Agent != "" {
				v.Rows = append(v.Rows, Row{ts, "session", e.Agent + " ready",
					fmt.Sprintf("%d ms · %s · image %s", e.BootMS, bootPath(e.Via), e.Image), "", false})
				break
			}
			v.Summary.BootMS, v.Summary.Kernel, v.Summary.Supervisor = e.BootMS, e.Kernel, e.Supervisor
			overlay := "overlay unknown"
			if e.Overlay != nil {
				overlay = fmt.Sprintf("overlay %t", *e.Overlay)
			}
			v.Rows = append(v.Rows, Row{ts, "session", "ready",
				fmt.Sprintf("%d ms · kernel %s · supervisor %s · %s", e.BootMS, e.Kernel, e.Supervisor, overlay), "", false})
		case recorder.TypeSessionEnd:
			v.Summary.Ended, v.Summary.EndReason = e.TS, e.Reason
			v.Rows = append(v.Rows, Row{ts, "session", "session end",
				fmt.Sprintf("%s after %d ms", e.Reason, e.DurationMS), "", false})
		case recorder.TypeCommandStart:
			v.Summary.Commands++
			byCall[e.Call] = len(v.Rows)
			v.Rows = append(v.Rows, Row{ts, "command", strings.Join(e.Cmd, " "),
				"via " + e.Via, "", false})
		case recorder.TypeCommandOutput:
			if i, ok := byCall[e.Call]; ok {
				data, _ := base64.StdEncoding.DecodeString(e.Data)
				prefix := ""
				if e.Stream == "stderr" {
					prefix = "stderr: "
				}
				v.Rows[i].Output += prefix + string(data)
			}
		case recorder.TypeCommandExit:
			code := -1
			if e.Code != nil {
				code = *e.Code
			}
			if code != 0 {
				v.Summary.Failed++
			}
			if i, ok := byCall[e.Call]; ok {
				v.Rows[i].IsError = code != 0
				v.Rows[i].Detail += fmt.Sprintf(" · exit %d · %d ms", code, e.DurationMS)
				if e.Error != nil {
					v.Rows[i].Detail += fmt.Sprintf(" · %s: %s", e.Error.Kind, e.Error.Message)
				}
			}
		case recorder.TypeFileWrite:
			v.Summary.FilesWritten++
			v.Rows = append(v.Rows, Row{ts, "file", "write " + e.Path,
				fmt.Sprintf("%d bytes · sha256 %s · via %s", e.Bytes, short(e.SHA256), e.Via), "", false})
		case recorder.TypeEgressAttempt:
			allowed := e.Allowed != nil && *e.Allowed
			kind, title := "egress-blocked", "BLOCKED "+e.Host
			if allowed {
				kind, title = "egress", "egress "+e.Host
				v.Summary.EgressOK++
				if e.Mode == "terminated" {
					v.Summary.Terminated++
				}
			} else {
				v.Summary.EgressBlock++
			}
			detail := fmt.Sprintf("port %d", e.Port)
			if e.Mode != "" {
				detail += " · " + e.Mode
			}
			if e.Reason != "" {
				detail += " · " + e.Reason
			}
			if e.BytesIn > 0 || e.BytesOut > 0 {
				detail += fmt.Sprintf(" · %d in / %d out", e.BytesIn, e.BytesOut)
			}
			v.Rows = append(v.Rows, Row{ts, kind, title, detail, "", !allowed})
		case recorder.TypePluginCall:
			v.Rows = append(v.Rows, Row{ts, "plugin", e.Name + "_" + e.Tool,
				fmt.Sprintf("%s · %d ms", e.Outcome, e.DurationMS), "", e.Outcome != "ok"})
		case recorder.TypePluginCrash:
			v.Rows = append(v.Rows, Row{ts, "plugin", "plugin " + e.Name + " stopped",
				e.Reason, "", true})
		case recorder.TypeSecretUse:
			if !seenSecret[e.Name+"@"+e.Host] {
				seenSecret[e.Name+"@"+e.Host] = true
				v.Summary.Secrets = append(v.Summary.Secrets, e.Name+" → "+e.Host)
			}
			v.Rows = append(v.Rows, Row{ts, "secret", "secret " + e.Name,
				"sent to " + e.Host + " · the value is not recorded anywhere", "", false})
		case recorder.TypeTeamMessage, recorder.TypeTeamRefused:
			refused := e.Type == recorder.TypeTeamRefused
			// The same arrow the lane view draws. A reply points back, because
			// it travels the return path of the ask that provoked it — and the
			// two views rendering one event in opposite directions is worse
			// than either being wrong on its own (F-D33).
			arrow := "→"
			if e.Kind == "reply" {
				arrow = "←"
			}
			kind, title := "team", fmt.Sprintf("%s %s %s", e.Agent, arrow, e.Peer)
			if refused {
				kind, title = "team-refused", fmt.Sprintf("REFUSED %s %s %s", e.Agent, arrow, e.Peer)
				v.Summary.TeamRefused++
			} else {
				v.Summary.TeamMessages++
			}
			detail := fmt.Sprintf("%s · %d bytes · sha256 %s", e.Kind, e.Bytes, short(e.SHA256))
			if e.Reason != "" {
				detail += " · " + e.Reason
			}
			v.Rows = append(v.Rows, Row{ts, kind, title, detail, e.Data, refused})
		case recorder.TypeTeamSpawn:
			if e.Outcome != "delivered" {
				v.Summary.TeamRefused++
				v.Rows = append(v.Rows, Row{ts, "team-refused",
					"REFUSED spawn by " + e.Agent, e.Reason, "", true})
				break
			}
			v.Rows = append(v.Rows, Row{ts, "team",
				fmt.Sprintf("%s %s", e.Kind, e.Peer), "requested by " + e.Agent, "", false})
		case recorder.TypeTeamStore:
			refused := e.Outcome != "delivered"
			detail := e.Outcome
			if e.Reason != "" {
				detail += " · " + e.Reason
			}
			if e.Bytes > 0 {
				detail += fmt.Sprintf(" · %d bytes", e.Bytes)
			}
			kind := "team"
			if refused {
				kind = "team-refused"
			}
			v.Rows = append(v.Rows, Row{ts,
				kind, fmt.Sprintf("%s %s %s", e.Agent, e.Kind, e.Peer), detail, "", refused})
		case recorder.TypeResourceSummary:
			// A team writes one receipt per agent into the same chain, so the
			// header's single receipt would show whichever machine stopped
			// last and call it the session's. Those become timeline rows
			// instead, and the header keeps the receipt only when there is
			// exactly one machine to have one (E1-7, E2-7).
			if e.Agent != "" {
				v.Rows = append(v.Rows, Row{ts, "session", "usage receipt · " + e.Agent,
					fmt.Sprintf("%.2f CPU-seconds%s · peak RSS %s · net %s in / %s out · disk %s written",
						e.CPUSeconds, quotaNote(e), HumanKiB(e.PeakRSSKiB),
						HumanBytes(e.NetInBytes), HumanBytes(e.NetOutBytes),
						HumanBytes(e.DiskWriteBytes)), "", false})
				break
			}
			v.Summary.Usage = &Usage{
				CPUSeconds: e.CPUSeconds, CPUQuota: e.CPUQuota, Vcpus: e.VcpuCount,
				PeakRSS: HumanKiB(e.PeakRSSKiB), MemMiB: e.MemMiB,
				NetIn: HumanBytes(e.NetInBytes), NetOut: HumanBytes(e.NetOutBytes),
				DiskRead: HumanBytes(e.DiskReadBytes), DiskWrite: HumanBytes(e.DiskWriteBytes),
			}
		case recorder.TypeResourceTimeout:
			v.Summary.TimedOut = e.Budget
			v.Rows = append(v.Rows, Row{ts, "oom", "timed out on " + e.Budget,
				fmt.Sprintf("budget %s · ran %s",
					time.Duration(e.BudgetMS)*time.Millisecond,
					(time.Duration(e.ElapsedMS) * time.Millisecond).Round(time.Second)), "", true})
		case recorder.TypeResourceOOM:
			// Flagged the way a blocked egress attempt is: this is a limit
			// firing, and a reader skimming the transcript should not have to
			// hunt for it.
			v.Summary.OOMKills++
			detail := fmt.Sprintf("pid %d · %s resident", e.PID, HumanKiB(e.RSSKiB))
			if e.MemMiB > 0 {
				detail += fmt.Sprintf(" · the machine had %d MiB", e.MemMiB)
			}
			v.Rows = append(v.Rows, Row{ts, "oom", "OOM-killed " + e.Comm, detail, "", true})
		}
	}
	v.Lanes, v.LaneRows = buildLanes(events)
	if n := len(v.Lanes); n > 0 {
		v.LaneWidth = template.CSS(fmt.Sprintf("grid-template-columns:88px repeat(%d,minmax(0,1fr))", n))
	}
	return tmpl.Execute(w, v)
}

// buildLanes turns the same events into a per-agent view.
//
// Lane order is first-appearance order, which for a team is boot order, so the
// columns read like the file the user wrote. An event with no agent belongs to
// the team rather than to any member and spans every lane; a message between
// two agents spans exactly the columns it connects, which is the whole point of
// drawing it this way instead of listing it (E2-7).
func buildLanes(events []recorder.Event) ([]string, []LaneRow) {
	col := map[string]int{}
	var lanes []string
	for _, e := range events {
		if e.Agent != "" {
			if _, ok := col[e.Agent]; !ok {
				col[e.Agent] = len(lanes)
				lanes = append(lanes, e.Agent)
			}
		}
	}
	if len(lanes) == 0 {
		return nil, nil
	}
	// A peer that never acted still needs a column, or a message to it would
	// have nowhere to point.
	for _, e := range events {
		if e.Peer == "" {
			continue
		}
		switch e.Type {
		case recorder.TypeTeamMessage, recorder.TypeTeamRefused, recorder.TypeTeamSpawn:
			if _, ok := col[e.Peer]; !ok {
				col[e.Peer] = len(lanes)
				lanes = append(lanes, e.Peer)
			}
		}
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
	var rows []LaneRow
	byCall := map[string]int{}
	for _, e := range events {
		ts := e.TS
		if len(ts) > 23 {
			ts = ts[11:23]
		}
		add := func(r LaneRow) int { rows = append(rows, r); return len(rows) - 1 }

		switch e.Type {
		case recorder.TypeTeamMessage, recorder.TypeTeamRefused:
			from, to := col[e.Agent], col[e.Peer]
			arrow := "\u2192"
			if e.Kind == "reply" {
				arrow = "\u2190"
			}
			kind, title := "team", fmt.Sprintf("%s %s %s", e.Agent, arrow, e.Peer)
			if e.Type == recorder.TypeTeamRefused {
				kind = "team-refused"
				title = "REFUSED " + title
			}
			detail := fmt.Sprintf("%s \u00b7 %d bytes \u00b7 sha256 %s", e.Kind, e.Bytes, short(e.SHA256))
			if e.Reason != "" {
				detail += " \u00b7 " + e.Reason
			}
			add(LaneRow{ts, kind, title, detail, e.Data,
				e.Type == recorder.TypeTeamRefused, span(from, to), true})

		case recorder.TypeTeamStore:
			// Inline in the acting agent's lane, because a store access is
			// something one agent did, not a message between two.
			refused := e.Outcome != "delivered"
			kind := "store"
			if refused {
				kind = "team-refused"
			}
			detail := e.Outcome
			if e.Reason != "" {
				detail += " \u00b7 " + e.Reason
			}
			if e.Bytes > 0 {
				detail += fmt.Sprintf(" \u00b7 %d bytes", e.Bytes)
			}
			add(LaneRow{ts, kind, fmt.Sprintf("store %s %s", e.Kind, e.Peer), detail, "",
				refused, laneOf(e.Agent), false})

		case recorder.TypeTeamSpawn:
			if e.Outcome != "delivered" {
				add(LaneRow{ts, "team-refused", "REFUSED spawn", e.Reason, "",
					true, laneOf(e.Agent), false})
				break
			}
			add(LaneRow{ts, "team", e.Kind + " " + e.Peer, "requested by " + e.Agent, "",
				false, span(col[e.Agent], col[e.Peer]), true})

		case recorder.TypeCommandStart:
			byCall[e.Call] = add(LaneRow{ts, "command", strings.Join(e.Cmd, " "),
				"via " + e.Via, "", false, laneOf(e.Agent), false})
		case recorder.TypeCommandOutput:
			if i, ok := byCall[e.Call]; ok {
				data, _ := base64.StdEncoding.DecodeString(e.Data)
				prefix := ""
				if e.Stream == "stderr" {
					prefix = "stderr: "
				}
				rows[i].Output += prefix + string(data)
			}
		case recorder.TypeCommandExit:
			code := -1
			if e.Code != nil {
				code = *e.Code
			}
			if i, ok := byCall[e.Call]; ok {
				rows[i].IsError = code != 0
				rows[i].Detail += fmt.Sprintf(" \u00b7 exit %d", code)
			}
		case recorder.TypeFileWrite:
			add(LaneRow{ts, "file", "write " + e.Path,
				fmt.Sprintf("%d bytes \u00b7 %s", e.Bytes, short(e.SHA256)), "",
				false, laneOf(e.Agent), false})
		case recorder.TypeEgressAttempt:
			allowed := e.Allowed != nil && *e.Allowed
			kind, title := "egress-blocked", "BLOCKED "+e.Host
			if allowed {
				kind, title = "egress", "egress "+e.Host
			}
			detail := e.Mode
			if e.Reason != "" {
				detail += " " + e.Reason
			}
			add(LaneRow{ts, kind, title, detail, "", !allowed, laneOf(e.Agent), false})
		case recorder.TypeSecretUse:
			add(LaneRow{ts, "secret", "secret " + e.Name, "sent to " + e.Host, "",
				false, laneOf(e.Agent), false})
		case recorder.TypeResourceOOM:
			add(LaneRow{ts, "oom", "OOM-killed " + e.Comm,
				fmt.Sprintf("pid %d \u00b7 %s resident", e.PID, HumanKiB(e.RSSKiB)), "",
				true, laneOf(e.Agent), false})
		case recorder.TypeResourceTimeout:
			add(LaneRow{ts, "oom", "timed out on " + e.Budget,
				fmt.Sprintf("budget %s", time.Duration(e.BudgetMS)*time.Millisecond), "",
				true, laneOf(e.Agent), false})
		case recorder.TypeResourceSummary:
			if e.Agent == "" {
				break
			}
			add(LaneRow{ts, "session", "usage receipt",
				fmt.Sprintf("%.2f CPU-seconds \u00b7 peak RSS %s", e.CPUSeconds, HumanKiB(e.PeakRSSKiB)),
				"", false, laneOf(e.Agent), false})
		case recorder.TypePluginCall:
			kind := "plugin"
			if e.Outcome != "ok" {
				kind = "team-refused"
			}
			add(LaneRow{ts, kind, e.Name + "_" + e.Tool,
				fmt.Sprintf("%s · %d ms", e.Outcome, e.DurationMS), "",
				e.Outcome != "ok", laneOf(e.Agent), false})
		case recorder.TypePluginCrash:
			add(LaneRow{ts, "team-refused", "plugin " + e.Name + " stopped", e.Reason, "",
				true, laneOf(e.Agent), false})
		case recorder.TypeMCPHostCall:
			add(LaneRow{ts, "client", "client called " + e.Name, e.Args, "",
				false, laneOf(e.Agent), false})
		case recorder.TypeMCPHostResult:
			// A refused call is drawn like a refused message, because it is the
			// same thing: the wall saying no, where a reader can see it.
			if e.Outcome != "ok" {
				detail := fmt.Sprintf("%d ms", e.DurationMS)
				if e.Error != nil {
					detail = e.Error.Message
				}
				add(LaneRow{ts, "team-refused", "REFUSED " + e.Name, detail, "",
					true, laneOf(e.Agent), false})
				break
			}
			add(LaneRow{ts, "client", e.Name + " ok", fmt.Sprintf("%d ms", e.DurationMS), "",
				false, laneOf(e.Agent), false})
		case recorder.TypeSessionReady:
			// The one row that says how this machine came to exist. F-D19 asks
			// for the two boot paths to be visible rather than inferred, and a
			// transcript that does not carry it is where it would go missing.
			add(LaneRow{ts, "session", "ready in " + fmt.Sprintf("%d ms", e.BootMS),
				bootPath(e.Via), "", false, laneOf(e.Agent), false})
		case recorder.TypeSessionStart:
			add(LaneRow{ts, "session", "team session start",
				fmt.Sprintf("arch %s \u00b7 kelyfos %s", e.Arch, e.Kelyfos), "", false, wide, false})
		case recorder.TypeSessionEnd:
			add(LaneRow{ts, "session", "team session end",
				fmt.Sprintf("%s after %d ms", e.Reason, e.DurationMS), "", false, wide, false})
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

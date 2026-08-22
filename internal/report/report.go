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
	Secrets      []string
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
			v.Rows = append(v.Rows, Row{ts, "session", "session start",
				fmt.Sprintf("image %s · arch %s · kelyfos %s", e.Image, e.Arch, e.Kelyfos), "", false})
		case recorder.TypeSessionReady:
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
		case recorder.TypeSecretUse:
			if !seenSecret[e.Name+"@"+e.Host] {
				seenSecret[e.Name+"@"+e.Host] = true
				v.Summary.Secrets = append(v.Summary.Secrets, e.Name+" → "+e.Host)
			}
			v.Rows = append(v.Rows, Row{ts, "secret", "secret " + e.Name,
				"sent to " + e.Host + " · the value is not recorded anywhere", "", false})
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
	return tmpl.Execute(w, v)
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

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

var tmpl = template.Must(template.New("report").Parse(reportHTML))

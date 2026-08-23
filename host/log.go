package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/report"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

func logCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos log", flag.ExitOnError)
	var (
		id     = fs.String("session", "", "session id (default: the most recent)")
		follow = fs.Bool("follow", false, "stream events as they are recorded")
		verify = fs.Bool("verify", false, "check the hash chain and report the first break")
		asJSON = fs.Bool("json", false, "print the raw events instead of a readable replay")
		list   = fs.Bool("list", false, "list recorded sessions")
		export = fs.String("export", "", "write a self-contained HTML report to this path")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos log [flags]

Replays a session's flight recorder — every command, its output, and from
phase 2 every egress attempt and secret use. The schema is documented in
docs/events.md.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	if *list {
		return listSessions()
	}

	sessionID, err := resolveSession(*id)
	if err != nil {
		return err
	}
	path := recorder.Path(sandbox.Root(), sessionID)

	if *export != "" {
		return exportSession(sessionID, path, *export)
	}
	if *verify {
		return verifySession(sessionID, path)
	}
	if *follow {
		return followSession(path, *asJSON)
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("no flight recorder for session %s: %w", sessionID, err)
	}
	defer f.Close()
	return replay(f, *asJSON)
}

func resolveSession(id string) (string, error) {
	if id != "" {
		return id, nil
	}
	dir := recorder.SessionsDir(sandbox.Root())
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return "", fmt.Errorf("no sessions recorded yet (looked in %s)", dir)
	}
	type cand struct {
		name string
		mod  time.Time
	}
	var found []cand
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := os.Stat(filepath.Join(dir, e.Name(), "events.jsonl"))
		if err != nil {
			continue
		}
		found = append(found, cand{e.Name(), info.ModTime()})
	}
	if len(found) == 0 {
		return "", fmt.Errorf("no sessions recorded yet (looked in %s)", dir)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].mod.After(found[j].mod) })
	return found[0].name, nil
}

func listSessions() error {
	dir := recorder.SessionsDir(sandbox.Root())
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("no sessions recorded yet (looked in %s)", dir)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name(), "events.jsonl")
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		events, _ := recorder.Read(f)
		f.Close()
		state := "open"
		for _, ev := range events {
			if ev.Type == recorder.TypeSessionEnd {
				state = ev.Reason
			}
		}
		fmt.Printf("%s  %s  %4d events  %s\n",
			e.Name(), info.ModTime().Format("2006-01-02 15:04:05"), len(events), state)
	}
	return nil
}

// exportSession renders the report. It verifies the chain as part of rendering,
// because a report that does not say whether its own source has been tampered
// with is worth very little as evidence.
func exportSession(id, path, dest string) error {
	blob, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("no flight recorder for session %s: %w", id, err)
	}
	events, err := recorder.Read(bytes.NewReader(blob))
	if err != nil {
		return err
	}
	_, verifyErr := recorder.Verify(bytes.NewReader(blob))

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := report.Render(f, id, events, verifyErr); err != nil {
		return err
	}
	info, _ := os.Stat(dest)
	fmt.Printf("wrote %s (%d events, %d bytes)\n", dest, len(events), sizeOf(info))
	if verifyErr != nil {
		fmt.Printf("  warning: the chain does NOT verify — the report says so prominently\n")
	}
	return nil
}

func verifySession(id, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("no flight recorder for session %s: %w", id, err)
	}
	defer f.Close()
	n, err := recorder.Verify(f)
	if err != nil {
		fmt.Printf("session %s: FAILED after %d events\n  %v\n", id, n, err)
		return &exitError{code: 1}
	}
	fmt.Printf("session %s: chain intact, %d events verified\n", id, n)
	return nil
}

func followSession(path string, asJSON bool) error {
	// Wait for the file: `kelyfos log --follow` is a natural thing to start
	// before, or at the same time as, the sandbox it is watching.
	var f *os.File
	for i := 0; ; i++ {
		var err error
		if f, err = os.Open(path); err == nil {
			break
		}
		if i > 100 {
			return fmt.Errorf("no flight recorder appeared at %s", path)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			printEvent(line, asJSON)
		}
		if err == io.EOF {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		if err != nil {
			return err
		}
	}
}

func replay(r io.Reader, asJSON bool) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		printEvent(append([]byte(nil), sc.Bytes()...), asJSON)
	}
	return sc.Err()
}

func printEvent(line []byte, asJSON bool) {
	if asJSON {
		os.Stdout.Write(line)
		if len(line) == 0 || line[len(line)-1] != '\n' {
			os.Stdout.Write([]byte{'\n'})
		}
		return
	}
	var e recorder.Event
	if err := json.Unmarshal(line, &e); err != nil {
		fmt.Printf("  ?? unparseable event: %s\n", strings.TrimSpace(string(line)))
		return
	}
	ts := e.TS
	if len(ts) > 23 {
		ts = ts[11:23]
	}
	switch e.Type {
	case recorder.TypeSessionStart:
		fmt.Printf("%s  session start   image=%s arch=%s kelyfos=%s\n", ts, e.Image, e.Arch, e.Kelyfos)
	case recorder.TypeSessionReady:
		overlay := "overlay=?"
		if e.Overlay != nil {
			overlay = fmt.Sprintf("overlay=%t", *e.Overlay)
		}
		fmt.Printf("%s  ready           %d ms  kernel=%s supervisor=%s %s\n",
			ts, e.BootMS, e.Kernel, e.Supervisor, overlay)
	case recorder.TypeSessionEnd:
		fmt.Printf("%s  session end     %s after %d ms\n", ts, e.Reason, e.DurationMS)
	case recorder.TypeCommandStart:
		fmt.Printf("%s  $ %s\n", ts, strings.Join(e.Cmd, " "))
	case recorder.TypeCommandOutput:
		data, _ := base64.StdEncoding.DecodeString(e.Data)
		prefix := "  | "
		if e.Stream == "stderr" {
			prefix = "  ! "
		}
		for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			fmt.Printf("%s%s%s\n", strings.Repeat(" ", len(ts)), prefix, l)
		}
	case recorder.TypeCommandExit:
		code := -1
		if e.Code != nil {
			code = *e.Code
		}
		extra := ""
		if e.Error != nil {
			extra = fmt.Sprintf("  (%s: %s)", e.Error.Kind, e.Error.Message)
		}
		fmt.Printf("%s  exit %-3d        %d ms%s\n", ts, code, e.DurationMS, extra)
	case recorder.TypeFileWrite:
		fmt.Printf("%s  write           %s  %d bytes  sha256=%s via=%s\n",
			ts, e.Path, e.Bytes, shortHash(e.SHA256), e.Via)
	case recorder.TypeEgressAttempt:
		verdict := "BLOCKED"
		if e.Allowed != nil && *e.Allowed {
			verdict = "allowed"
		}
		fmt.Printf("%s  egress %-7s %s:%d  mode=%s %s\n", ts, verdict, e.Host, e.Port, e.Mode, e.Reason)
	case recorder.TypeSecretUse:
		fmt.Printf("%s  secret          %s -> %s\n", ts, e.Name, e.Host)
	case recorder.TypeResourceSummary:
		fmt.Printf("%s  usage           %.2f CPU-seconds%s · peak RSS %s (VMM)%s · net %s in / %s out · disk %s written\n",
			ts, e.CPUSeconds, quotaSuffix(e), report.HumanKiB(e.PeakRSSKiB),
			capSuffix(e.MemMiB), humanBytes(e.NetInBytes), humanBytes(e.NetOutBytes),
			humanBytes(e.DiskWriteBytes))
	case recorder.TypeResourceTimeout:
		fmt.Printf("%s  timed out       the %s budget of %s expired after %s\n",
			ts, e.Budget, time.Duration(e.BudgetMS)*time.Millisecond,
			(time.Duration(e.ElapsedMS) * time.Millisecond).Round(time.Second))
	case recorder.TypeResourceOOM:
		fmt.Printf("%s  OOM-killed      %s (pid %d) holding %s of a %d MiB machine\n",
			ts, e.Comm, e.PID, report.HumanKiB(e.RSSKiB), e.MemMiB)
	default:
		fmt.Printf("%s  %-15s %s\n", ts, e.Type, strings.TrimSpace(string(line)))
	}
}

// quotaSuffix and capSuffix say what a number was measured against, when there
// was something to measure it against. A receipt that reports consumption
// without the cap it was consumed under is half a receipt.
func quotaSuffix(e recorder.Event) string {
	switch {
	case e.CPUQuota > 0:
		return fmt.Sprintf(" (quota %d%% of one core)", e.CPUQuota)
	case e.VcpuCount > 0:
		return fmt.Sprintf(" across %d core(s), no quota", e.VcpuCount)
	}
	return ""
}

// capSuffix names the machine's RAM beside the VMM's peak resident set without
// claiming the second is a share of the first. It is not: the figure is the
// Firecracker process's own high-water mark, which covers the guest's memory
// *and* whatever the host cached for the block devices it was writing, so it
// routinely exceeds the guest's RAM cap without the guest having exceeded
// anything (docs/events.md).
func capSuffix(memMiB int) string {
	if memMiB <= 0 {
		return ""
	}
	return fmt.Sprintf(" · machine %d MiB", memMiB)
}

func humanBytes(n int64) string {
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

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

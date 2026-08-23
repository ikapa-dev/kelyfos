package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sample() []runRow {
	return []runRow{
		{Session: "7f3c1a2b", Image: "dev", Command: "kelyfos run -- make test"},
		{Session: "7f3c9999", Image: "dev", Command: "kelyfos run"},
		{Session: "aa11bb22", Image: "base", Command: "kelyfos team up"},
	}
}

// An id is eight hex characters and nobody should have to type all of them off
// a listing — but a prefix that matches two sessions is not guessed at.
func TestFindRunByPrefix(t *testing.T) {
	rows := sample()
	if r, err := findRun(rows, "aa11"); err != nil || r.Session != "aa11bb22" {
		t.Errorf("a unique prefix did not resolve: %v %v", r, err)
	}
	if r, err := findRun(rows, "7f3c1a2b"); err != nil || r.Image != "dev" {
		t.Errorf("a whole id did not resolve: %v %v", r, err)
	}
	_, err := findRun(rows, "7f3c")
	if err == nil {
		t.Fatal("an ambiguous prefix was resolved to one of them")
	}
	for _, want := range []string{"7f3c1a2b", "7f3c9999", "say more"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
	_, err = findRun(rows, "zzzz")
	if err == nil || !strings.Contains(err.Error(), "kelyfos runs") {
		t.Errorf("a miss should point at the listing: %v", err)
	}
}

// The cells a reader scans. "still running" and "succeeded" are the two things
// they most need to be able to tell apart, so an open session never shows a 0.
func TestExitCellSaysWhichKindOfNothing(t *testing.T) {
	zero, three := 0, 3
	for _, tc := range []struct {
		row  runRow
		want string
	}{
		{runRow{Exit: &three}, "3"},
		{runRow{Exit: &zero}, "0"},
		{runRow{}, "open"},
		{runRow{Reason: "shutdown"}, "—"},
		{runRow{Reason: "timeout"}, "timeout"},
	} {
		if got := exitCell(tc.row); got != tc.want {
			t.Errorf("%+v -> %q, want %q", tc.row, got, tc.want)
		}
	}
}

func TestDurationCell(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{0, "—"},
		{450 * time.Millisecond, "450ms"},
		{2500 * time.Millisecond, "2.5s"},
		{90 * time.Second, "1m30s"},
	} {
		if got := durationCell(tc.d); got != tc.want {
			t.Errorf("%s -> %q, want %q", tc.d, got, tc.want)
		}
	}
}

// A rerun must not pick up a --policy twice, and the frozen one is only
// inserted when there is one.
func TestHasFlagSpotsEverySpelling(t *testing.T) {
	argv := []string{"kelyfos", "run", "--policy=/tmp/a.toml", "--", "true"}
	if !hasFlag(argv, "policy") {
		t.Error("--policy=… was not seen")
	}
	if !hasFlag([]string{"kelyfos", "run", "-policy", "/tmp/a.toml"}, "policy") {
		t.Error("-policy was not seen")
	}
	if hasFlag([]string{"kelyfos", "run", "--policy-ish"}, "policy") {
		t.Error("--policy-ish is not --policy")
	}
}

// The recorder writes its own timestamp format, and a listing sorts on it.
func TestParseRecorderTimestamp(t *testing.T) {
	got := parseTS("2026-08-23T18:40:37.903Z")
	if got.IsZero() {
		t.Fatal("a real timestamp did not parse")
	}
	if got.UTC().Format("2006-01-02 15:04:05") != "2026-08-23 18:40:37" {
		t.Errorf("parsed to %s", got.UTC())
	}
	if !parseTS("nonsense").IsZero() {
		t.Error("nonsense parsed to something")
	}
}

// The policy freeze is best effort and beside the record, never inside the run
// directory — which is deleted when the sandbox stops.
func TestFrozenPolicyPathIsEmptyWhenThereIsNone(t *testing.T) {
	if got := frozenPolicyPath("no-such-session-at-all"); got != "" {
		t.Errorf("invented a frozen policy at %s", got)
	}
}

func TestDescribeArgvDropsTheBinaryPath(t *testing.T) {
	got := describeArgv([]string{"/opt/build/bin/kelyfos", "run", "--allow", "github.com"})
	if got != "kelyfos run --allow github.com" {
		t.Errorf("got %q", got)
	}
	if describeArgv(nil) != "" {
		t.Error("nothing should describe as nothing")
	}
}

// A session whose record is only a fragment still reads, because a listing that
// silently dropped one would be hiding a machine that existed.
func TestReadRunOfAnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readRun(path, "deadbeef"); ok {
		t.Error("an empty record produced a row")
	}
}

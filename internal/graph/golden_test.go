package graph

import (
	"os"
	"path/filepath"
	"testing"
)

// Golden tests exist for the reason the task text gives one: "a layout that
// moves between two runs of the same team is a diff nobody can read." These
// fixtures freeze what Layout + Terminal draw for a handful of real team
// shapes, so an unintended change in placement or routing shows up as a
// readable text diff in code review instead of as a picture that quietly
// moved.
//
// Regenerate with: UPDATE_GRAPH_GOLDEN=1 go test ./internal/graph/ -run TestGolden
// Inspect the diff before committing a regenerated file — a golden test that
// is updated without being read is a test that has stopped testing anything.

func goldenFixtures() map[string]Input {
	return map[string]Input{
		// The scenario the task text itself describes: a hub reaching every
		// worker, plus a store key that lets a worker relay to the master
		// without a declared edge, an egress domain, and a bound secret —
		// one of each resource kind, so the golden file also freezes the
		// Domain/StoreKey/Secret row ordering.
		"star_with_resources": {
			Agents: []Agent{
				{ID: "hub"}, {ID: "worker-1", Group: "worker"},
				{ID: "worker-2", Group: "worker"}, {ID: "worker-3", Group: "worker"},
			},
			Edges: []Edge{
				{From: "hub", To: "worker-1"}, {From: "worker-1", To: "hub"},
				{From: "hub", To: "worker-2"}, {From: "worker-2", To: "hub"},
				{From: "hub", To: "worker-3"}, {From: "worker-3", To: "hub"},
			},
			Resources: []Resource{
				{ID: "github.com", Kind: Domain},
				{ID: "findings/*", Kind: StoreKey},
				{ID: "GITHUB_TOKEN@github.com", Kind: Secret},
			},
			Access: []Access{
				{Agent: "hub", Resource: "github.com"},
				{Agent: "worker-1", Resource: "findings/*", Write: true},
				{Agent: "worker-2", Resource: "findings/*", Write: true},
				{Agent: "worker-3", Resource: "findings/*", Write: true},
				{Agent: "hub", Resource: "findings/*"},
				{Agent: "hub", Resource: "GITHUB_TOKEN@github.com"},
			},
		},

		// A pipeline: no hub, a straight chain of unidirectional edges.
		"pipeline": {
			Agents: []Agent{{ID: "fetch"}, {ID: "parse"}, {ID: "publish"}},
			Edges: []Edge{
				{From: "fetch", To: "parse"},
				{From: "parse", To: "publish"},
			},
		},

		// Two independent teams' worth of agents with no edges to each
		// other at all, plus one agent with no edges anywhere.
		"disconnected": {
			Agents: []Agent{
				{ID: "left-a"}, {ID: "left-b"},
				{ID: "right-a"}, {ID: "right-b"}, {ID: "right-c"},
				{ID: "lonely"},
			},
			Edges: []Edge{
				{From: "left-a", To: "left-b"},
				{From: "right-a", To: "right-b"},
				{From: "right-a", To: "right-c"},
			},
		},

		// A single agent, no edges, no resources — the smallest non-empty
		// case.
		"single_agent": {
			Agents: []Agent{{ID: "solo"}},
		},
	}
}

func TestGoldenTerminalLayout(t *testing.T) {
	update := os.Getenv("UPDATE_GRAPH_GOLDEN") != ""

	for name, in := range goldenFixtures() {
		t.Run(name, func(t *testing.T) {
			l, err := Layout(in)
			if err != nil {
				t.Fatalf("Layout: %v", err)
			}
			got := Terminal(l).String() + "\n"

			path := filepath.Join("testdata", "golden", name+".txt")
			if update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}

			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading golden file %s: %v (run with UPDATE_GRAPH_GOLDEN=1 to create it)", path, err)
			}
			if got != string(want) {
				t.Errorf("terminal rendering for %q changed.\n--- got ---\n%s--- want ---\n%s"+
					"\n(run with UPDATE_GRAPH_GOLDEN=1 to update, and read the diff before committing it)",
					name, got, string(want))
			}
		})
	}
}

// TestGoldenLayoutIsStableAcrossRuns re-runs Layout on every fixture twice in
// the same process and requires byte-identical output, so this suite catches
// a determinism regression even before anyone regenerates the golden files.
func TestGoldenLayoutIsStableAcrossRuns(t *testing.T) {
	for name, in := range goldenFixtures() {
		t.Run(name, func(t *testing.T) {
			l1, err := Layout(in)
			if err != nil {
				t.Fatal(err)
			}
			l2, err := Layout(in)
			if err != nil {
				t.Fatal(err)
			}
			if Terminal(l1).String() != Terminal(l2).String() {
				t.Error("two runs of Layout on the same Input produced different terminal output")
			}
		})
	}
}

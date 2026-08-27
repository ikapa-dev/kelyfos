package config

import (
	"strings"
	"testing"
	"time"
)

const teamFile = `
[sandbox]
image = "dev"

[team]
name = "reviewers"
record_payloads = false

[[team.agent]]
name  = "master"
image = "dev"
allow = ["github.com"]
secrets = ["GITHUB_TOKEN@api.github.com"]

  [team.agent.resources]
  cpus      = 2
  mem       = "2G"
  cpu_quota = "150%"

  [team.agent.spawn]
  max      = 4
  image    = ["dev"]
  lifetime = "10m"

    [team.agent.spawn.resources]
    cpus = 1
    mem  = "1G"

[[team.agent]]
name  = "worker"
image = "dev"
count = 3

  [team.agent.resources]
  cpus = 1
  mem  = "1G"

[[team.edge]]
from = "master"
to   = "worker-*"

[[team.edge]]
from = "worker-1"
to   = "worker-2"
bidirectional = false

[team.store]
enabled = true

  [[team.store.key]]
  name  = "findings/*"
  write = ["worker-*"]
  read  = ["master"]
`

// The whole schema docs/teams.md specifies, read back field by field. A parser
// that is trusted with policy has to be checked against the policy it claims to
// read, not against a smaller thing that happens to parse.
func TestTeamFileParsesEveryPart(t *testing.T) {
	cfg := writeAndLoad(t, teamFile)
	if cfg.Image != "dev" {
		t.Errorf("the [sandbox] half was lost: %q", cfg.Image)
	}
	tm := cfg.Team
	if tm == nil {
		t.Fatal("no [team] section was parsed")
	}
	if tm.Name != "reviewers" || tm.RecordPayloads {
		t.Errorf("team = %+v", tm)
	}

	if len(tm.Agents) != 2 {
		t.Fatalf("parsed %d agents, want 2", len(tm.Agents))
	}
	m := tm.Agents[0]
	if m.Name != "master" || m.Image != "dev" || m.Count != 1 {
		t.Errorf("master = %+v", m)
	}
	if len(m.Allow) != 1 || m.Allow[0] != "github.com" {
		t.Errorf("master allow = %v", m.Allow)
	}
	if len(m.Secrets) != 1 || m.Secrets[0] != "GITHUB_TOKEN@api.github.com" {
		t.Errorf("master secrets = %v", m.Secrets)
	}
	if m.Resources.CPUs != 2 || m.Resources.MemMiB != 2048 || m.Resources.CPUQuota != 150 {
		t.Errorf("master resources = %+v", m.Resources)
	}
	if m.Spawn == nil {
		t.Fatal("the master has no spawn budget")
	}
	if m.Spawn.Max != 4 || m.Spawn.Lifetime != 10*time.Minute {
		t.Errorf("spawn = %+v", m.Spawn)
	}
	if len(m.Spawn.Images) != 1 || m.Spawn.Images[0] != "dev" {
		t.Errorf("spawn images = %v", m.Spawn.Images)
	}
	// A nested table belongs to the array element above it, so the spawn
	// budget's resources must not have leaked into the agent's own.
	if m.Spawn.Resources.CPUs != 1 || m.Resources.CPUs != 2 {
		t.Errorf("nested tables crossed: agent %d cpus, spawn %d cpus",
			m.Resources.CPUs, m.Spawn.Resources.CPUs)
	}

	w := tm.Agents[1]
	if w.Name != "worker" || w.Count != 3 || w.Resources.CPUs != 1 {
		t.Errorf("worker = %+v", w)
	}
	if w.Spawn != nil {
		t.Errorf("the worker picked up the master's spawn budget: %+v", w.Spawn)
	}

	if len(tm.Edges) != 2 {
		t.Fatalf("parsed %d edges, want 2", len(tm.Edges))
	}
	// Bidirectional defaults to true, and an explicit false is honoured.
	if !tm.Edges[0].Bidirectional {
		t.Error("an edge without bidirectional did not default to true")
	}
	if tm.Edges[1].Bidirectional {
		t.Error("bidirectional = false was ignored")
	}

	if tm.Store == nil || !tm.Store.Enabled || len(tm.Store.Keys) != 1 {
		t.Fatalf("store = %+v", tm.Store)
	}
	k := tm.Store.Keys[0]
	if k.Name != "findings/*" || len(k.Write) != 1 || k.Write[0] != "worker-*" || k.Read[0] != "master" {
		t.Errorf("store key = %+v", k)
	}
}

// A file with no [team] is an ordinary policy and must stay one.
func TestAFileWithNoTeamHasNoTeam(t *testing.T) {
	cfg := writeAndLoad(t, "[sandbox]\nimage = \"dev\"\n")
	if cfg.Team != nil {
		t.Errorf("a plain policy grew a team: %+v", cfg.Team)
	}
}

// Anything the subset does not understand is refused by name and line. That is
// the property F-D16 traded a TOML library for, so it is the property to test.
func TestTheSubsetRefusesWhatItDoesNotUnderstand(t *testing.T) {
	cases := map[string]string{
		"a nested table with no array element above it": "[team.agent.resources]\ncpus = 1\n",
		"a section that does not exist":                 "[team.agents]\n",
		"an array-of-tables that is not one":            "[[team.agentz]]\n",
		"an unknown key in [team]":                      "[team]\nnmae = \"x\"\n",
		"an unknown key in an agent":                    "[[team.agent]]\nimg = \"dev\"\n",
		"an unknown key in agent resources":             "[[team.agent]]\n[team.agent.resources]\ncors = 2\n",
		"an unknown key in an edge":                     "[[team.edge]]\nfrom = \"a\"\nvia = \"b\"\n",
		"an unknown key in a store rule":                "[[team.store.key]]\nnaem = \"k\"\n",
		"a non-boolean where a boolean belongs":         "[team]\nrecord_payloads = yes\n",
		"a count below one":                             "[[team.agent]]\ncount = 0\n",
		"a count over the ceiling":                      "[[team.agent]]\ncount = 65\n",
		"an unterminated header":                        "[team\n",
		"an empty header":                               "[]\n",
		"an unknown key in the team budget":             "[team.resources]\ncpu_quata = \"200%\"\n",
		"a per-agent cap written at team level":         "[team.resources]\nmem = \"2G\"\n",
		"a team quota that is not a percentage":         "[team.resources]\ncpu_quota = 200\n",
	}
	for what, body := range cases {
		_, err := loadString(t, body)
		if err == nil {
			t.Errorf("accepted %s:\n%s", what, body)
			continue
		}
		// Every refusal names the file and line, because a policy error the
		// user cannot locate is barely better than a silent one.
		if !strings.Contains(err.Error(), ".toml:") {
			t.Errorf("%s: refusal does not name a line: %v", what, err)
		}
	}
}

// count has a ceiling for the same reason count < 1 is refused: unlike a
// negative count, an absurdly large one parses cleanly and only fails later,
// where the failure is host/teamplan.go's expandCount allocating a slice with
// that capacity — an unrecoverable OOM abort, not a catchable error, from
// parsing a file alone (F4). The boundary itself must stay usable, and the
// finding's own repro number must be refused with a message a reader can act
// on rather than crash the process.
func TestCountHasACeiling(t *testing.T) {
	atCeiling := "[[team.agent]]\nname = \"a\"\ncount = 64\n"
	cfg := writeAndLoad(t, atCeiling)
	if cfg.Team.Agents[0].Count != maxAgentCount {
		t.Errorf("count at the ceiling (%d) was not accepted: got %d", maxAgentCount, cfg.Team.Agents[0].Count)
	}

	overCeiling := "[[team.agent]]\nname = \"a\"\ncount = 65\n"
	if _, err := loadString(t, overCeiling); err == nil {
		t.Error("count one over the ceiling was accepted")
	} else if !strings.Contains(err.Error(), "count") || !strings.Contains(err.Error(), "64") {
		t.Errorf("refusal does not explain itself: %v", err)
	}

	// The finding's own reproduction: a count large enough that
	// make([]string, 0, count) would abort the process rather than return an
	// error. If this ever regresses to an accepted value, the test process
	// itself would be the one to OOM — which is the point of asserting the
	// refusal instead of expanding it.
	hugeCount := "[[team.agent]]\nname = \"a\"\ncount = 999999999999\n"
	if _, err := loadString(t, hugeCount); err == nil {
		t.Fatal("a count of 999999999999 was accepted instead of refused")
	}
}

// The [resources] keys mean the same thing per agent as they do per run, so
// they are read by one function — and this is the test that says so.
func TestAgentResourcesUseTheSameGrammarAsARun(t *testing.T) {
	cfg := writeAndLoad(t, `
[[team.agent]]
name = "a"
  [team.agent.resources]
  cpus         = 4
  mem          = "2G"
  disk         = "8G"
  scratch      = "512M"
  cpu_quota    = "150%"
  net_mbps_rx  = 10
  net_mbps_tx  = 5
  disk_iops    = 500
  disk_mbps    = 50
  max_runtime  = "30m"
  idle_timeout = "5m"
`)
	r := cfg.Team.Agents[0].Resources
	if r.CPUs != 4 || r.MemMiB != 2048 || r.DiskByte != 8<<30 || r.ScratchByte != 512<<20 ||
		r.CPUQuota != 150 || r.NetMbpsRx != 10 || r.NetMbpsTx != 5 || r.DiskIOPS != 500 ||
		r.DiskMbps != 50 || r.MaxRuntime != 30*time.Minute || r.IdleTimeout != 5*time.Minute {
		t.Errorf("resources = %+v", r)
	}
}

// [team.resources] is the collective budget and is bound to the team, not to an
// element above it — so unlike [team.agent.resources] it may be written
// anywhere in the file (E2-6, F-D21).
func TestTheTeamBudgetParsesWhereverItIsWritten(t *testing.T) {
	before := writeAndLoad(t, `
[team]
name = "t"

  [team.resources]
  cpu_quota = "200%"

[[team.agent]]
name = "a"
`)
	after := writeAndLoad(t, `
[team]
name = "t"

[[team.agent]]
name = "a"

  [team.resources]
  cpu_quota = "200%"
`)
	for what, cfg := range map[string]*Config{"before the agents": before, "after the agents": after} {
		if cfg.Team.Budget.CPUQuota != 200 {
			t.Errorf("%s: cpu_quota = %d, want 200", what, cfg.Team.Budget.CPUQuota)
		}
		line, ok := cfg.Team.Ceiling("cpu_quota")
		if !ok || line == 0 {
			t.Errorf("%s: the budget forgot which line it was written on (%d, %v)", what, line, ok)
		}
	}
	// A team that declared no budget has none, rather than a zero that would
	// read as a cap of nothing.
	plain := writeAndLoad(t, "[team]\nname = \"t\"\n[[team.agent]]\nname = \"a\"\n")
	if plain.Team.Budget.CPUQuota != 0 {
		t.Errorf("a team with no [team.resources] got a budget: %+v", plain.Team.Budget)
	}
}

// A per-agent cap written at team level is a wrong mental model rather than a
// typo, so the refusal answers the question actually being asked instead of
// saying "unknown key".
func TestAPerAgentCapAtTeamLevelSaysWhereItBelongs(t *testing.T) {
	_, err := loadString(t, "[team.resources]\nmem = \"2G\"\n")
	if err == nil {
		t.Fatal("mem was accepted as a team-wide cap")
	}
	for _, want := range []string{"per-agent cap", "[team.agent.resources]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

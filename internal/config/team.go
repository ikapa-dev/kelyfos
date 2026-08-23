package config

import (
	"fmt"
	"strings"
	"time"
)

// The team half of a policy file, parsed by the same hand-rolled reader as the
// rest of it (F-D16).
//
// What this understands, and nothing more: `[team]`, `[team.resources]`,
// `[[team.agent]]`, `[team.agent.resources]`, `[team.agent.spawn]`,
// `[team.agent.spawn.resources]`, `[team.store]` and `[[team.store.key]]`. A
// nested table always belongs to the array element above it, which is what
// makes one level of nesting enough for this schema and keeps the state a
// reader has to hold to two things: which section, and which element.

// Team is the [team] section of a policy file. Nil when the file has none, and
// a file without one is an ordinary single-sandbox policy.
type Team struct {
	Name           string
	RecordPayloads bool
	Agents         []TeamAgent
	Edges          []TeamEdge
	Store          *TeamStore

	// Budget is [team.resources]: the collective cap the whole team shares,
	// as distinct from the per-agent ceilings in [team.agent.resources]
	// (E2-6, F-D21). ResLine remembers where each key was written, so a
	// refusal can name the line the user has to go and change.
	Budget  TeamBudget
	ResLine map[string]int
}

// TeamBudget is [team.resources]. One key today, deliberately: cpu_quota is the
// only cap a team can meaningfully share, because it is the only one the kernel
// will divide for us through a cgroup hierarchy. Memory, cores and disk are
// each agent's own machine and cannot be pooled by a parent slice.
type TeamBudget struct {
	CPUQuota int
}

// Ceiling reports the line a [team.resources] key was written on.
func (t *Team) Ceiling(key string) (line int, ok bool) {
	if t == nil || t.ResLine == nil {
		return 0, false
	}
	line, ok = t.ResLine[key]
	return line, ok
}

// TeamAgent is one [[team.agent]].
type TeamAgent struct {
	Name      string
	Image     string
	Count     int
	Allow     []string
	Secrets   []string
	Workspace string
	Resources AgentResources
	Spawn     *SpawnBudget
	Line      int
}

// AgentResources is the [resources] keys, per agent. Deliberately the same
// names and the same units as a single run: a team is not a second vocabulary
// for the same caps.
type AgentResources struct {
	CPUs        int
	MemMiB      int
	DiskByte    int64
	ScratchByte int64
	CPUQuota    int
	NetMbpsRx   int
	NetMbpsTx   int
	DiskIOPS    int
	DiskMbps    int
	MaxRuntime  time.Duration
	IdleTimeout time.Duration
}

// SpawnBudget is what an agent with team.spawn may ask for at runtime. The
// budget is the user's, written before the run; the decision to spawn is the
// agent's (E2-5).
type SpawnBudget struct {
	Max       int
	Images    []string
	Lifetime  time.Duration
	Resources AgentResources
}

// TeamEdge is one [[team.edge]]. Bidirectional defaults to true, so a file that
// says nothing gets the behaviour the spec documents.
type TeamEdge struct {
	From          string
	To            string
	Bidirectional bool
	Line          int
}

// TeamStore is [team.store] and its [[team.store.key]] rules.
type TeamStore struct {
	Enabled bool
	Keys    []TeamStoreKey
}

// TeamStoreKey is one [[team.store.key]].
type TeamStoreKey struct {
	Name  string
	Read  []string
	Write []string
	Line  int
}

// header interprets a section line and returns the section path it selects.
//
// An array-of-tables header starts a new element; a plain header selects a
// table. Both are validated against the schema here rather than at the key, so
// a misspelt section is refused at the line that spells it.
func (c *Config) header(line, where string) (string, error) {
	if !strings.HasSuffix(line, "]") {
		return "", fmt.Errorf("%s: unterminated section header", where)
	}
	array := strings.HasPrefix(line, "[[")
	name := strings.Trim(line, "[]")
	if name == "" {
		return "", fmt.Errorf("%s: an empty section header selects nothing", where)
	}

	switch {
	case !array && (name == "sandbox" || name == "resources" || name == "mcp"):
		return name, nil

	case !array && name == "team":
		c.ensureTeam()
		return name, nil

	// Bound to the team rather than to an element above it, so unlike
	// [team.agent.resources] it may be written before or after the agents.
	case !array && name == "team.resources":
		c.ensureTeam()
		return name, nil

	case array && name == "team.agent":
		c.ensureTeam()
		c.Team.Agents = append(c.Team.Agents, TeamAgent{Count: 1, Line: lineOf(where)})
		return name, nil

	case !array && (name == "team.agent.resources" || name == "team.agent.spawn" ||
		name == "team.agent.spawn.resources"):
		if c.Team == nil || len(c.Team.Agents) == 0 {
			return "", fmt.Errorf("%s: [%s] has no [[team.agent]] above it to belong to", where, name)
		}
		if name != "team.agent.resources" {
			a := &c.Team.Agents[len(c.Team.Agents)-1]
			if a.Spawn == nil {
				a.Spawn = &SpawnBudget{}
			}
		}
		return name, nil

	case !array && name == "team.store":
		c.ensureTeam()
		if c.Team.Store == nil {
			c.Team.Store = &TeamStore{}
		}
		return name, nil

	case array && name == "team.store.key":
		c.ensureTeam()
		if c.Team.Store == nil {
			c.Team.Store = &TeamStore{}
		}
		c.Team.Store.Keys = append(c.Team.Store.Keys, TeamStoreKey{Line: lineOf(where)})
		return name, nil

	case array && name == "team.edge":
		c.ensureTeam()
		// Bidirectional defaults to true, so it is set here rather than when
		// the key is absent — a default that lives in the constructor cannot be
		// forgotten by a branch that never runs.
		c.Team.Edges = append(c.Team.Edges, TeamEdge{Bidirectional: true, Line: lineOf(where)})
		return name, nil
	}

	kind := "[" + name + "]"
	if array {
		kind = "[[" + name + "]]"
	}
	return "", fmt.Errorf("%s: unknown section %s; this file understands [sandbox], [resources], "+
		"[team] with [team.resources], [[team.agent]] with [team.agent.resources] and "+
		"[team.agent.spawn], [[team.edge]], [team.store] and [[team.store.key]]", where, kind)
}

func (c *Config) ensureTeam() {
	if c.Team == nil {
		c.Team = &Team{}
	}
}

// teamKey assigns one key inside the team half of the file.
func (c *Config) teamKey(section, key, value, where string) error {
	var err error
	switch section {
	case "team":
		switch key {
		case "name":
			c.Team.Name, err = parseString(value, where)
		case "record_payloads":
			c.Team.RecordPayloads, err = parseBool(value, where)
		default:
			return unknown(where, key, section)
		}

	case "team.resources":
		if c.Team.ResLine == nil {
			c.Team.ResLine = map[string]int{}
		}
		c.Team.ResLine[key] = lineOf(where)
		switch key {
		case "cpu_quota":
			c.Team.Budget.CPUQuota, err = parsePercent(value, where)
		case "cpus", "mem", "disk", "scratch", "net_mbps_rx", "net_mbps_tx",
			"disk_iops", "disk_mbps", "max_runtime", "idle_timeout":
			// Not a typo, so not an "unknown key": a wrong mental model, which
			// deserves the answer to the question actually being asked.
			return fmt.Errorf("%s: %s is %s\n"+
				"    [team.resources] is the collective budget, and cpu_quota is the only cap "+
				"a team can share \u2014 cores, RAM and disk are each agent's own machine",
				where, key, teamResourcesRefusal)
		default:
			return unknown(where, key, section)
		}

	case "team.agent":
		a := &c.Team.Agents[len(c.Team.Agents)-1]
		switch key {
		case "name":
			a.Name, err = parseString(value, where)
		case "image":
			a.Image, err = parseString(value, where)
		case "workspace":
			a.Workspace, err = parseString(value, where)
		case "count":
			a.Count, err = parseInt(value, where)
			if err == nil && a.Count < 1 {
				return fmt.Errorf("%s: count must be at least 1", where)
			}
		case "allow":
			a.Allow, err = parseArray(value, where)
		case "secrets":
			a.Secrets, err = parseArray(value, where)
		default:
			return unknown(where, key, section)
		}

	case "team.agent.resources":
		err = assignResources(&c.Team.Agents[len(c.Team.Agents)-1].Resources, key, value, where)

	case "team.agent.spawn":
		sp := c.Team.Agents[len(c.Team.Agents)-1].Spawn
		switch key {
		case "max":
			sp.Max, err = parseInt(value, where)
		case "image":
			sp.Images, err = parseArray(value, where)
		case "lifetime":
			sp.Lifetime, err = parseDuration(value, where, key)
		default:
			return unknown(where, key, section)
		}

	case "team.agent.spawn.resources":
		err = assignResources(&c.Team.Agents[len(c.Team.Agents)-1].Spawn.Resources, key, value, where)

	case "team.edge":
		e := &c.Team.Edges[len(c.Team.Edges)-1]
		switch key {
		case "from":
			e.From, err = parseString(value, where)
		case "to":
			e.To, err = parseString(value, where)
		case "bidirectional":
			e.Bidirectional, err = parseBool(value, where)
		default:
			return unknown(where, key, section)
		}

	case "team.store":
		switch key {
		case "enabled":
			c.Team.Store.Enabled, err = parseBool(value, where)
		default:
			return unknown(where, key, section)
		}

	case "team.store.key":
		k := &c.Team.Store.Keys[len(c.Team.Store.Keys)-1]
		switch key {
		case "name":
			k.Name, err = parseString(value, where)
		case "read":
			k.Read, err = parseArray(value, where)
		case "write":
			k.Write, err = parseArray(value, where)
		default:
			return unknown(where, key, section)
		}

	default:
		return fmt.Errorf("%s: %q appears in a section this file does not understand", where, key)
	}
	return err
}

// assignResources is the one place a [resources] key is read, so a per-agent
// cap and a per-run cap cannot drift apart in name, unit or meaning.
func assignResources(r *AgentResources, key, value, where string) error {
	var err error
	switch key {
	case "cpus":
		r.CPUs, err = parseInt(value, where)
	case "mem":
		r.MemMiB, err = parseMiB(value, where)
	case "disk":
		r.DiskByte, err = parseBytes(value, where)
	case "scratch":
		r.ScratchByte, err = parseBytes(value, where)
	case "cpu_quota":
		r.CPUQuota, err = parsePercent(value, where)
	case "net_mbps_rx":
		r.NetMbpsRx, err = parseRate(value, where, key)
	case "net_mbps_tx":
		r.NetMbpsTx, err = parseRate(value, where, key)
	case "disk_iops":
		r.DiskIOPS, err = parseRate(value, where, key)
	case "disk_mbps":
		r.DiskMbps, err = parseRate(value, where, key)
	case "max_runtime":
		r.MaxRuntime, err = parseDuration(value, where, key)
	case "idle_timeout":
		r.IdleTimeout, err = parseDuration(value, where, key)
	default:
		return unknown(where, key, "resources")
	}
	return err
}

// unknown names the section's real key list, which comes from the schema. That
// is what stops the schema from becoming a copy of the truth that nothing reads.
func unknown(where, key, section string) error {
	return unknownKey(where, key, section)
}

func parseBool(value, where string) (bool, error) {
	switch strings.TrimSpace(value) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("%s: expected true or false, got %s", where, value)
}

// lineOf pulls the line number back out of a "path:line" locator, so a section
// can record where it was declared without threading the number separately.
func lineOf(where string) int {
	i := strings.LastIndexByte(where, ':')
	if i < 0 {
		return 0
	}
	n, err := parseInt(where[i+1:], where)
	if err != nil {
		return 0
	}
	return n
}

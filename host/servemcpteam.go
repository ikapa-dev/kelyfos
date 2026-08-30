package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/mcp"
)

// team_up, team_ps and team_down (E4-3).
//
// The bargain these tools make is the one the guest's own team_spawn makes, and
// it is the whole reason they can exist at all: capacity is grantable, topology
// is not. An outside agent can raise the team the project declared and retire
// it, and there is no argument here that adds an agent or an edge — the shape
// is the file's (docs/mcp-surface.md §1, §2.2).
//
// team_up takes no parameters for that reason. It is not an oversight that
// there is nothing to pass.

// teamReadyTimeout is how long one guest gets to answer. The command line makes
// it a flag; here it is fixed, because a caller that could raise it could wait
// out a wedged machine on the server's time.
const teamReadyTimeout = 60 * time.Second

func teamToolDefinitions() []mcp.Tool {
	return []mcp.Tool{
		{
			Name:  "team_up",
			Title: "Raise the declared team",
			Description: "Boot the team this project's kelyfos.toml declares — every agent, the " +
				"edges between them, and the collective CPU budget — and return the roster. There " +
				"are no parameters: the topology is the file's, and no tool here can add an agent " +
				"or an edge. This server holds one team at a time; other teams may be running " +
				"beside it, raised by somebody else.",
			InputSchema: mcp.Schema{Type: "object"},
		},
		{
			Name:  "team_ps",
			Title: "The team roster",
			Description: "Who is in the team this server raised — what each agent has consumed " +
				"against its cap, what each may reach on the network, and who it can message. " +
				"With no team of its own it answers about the only team running on the host, and " +
				"names them all rather than guessing when several are. Returns structured data as " +
				"well as a table.",
			InputSchema: mcp.Schema{Type: "object"},
		},
		{
			Name:  "team_down",
			Title: "Retire the team",
			Description: "Stop every agent in the running team, write back their workspaces and " +
				"close the team's transcript. Only a team this server raised can be retired here.",
			InputSchema: mcp.Schema{Type: "object"},
		},
	}
}

// syncBuffer collects a team's progress lines for the tool that asked for them.
//
// It is guarded because a team writes from more than one goroutine: teardown
// reports each workspace as it is written back, while a spawn or a lifetime
// timer may still be reporting from its own. An unguarded buffer here is a data
// race, and the machines it takes to trigger one are machines CI does not have.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// take returns everything written since the last take, and empties it.
func (b *syncBuffer) take() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.buf.String()
	b.buf.Reset()
	return strings.TrimRight(out, "\n")
}

func (s *hostServer) toolTeamUp() *mcp.CallToolResult {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	if s.team != nil {
		return mcp.Errorf("this server already has team %q up. Retire it with team_down before "+
			"raising another; this server holds one team at a time.", s.team.plan.name)
	}
	if s.policy == nil || s.policy.Team == nil {
		return mcp.Errorf("this project declares no team. A team is a [team] section in %s with an "+
			"agent list and an edge list — see docs/teams.md — and it is a file a person writes, "+
			"not something a tool here can compose.", s.policyPath())
	}

	// Progress goes into a buffer rather than to stdout, because out here
	// stdout is the protocol. What the command line prints as it boots becomes
	// the tool's answer, and the buffer stays for the rest of the team's life so
	// that team_down can show the write-backs instead of claiming them.
	s.teamLog = &syncBuffer{}
	rig, err := raiseTeam(context.Background(), teamOptions{
		cfg: s.policy, arch: s.arch, timeout: teamReadyTimeout,
		argv: s.argv, owner: ownerServeMCP, out: s.teamLog,
		reason: "raised through serve-mcp session " + s.auditID,
	})
	if err != nil {
		s.teamLog = nil
		return mcp.Errorf("team_up: %v", err)
	}
	s.team = rig

	// This team's own state and not "the running team": another team may have
	// come up on this host between raiseTeam returning and this line (P7-16).
	st, stErr := teamStateOf(rig.session)
	res := &mcp.CallToolResult{Content: []mcp.Content{mcp.Text(s.teamLog.take())}}
	if stErr == nil {
		res.StructuredContent = map[string]any{
			"team": rig.plan.name, "session": rig.session, "summary": rig.summary,
			"agents": teamMembers(st), "edges": st.Edges, "budget": readTeamBudget(st),
		}
	}
	return res
}

func (s *hostServer) toolTeamPS() *mcp.CallToolResult {
	// The team this server raised, when it has one. Falling through to "the
	// running team" would report a stranger's team as this server's the moment
	// two are up, which is now an ordinary state rather than a refused one
	// (P7-16). With no team of its own the old behaviour stands, and selectTeam
	// names them all rather than guessing when several are running.
	st, err := s.ownTeamState()
	if err != nil {
		return mcp.Errorf("%v; raise one with team_up", err)
	}
	members := teamMembers(st)

	var text strings.Builder
	fmt.Fprintf(&text, "team %s — up %s, session %s\n",
		st.Name, time.Since(st.StartedAt).Truncate(time.Second), st.Session)
	for _, m := range members {
		where := "no network interface at all"
		if len(m.Allow) > 0 {
			where = "egress " + strings.Join(m.Allow, ", ")
		}
		if !m.Alive {
			where = "gone"
		}
		fmt.Fprintf(&text, "  %-12s %s  %s", m.Name, m.Sandbox, where)
		if m.Sampled {
			fmt.Fprintf(&text, "  %.1fs cpu", m.CPUSeconds)
		}
		if len(m.Reaches) > 0 {
			fmt.Fprintf(&text, "  reaches %s", strings.Join(m.Reaches, " "))
		}
		text.WriteString("\n")
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.Text(strings.TrimRight(text.String(), "\n"))},
		StructuredContent: map[string]any{
			"team": st.Name, "session": st.Session, "agents": members,
			"edges": st.Edges, "budget": readTeamBudget(st),
			"owner": st.Owner, "started_at": st.StartedAt.UTC().Format(time.RFC3339),
		},
	}
}

func (s *hostServer) toolTeamDown() *mcp.CallToolResult {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	if s.team == nil {
		// A team somebody else raised is theirs to stop, exactly as a sandbox
		// somebody else started is (E4-1). Say which case this is.
		others, _, lerr := liveTeams()
		if lerr == nil && len(others) > 0 {
			return mcp.Errorf("this server raised no team. %d %s running and %s somebody else's to "+
				"stop, with `kelyfos team down`:\n%s", len(others),
				map[bool]string{true: "is", false: "are"}[len(others) == 1],
				map[bool]string{true: "it is", false: "they are"}[len(others) == 1],
				teamRoster(others))
		}
		return mcp.Errorf("no team is running")
	}
	name := s.team.plan.name
	started := time.Now()
	s.team.down()
	s.team = nil

	// What teardown reported on the way out, rather than a claim that it
	// happened: a workspace write-back names the directory it landed in, and
	// that is the part a caller has to be able to check.
	tail := ""
	if s.teamLog != nil {
		tail = s.teamLog.take()
		s.teamLog = nil
	}
	text := fmt.Sprintf("team %s down in %d ms; every agent stopped",
		name, time.Since(started).Milliseconds())
	if tail != "" {
		text += "\n" + tail
	}
	return &mcp.CallToolResult{
		Content:           []mcp.Content{mcp.Text(text)},
		StructuredContent: map[string]any{"team": name, "teardown": tail},
	}
}

// teamMemberHint explains an id that came from team_ps and was handed to a
// sandbox tool.
//
// The sandbox tools deliberately do not reach into a team: an outside client
// may raise the team its project declares and retire it, and what runs inside
// is the team's own business, bounded by the same file (docs/mcp-surface.md
// §2.2). That is a boundary rather than an omission, so the refusal says which
// it is instead of insisting the machine does not exist.
func teamMemberHint(id string) string {
	// Every team on the host, not just the one this server raised and not just
	// "the running team": the id in front of us belongs to whichever team owns
	// it, and answering "no such machine" because a stranger's team owns it is
	// the refusal this function exists to replace (P7-16).
	teams, _, err := liveTeams()
	if err != nil {
		return ""
	}
	for _, st := range teams {
		for _, a := range st.Agents {
			if a.Sandbox != id {
				continue
			}
			return fmt.Sprintf("\n    %s is %s in team %s, which these tools do not reach into: a "+
				"team runs the work its own kelyfos.toml declares. team_ps shows what it is doing.",
				id, a.Name, st.Name)
		}
	}
	return ""
}

// ownTeamState is the state file of the team this server raised, or the only
// team on the host when it raised none.
func (s *hostServer) ownTeamState() (*teamState, error) {
	if s.team != nil {
		return teamStateOf(s.team.session)
	}
	return selectTeam("")
}

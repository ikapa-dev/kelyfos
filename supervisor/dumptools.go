package main

import (
	"encoding/json"
	"io"

	"github.com/p4r4n0rm4l/KelyfOS/internal/mcp"
)

// dumpTools prints the guest's whole tool surface for `make docs`.
//
// It is written here rather than in the generator because the generator would
// then be a second opinion about what the guest offers, and the point of a
// generated reference is that there is only one. What comes out is the
// `tools/list` result three times over — the tools every sandbox has, the ones a
// team member gains, and the one a spawn budget adds — because those three sets
// are exactly the conditions under which a tool is advertised (F-D18), and a
// reference that flattened them would tell an agent it can call something it
// will never be shown.
//
// This runs as an ordinary process on the host with no guest around it, so it
// must not touch the filesystem, open a channel, or read /proc/cmdline. It
// reads the definitions and returns.
type toolDump struct {
	Base      []mcp.Tool `json:"base"`
	Team      []mcp.Tool `json:"team"`
	TeamSpawn []mcp.Tool `json:"team_spawn"`
}

func dumpTools(w io.Writer) error {
	withoutSpawn := teamToolDefinitions(false)
	withSpawn := teamToolDefinitions(true)

	// The spawn set is whatever the budget adds on top, found by difference so
	// that this cannot drift if another conditional tool is ever added.
	have := map[string]bool{}
	for _, t := range withoutSpawn {
		have[t.Name] = true
	}
	var extra []mcp.Tool
	for _, t := range withSpawn {
		if !have[t.Name] {
			extra = append(extra, t)
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(toolDump{
		Base:      toolDefinitions(),
		Team:      withoutSpawn,
		TeamSpawn: extra,
	})
}

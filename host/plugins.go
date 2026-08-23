package main

import (
	"fmt"
	"path/filepath"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// packPlugins builds the read-only plugins device a policy declares, or returns
// nil when it declares none (E4-6).
//
// One function for every door, because a plugin is part of what a project is: a
// sandbox raised through `kelyfos run` and one raised through `serve-mcp` should
// carry the same tools, and two call sites that each remembered to pack would
// eventually be one that did and one that forgot.
func packPlugins(cfg *config.Config, id string) (*sandbox.Plugins, error) {
	if cfg == nil || len(cfg.Plugins) == 0 {
		return nil, nil
	}
	if err := cfg.CheckPlugins(); err != nil {
		return nil, err
	}
	specs := make([]sandbox.PluginSpec, 0, len(cfg.Plugins))
	for _, p := range cfg.Plugins {
		// Relative to the policy file, not the working directory: the file
		// describes its own project, wherever it is invoked from. Same rule the
		// workspace path follows, and it matters more here — a client launches
		// serve-mcp from a directory nobody chose.
		dir := p.Path
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(filepath.Dir(cfg.Path), dir)
		}
		specs = append(specs, sandbox.PluginSpec{
			Name: p.Name, Dir: dir, Command: p.Command, Args: p.Args,
		})
	}
	plugins, err := sandbox.PackPlugins(specs,
		filepath.Join(sandbox.Root(), "plugins", id+".ext4"))
	if err != nil {
		return nil, fmt.Errorf("pack the plugins device: %w", err)
	}
	return plugins, nil
}

// pluginEvent turns what the guest reported into what the host records.
//
// The guest reports facts and the host writes the chain, exactly as it does for
// resource.oom: a guest that could write its own audit trail could forge it
// (docs/events.md §1). Every field here is one the guest sent, and the source
// says so.
func pluginEvent(ev proto.GuestEvent) recorder.Event {
	out := recorder.Event{Source: recorder.SourceGuest, Name: ev.Name}
	switch ev.Type {
	case proto.GuestEventPluginCall:
		out.Type = recorder.TypePluginCall
		out.Tool = ev.Tool
		out.Outcome = ev.Outcome
		out.DurationMS = ev.DurationMS
		out.Args = ev.Args
	case proto.GuestEventPluginCrash:
		out.Type = recorder.TypePluginCrash
		out.Reason = ev.Message
	}
	return out
}

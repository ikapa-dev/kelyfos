package main

import (
	"fmt"
	"path/filepath"

	"github.com/ikapa-dev/kelyfos/internal/config"
	"github.com/ikapa-dev/kelyfos/internal/proto"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// packPlugins builds the read-only plugins device a policy declares, or returns
// nil when it declares none (E4-6).
//
// One function for every door, because a plugin is part of what a project is: a
// sandbox raised through `kelyfos run` and one raised through `serve-mcp` should
// carry the same tools, and two call sites that each remembered to pack would
// eventually be one that did and one that forgot.
// allowedPaths is what the operator typed with --plugin-path. The scope check
// lives here rather than at the two callers for the reason F7 gives about
// snapshotDir in this same task: a rule enforced at some call sites is a rule
// the next call site will miss (P7-17/F21).
func packPlugins(cfg *config.Config, id string, allowedPaths []string) (*sandbox.Plugins, error) {
	if cfg == nil || len(cfg.Plugins) == 0 {
		return nil, nil
	}
	if err := cfg.CheckPlugins(); err != nil {
		return nil, err
	}
	if err := checkPluginScope(cfg, allowedPaths); err != nil {
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

// guestEventRecorder builds the sandbox.Options.OnGuestEvent handler for any
// door that resumes a machine into a recorder it already has open: an OOM kill
// or a plugin call/crash goes into that machine's own chain, the same two
// cases memberOptions has always handled for a team member.
//
// It exists because memberOptions was the only place that got this right.
// host/fork.go, host/snapshot.go, host/sessions.go and host/servemcpstate.go's
// restore and fork tools each built a bare sandbox.Options{} for
// sandbox.Restore with no OnGuestEvent at all — sandbox.go's serveEvents drops
// a guest frame silently when the handler is nil, so a guest OOM kill or
// plugin crash on any restored, forked or resumed session left no trace in the
// flight recorder (F3). agent tags the event the way a team member's name
// does; pass "" where the door has no such concept.
func guestEventRecorder(rec *recorder.Recorder, agent string, memMiB int) func(proto.GuestEvent) {
	return func(ev proto.GuestEvent) {
		switch ev.Type {
		case proto.GuestEventOOM:
			_ = rec.Append(recorder.Event{
				Type: recorder.TypeResourceOOM, Source: recorder.SourceGuest, Agent: agent,
				PID: ev.PID, Comm: ev.Comm, RSSKiB: ev.RSSKiB, MemMiB: memMiB,
			})
		case proto.GuestEventPluginCall, proto.GuestEventPluginCrash:
			e := pluginEvent(ev)
			e.Agent = agent
			_ = rec.Append(e)
		}
	}
}

// channelRefusedRecorder builds the sandbox.Options.OnChannelRefused handler
// for the same doors: every connection refused on a guest-initiated channel
// for lacking the session's credential lands in the chain that machine is
// already writing (audit 2026-09-01, A2/A3). The refusal is the host's own
// act — source host — and the port and the reason are all the event holds,
// because everything else the peer sent stopped at the gate.
func channelRefusedRecorder(rec *recorder.Recorder, agent string) func(port uint32, reason string) {
	return func(port uint32, reason string) {
		_ = rec.Append(recorder.Event{
			Type: recorder.TypeChannelRefused, Source: recorder.SourceHost, Agent: agent,
			Port: int(port), Reason: proto.SafeText(reason),
		})
	}
}

// vmmActionRecorder builds the sandbox.Options.OnVMMAction handler: every
// state-changing Firecracker API call the host makes is in the transcript
// (audit 2026-09-01, A11), where before pause, resume, snapshot create/load
// and drive patch happened with nothing saying so.
func vmmActionRecorder(rec *recorder.Recorder, agent string) func(action string) {
	return func(action string) {
		_ = rec.Append(recorder.Event{
			Type: recorder.TypeVMMAction, Source: recorder.SourceHost, Agent: agent,
			Mode: proto.SafeText(action),
		})
	}
}

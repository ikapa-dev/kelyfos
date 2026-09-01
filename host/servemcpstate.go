package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/denial"
	"github.com/ikapa-dev/kelyfos/internal/egress"
	"github.com/ikapa-dev/kelyfos/internal/mcp"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
	"github.com/ikapa-dev/kelyfos/internal/sessionpolicy"
)

// sandbox_snapshot, sandbox_restore and sandbox_fork (E4-2).
//
// The machinery is P3's, unchanged. What this layer adds is the two things an
// outside caller changes about the problem: a snapshot name now arrives from a
// model rather than from a person's flag, and a restored machine is a machine
// this server is answerable for — so it is held to the same ceiling, counted
// against the same limit, and recorded in the same way as one it booted.

// validSnapshotName decides what a name may be.
//
// A name becomes a directory under the sandbox root. On the command line it
// comes from a person typing into their own shell, where a slash in it is their
// business; here it comes from a model on the far side of the wall, so it is
// checked rather than trusted. Nothing that could walk out of the snapshots
// directory gets as far as being joined to a path.
func validSnapshotName(name string) error {
	if name == "" {
		return fmt.Errorf("this tool needs a snapshot `name`")
	}
	if len(name) > 64 {
		return fmt.Errorf("snapshot name %q is longer than 64 characters", name)
	}
	// The character rule is checked first so that a name like "../evil" is
	// refused for the reason a reader cares about — the slash — rather than for
	// the dot it also happens to start with.
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return fmt.Errorf("snapshot name %q contains %q; names are letters, digits, dot, "+
				"dash and underscore, because a name is a directory", name, string(r))
		}
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("snapshot name %q may not start with a dot", name)
	}
	return nil
}

// --- sandbox_snapshot --------------------------------------------------------

func (s *hostServer) toolSnapshot(raw json.RawMessage) *mcp.CallToolResult {
	var a struct {
		Sandbox string `json:"sandbox"`
		Name    string `json:"name"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return mcp.Errorf("sandbox_snapshot: %v", err)
	}
	b, err := s.box(a.Sandbox)
	if err != nil {
		return mcp.Errorf("%v", err)
	}
	// snapshotDir is the gate now (P7-17/F7): it calls validSnapshotName
	// itself, so the check is not repeated here — a rule enforced at some call
	// sites is the finding, and a rule enforced at the call site AND in the
	// function is the same rule twice with two places to drift.
	dir, err := snapshotDir(a.Name)
	if err != nil {
		return mcp.Errorf("%v", err)
	}
	started := time.Now()
	statePath, memPath, err := sandbox.SnapshotRunning(&b.sb.State, dir)
	if err != nil {
		return mcp.Errorf("sandbox_snapshot: %v", err)
	}
	stateInfo, _ := os.Stat(statePath)
	memInfo, _ := os.Stat(memPath)
	elapsed := time.Since(started)
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.Text(fmt.Sprintf(
			"saved snapshot %q from sandbox %s in %d ms; the sandbox is still running",
			a.Name, a.Sandbox, elapsed.Milliseconds()))},
		StructuredContent: map[string]any{
			"name": a.Name, "sandbox": a.Sandbox, "took_ms": elapsed.Milliseconds(),
			"state_bytes": sizeOf(stateInfo), "memory_bytes": sizeOf(memInfo),
		},
	}
}

// --- sandbox_restore ---------------------------------------------------------

func (s *hostServer) toolRestore(raw json.RawMessage) *mcp.CallToolResult {
	var a struct {
		Name        string   `json:"name"`
		Allow       []string `json:"allow"`
		Traceparent string   `json:"traceparent"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return mcp.Errorf("sandbox_restore: %v", err)
	}
	// snapshotDir is the gate now (P7-17/F7): it calls validSnapshotName
	// itself, so the check is not repeated here — a rule enforced at some call
	// sites is the finding, and a rule enforced at the call site AND in the
	// function is the same rule twice with two places to drift.
	dir, err := snapshotDir(a.Name)
	if err != nil {
		return mcp.Errorf("%v", err)
	}
	meta, err := sandbox.ReadSnapshotMeta(dir)
	if err != nil {
		return mcp.Errorf("no snapshot named %q: %v", a.Name, err)
	}
	if err = s.checkSnapshotFits(a.Name, meta); err != nil {
		return mcp.Errorf("%v", err)
	}
	// What the machine may reach is settled before anything else: a request the
	// policy forbids is wrong for good, and saying so first is more use than
	// reporting a collision that would have cleared on its own.
	var allow []string
	if meta.HasNetwork {
		if allow, err = s.restoreAllow(a.Name, a.Allow, meta); err != nil {
			return mcp.Errorf("%v", err)
		}
	}
	if err := s.holdsTheAddress(a.Name, meta); err != nil {
		return mcp.Errorf("%v", err)
	}
	if err := s.room(1); err != nil {
		return mcp.Errorf("%v", err)
	}

	opts := sandbox.Options{Arch: meta.Arch, Flavor: meta.Flavor, Quiet: true,
		VcpuCount: meta.VcpuCount, MemMiB: meta.MemMiB}
	if opts.Arch == "" {
		opts.Arch = s.arch
	}
	// The id is chosen here rather than deeper down so that everything this
	// machine will be watched by — its cgroup, its proxy, its recorder — can be
	// built and wired before it is resumed. A restored guest runs the instant
	// Restore returns, and an audit trail that starts a moment later is an audit
	// trail with a hole at the front of it.
	id, err := sandbox.NewID()
	if err != nil {
		return mcp.Errorf("sandbox_restore: %v", err)
	}
	opts.ID = id
	b := &servedBox{image: opts.Flavor, created: time.Now()}
	ok := false
	defer func() {
		if !ok {
			b.close("error")
		}
	}()

	if s.policy != nil && s.policy.ResCPUQuota > 0 {
		if b.slice, err = sandbox.NewCPUSlice(id, s.policy.ResCPUQuota); err != nil {
			return mcp.Errorf("sandbox_restore: %v", err)
		}
		opts.CPUSlice = b.slice
	}

	var ca *egress.CA
	// Hoisted so session.policy can read it back once the machine is ready
	// (P7-2, docs/policy-record.md §5) — scoped to building the proxy above,
	// but what it bound is part of what this restore was permitted.
	var boundSecrets []*egress.Secret
	if meta.HasNetwork {
		if s.policy != nil {
			for _, spec := range s.policy.Secrets {
				sec, err := egress.ParseSecret(spec)
				if err != nil {
					return mcp.Errorf("sandbox_restore: %v", err)
				}
				if containsDomain(allow, sec.Domain) {
					boundSecrets = append(boundSecrets, sec)
				}
			}
		}
		if b.proxy, ca, err = restoreNetwork(meta, allow, boundSecrets, &opts); err != nil {
			return mcp.Errorf("sandbox_restore: %v", err)
		}
		b.net = opts.Net
		b.allow = allow
	}

	rec, err := recorder.Open(sandbox.Root(), id)
	if err != nil {
		return mcp.Errorf("sandbox_restore: %v", err)
	}
	b.setRec(rec)
	_ = b.rec.Append(recorder.Event{
		Type: recorder.TypeSessionStart, Image: opts.Flavor, Arch: opts.Arch,
		Kelyfos: Version, Argv: s.argv, Reason: "restored from " + a.Name + " through serve-mcp session " + s.auditID,
	})
	b.wireAudit()
	// Wired before Restore, same as sandbox_snapshot's CLI sibling in
	// snapshot.go: the guest is live and reporting well before Restore
	// returns, and an OOM kill or a plugin crash here otherwise left no trace
	// at all (F3).
	opts.OnGuestEvent = guestEventRecorder(rec, "", meta.MemMiB)

	sb, elapsed, err := sandbox.Restore(dir, opts)
	if err != nil {
		return mcp.Errorf("sandbox_restore: %v", err)
	}
	b.sb = sb
	// D6 mints a fresh CA every run, so a restored guest carries an anchor for a
	// CA that no longer exists. Replace it before anything in there reaches for
	// a secret-bound domain.
	if ca != nil {
		if err := sb.InstallTrustAnchor(ca.AnchorPEM()); err != nil {
			return mcp.Errorf("sandbox_restore: %v", err)
		}
	}
	_ = b.rec.Append(recorder.Event{
		Type: recorder.TypeSessionReady, BootMS: elapsed.Milliseconds(),
	}.WithPosture(sb.State.Jailed, sb.State.Profile))

	// What this restore was permitted (P7-2, docs/policy-record.md §5).
	// scratch, the rate caps and both budgets are genuinely absent here — a
	// restore's opts carries only Arch/Flavor/Quiet/VcpuCount/MemMiB (above),
	// the same enforcement gap host/snapshot.go's own restore has.
	cpuQuota := 0
	if s.policy != nil {
		cpuQuota = s.policy.ResCPUQuota
	}
	rootfsSHA, kernelSHA := sessionpolicy.Digests(sandbox.ImageDir(opts.Arch))
	_ = b.rec.Append(recorder.NewSessionPolicy("", recorder.PolicyFields{
		VcpuCount: opts.VcpuCount, MemMiB: opts.MemMiB, CPUQuota: cpuQuota,
		Allow: b.allow, Ports: sessionpolicy.Ports(b.allow),
		Secrets:       sessionpolicy.Secrets(boundSecrets),
		Tools:         sessionpolicy.MCPTools,
		ParentSession: meta.SourceSession,
		RootfsSHA256:  rootfsSHA,
		KernelSHA256:  kernelSHA,
		Traceparent:   a.Traceparent,
	}))

	if err := s.adopt(b); err != nil {
		return mcp.Errorf("%v", err)
	}
	ok = true
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.Text(fmt.Sprintf(
			"sandbox %s restored from %q in %d ms (%s)",
			sb.State.ID, a.Name, elapsed.Milliseconds(), describeAllow(b.allow)))},
		StructuredContent: map[string]any{
			"sandbox": sb.State.ID, "snapshot": a.Name, "image": b.image,
			"restore_ms": elapsed.Milliseconds(), "allow": b.allow,
		},
	}
}

// restoreAllow decides what a restored machine may reach.
//
// Two ceilings apply and neither may be crossed: the project's policy, because
// that is the wall (F-D5), and the snapshot's own allowlist, because a machine
// that was frozen unable to reach somewhere does not gain the ability by being
// thawed. The default is the snapshot's list, so a restore never silently
// widens anything (D22).
func (s *hostServer) restoreAllow(name string, asked []string, meta *sandbox.SnapshotMeta) ([]string, error) {
	list := asked
	if len(list) == 0 {
		list = meta.Allow
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("snapshot %q was taken from a networked sandbox but recorded no "+
			"allowlist, so there is nothing to restore it with; name one in `allow`", name)
	}
	for _, d := range list {
		if !containsDomain(meta.Allow, d) {
			return nil, denial.AllowSnapshot.Err(denial.V{
				"domain": d, "name": name, "permitted": describeAllow(meta.Allow)})
		}
		if s.policy != nil && !containsDomain(s.policy.Allow, d) {
			return nil, denial.AllowProject.Err(denial.V{
				"domain": d, "file": s.policy.Path, "permitted": describeAllow(s.policy.Allow)})
		}
	}
	return list, nil
}

// checkSnapshotFits holds a frozen machine to the same ceiling a fresh one gets.
//
// Firecracker takes vcpu and memory from the state file, so a restore cannot
// shrink a machine to fit — the only honest answers are to allow it or refuse
// it. A snapshot from an older kelyfos does not say what it holds; when there
// is a ceiling to enforce, that unknown is refused rather than waved through,
// because a wall with an exception in it is not a wall.
func (s *hostServer) checkSnapshotFits(name string, meta *sandbox.SnapshotMeta) error {
	cfg := s.policy
	if cfg == nil || (cfg.ResCPUs == 0 && cfg.ResMemMiB == 0) {
		return nil
	}
	if meta.VcpuCount == 0 && meta.MemMiB == 0 {
		return denial.CeilingSnapshotUnknown.Err(denial.V{"name": name, "file": cfg.Path})
	}
	if cfg.ResCPUs > 0 && meta.VcpuCount > cfg.ResCPUs {
		line, _ := cfg.Ceiling("cpus")
		return denial.CeilingSnapshot.Err(denial.V{
			"name": name, "held": fmt.Sprintf("%d vcpu", meta.VcpuCount), "key": "cpus",
			"limit": strconv.Itoa(cfg.ResCPUs), "file": cfg.Path, "line": strconv.Itoa(line)})
	}
	if cfg.ResMemMiB > 0 && meta.MemMiB > cfg.ResMemMiB {
		line, _ := cfg.Ceiling("mem")
		return denial.CeilingSnapshot.Err(denial.V{
			"name": name, "held": fmt.Sprintf("%d MiB", meta.MemMiB), "key": "mem",
			"limit": fmt.Sprintf("%d MiB", cfg.ResMemMiB), "file": cfg.Path,
			"line": strconv.Itoa(line)})
	}
	return nil
}

// --- sandbox_fork ------------------------------------------------------------

// maxForkCall is the most machines one sandbox_fork call may ask for.
//
// It is a hard constant rather than a policy key, because its job is to stand
// between a client's count and arithmetic that the count could overflow: the
// ceiling checks below multiply and add, and a count near the largest signed
// integer wrapped both of them — through the fleet ceiling and into a
// make([]result, n) that panicked the server and orphaned every machine it
// owned (independent audit 2026-09-01, A1). Nothing that survives this bound
// can wrap: 256 × any workspace size fits an int64 many times over, and
// [mcp] max_sandboxes still says how many of the batch may run at once.
const maxForkCall = 256

func (s *hostServer) toolFork(raw json.RawMessage) *mcp.CallToolResult {
	var a struct {
		Name        string `json:"name"`
		Count       int    `json:"count"`
		Traceparent string `json:"traceparent"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return mcp.Errorf("sandbox_fork: %v", err)
	}
	// The name before the count, which is the order this tool has always
	// reported them in; snapshotDir is what checks it now (P7-17/F7).
	dir, err := snapshotDir(a.Name)
	if err != nil {
		return mcp.Errorf("%v", err)
	}
	if a.Count < 1 {
		return mcp.Errorf("sandbox_fork needs a `count` of at least 1")
	}
	// The count is bounded before anything is done with it — before the space
	// check, which multiplies it by a workspace size, and before the fleet
	// ceiling, which adds it to what is running. Both were wrappable with an
	// unbounded count, and the second wrapped into a panic that killed this
	// server and every machine it owned (audit 2026-09-01, A1).
	if a.Count > maxForkCall {
		return mcp.Errorf("%v", denial.ForkCount.Err(denial.V{
			"asked": strconv.Itoa(a.Count), "limit": strconv.Itoa(maxForkCall)}))
	}
	meta, err := sandbox.ReadSnapshotMeta(dir)
	if err != nil {
		return mcp.Errorf("no snapshot named %q: %v", a.Name, err)
	}
	if err := s.checkSnapshotFits(a.Name, meta); err != nil {
		return mcp.Errorf("%v", err)
	}
	// P3-2's rule, unchanged: forks are vsock-only, because the guest's address
	// lives inside the memory image every fork shares and N forks would each
	// believe they were the same host.
	if meta.HasNetwork {
		return mcp.Errorf("snapshot %q was taken from a sandbox with egress (%s), and forks are "+
			"vsock-only in v0.x: forking needs one network identity per fork, and the guest's "+
			"address is baked into the shared memory image.\n"+
			"    restore it as a single machine with sandbox_restore, or prepare a snapshot "+
			"without egress and fork that.", a.Name, describeAllow(meta.Allow))
	}
	if meta.HasWorkspace {
		if err := sandbox.CheckForkSpace(sandbox.RunRoot(), a.Count, meta.WorkspaceSize); err != nil {
			return mcp.Errorf("sandbox_fork: %v", err)
		}
	}
	if err := s.room(a.Count); err != nil {
		return mcp.Errorf("%v", err)
	}

	arch := meta.Arch
	if arch == "" {
		arch = s.arch
	}
	type result struct {
		sb      *sandbox.Sandbox
		rec     *recorder.Recorder
		elapsed time.Duration
		err     error
	}
	results := make([]result, a.Count)
	started := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < a.Count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := sandbox.NewID()
			if err != nil {
				results[i] = result{err: err}
				return
			}
			// Opened and wired before Restore, not after it returns as this
			// used to do: the guest is live and reporting from the instant
			// Restore resumes it, and a recorder opened only once every fork
			// in the batch has finished is a recorder that missed whatever
			// the fastest of them said first (F3).
			rec, err := recorder.Open(sandbox.Root(), id)
			if err != nil {
				results[i] = result{err: err}
				return
			}
			_ = rec.Append(recorder.Event{
				Type: recorder.TypeSessionStart, Image: meta.Flavor, Arch: arch,
				Kelyfos: Version, Argv: s.argv,
				Reason: "forked from " + a.Name + " through serve-mcp session " + s.auditID,
			})
			sb, elapsed, err := sandbox.Restore(dir, sandbox.Options{
				ID: id, Arch: arch, Flavor: meta.Flavor, Quiet: true,
				VcpuCount: meta.VcpuCount, MemMiB: meta.MemMiB,
				OnGuestEvent: guestEventRecorder(rec, "", meta.MemMiB),
			})
			if err != nil {
				_ = rec.Append(recorder.Event{Type: recorder.TypeSessionEnd, Reason: "error",
					DurationMS: rec.Since().Milliseconds()})
				_ = rec.Close()
				results[i] = result{err: err}
				return
			}
			results[i] = result{sb: sb, rec: rec, elapsed: elapsed}
		}(i)
	}
	wg.Wait()
	total := time.Since(started)

	var ids []string
	var failures []string
	for i, r := range results {
		if r.err != nil {
			failures = append(failures, fmt.Sprintf("fork %d: %v", i+1, r.err))
			continue
		}
		b := &servedBox{sb: r.sb, image: meta.Flavor, created: time.Now()}
		b.setRec(r.rec)
		_ = r.rec.Append(recorder.Event{
			Type: recorder.TypeSessionReady, BootMS: r.elapsed.Milliseconds(),
		}.WithPosture(r.sb.State.Jailed, r.sb.State.Profile))
		// What this fork was permitted (P7-2, docs/policy-record.md §5).
		// Always no network, no secrets, no workspace: a networked snapshot
		// is refused before any of this runs (above). cpu_quota is genuinely
		// unapplied on this door — nothing here builds a CPUSlice, unlike
		// `kelyfos fork`'s own -cpu-quota flag.
		rootfsSHA, kernelSHA := sessionpolicy.Digests(sandbox.ImageDir(arch))
		_ = r.rec.Append(recorder.NewSessionPolicy("", recorder.PolicyFields{
			VcpuCount: meta.VcpuCount, MemMiB: meta.MemMiB,
			Tools:         sessionpolicy.MCPTools,
			ParentSession: meta.SourceSession,
			RootfsSHA256:  rootfsSHA,
			KernelSHA256:  kernelSHA,
			Traceparent:   a.Traceparent,
		}))
		if err := s.adopt(b); err != nil {
			// The limit was checked before any of this started, so getting here
			// means another call took the room. Stop the fork rather than
			// running a machine nobody is counting.
			b.close("error")
			failures = append(failures, fmt.Sprintf("fork %d: %v", i+1, err))
			continue
		}
		ids = append(ids, r.sb.State.ID)
	}
	if len(ids) == 0 {
		return mcp.Errorf("no fork could be restored from snapshot %q:\n    %s",
			a.Name, strings.Join(failures, "\n    "))
	}

	var text strings.Builder
	fmt.Fprintf(&text, "%d fork(s) of %q live in %d ms wall clock: %s",
		len(ids), a.Name, total.Milliseconds(), strings.Join(ids, " "))
	for _, f := range failures {
		fmt.Fprintf(&text, "\n%s", f)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.Text(text.String())},
		StructuredContent: map[string]any{
			"sandboxes": ids, "snapshot": a.Name, "wall_ms": total.Milliseconds(),
			"failed": failures,
		},
	}
}

// --- bookkeeping shared by the doors that create machines ---------------------

// room refuses before anything is built when the limit could not hold what is
// being asked for. adopt is the same check again at the moment of registration,
// because between the two another call may have taken the space.
//
// The comparison is written as a subtraction, `n > s.max-have`, and never as
// the addition it replaced: `have+n` wraps for an n near MaxInt64 and reads as
// though there were room when there is none (audit 2026-09-01, A1). have
// cannot exceed s.max — adopt refuses the registration that would — so
// s.max-have is never negative, and no unsigned count survives it.
func (s *hostServer) room(n int) error {
	s.mu.Lock()
	have := len(s.boxes)
	s.mu.Unlock()
	if n > s.max-have {
		return denial.BudgetSandboxes.Err(denial.V{
			"running": strconv.Itoa(have), "asked": strconv.Itoa(n),
			"limit": strconv.Itoa(s.max), "file": s.policyPath()})
	}
	return nil
}

func (s *hostServer) adopt(b *servedBox) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.boxes) >= s.max {
		return denial.BudgetSandboxes.Err(denial.V{
			"running": strconv.Itoa(s.max), "asked": "1",
			"limit": strconv.Itoa(s.max), "file": s.policyPath()})
	}
	s.boxes[b.sb.State.ID] = b
	// Every door that builds a machine on this server arrives here, which is
	// why the watcher starts here rather than at the three setRec calls
	// (P7-17/F13(b)).
	go s.watchRecorder(b.sb.State.ID, b)
	return nil
}

// holdsTheAddress refuses a restore that would collide with a machine already
// running on the address the snapshot expects.
//
// A networked guest's own address and proxy port live inside its memory image
// and cannot be changed from out here (D22), so exactly one machine can hold
// them at a time — including the machine the snapshot was taken from, which
// serve-mcp usually still has running. Without this the failure is a bind error
// from deep inside the egress proxy, which is true and tells nobody anything.
func (s *hostServer) holdsTheAddress(name string, meta *sandbox.SnapshotMeta) error {
	if !meta.HasNetwork || meta.HostIP == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, b := range s.boxes {
		if b.sb == nil || b.sb.State.HostIP != meta.HostIP {
			continue
		}
		return fmt.Errorf("snapshot %q expects the address %s, and sandbox %s is still on it. A "+
			"networked guest's address is inside the memory image it was frozen with, so only one "+
			"machine can hold it at a time.\n"+
			"    stop %s with sandbox_stop and restore again, or take the snapshot from a sandbox "+
			"with no egress, which forks as many times as you like.",
			name, meta.HostIP, id, id)
	}
	return nil
}

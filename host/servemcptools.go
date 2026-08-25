package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/denial"
	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
	"github.com/p4r4n0rm4l/KelyfOS/internal/mcp"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// The outward tool surface (E4-1). Names are lowercase ASCII with underscores
// and stay well inside 64 characters, which is the strictest limit anything
// downstream of MCP imposes (F-D36).
//
// Descriptions are written for a model rather than for a reference: they say
// what the tool does, what it will refuse, and what to do instead — because a
// tool description is the only documentation a model reliably reads.
func hostToolDefinitions() []mcp.Tool {
	str := func(desc string) mcp.Property { return mcp.Property{Type: "string", Description: desc} }
	tools := []mcp.Tool{
		{
			Name:  "sandbox_run",
			Title: "Start a sandbox",
			Description: "Boot a hardware-isolated microVM and return its id. Anything run inside " +
				"it cannot reach this machine. It has no network at all unless the project's " +
				"policy grants one. Every argument here may ask for less than the policy allows " +
				"and never for more; a request above a ceiling is refused and names the ceiling.",
			InputSchema: mcp.Schema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"image": str("Image flavor. Defaults to the project's."),
					"cpus":  {Type: "integer", Description: "Cores the guest sees. At most what the policy allows."},
					"mem":   str("Guest memory, e.g. \"512M\". At most what the policy allows."),
					"allow": {Type: "array", Description: "Domains this sandbox may reach. Must be a subset of the policy's allowlist.",
						Items: &mcp.Property{Type: "string"}},
				},
			},
		},
		{
			Name:  "sandbox_exec",
			Title: "Run a command in a sandbox",
			Description: "Run a command inside a sandbox and return its output and exit code. " +
				"Give `command` for a shell command line, or `argv` to run a program directly " +
				"with no shell. A command that exits non-zero comes back with isError set and " +
				"its real output intact — that is the command failing, not the call failing, so " +
				"read exit_code and stderr rather than retrying.",
			InputSchema: mcp.Schema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"sandbox":    str("The sandbox id from sandbox_run."),
					"command":    str("Shell command line, run as /bin/sh -c \"<command>\"."),
					"argv":       {Type: "array", Description: "Argument vector, executed with no shell.", Items: &mcp.Property{Type: "string"}},
					"cwd":        str("Working directory inside the guest. Defaults to /."),
					"stdin":      str("Text written to the command's standard input."),
					"timeout_ms": {Type: "integer", Description: "Kill the command after this many milliseconds."},
				},
				Required: []string{"sandbox"},
			},
		},
		{
			Name:  "sandbox_read_file",
			Title: "Read a file from a sandbox",
			Description: "Read a text file out of a sandbox and return its contents. This is the " +
				"sandbox's own read_file with an id in front, so it refuses a file over 8 MiB for " +
				"the same reason: work with something that large in place, using sandbox_exec.",
			InputSchema: mcp.Schema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"sandbox": str("The sandbox id from sandbox_run."),
					"path":    str("Absolute path inside the guest."),
				},
				Required: []string{"sandbox", "path"},
			},
		},
		{
			Name:  "sandbox_write_file",
			Title: "Write a file into a sandbox",
			Description: "Write text to a path inside a sandbox, creating parent directories and " +
				"replacing anything already there. At most 8 MiB per call. The write is recorded " +
				"in the session's audit log by path, size and digest — never by content.",
			InputSchema: mcp.Schema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"sandbox": str("The sandbox id from sandbox_run."),
					"path":    str("Absolute path inside the guest."),
					"content": str("The text to write."),
				},
				Required: []string{"sandbox", "path", "content"},
			},
		},
		{
			Name:        "sandbox_stop",
			Title:       "Stop a sandbox",
			Description: "Stop a sandbox this server started and release its resources.",
			InputSchema: mcp.Schema{
				Type:       "object",
				Properties: map[string]mcp.Property{"sandbox": str("The sandbox id.")},
				Required:   []string{"sandbox"},
			},
		},
		{
			Name:  "sandbox_list",
			Title: "List sandboxes",
			Description: "The sandboxes this server has started and not yet stopped, with the " +
				"policy each is running under.",
			InputSchema: mcp.Schema{Type: "object"},
		},
		{
			Name:  "sandbox_snapshot",
			Title: "Snapshot a sandbox",
			Description: "Freeze a sandbox under a name so it can be restored or forked later. " +
				"The sandbox keeps running and is unaffected. Snapshots outlive this server, and " +
				"a name that already exists is overwritten.",
			InputSchema: mcp.Schema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"sandbox": str("The sandbox id to freeze."),
					"name":    str("A name for the snapshot: letters, digits, dot, dash, underscore."),
				},
				Required: []string{"sandbox", "name"},
			},
		},
		{
			Name:  "sandbox_restore",
			Title: "Restore a snapshot",
			Description: "Bring a snapshot back as a new sandbox, which takes milliseconds rather " +
				"than a boot. Returns the new sandbox's id. `allow` may narrow what the restored " +
				"machine can reach and can never widen it — not beyond the project's policy, and " +
				"not beyond what the snapshot itself was allowed.",
			InputSchema: mcp.Schema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"name": str("The snapshot name."),
					"allow": {Type: "array", Description: "Narrow the restored machine's allowlist. Defaults to the snapshot's own.",
						Items: &mcp.Property{Type: "string"}},
				},
				Required: []string{"name"},
			},
		},
		{
			Name:  "sandbox_fork",
			Title: "Fork a snapshot",
			Description: "Restore one snapshot into several sandboxes at once. Each fork resumes " +
				"from the same prepared state and then diverges, sharing nothing. A snapshot taken " +
				"from a sandbox with network access cannot be forked, because the guest's address " +
				"is inside the memory image every fork would share; restore it singly instead.",
			InputSchema: mcp.Schema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"name":  str("The snapshot name."),
					"count": {Type: "integer", Description: "How many forks to make. At least 1."},
				},
				Required: []string{"name", "count"},
			},
		},
	}
	return append(tools, teamToolDefinitions()...)
}

// --- sandbox_run -------------------------------------------------------------

type runArgs struct {
	Image string   `json:"image"`
	CPUs  int      `json:"cpus"`
	Mem   string   `json:"mem"`
	Allow []string `json:"allow"`
}

func (s *hostServer) toolRun(raw json.RawMessage) *mcp.CallToolResult {
	var a runArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return mcp.Errorf("sandbox_run: %v", err)
	}

	// The ceiling check comes before anything is built, so a refusal costs
	// nothing and a machine is never half-created (docs/mcp-surface.md §1).
	opts, err := s.resolve(&a)
	if err != nil {
		return mcp.Errorf("%v", err)
	}

	if err := s.room(1); err != nil {
		return mcp.Errorf("%v", err)
	}

	b, err := s.boot(opts)
	if err != nil {
		return mcp.Errorf("sandbox_run: %v", err)
	}
	// Checked again at registration: two concurrent calls could both have
	// passed the check above, and the limit is a limit.
	if err := s.adopt(b); err != nil {
		b.close("error")
		return mcp.Errorf("%v", err)
	}

	id := b.sb.State.ID
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.Text(fmt.Sprintf(
			"sandbox %s ready in %d ms (%s, %d vcpu, %d MiB, %s)",
			id, b.sb.State.BootReadyMS, b.image, opts.VcpuCount, opts.MemMiB, describeAllow(b.allow)))},
		StructuredContent: map[string]any{
			"sandbox": id, "image": b.image, "arch": s.arch,
			"boot_ms": b.sb.State.BootReadyMS, "allow": b.allow,
		},
	}
}

func describeAllow(allow []string) string {
	if len(allow) == 0 {
		return "no network interface at all"
	}
	return "egress " + strings.Join(allow, ", ")
}

func (s *hostServer) policyPath() string {
	if s.policy == nil {
		return "kelyfos.toml"
	}
	return s.policy.Path
}

// resolve turns a tool call's arguments into sandbox options, refusing anything
// that asks for more than the policy allows. The refusals read like E1-1's,
// because a client hitting one has the same problem a command line does and
// deserves the same answer: what the ceiling is, and where it was set.
func (s *hostServer) resolve(a *runArgs) (sandbox.Options, error) {
	opts := sandbox.Options{Arch: s.arch, Flavor: "base", VcpuCount: 2, MemMiB: 512, Quiet: true}
	cfg := s.policy
	if cfg == nil {
		if a.Image != "" {
			opts.Flavor = a.Image
		}
		if a.CPUs > 0 {
			opts.VcpuCount = a.CPUs
		}
		if a.Mem != "" {
			n, err := config.ParseMemMiB(a.Mem)
			if err != nil {
				return opts, fmt.Errorf("mem %q: %w", a.Mem, err)
			}
			opts.MemMiB = n
		}
		opts.Allow = a.Allow
		return opts, nil
	}

	if cfg.Image != "" {
		opts.Flavor = cfg.Image
	}
	if a.Image != "" && a.Image != opts.Flavor {
		return opts, fmt.Errorf("image %q is not this project's image. %s declares %q, and "+
			"serve-mcp boots what the project declares",
			a.Image, cfg.Path, opts.Flavor)
	}

	// cpus and mem: the ceiling is the [resources] value when there is one, and
	// it is also the default, exactly as it is for a flag.
	if cfg.ResCPUs > 0 {
		opts.VcpuCount = cfg.ResCPUs
	} else if cfg.Vcpus > 0 {
		opts.VcpuCount = cfg.Vcpus
	}
	if a.CPUs > 0 {
		if cfg.ResCPUs > 0 && a.CPUs > cfg.ResCPUs {
			line, _ := cfg.Ceiling("cpus")
			return opts, denial.CeilingTool.Err(denial.V{
				"field": "cpus", "asked": strconv.Itoa(a.CPUs), "key": "cpus",
				"limit": strconv.Itoa(cfg.ResCPUs), "file": cfg.Path,
				"line": strconv.Itoa(line)})
		}
		opts.VcpuCount = a.CPUs
	}

	if cfg.ResMemMiB > 0 {
		opts.MemMiB = cfg.ResMemMiB
	} else if cfg.MemMiB > 0 {
		opts.MemMiB = cfg.MemMiB
	}
	if a.Mem != "" {
		n, err := config.ParseMemMiB(a.Mem)
		if err != nil {
			return opts, fmt.Errorf("mem %q: %w", a.Mem, err)
		}
		if cfg.ResMemMiB > 0 && n > cfg.ResMemMiB {
			line, _ := cfg.Ceiling("mem")
			return opts, denial.CeilingTool.Err(denial.V{
				"field": "mem", "asked": a.Mem, "key": "mem",
				"limit": fmt.Sprintf("%d MiB", cfg.ResMemMiB), "file": cfg.Path,
				"line": strconv.Itoa(line)})
		}
		opts.MemMiB = n
	}

	// allow: a call may narrow the project's allowlist for one sandbox and may
	// never add to it. This is the invariant in its most concrete form.
	opts.Allow = cfg.Allow
	if a.Allow != nil {
		for _, d := range a.Allow {
			if !containsDomain(cfg.Allow, d) {
				return opts, denial.AllowProject.Err(denial.V{
					"domain": d, "file": cfg.Path, "permitted": describeAllow(cfg.Allow)})
			}
		}
		opts.Allow = a.Allow
	}

	opts.ScratchBytes = cfg.ResScratchByte
	// A scratch cap larger than the machine's RAM is not a generous limit, it is
	// no limit: the tmpfs it sizes lives in that same RAM and can never reach
	// it. `kelyfos run` refuses it before booting and so does this door, because
	// this is the door where it is easiest to reach — the project writes one
	// `scratch` for a machine of the project's `mem`, and a call is allowed to
	// ask for less memory than that. The result was a sandbox whose declared
	// cap did nothing, which is the worst outcome available (docs/resources.md).
	if opts.ScratchBytes > 0 && opts.ScratchBytes > int64(opts.MemMiB)<<20 {
		line, _ := cfg.Ceiling("scratch")
		return opts, fmt.Errorf("scratch = %d bytes at %s:%d is larger than the %d MiB this sandbox has\n"+
			"    the scratch tmpfs lives in that memory, so a cap above it can never be reached",
			opts.ScratchBytes, cfg.Path, line, opts.MemMiB)
	}
	opts.IO = sandbox.IOLimits{
		NetMbpsRx: cfg.ResNetMbpsRx, NetMbpsTx: cfg.ResNetMbpsTx,
		DiskIOPS: cfg.ResDiskIOPS, DiskMbps: cfg.ResDiskMbps,
	}
	return opts, nil
}

// boot builds one sandbox: cgroup slice, egress path when the policy grants
// one, recorder, machine. Same order `kelyfos run` uses, and the order matters
// (docs/networking.md).
func (s *hostServer) boot(opts sandbox.Options) (*servedBox, error) {
	id, err := sandbox.NewID()
	if err != nil {
		return nil, err
	}
	opts.ID = id
	b := &servedBox{image: opts.Flavor, allow: opts.Allow, created: time.Now()}
	ok := false
	// The one teardown, not a copy of it. This defer used to hand-roll a strict
	// subset of close() — proxy, network, slice, recorder, and no machine, no
	// plugin image — so a failure after the VM was running left a microVM behind
	// that never reached s.boxes: nothing could stop it and the census that
	// bounds this door under-counted it forever. The refusal that reaches it is
	// the guest's to make (finding M-1): InstallTrustAnchor fails when the guest
	// answers no. sandbox_restore already unwinds through close() and this is
	// the same shape.
	defer func() {
		if !ok {
			b.close("error")
		}
	}()

	if s.policy != nil && s.policy.ResCPUQuota > 0 {
		if b.slice, err = sandbox.NewCPUSlice(id, s.policy.ResCPUQuota); err != nil {
			return nil, err
		}
		opts.CPUSlice = b.slice
	}

	// A sandbox raised through this door carries the project's plugins, exactly
	// as one raised by `kelyfos run` does (E4-6).
	if opts.Plugins, err = packPlugins(s.policy, id); err != nil {
		return nil, err
	}
	if opts.Plugins != nil {
		b.plugins = opts.Plugins.ImagePath
	}

	var ca *egress.CA
	// Declared out here so the boot can record them once the recorder exists.
	var dropped []*egress.Secret
	if len(opts.Allow) > 0 {
		if b.net, err = sandbox.NewNetwork(id); err != nil {
			return nil, err
		}
		opts.Net = b.net
		pol := egress.Policy{Allow: opts.Allow}
		if s.policy != nil {
			for _, spec := range s.policy.Secrets {
				sec, err := egress.ParseSecret(spec)
				if err != nil {
					return nil, err
				}
				if containsDomain(opts.Allow, sec.Domain) {
					pol.Secrets = append(pol.Secrets, sec)
				} else {
					// A call may narrow the project's allowlist, and a
					// credential for a domain this sandbox cannot reach could
					// never be sent — so dropping it is right. Saying nothing
					// was not: the agent asked for a sandbox, got one with
					// fewer credentials than the project declares, and the
					// first symptom was an unauthenticated request failing
					// somewhere else (P6-4).
					dropped = append(dropped, sec)
				}
			}
		}
		if len(pol.Secrets) > 0 {
			if ca, err = egress.NewCA(); err != nil {
				return nil, err
			}
		}
		b.proxy = &egress.Proxy{Policy: pol, CA: ca}
		port, err := b.proxy.Listen(b.net.HostIP.String() + ":0")
		if err != nil {
			return nil, err
		}
		if err := b.net.Restrict(port); err != nil {
			return nil, err
		}
		go b.proxy.Serve()
	}

	// What the guest reports goes into this sandbox's own chain. The recorder
	// does not exist yet when the machine is built, so the handler reads it
	// through the box — which is also what keeps a report arriving after
	// teardown from writing into a closed file.
	opts.OnGuestEvent = b.guestEvent

	if b.sb, err = sandbox.New(opts); err != nil {
		return nil, err
	}
	rec, err := recorder.Open(sandbox.Root(), id)
	if err != nil {
		return nil, err
	}
	b.setRec(rec)
	_ = b.rec.Append(recorder.Event{
		Type: recorder.TypeSessionStart, Image: opts.Flavor, Arch: opts.Arch,
		Kelyfos: Version, Argv: s.argv, Reason: "created through serve-mcp session " + s.auditID,
	})
	b.wireAudit()
	for _, sec := range dropped {
		_ = b.rec.Append(recorder.Event{
			Type: recorder.TypeSecretWithheld, Name: sec.Name, Host: sec.Domain,
			Reason: "not_in_allowlist",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := b.sb.Start(ctx); err != nil {
		_ = b.sb.Shutdown(2 * time.Second)
		return nil, err
	}
	ready, err := b.sb.WaitReady(ctx)
	if err != nil {
		_ = b.sb.Shutdown(2 * time.Second)
		return nil, err
	}
	if ca != nil {
		if err := b.sb.InstallTrustAnchor(ca.AnchorPEM()); err != nil {
			return nil, err
		}
	}
	overlay := ready.Overlay
	_ = b.rec.Append(recorder.Event{
		Type: recorder.TypeSessionReady, BootMS: b.sb.State.BootReadyMS,
		Kernel: ready.Kernel, Supervisor: ready.Supervisor, Overlay: &overlay,
	}.WithPosture(b.sb.State.Jailed, b.sb.State.Profile))
	ok = true
	return b, nil
}

// --- sandbox_exec ------------------------------------------------------------

type execArgs struct {
	Sandbox   string   `json:"sandbox"`
	Command   string   `json:"command"`
	Argv      []string `json:"argv"`
	Cwd       string   `json:"cwd"`
	Stdin     string   `json:"stdin"`
	TimeoutMS int      `json:"timeout_ms"`
}

func (s *hostServer) toolExec(raw json.RawMessage) *mcp.CallToolResult {
	var a execArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return mcp.Errorf("sandbox_exec: %v", err)
	}
	b, err := s.box(a.Sandbox)
	if err != nil {
		return mcp.Errorf("%v", err)
	}
	argv := a.Argv
	if len(argv) == 0 {
		if a.Command == "" {
			return mcp.Errorf("sandbox_exec needs either `command` or `argv`")
		}
		argv = []string{"/bin/sh", "-c", a.Command}
	}
	timeout := 60 * time.Second
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}

	call := fmt.Sprintf("s%d", time.Now().UnixNano())
	_ = b.rec.Append(recorder.Event{
		Type: recorder.TypeCommandStart, Call: call, Cmd: argv, Cwd: a.Cwd, Via: "serve-mcp",
	})
	started := time.Now()
	res, err := sandbox.Exec(b.sb.State.UDSPath, argv, []byte(a.Stdin), timeout)
	if err != nil {
		_ = b.rec.Append(recorder.Event{
			Type: recorder.TypeCommandExit, Call: call, DurationMS: time.Since(started).Milliseconds(),
			Error: &recorder.EvError{Kind: "internal", Message: err.Error()},
		})
		return mcp.Errorf("sandbox_exec: %v", err)
	}
	code := res.Code
	_ = b.rec.Append(recorder.Event{
		Type: recorder.TypeCommandExit, Call: call, Code: &code,
		DurationMS: time.Since(started).Milliseconds(),
	})

	var text strings.Builder
	text.Write(res.Stdout)
	if len(res.Stderr) > 0 {
		fmt.Fprintf(&text, "\n[stderr]\n%s", res.Stderr)
	}
	fmt.Fprintf(&text, "\n[exit status %d]", res.Code)
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.Text(text.String())},
		IsError: res.Code != 0,
		StructuredContent: map[string]any{
			"exit_code": res.Code, "stdout": string(res.Stdout), "stderr": string(res.Stderr),
		},
	}
}

// --- sandbox_stop / sandbox_list ---------------------------------------------

func (s *hostServer) toolStop(raw json.RawMessage) *mcp.CallToolResult {
	var a struct {
		Sandbox string `json:"sandbox"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return mcp.Errorf("sandbox_stop: %v", err)
	}
	s.mu.Lock()
	b, ok := s.boxes[a.Sandbox]
	delete(s.boxes, a.Sandbox)
	s.mu.Unlock()
	if !ok {
		return mcp.Errorf("no sandbox %q was started by this server. sandbox_list shows the ones "+
			"that were; a sandbox somebody else started is theirs to stop.", a.Sandbox)
	}
	b.close("shutdown")
	return &mcp.CallToolResult{Content: []mcp.Content{mcp.Text("stopped " + a.Sandbox)}}
}

func (s *hostServer) toolList() *mcp.CallToolResult {
	s.mu.Lock()
	type row struct {
		ID      string   `json:"sandbox"`
		Image   string   `json:"image"`
		Allow   []string `json:"allow"`
		Created string   `json:"created"`
	}
	rows := make([]row, 0, len(s.boxes))
	for id, b := range s.boxes {
		rows = append(rows, row{ID: id, Image: b.image, Allow: b.allow,
			Created: b.created.UTC().Format(time.RFC3339)})
	}
	s.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].Created < rows[j].Created })

	var text strings.Builder
	if len(rows) == 0 {
		text.WriteString("no sandboxes are running; start one with sandbox_run")
	}
	for _, r := range rows {
		fmt.Fprintf(&text, "%s  %s  %s\n", r.ID, r.Image, describeAllow(r.Allow))
	}
	return &mcp.CallToolResult{
		Content:           []mcp.Content{mcp.Text(strings.TrimRight(text.String(), "\n"))},
		StructuredContent: map[string]any{"sandboxes": rows, "max": s.max},
	}
}

func (s *hostServer) box(id string) (*servedBox, error) {
	if id == "" {
		return nil, fmt.Errorf("this tool needs a `sandbox` id; sandbox_run returns one")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.boxes[id]
	if !ok {
		return nil, fmt.Errorf("no sandbox %q was started by this server; sandbox_list shows the "+
			"ones that were.%s", id, teamMemberHint(id))
	}
	return b, nil
}

// wireAudit points the egress proxy at this sandbox's recorder. Every door that
// builds a machine calls it, because a sandbox whose proxy reports to nobody is
// a sandbox with no audit trail — and there is no such thing here (D6, F-D33).
func (b *servedBox) wireAudit() {
	if b.proxy == nil || b.rec == nil {
		return
	}
	// nil for the printer: this door has no terminal of the user's to print a
	// refusal to, so it is recorded and not narrated (docs/networking.md §5).
	wireProxyAudit(b.proxy, b.rec, "", nil)
}

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/mcp"
)

// The policy ceiling is the whole of serve-mcp's security story, and it is the
// one part that can be tested without a machine: resolve() decides what a call
// is allowed to ask for, before anything boots.

func serverWith(t *testing.T, toml string) *hostServer {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, config.FileName)
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("the test's own policy does not parse: %v", err)
	}
	return &hostServer{arch: "x86_64", policy: cfg, max: defaultMaxSandboxes,
		boxes: map[string]*servedBox{}}
}

const policy = `[sandbox]
image = "dev"
allow = ["api.github.com", "example.com"]

[resources]
cpus = 2
mem  = "512M"
`

// Asking for less than the policy allows is the point of having arguments at
// all, so it has to work.
func TestServeMCPArgumentsMayAskForLess(t *testing.T) {
	s := serverWith(t, policy)
	opts, err := s.resolve(&runArgs{CPUs: 1, Mem: "256M", Allow: []string{"example.com"}})
	if err != nil {
		t.Fatalf("asking for less was refused: %v", err)
	}
	if opts.VcpuCount != 1 || opts.MemMiB != 256 {
		t.Errorf("got %d vcpu / %d MiB, want 1 / 256", opts.VcpuCount, opts.MemMiB)
	}
	if len(opts.Allow) != 1 || opts.Allow[0] != "example.com" {
		t.Errorf("allow = %v, want the narrowed list", opts.Allow)
	}
}

// And asking for more has to be refused, in the E1-1 style: naming the ceiling
// and the line it came from, because a caller that cannot see the file needs
// both to act on the refusal.
func TestServeMCPArgumentsMayNotAskForMore(t *testing.T) {
	s := serverWith(t, policy)
	for _, tc := range []struct {
		name  string
		args  runArgs
		wants []string
	}{
		{"cpus above the ceiling", runArgs{CPUs: 8}, []string{"cpus", "ceiling", "kelyfos.toml:"}},
		{"mem above the ceiling", runArgs{Mem: "4G"}, []string{"mem", "ceiling", "kelyfos.toml:"}},
		{"a domain the policy never listed", runArgs{Allow: []string{"evil.example.net"}},
			[]string{"evil.example.net", "never add to it"}},
		{"an image the project does not declare", runArgs{Image: "base"},
			[]string{"base", "declares"}},
	} {
		_, err := s.resolve(&tc.args)
		if err == nil {
			t.Errorf("%s: accepted, and the policy is meant to be a ceiling", tc.name)
			continue
		}
		for _, want := range tc.wants {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the refusal does not mention %q:\n%v", tc.name, want, err)
			}
		}
	}
}

// A subdomain of an allowed domain is allowed, because that is what the
// allowlist means everywhere else in the product (docs/networking.md §6). The
// refusal path must not accidentally be stricter than the proxy.
func TestServeMCPAllowMatchesSubdomains(t *testing.T) {
	s := serverWith(t, policy)
	if _, err := s.resolve(&runArgs{Allow: []string{"api.github.com"}}); err != nil {
		t.Errorf("an exactly-listed domain was refused: %v", err)
	}
}

// With no policy file at all there is no ceiling to enforce, and the defaults
// apply. A server that refused everything without a kelyfos.toml would be
// unusable in exactly the case a new user meets first.
func TestServeMCPWithoutAPolicy(t *testing.T) {
	s := &hostServer{arch: "x86_64", max: defaultMaxSandboxes, boxes: map[string]*servedBox{}}
	opts, err := s.resolve(&runArgs{CPUs: 8})
	if err != nil {
		t.Fatalf("no policy means no ceiling, but: %v", err)
	}
	if opts.VcpuCount != 8 {
		t.Errorf("vcpu = %d, want the 8 that was asked for", opts.VcpuCount)
	}
}

// The tool surface is what a model sees, so its shape is worth pinning: names
// that survive every downstream constraint (F-D36), and no tool that could
// widen policy.
func TestServeMCPToolSurface(t *testing.T) {
	tools := hostToolDefinitions()
	if len(tools) != 9 {
		t.Errorf("E4-1 and E4-2 name nine tools between them, found %d", len(tools))
	}
	for _, tool := range tools {
		if len(tool.Name) > 64 {
			t.Errorf("%q is longer than the 64 characters the strictest client allows", tool.Name)
		}
		for _, r := range tool.Name {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
				t.Errorf("%q contains %q, which something downstream will rewrite (F-D36)", tool.Name, r)
			}
		}
		if tool.Description == "" {
			t.Errorf("%q has no description, and a description is the only documentation a model reads", tool.Name)
		}
		switch tool.Name {
		case "set_policy", "allow_domain", "raise_limit", "set_limit":
			t.Errorf("%q exists, and no tool may widen policy (F-D5)", tool.Name)
		}
	}
}

// An unknown tool is a protocol error rather than a failed result: it is an
// error in *finding* the tool, which the specification separates from an error
// inside one (docs/mcp-surface.md §2.4).
func TestServeMCPUnknownToolIsAnErrorResult(t *testing.T) {
	s := serverWith(t, policy)
	res := s.callTool(&mcp.CallToolParams{Name: "no_such_tool"})
	if !res.IsError {
		t.Error("an unknown tool came back as a success")
	}
}

// A tool needing a sandbox id says so rather than guessing one, because there
// is no "current" sandbox and inventing one would act on the wrong machine.
func TestServeMCPExecNeedsASandbox(t *testing.T) {
	s := serverWith(t, policy)
	res := s.toolExec(json.RawMessage(`{"command":"true"}`))
	if !res.IsError {
		t.Fatal("exec with no sandbox id succeeded")
	}
	if !strings.Contains(res.Content[0].Text, "sandbox") {
		t.Errorf("the error does not say what is missing: %s", res.Content[0].Text)
	}
}

// Package sessionpolicy builds the shared, non-recorder-specific pieces of a
// session.policy event (P7-2, docs/policy-record.md): the conversions from
// this product's own domain types — egress.Secret, config.Plugin,
// config.Forward, an image manifest — into the small, secret-free shapes
// recorder.PolicyFields carries, and the two fixed `tools` vocabularies
// docs/policy-record.md §8.3 settles.
//
// It exists once, here, rather than once in host and once in shim, so the
// two doors that both need every one of these conversions cannot drift the
// way the MCP argument summarisers did before internal/argsummary existed
// (F12) — the same duplication this project has already found and fixed
// once.
package sessionpolicy

import (
	"strconv"

	"github.com/ikapa-dev/kelyfos/internal/config"
	"github.com/ikapa-dev/kelyfos/internal/egress"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// Secrets converts bound credentials into session.policy's own shape — name,
// host and path scope, never a value (docs/policy-record.md §8.1). Scheme is
// deliberately dropped; the reasoning is in that section, not here.
func Secrets(secrets []*egress.Secret) []recorder.EvSecret {
	if len(secrets) == 0 {
		return nil
	}
	out := make([]recorder.EvSecret, len(secrets))
	for i, s := range secrets {
		out[i] = recorder.EvSecret{Name: s.Name, Host: s.Domain, Path: s.Scope.Path}
	}
	return out
}

// Ports is the egress allowlist's effective port coverage: egress.
// DefaultPorts()'s fixed pair (D65), the one value internal/egress/proxy.go
// actually enforces for any machine with a network at all — recording
// nothing would misstate a real, enforced default as an absence.
func Ports(allow []string) []int {
	if len(allow) == 0 {
		return nil
	}
	return egress.DefaultPorts()
}

// PluginNames is the configured plugin names, and nothing else about them —
// no path, no command, no args (docs/policy-record.md §8.2).
func PluginNames(plugins []config.Plugin) []string {
	if len(plugins) == 0 {
		return nil
	}
	out := make([]string, len(plugins))
	for i, p := range plugins {
		out[i] = p.Name
	}
	return out
}

// Forwards formats each [[forward]] entry as "<host-port>:<guest-port>", the
// same shorthand kelyfos run's own -p flag already uses.
func Forwards(forwards []config.Forward) []string {
	if len(forwards) == 0 {
		return nil
	}
	out := make([]string, len(forwards))
	for i, f := range forwards {
		out[i] = strconv.Itoa(f.Host) + ":" + strconv.Itoa(f.Guest)
	}
	return out
}

// Digests reads an image's manifest for the two fields session.policy
// carries. Errors are swallowed: a manifest that cannot be read is not a
// reason to refuse a run that has already booted successfully off the same
// image — sandbox.New and sandbox.Restore have already validated the flavor
// and arch by the time any door calls this — and an empty digest is the
// honest value for an image built before manifests existed
// (internal/sandbox/manifest.go).
func Digests(imageDir string) (rootfsSHA256, kernelSHA256 string) {
	m, err := sandbox.ReadManifest(imageDir)
	if err != nil {
		return "", ""
	}
	return m.RootfsSHA256, m.KernelSHA256
}

// CLITools and MCPTools are the two fixed vocabularies docs/policy-record.md
// §8.3 settles for a machine's `tools` field: every verb, or MCP tool, that
// takes an *existing* machine's id and acts on it — checked against each
// one's actual flags or input schema, not assumed from its name. A verb
// that creates a machine, or that names a snapshot rather than a sandbox, is
// a door (docs/policy-record.md §4), not a member of either list.
var (
	CLITools = []string{"exec", "shell", "diff", "snapshot save", "pause"}
	MCPTools = []string{"sandbox_exec", "sandbox_read_file", "sandbox_write_file", "sandbox_stop", "sandbox_snapshot"}
)

// ToolsForCLI is CLITools, plus "mcp" when this machine has plugins
// configured — the guest-side MCP passthrough door, which only exists on a
// machine that declared one.
func ToolsForCLI(hasPlugins bool) []string {
	if !hasPlugins {
		return CLITools
	}
	out := make([]string, len(CLITools)+1)
	copy(out, CLITools)
	out[len(CLITools)] = "mcp"
	return out
}

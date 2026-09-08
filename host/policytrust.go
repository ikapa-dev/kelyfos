package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ikapa-dev/kelyfos/internal/config"
	"github.com/ikapa-dev/kelyfos/internal/proto"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// The second gate on a discovered policy file: its secrets (D101, security
// review 2026-09-03).
//
// config.Trust answers whether a file found by walking up may be believed at
// all, and it answers on ownership. That closes the file another local user
// left in a parent directory, and it does nothing for the file that arrives
// with a repository: whoever cloned it owns the clone. Such a file names the
// operator's own environment variables and the domains they go to, and until
// this gate a bare `kelyfos run` in the checkout honoured that on the strength
// of a banner. A credential is the asset the whole architecture is bent around
// (docs/threat-model.md §2), so a stranger's say-so is not enough for one.
//
// The rule: a DISCOVERED file that binds any secret must have been approved,
// once, for its current contents — interactively, here, when there is a person
// at the terminal to ask; or with `kelyfos trust <file>`; or by naming the file
// with --policy, which is the same decision made on the command line. A file
// that binds nothing is not asked about, because there is nothing to approve.

// approvePolicySecrets is the gate loadPolicyAt applies to a discovered file.
func approvePolicySecrets(cfg *config.Config, path string) error {
	interactive := onATerminal(os.Stdin) && onATerminal(os.Stderr)
	return approvePolicySecretsWith(cfg, path, sandbox.Root(), os.Stdin, os.Stderr, interactive)
}

// approvePolicySecretsWith is the decision on explicit inputs, so a test can
// drive it without a terminal or the real cache root.
func approvePolicySecretsWith(cfg *config.Config, path, root string, in io.Reader, out io.Writer, interactive bool) error {
	if !cfg.DeclaresSecrets() {
		return nil
	}
	trusted, err := config.SecretsTrusted(root, path)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	fmt.Fprintf(out, "kelyfos found %s by walking up from this directory, and it binds environment\n"+
		"variables of yours to domains:\n", path)
	for _, line := range secretBindings(cfg) {
		fmt.Fprintf(out, "    %s\n", line)
	}
	refusal := fmt.Errorf("a policy file you did not name does not get to attach your credentials on its own say-so.\n"+
		"    Approve this file once, for its current contents:  kelyfos trust %s\n"+
		"    or name it yourself, which is the same decision:    --policy %s", path, path)
	if !interactive {
		return refusal
	}
	fmt.Fprintf(out, "Bind these from %s? The approval is recorded for this file's current contents,\n"+
		"so you are not asked again until it changes. [y/N] ", path)
	if !yes(readLine(in)) {
		return refusal
	}
	entry, err := config.TrustSecrets(root, path)
	if err != nil {
		return fmt.Errorf("record the approval: %w", err)
	}
	fmt.Fprintf(out, "recorded in %s (sha256 %s)\n", config.SecretTrustFile(root), shortDigest(entry.SHA256))
	return nil
}

// secretBindings is what a policy file would attach, one line per binding,
// naming the variable and the host and never a value — the same rule
// printPolicyReach follows, extended to a team's agents.
func secretBindings(cfg *config.Config) []string {
	var out []string
	add := func(prefix, spec string) {
		name, rest, ok := strings.Cut(spec, "@")
		if !ok {
			out = append(out, prefix+proto.SafeText(spec))
			return
		}
		where := rest
		if host, _, cut := strings.Cut(rest, "/"); cut {
			where = host + " (path " + strings.TrimPrefix(rest, host) + ")"
		}
		out = append(out, fmt.Sprintf("%s$%s of your environment, attached to requests to %s",
			prefix, proto.SafeText(name), proto.SafeText(where)))
	}
	for _, spec := range cfg.Secrets {
		add("", spec)
	}
	if cfg.Team != nil {
		for _, a := range cfg.Team.Agents {
			for _, spec := range a.Secrets {
				add("agent "+proto.SafeText(a.Name)+": ", spec)
			}
		}
	}
	return out
}

// readLine reads one line, a byte at a time, so nothing past the newline is
// taken from a stdin that the command about to run — `kelyfos run -- claude`
// hands its standard input to the agent — will read next.
func readLine(in io.Reader) string {
	var b strings.Builder
	buf := make([]byte, 1)
	for b.Len() < 64 {
		n, err := in.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				break
			}
			b.WriteByte(buf[0])
		}
		if err != nil {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

func yes(answer string) bool {
	switch strings.ToLower(answer) {
	case "y", "yes":
		return true
	}
	return false
}

func shortDigest(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

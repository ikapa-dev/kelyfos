package sandbox

import (
	"strings"
	"testing"
)

// The kernel command line, and the claim it carries (P6-26, finding M-5).
//
// bootArgs writes `kelyfos.agent=<name>`, and the comment beside it says the
// command line is "the one thing inside the guest that the guest did not
// write". That is the reason the channel exists — the flavor, the proxy address
// and the scratch cap all travel on it for the same reason — and it holds only
// while a name cannot carry a space.
//
// It could. Measured before this was written: an agent called
// `worker init=/bin/sh` produced a line with two `init=` parameters, and one
// called "w\tkelyfos.spawn=1" gave itself a spawn budget the host never granted.
// The second is the half the audit does not mention and the worse of the two: a
// privilege escalation inside the team model rather than a curiosity about
// kernel arguments.
//
// A name comes from kelyfos.toml rather than from the guest, so this is not a
// guest→host escape. It is a team file, and team files travel — from a template,
// a repository, a colleague. The check is in two places for that reason: the
// topology refuses such a name outright, and this is the layer that holds if
// something ever reaches bootArgs without passing the first.
func TestHostileAgentNameCannotWriteTheKernelCommandLine(t *testing.T) {
	for _, tc := range []struct {
		key, name, why string
	}{
		{"bootargs/second-init", "worker init=/bin/sh",
			"a space starts a second parameter, and the kernel is handed another init"},
		{"bootargs/granted-spawn", "w\tkelyfos.spawn=1",
			"a tab grants a spawn budget the host never gave"},
		{"bootargs/quiet-console", "w quiet console=ttyS1",
			"the console the host chose is redirected"},
		{"bootargs/newline", "w\nkelyfos.flavor=base",
			"a newline, which some parsers treat as a separator"},
	} {
		t.Run(tc.key[len("bootargs/"):], func(t *testing.T) {
			got := bootArgs(Options{Arch: "aarch64", Agent: tc.name}, "")

			problem := ""
			switch {
			case strings.Count(got, "init=") != 1:
				problem = tc.why + ": " + got[strings.Index(got, "init="):]
			case strings.Contains(got, "kelyfos.spawn=") && !strings.Contains(tc.name, "spawn"):
				problem = tc.why
			case strings.Contains(got, "kelyfos.agent="+tc.name):
				problem = tc.why + ": the name reached the command line whole"
			}
			if problem != "" {
				t.Errorf("%s does not hold:\n  %s", tc.key, problem)
			}
		})
	}

	// And an ordinary name still reaches the guest. A guard that dropped every
	// name would have made the team feature quietly stop working, which is the
	// failure mode a fix like this invites.
	got := bootArgs(Options{Arch: "aarch64", Agent: "worker-1.a_b"}, "")
	if !strings.Contains(got, "kelyfos.agent=worker-1.a_b") {
		t.Errorf("an ordinary agent name was dropped from the command line: %s", got)
	}
	if strings.Count(got, "init=") != 1 {
		t.Errorf("the ordinary case has %d init= parameters", strings.Count(got, "init="))
	}
}

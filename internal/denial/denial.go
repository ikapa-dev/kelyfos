// Package denial is every refusal KelyfOS makes, in one place, with the fix.
//
// A sandbox is a thing that says no. It says no to a domain that is not in the
// allowlist, to a flag above a ceiling, to a message along an edge that was
// never declared. Each of those refusals is correct, and each of them lands on
// somebody who now has to work out what to type instead — and until this
// package existed, what they got varied by which part of the codebase happened
// to refuse them. Some named the file and the line. Some named neither.
//
// So the message and the fix live together here, as data, for three reasons:
//
//   - They cannot drift apart. A message is not written in one file and its
//     remedy in another, because they are one record.
//   - They can be listed. `docs/reference/denials.md` is generated from All(),
//     so the catalog in the documentation is the catalog the product raises —
//     and gendocs fails the build if an entry here is raised nowhere, which is
//     how a refusal that was deleted stops being documented (F-D4).
//   - They can be recognised. A refusal is a *Refusal, carrying its ID, so a
//     caller can branch on which refusal it was rather than on its prose.
//
// What is in here is refusals: things KelyfOS decided not to do because a
// policy said so. Failures are not refusals and are not in here. "The upstream
// did not answer" has no fix line, because nothing the user types changes it,
// and a fix line that says "try again" teaches people to stop reading them.
package denial

import (
	"errors"
	"sort"
	"strings"
)

// V is the values a refusal names: the host, the ceiling, the file. The keys
// are the <placeholders> in Msg and Fix.
type V map[string]string

// A Denial is one refusal: what it means, what it says, and what to do about it.
//
// Msg and Fix are written with <name> placeholders rather than printf verbs, so
// that the order of the values is not part of the format and a reader of this
// table can see what each hole is for.
type Denial struct {
	// ID is stable and printed with the refusal, in brackets. It is what a
	// person looks up in the reference and what a program branches on.
	ID string
	// Doc says what the refusal means, for the reference page.
	Doc string
	// Msg is the refusal itself.
	Msg string
	// Fix is what to do about it: one line, imperative, naming something the
	// reader can type or edit. Every entry has one — a refusal without a fix is
	// a dead end, and the test in this package will not let one be added.
	Fix string
	// Sample gives every placeholder a plausible value, so the reference can
	// print a real refusal rather than a template. It is also how the tests
	// prove a placeholder was never left without a value.
	Sample V
}

// Err returns this refusal as an error, with v filling its placeholders.
func (d Denial) Err(v V) error { return &Refusal{d: d, v: v, text: d.Render(v)} }

// Render is the refusal as a person sees it: the message, its ID, and the fix
// line indented beneath.
func (d Denial) Render(v V) string {
	return fill(d.Msg, v) + " [" + d.ID + "]\n    " + fill(d.Fix, v)
}

// fill substitutes <name> for v["name"]. A placeholder with no value is left
// standing, visibly, because a hole in a refusal should be reported as a bug
// rather than quietly closed up into a sentence that reads fine and says less.
func fill(s string, v V) string {
	if len(v) == 0 {
		return s
	}
	pairs := make([]string, 0, len(v)*2)
	for k, val := range v {
		pairs = append(pairs, "<"+k+">", val)
	}
	return strings.NewReplacer(pairs...).Replace(s)
}

// A Refusal is a raised Denial: the error a caller gets back.
type Refusal struct {
	d    Denial
	v    V
	text string
}

func (r *Refusal) Error() string { return r.text }

// ID is which refusal this was.
func (r *Refusal) ID() string { return r.d.ID }

// Denial is the catalog entry this refusal came from.
func (r *Refusal) Denial() Denial { return r.d }

// Values are the things it named.
func (r *Refusal) Values() V { return r.v }

// Of reports whether err is a refusal, and which one.
func Of(err error) (*Refusal, bool) {
	var r *Refusal
	ok := errors.As(err, &r)
	return r, ok
}

// Is reports whether err is the refusal with this id.
func Is(err error, id string) bool {
	r, ok := Of(err)
	return ok && r.ID() == id
}

// The catalog. Adding one here is what documents it; raising it somewhere is
// what keeps it here (gendocs checks both directions).
var (
	// --- egress: what a sandbox may reach ---------------------------------

	EgressHost = Denial{
		ID:     "egress.host",
		Doc:    "a guest tried to reach a domain the sandbox's allowlist does not permit",
		Msg:    "<host> is not in this sandbox's allowlist",
		Fix:    `add allow = ["<host>"] to kelyfos.toml, or rerun with --allow <host>`,
		Sample: V{"host": "api.stripe.com"},
	}

	EgressPort = Denial{
		ID:  "egress.port",
		Doc: "a guest tried to reach a permitted domain on a port the proxy does not carry",
		Msg: "port <port> is not permitted, to <host> or to anywhere else",
		Fix: "use 80 or 443 — those are the two ports the egress proxy carries, and no " +
			"policy key widens that today",
		Sample: V{"host": "api.stripe.com", "port": "8443"},
	}

	EgressResolvedAddr = Denial{
		ID: "egress.resolved_addr",
		Doc: "an allowlisted domain resolved to an address the proxy refuses to dial: loopback, " +
			"link-local (which includes the cloud instance metadata address, 169.254.169.254), " +
			"CGNAT, or other private/reserved space no legitimate public domain should ever " +
			"resolve to. The address itself is in the flight recorder as the attempt's " +
			"resolved_addr, not in this message",
		Msg: "<host> resolved to an address this proxy will not dial",
		Fix: "this is not something to work around by retrying — it usually means <host>'s DNS is " +
			"compromised, hijacked or misconfigured; a destination that is genuinely internal does " +
			"not belong behind this proxy's allowlist at all",
		// No "addr": the message deliberately names none. The address the
		// name resolved to goes to the flight recorder and stops there —
		// telling a guest which address an allowlisted name resolves to is a
		// DNS lookup it may not be able to perform itself, handed over one
		// name at a time (F14).
		Sample: V{"host": "api.example.com"},
	}

	SecretUnallowed = Denial{
		ID:  "secret.unbound",
		Doc: "a secret was bound to a domain the sandbox cannot reach, so it could never be sent",
		Msg: "--secret <spec>: <domain> is not in --allow",
		Fix: "add <domain> to --allow, or drop the secret — a credential for a domain the " +
			"sandbox cannot reach is a credential nothing will ever use",
		Sample: V{"spec": "STRIPE_KEY@api.stripe.com", "domain": "api.stripe.com"},
	}

	// --- ceilings: [resources] is a maximum, never a default --------------

	CeilingFlag = Denial{
		ID:  "ceiling.flag",
		Doc: "a command-line flag asked for more than the policy file's [resources] ceiling permits",
		Msg: "--<flag> <asked> exceeds the ceiling <key> = <limit> set at <file>:<line>",
		Fix: "lower the flag, or raise the ceiling in <file>",
		Sample: V{"flag": "cpus", "asked": "8", "key": "cpus", "limit": "4",
			"file": "/home/you/project/kelyfos.toml", "line": "12"},
	}

	CeilingTool = Denial{
		ID:  "ceiling.tool",
		Doc: "an MCP tool call asked for more than the policy file's [resources] ceiling permits",
		Msg: "<field> <asked> exceeds the ceiling <key> = <limit> set at <file>:<line>",
		Fix: "ask for less — or raise the ceiling in <file>, which is a change a person " +
			"makes to a file and not something a tool here can do",
		Sample: V{"field": "cpus", "asked": "8", "key": "cpus", "limit": "4",
			"file": "/home/you/project/kelyfos.toml", "line": "12"},
	}

	// CeilingToolLegacy is an MCP tool call over a legacy [sandbox] size key —
	// vcpus or mem_mib. On the CLI those keys are defaults a flag may exceed;
	// on this door the tool schema promises "at most what the policy allows",
	// so a declared size is a ceiling whichever key spells it (audit
	// 2026-09-01, A8). Its own entry rather than CeilingTool's because the fix
	// is different: the size lives in [sandbox], not [resources], and it has no
	// line to name — config does not track the legacy keys' positions.
	CeilingToolLegacy = Denial{
		ID: "ceiling.tool_legacy",
		Doc: "an MCP tool call asked for more than a legacy [sandbox] size key — vcpus or " +
			"mem_mib — which on this door is a ceiling and not merely a default (audit 2026-09-01, A8)",
		Msg: "<field> <value> exceeds the ceiling <key> = <limit> set at <file> — on this door " +
			"a declared size is a ceiling, not a default",
		Fix: "ask for less, or move the size into <file>'s [resources] and raise it there if " +
			"the machine is meant to have more",
		Sample: V{"field": "cpus", "value": "4", "key": "vcpus", "limit": "2",
			"file": "/home/you/project/kelyfos.toml"},
	}

	CeilingSnapshot = Denial{
		ID:  "ceiling.snapshot",
		Doc: "a snapshot holds a machine larger than the ceiling now in force",
		Msg: "snapshot <name> holds a <held> machine, over the ceiling <key> = <limit> " +
			"set at <file>:<line>, and a restore cannot resize it",
		Fix: "take the snapshot again from a smaller sandbox, or raise the ceiling in <file>",
		Sample: V{"name": "before-the-migration", "held": "8 vcpu", "key": "cpus", "limit": "4",
			"file": "/home/you/project/kelyfos.toml", "line": "12"},
	}

	CeilingSnapshotUnknown = Denial{
		ID: "ceiling.snapshot_unknown",
		Doc: "a snapshot does not record how large its machine is, and a ceiling cannot be " +
			"checked against nothing",
		Msg: "snapshot <name> does not record how large its machine is — it was taken by an " +
			"older kelyfos — and <file> sets a ceiling that cannot be checked against nothing",
		Fix:    "take the snapshot again with this version, and it will say",
		Sample: V{"name": "before-the-migration", "file": "/home/you/project/kelyfos.toml"},
	}

	// CeilingHost is the machine's own ceiling, which no policy file raises
	// and no flag widens (audit 2026-09-01, A8). It is checked after the
	// policy's, because a policy that permits more than the host can run is
	// still bounded by the host.
	CeilingHost = Denial{
		ID: "ceiling.host",
		Doc: "a machine was asked for that is larger than the physical host itself — RAM or " +
			"cores beyond what the machine has, which no policy can grant (audit 2026-09-01, A8)",
		Msg: "<field> <asked> exceeds what this host can run (<limit>)",
		Fix: "ask for a smaller machine — this is the physical host's ceiling, and no " +
			"policy file or tool argument raises it",
		Sample: V{"field": "mem", "asked": "262144 MiB", "limit": "8192 MiB"},
	}

	// CeilingHostSnapshot is a snapshot that holds a machine larger than the
	// physical host it is being restored on (audit 2026-09-01, A8). Firecracker
	// takes vcpu and memory from the state file, so a restore cannot shrink the
	// machine to fit — the only honest answers are to allow it or refuse it, and
	// a machine larger than the host has cannot be allowed. It applies even with
	// no policy: the host is nobody's to edit. Its own entry rather than
	// CeilingHost's because it names the snapshot, and there is no argument to
	// lower — the size is frozen.
	CeilingHostSnapshot = Denial{
		ID: "ceiling.host_snapshot",
		Doc: "a snapshot holds a machine larger than the physical host itself — more cores or " +
			"RAM than the machine has — and a restore cannot resize it (audit 2026-09-01, A8)",
		Msg: "snapshot <name> holds a <held> machine, over what this host can run (<limit>), " +
			"and a restore cannot resize it",
		Fix: "restore it on a larger host, or take the snapshot again from a machine that fits " +
			"this one — this is the physical host's ceiling, which no policy raises",
		Sample: V{"name": "before-the-migration", "held": "8 vcpu", "limit": "4"},
	}

	CeilingResume = Denial{
		ID: "ceiling.resume",
		Doc: "a paused session's frozen policy asks for more than the current policy's ceiling, " +
			"and a resume runs the frozen one",
		Msg: "session <name> was paused under <key> = <frozen>, and <file>:<line> now sets a " +
			"ceiling of <limit>; a resume runs the frozen policy, so it cannot be a way past " +
			"the current one",
		Fix: "raise the ceiling in <file>, or start a new sandbox rather than resuming",
		Sample: V{"name": "before-the-migration", "key": "cpus", "frozen": "8", "limit": "4",
			"file": "/home/you/project/kelyfos.toml", "line": "12"},
	}

	// --- allowlists: narrowing is always permitted, widening never --------

	AllowProject = Denial{
		ID:  "allow.project",
		Doc: "a tool call asked for a domain the project's policy file does not permit",
		Msg: "allow <domain> is not in this project's allowlist; <file> permits <permitted>",
		Fix: "add <domain> to allow in <file> — a tool may narrow what the policy permits " +
			"and may never widen it",
		Sample: V{"domain": "api.stripe.com", "file": "/home/you/project/kelyfos.toml",
			"permitted": "github.com, api.github.com"},
	}

	AllowSnapshot = Denial{
		ID:  "allow.snapshot",
		Doc: "a restore asked for a domain the frozen machine itself could not reach",
		Msg: "allow <domain> is not in snapshot <name>'s own allowlist (<permitted>)",
		Fix: "restore with a subset of <permitted>; a restore may narrow what the frozen " +
			"machine could reach and never widen it",
		Sample: V{"domain": "api.stripe.com", "name": "before-the-migration",
			"permitted": "github.com"},
	}

	AllowResume = Denial{
		ID:  "allow.resume",
		Doc: "a paused session's frozen allowlist names a domain the current policy no longer permits",
		Msg: "session <name> was paused with <domain> in its allowlist, and <file> no longer " +
			"permits it; a resume runs the frozen policy, so it cannot be a way past the " +
			"current one",
		Fix: "add <domain> back to allow in <file>, or start a new sandbox rather than resuming",
		Sample: V{"name": "before-the-migration", "domain": "api.stripe.com",
			"file": "/home/you/project/kelyfos.toml"},
	}

	AllowSingleLabel = Denial{
		ID: "allow.single_label",
		Doc: "an allowlist or credential binding named a bare top-level domain — org, com, io — " +
			"and the allowlist's suffix rule would then match every site under it: egress to the " +
			"whole TLD, credentials included (audit 2026-09-01, A6)",
		Msg: "allow <domain> is a bare top-level domain, and the allowlist's suffix rule " +
			"would match every site under it",
		Fix: "name the hosts you mean — for example <example> instead of <domain> — " +
			"so the entry permits what it says and nothing more",
		Sample: V{"domain": "org", "example": "example.org"},
	}

	// --- budgets: how many machines this server may have at once ----------

	BudgetSandboxes = Denial{
		ID:  "budget.sandboxes",
		Doc: "an MCP client asked for a sandbox beyond [mcp] max_sandboxes",
		Msg: "this server has <running> sandbox(es) running, <asked> more were asked for, " +
			"and [mcp] max_sandboxes is <limit>",
		Fix: "stop some with sandbox_stop, or raise max_sandboxes in <file> — which is a " +
			"change a person makes to a file, not something a tool here can do",
		Sample: V{"running": "4", "asked": "1", "limit": "4",
			"file": "/home/you/project/kelyfos.toml"},
	}

	ForkCount = Denial{
		ID: "fork.count",
		Doc: "a fork asked for more machines in one call than any fleet limit could honour " +
			"— a count near the largest signed integer once overflowed the ceiling arithmetic " +
			"and crashed the server, so the count is bounded before anything multiplies it",
		Msg: "sandbox_fork cannot restore <asked> machines in one call; <limit> is the most " +
			"one call may ask for",
		Fix: "ask for a smaller count — [mcp] max_sandboxes still bounds how many machines " +
			"run at once, so a batch larger than <limit> could never be honoured",
		Sample: V{"asked": "9223372036854775807", "limit": "256"},
	}

	// --- the jail: the wall around the VMM --------------------------------

	JailNoSudo = Denial{
		ID: "jail.no_sudo",
		Doc: "this machine cannot run the jailer, which needs passwordless sudo, and a run " +
			"is jailed by default",
		Msg: "this build runs Firecracker under the jailer, which needs passwordless sudo (<reason>)",
		Fix: "add a sudoers line — <sudoers> — or rerun with --no-jail, which says what is " +
			"not enforced, every time",
		Sample: V{
			"reason":  "sudo: a password is required",
			"sudoers": `you ALL=(root) NOPASSWD: /usr/local/bin/jailer`,
		},
	}

	// --- the guest profile: what the supervisor grants what it spawns -----

	ProfileNotEnforced = Denial{
		ID: "profile.not_enforced",
		Doc: "the guest came up but its supervisor could not apply the per-flavor confinement " +
			"profile, so nothing it spawned would be confined",
		Msg: "the guest cannot confine what it runs (<reason>)",
		Fix: "rebuild the image — the guest kernel needs CONFIG_SECURITY_LANDLOCK=y and " +
			"landlock named in CONFIG_LSM, and an LSM that is built but not named is not enabled",
		Sample: V{"reason": "landlock is not available in this kernel (function not implemented)"},
	}

	// --- the host syscall filter ------------------------------------------

	SeccompNotInForce = Denial{
		ID: "seccomp.not_in_force",
		Doc: "the VMM came up without the syscall filter Firecracker compiles into its own " +
			"release binaries, which a KelyfOS run requires rather than hopes for",
		Msg: "Firecracker is running without its syscall filter (<detail>)",
		Fix: "install an official Firecracker release — bash dev/install-firecracker.sh — " +
			"because the filter is built into that binary, and a debug build or an " +
			"unsupported target ships an empty one that installs nothing",
		Sample: V{"detail": "fc_vcpu 0 (tid 41207) reports Seccomp: 0"},
	}

	// --- forwards: what is listening at the other end ---------------------

	ForwardClosed = Denial{
		ID:  "forward.closed",
		Doc: "a connection reached a forwarded port and nothing inside the sandbox was listening",
		Msg: "a connection to the forwarded port <host> found nothing listening on port " +
			"<guest> inside the sandbox",
		Fix: "start the server in the guest before connecting, or forward the port it is " +
			"actually on — a forward carries a connection, it does not start anything",
		Sample: V{"host": "8080", "guest": "80"},
	}

	// --- teams: the edges, the store and the spawn budget -----------------

	TeamEdge = Denial{
		ID:  "team.edge",
		Doc: "an agent addressed another agent it has no declared edge to",
		Msg: "this team has no edge from <from> to <to>",
		Fix: `add [[team.edge]] with from = "<from>" and to = "<to>" to the team file, ` +
			"if that path is meant to exist",
		Sample: V{"from": "worker-1", "to": "worker-2"},
	}

	TeamSpawnNone = Denial{
		ID:  "team.spawn_none",
		Doc: "an agent asked to spawn a worker without any spawn budget at all",
		Msg: "<agent> has no spawn budget",
		Fix: `grant one with [team.agent.spawn] under that agent in the team file — a budget ` +
			"is written before the run, never asked for during it",
		Sample: V{"agent": "master"},
	}

	TeamSpawnBudget = Denial{
		ID:     "team.spawn_budget",
		Doc:    "an agent asked to spawn a worker while its budget was already full",
		Msg:    "<agent> already has <live> of its <max> spawned workers running",
		Fix:    "let one finish, or raise max in [team.agent.spawn] for <agent> in the team file",
		Sample: V{"agent": "master", "live": "4", "max": "4"},
	}

	TeamSpawnImage = Denial{
		ID:     "team.spawn_image",
		Doc:    "an agent asked to spawn a worker from an image its budget does not list",
		Msg:    "<agent> may not spawn the <image> image; its budget permits <permitted>",
		Fix:    `add "<image>" to image in [team.agent.spawn] for <agent> in the team file`,
		Sample: V{"agent": "master", "image": "python", "permitted": "dev"},
	}

	TeamStore = Denial{
		ID:  "team.store",
		Doc: "an agent touched a store key a [[team.store.key]] rule does not grant it",
		Msg: "<agent> may not <verb> <key>",
		Fix: `add "<agent>" to <verb> in the [[team.store.key]] rule that matches <key>, ` +
			"in the team file",
		Sample: V{"agent": "worker-1", "verb": "read", "key": "plan"},
	}
)

// All is the catalog, by ID. The IDs are prefixed by what refuses, so sorting
// them groups them.
func All() []Denial {
	all := []Denial{
		AllowProject, AllowResume, AllowSnapshot, AllowSingleLabel,
		BudgetSandboxes,
		CeilingFlag, CeilingHost, CeilingHostSnapshot, CeilingResume, CeilingSnapshot,
		CeilingSnapshotUnknown, CeilingTool, CeilingToolLegacy,
		EgressHost, EgressPort, EgressResolvedAddr,
		ForkCount,
		ForwardClosed,
		JailNoSudo,
		ProfileNotEnforced,
		SeccompNotInForce,
		SecretUnallowed,
		TeamEdge, TeamSpawnBudget, TeamSpawnImage, TeamSpawnNone, TeamStore,
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all
}

// Lookup finds a catalog entry by ID.
func Lookup(id string) (Denial, bool) {
	for _, d := range All() {
		if d.ID == id {
			return d, true
		}
	}
	return Denial{}, false
}

// Placeholders are the <names> a denial's message and fix between them use, in
// sorted order. gendocs prints them; the tests check every one has a Sample.
func (d Denial) Placeholders() []string {
	seen := map[string]bool{}
	for _, s := range []string{d.Msg, d.Fix} {
		for {
			i := strings.Index(s, "<")
			if i < 0 {
				break
			}
			j := strings.Index(s[i:], ">")
			if j < 0 {
				break
			}
			name := s[i+1 : i+j]
			// Not every angle bracket is a placeholder: a name is a single
			// lower-case word, so prose like "<file>:<line>" is caught and an
			// e-mail address or a comparison is not.
			if name != "" && strings.IndexFunc(name, func(r rune) bool {
				return !(r >= 'a' && r <= 'z') && r != '_'
			}) < 0 {
				seen[name] = true
			}
			s = s[i+j:]
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

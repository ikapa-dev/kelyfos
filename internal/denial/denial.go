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
		AllowProject, AllowResume, AllowSnapshot,
		BudgetSandboxes,
		CeilingFlag, CeilingResume, CeilingSnapshot, CeilingSnapshotUnknown, CeilingTool,
		EgressHost, EgressPort,
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

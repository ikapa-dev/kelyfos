package config

import (
	"fmt"
	"sort"
	"strings"
)

// The schema of kelyfos.toml, as data.
//
// This exists because a documented key that the parser does not accept, or a key
// the parser accepts and nobody documented, is the exact failure mode F-D4 was
// written to prevent: an LLM writes confidently against the reference and gets a
// file that refuses to load. So the reference is generated from this table
// (tools/gendocs) rather than typed, and two tests keep the table honest —
// TestSchemaKeysAllParse feeds every row to the parser, and TestSchemaCoversThe
// Parser reads this package's own source and fails if a `case` here has no row.
//
// It is not a second parser. The table describes; the switch decides. What binds
// them is that the switch's own error messages are built from this table, so a
// key added to one and not the other is visible the first time somebody makes a
// typo — and the tests make it visible before that.

// KeyType is the vocabulary docs/resources.md uses for a value's shape.
type KeyType string

const (
	TypeString   KeyType = "string"
	TypeStrings  KeyType = "string array"
	TypeInt      KeyType = "integer"
	TypeBool     KeyType = "boolean"
	TypeSize     KeyType = "size"       // 512M, 2G, or a bare byte count
	TypePercent  KeyType = "percentage" // "150%" — one core's worth is 100%
	TypeDuration KeyType = "duration"   // "30m", "90s"
)

// Key is one key kelyfos.toml understands, or one it deliberately refuses.
type Key struct {
	Section string  // "resources", "team.agent", "" for the bare/[sandbox] keys
	Name    string  // the key as written in the file
	Type    KeyType //
	Default string  // what happens when it is absent; "" when absence means nothing
	Doc     string  // one line, imperative, no trailing full stop
	Sample  string  // a value that must parse — used by the round-trip test and by examples

	// Refused marks a key the parser recognises and rejects on purpose, with the
	// reason. A recognised refusal is a better answer than "unknown key" because
	// the mistake it catches is a wrong mental model rather than a typo.
	Refused string

	// RefusedLater marks a key that parses here and is refused before boot. The
	// distinction matters to a reader: the file loads, and the run does not
	// start.
	RefusedLater string
}

// Accepted reports whether writing this key actually works.
func (k Key) Accepted() bool { return k.Refused == "" && k.RefusedLater == "" }

// Section is one table header the file understands.
type Section struct {
	Name     string // "team.agent"; "" is the bare top level
	Header   string // how it is written: "[team.agent]" or "[[team.agent]]"
	Repeated bool   // an array of tables
	Doc      string
}

// resourceKeys are the caps, defined once. They appear verbatim under
// [resources] for a single run and under [team.agent.resources] and
// [team.agent.spawn.resources] for a team member, because assignResources is
// the one function that reads them and a per-agent cap must not drift from a
// per-run one in name, unit or meaning.
func resourceKeys() []Key {
	return []Key{
		{Name: "cpus", Type: TypeInt, Default: "2 cores", Sample: "2",
			Doc: "cores the guest sees — KVM machine config, absolute"},
		{Name: "mem", Type: TypeSize, Default: "512 MiB", Sample: `"2G"`,
			Doc: "guest RAM — KVM machine config, absolute; a bare number here is bytes, unlike --mem"},
		{Name: "disk", Type: TypeSize, Default: "no ceiling", Sample: `"4G"`,
			Doc: "ceiling on the packed workspace image, refused before boot; not the /work device size"},
		{Name: "scratch", Type: TypeSize, Default: "half the guest's RAM", Sample: `"512M"`,
			Doc: "size= on the tmpfs behind the overlay: everything written outside /work"},
		{Name: "cpu_quota", Type: TypePercent, Default: "uncapped", Sample: `"150%"`,
			Doc: "host CPU time as a share of one core — cgroup v2 cpu.max, throttling"},
		{Name: "net_mbps_rx", Type: TypeInt, Default: "unthrottled", Sample: "50",
			Doc: "inbound network rate, decimal megabits — Firecracker token bucket"},
		{Name: "net_mbps_tx", Type: TypeInt, Default: "unthrottled", Sample: "50",
			Doc: "outbound network rate, decimal megabits — Firecracker token bucket"},
		{Name: "disk_iops", Type: TypeInt, Default: "unthrottled", Sample: "500",
			Doc: "operations per second, on each block device — Firecracker token bucket"},
		{Name: "disk_mbps", Type: TypeInt, Default: "unthrottled", Sample: "100",
			Doc: "bytes per second, decimal megabytes, on each block device"},
		{Name: "max_runtime", Type: TypeDuration, Default: "no budget", Sample: `"30m"`,
			Doc: "wall-clock budget; expiry is SIGTERM, grace, sync-back, exit 124"},
		{Name: "idle_timeout", Type: TypeDuration, Default: "no budget", Sample: `"5m"`,
			Doc: "no tool call and no proxy traffic for this long ends the run"},
	}
}

func inSection(section string, keys []Key) []Key {
	out := make([]Key, 0, len(keys))
	for _, k := range keys {
		k.Section = section
		out = append(out, k)
	}
	return out
}

// Sections describes every table header the file understands, in the order a
// reader meets them.
func Sections() []Section {
	return []Section{
		{Name: "", Header: "(bare) or [sandbox]", Doc: "what to boot, and what it may reach"},
		{Name: "resources", Header: "[resources]", Doc: "hard ceilings for a single run, and the value when no flag asks: a flag may ask for less, never more"},
		{Name: "sessions", Header: "[sessions]", Doc: "retention for the flight recorder's own history, read by kelyfos sessions prune"},
		{Name: "team", Header: "[team]", Doc: "several agents on one host, and the paths between them"},
		{Name: "mcp", Header: "[mcp]", Doc: "limits on the outward MCP server, kelyfos serve-mcp"},
		{Name: "team.resources", Header: "[team.resources]", Doc: "the collective budget — cpu_quota is the only cap a team can share"},
		{Name: "team.agent", Header: "[[team.agent]]", Repeated: true, Doc: "one agent, or count of them"},
		{Name: "team.agent.resources", Header: "[team.agent.resources]", Doc: "that agent's own caps: exactly the [resources] keys"},
		{Name: "team.agent.spawn", Header: "[team.agent.spawn]", Doc: "the budget within which this agent may create workers at runtime"},
		{Name: "team.agent.spawn.resources", Header: "[team.agent.spawn.resources]", Doc: "the caps a spawned worker gets"},
		{Name: "team.edge", Header: "[[team.edge]]", Repeated: true, Doc: "one permitted path; the edge list is the topology"},
		{Name: "team.store", Header: "[team.store]", Doc: "the permissioned key/blob store shared by the team"},
		{Name: "team.store.key", Header: "[[team.store.key]]", Repeated: true, Doc: "who may read and write one key or glob"},
		{Name: "plugin", Header: "[[plugin]]", Repeated: true, Doc: "one MCP server to run inside the guest; its tools are advertised as <name>_<tool> — kelyfos team up refuses a file that also has a [team] section, because a team boot does not launch plugin servers yet (P7-4)"},
		{Name: "forward", Header: "[[forward]]", Repeated: true, Doc: "one host port carried to a guest-local port over vsock; the firewall is untouched — kelyfos team up refuses a file that also has a [team] section, because a team boot does not open forwarded ports yet (P7-4)"},
	}
}

// teamResourcesRefusal is the message a per-agent cap gets when it is written at
// team level. It is one string because the refusal and the documentation of the
// refusal must say the same thing.
const teamResourcesRefusal = "a per-agent cap, not a team-wide one; write it in [team.agent.resources]"

// Schema is every key, in file order within each section.
func Schema() []Key {
	keys := []Key{
		{Name: "image", Type: TypeString, Default: `"base"`, Sample: `"dev"`,
			Doc: "image flavor to boot; refused at boot if it does not match the image's manifest"},
		{Name: "arch", Type: TypeString, Default: "the build host's architecture", Sample: `"x86_64"`,
			Doc: "guest architecture: aarch64 or x86_64"},
		{Name: "workspace", Type: TypeString, Default: "no /work device", Sample: `"."`,
			Doc: "host directory to pack and attach at /work, resolved against this file. " +
				"It must be inside this file's own directory tree: the directory is packed " +
				"into the guest and written back over on shutdown, and a policy file " +
				"describes its own project. Pass --workspace with the same value to use one " +
				"outside it, which makes it the operator's decision rather than the file's"},
		{Name: "allow", Type: TypeStrings, Default: "no network interface at all", Sample: `["github.com"]`,
			Doc: "egress allowlist; a bare hostname also matches its subdomains"},
		{Name: "secrets", Type: TypeStrings, Default: "none", Sample: `["GITHUB_TOKEN@api.github.com"]`,
			Doc: "NAME@host[:bearer|basic][/path] — names only; a value here is refused. " +
				"A path binds the credential to that endpoint on that host exactly, instead of " +
				"to the domain and every subdomain of it"},
		{Name: "vcpus", Type: TypeInt, Default: "2", Sample: "2",
			Doc: "pre-v0.4 spelling of a cpus default; kept working, prefer [resources] cpus"},
		{Name: "mem_mib", Type: TypeInt, Default: "512", Sample: "1024",
			Doc: "pre-v0.4 spelling of a mem default, in MiB; prefer [resources] mem"},
		{Name: "notify", Type: TypeBool, Default: "false", Sample: "true",
			Doc: "send a desktop notification when a run finishes, is blocked, times out, or waits for a review"},
	}
	out := inSection("", keys)
	out = append(out, inSection("resources", resourceKeys())...)

	out = append(out,
		Key{Section: "sessions", Name: "retention_days", Type: TypeInt,
			Default: "180 (the EU AI Act's own floor for a general-purpose system, D61)", Sample: "365",
			Doc: "the floor kelyfos sessions prune reads: it never deletes a recorded session younger " +
				"than this, however it is invoked. 0 (including an absent key) means the built-in " +
				"180-day default applies, not that every session is immediately prunable"},
	)

	out = append(out,
		Key{Section: "mcp", Name: "max_sandboxes", Type: TypeInt, Default: "4", Sample: "2",
			Doc: "how many sandboxes one `kelyfos serve-mcp` may have running at once"},
	)

	out = append(out,
		Key{Section: "plugin", Name: "name", Type: TypeString, Default: "", Sample: `"browser"`,
			Doc: "the plugin's name and the prefix of every tool it advertises; " +
				"lowercase letters, digits and dashes, at most 24 characters"},
		Key{Section: "plugin", Name: "path", Type: TypeString, Default: "", Sample: `"./plugins/browser"`,
			Doc: "host directory packed into the read-only plugins device, resolved against this file"},
		Key{Section: "plugin", Name: "command", Type: TypeString, Default: "", Sample: `"node"`,
			Doc: "what the supervisor launches, resolved inside that plugin's directory"},
		Key{Section: "plugin", Name: "args", Type: TypeStrings, Default: "no arguments", Sample: `["server.js"]`,
			Doc: "arguments to the command"},
	)

	out = append(out,
		Key{Section: "forward", Name: "host", Type: TypeInt, Default: "", Sample: "8080",
			Doc: "port on this machine's loopback; --p-bind is the only way to bind anything else"},
		Key{Section: "forward", Name: "guest", Type: TypeInt, Default: "", Sample: "80",
			Doc: "guest-local port the supervisor dials on 127.0.0.1 inside the sandbox"},
	)

	out = append(out,
		Key{Section: "team", Name: "name", Type: TypeString, Default: "", Sample: `"reviewers"`,
			Doc: "the team's name; required, and it names the cgroup slice"},
		Key{Section: "team", Name: "record_payloads", Type: TypeBool, Default: "false", Sample: "true",
			Doc: "write message bodies into the record as well as their hashes"},
	)

	out = append(out,
		Key{Section: "team.resources", Name: "cpu_quota", Type: TypePercent, Default: "no collective cap", Sample: `"200%"`,
			Doc: "host CPU time for the whole team — the parent cgroup slice every agent sits in"},
	)
	for _, k := range resourceKeys() {
		if k.Name == "cpu_quota" {
			continue
		}
		k.Section = "team.resources"
		k.Refused = teamResourcesRefusal
		out = append(out, k)
	}

	out = append(out,
		Key{Section: "team.agent", Name: "name", Type: TypeString, Sample: `"master"`,
			Doc: "the agent's name; required, and how every other agent addresses it"},
		Key{Section: "team.agent", Name: "image", Type: TypeString, Default: "the file's image, else \"base\"", Sample: `"dev"`,
			Doc: "image flavor for this agent"},
		Key{Section: "team.agent", Name: "workspace", Type: TypeString, Default: "no /work device", Sample: `"./ws"`,
			// Same resolution rule as the top-level workspace, and it has to be
			// said in both rows: a reader comparing them reads a difference in
			// wording as a difference in behaviour, and this was the last
			// workspace path in the product still resolved against the process's
			// own directory until L-5 moved it onto the file.
			Doc: "host directory for this agent alone, resolved against this file; refused when " +
				"count is above 1, and when a second agent names the same directory"},
		Key{Section: "team.agent", Name: "count", Type: TypeInt, Default: "1", Sample: "4",
			Doc: "how many of this agent; above 1 they are named name-1 … name-N"},
		Key{Section: "team.agent", Name: "allow", Type: TypeStrings, Default: "no network interface at all", Sample: `["example.com"]`,
			Doc: "this agent's own egress allowlist; there is deliberately no team-wide one"},
		Key{Section: "team.agent", Name: "secrets", Type: TypeStrings, Default: "none", Sample: `["TOKEN@example.com"]`,
			Doc: "this agent's secrets; each domain must appear in this agent's allow"},
	)

	for _, k := range resourceKeys() {
		k.Section = "team.agent.resources"
		if k.Name == "idle_timeout" {
			k.RefusedLater = "refused before boot inside a team (F-D20): a team shares one " +
				"flight recorder, so the host cannot yet tell which agent went quiet — use max_runtime"
		}
		out = append(out, k)
	}

	out = append(out,
		Key{Section: "team.agent.spawn", Name: "max", Type: TypeInt, Default: "0, which permits no spawn", Sample: "2",
			Doc: "how many spawned workers this agent may have running at once"},
		Key{Section: "team.agent.spawn", Name: "image", Type: TypeStrings, Default: "empty, which permits nothing", Sample: `["dev"]`,
			Doc: "image flavors a spawned worker may use; an empty list permits none, not all"},
		Key{Section: "team.agent.spawn", Name: "lifetime", Type: TypeDuration, Default: "no lifetime", Sample: `"10m"`,
			Doc: "how long a spawned worker lives before the host despawns it"},
	)
	for _, k := range resourceKeys() {
		k.Section = "team.agent.spawn.resources"
		switch k.Name {
		case "idle_timeout":
			k.RefusedLater = "refused before boot (F-D20, F-D33): a team shares one flight recorder, " +
				"so the host cannot tell which agent went quiet — use [team.agent.spawn] lifetime"
		case "max_runtime":
			k.RefusedLater = "refused before boot (F-D33): this is [team.agent.spawn] lifetime under " +
				"another name, and lifetime is the one that is enforced"
		}
		out = append(out, k)
	}

	out = append(out,
		Key{Section: "team.edge", Name: "from", Type: TypeString, Sample: `"master"`,
			Doc: "the initiating agent; required. A trailing * globs over agent names"},
		Key{Section: "team.edge", Name: "to", Type: TypeString, Sample: `"worker-*"`,
			Doc: "the addressed agent; required"},
		Key{Section: "team.edge", Name: "bidirectional", Type: TypeBool, Default: "true", Sample: "false",
			Doc: "whether the far end may initiate too; a reply to an ask never needs an edge"},
		Key{Section: "team.store", Name: "enabled", Type: TypeBool, Default: "false", Sample: "true",
			Doc: "whether the team has a store at all; key rules without it are inert"},
		Key{Section: "team.store.key", Name: "name", Type: TypeString, Sample: `"findings/*"`,
			Doc: "the key or trailing-* glob this rule covers; required"},
		Key{Section: "team.store.key", Name: "read", Type: TypeStrings, Default: "nobody, once a rule matches", Sample: `["*"]`,
			Doc: "agent names or globs that may read it; * is everyone"},
		Key{Section: "team.store.key", Name: "write", Type: TypeStrings, Default: "nobody, once a rule matches", Sample: `["master"]`,
			Doc: "agent names or globs that may write it"},
	)
	return out
}

// KeysIn returns the schema rows for one section, accepted and refused alike.
func KeysIn(section string) []Key {
	var out []Key
	for _, k := range Schema() {
		if k.Section == section {
			out = append(out, k)
		}
	}
	return out
}

// knownKeys is the hint appended to an unknown-key error. It is built from the
// schema on purpose: it is what makes the table load-bearing rather than a
// second copy of the truth that nothing reads.
func knownKeys(section string) string {
	var names []string
	for _, k := range KeysIn(section) {
		if k.Accepted() || k.RefusedLater != "" {
			names = append(names, k.Name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return "\n    this section takes: " + strings.Join(names, ", ")
}

func unknownKey(where, key, section string) error {
	label := section
	if label == "" {
		label = "sandbox"
	}
	return fmt.Errorf("%s: unknown key %q in [%s]%s", where, key, label, knownKeys(section))
}

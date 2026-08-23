package recorder

// The flight recorder's schema, as data.
//
// docs/events.md is the concept half — why the host writes it, what
// tamper-evidence buys, why a refused message is its own type. The tables are
// generated from here by tools/gendocs, because a payload field that the
// reference names and the writer never sets is how a consumer ends up parsing
// for something that is never there.
//
// Two tests keep this honest: TestSchemaCoversEveryType reads this package's own
// source and fails if a Type* constant has no row, and TestSchemaFieldsExist
// checks every field name against the struct's json tags.

// Field is one payload field on one event type.
type Field struct {
	Name string // the JSON key
	Type string // integer, string, boolean, string array, object
	Doc  string
	When string // non-empty: the condition under which it appears
}

// EventType is one type string the recorder writes.
type EventType struct {
	Type   string
	Source string // SourceHost unless the guest is the one reporting it
	Doc    string
	Fields []Field
}

const agentDoc = "which machine produced it; present inside a team"

func agentField() Field {
	return Field{Name: "agent", Type: "string", Doc: agentDoc, When: "in a team"}
}

// CommonFields are on every event, in the order they are hashed. The order is
// the declaration order of Event, and is load-bearing: it is what an
// independent implementation has to reproduce to verify a chain.
func CommonFields() []Field {
	return []Field{
		{Name: "v", Type: "integer", Doc: "schema version — 1"},
		{Name: "seq", Type: "integer", Doc: "position in the session, from 1, no gaps"},
		{Name: "ts", Type: "string", Doc: "RFC 3339 with milliseconds, UTC, host clock"},
		{Name: "sandbox", Type: "string", Doc: "the session's id; for a team, the team's"},
		{Name: "type", Type: "string", Doc: "one of the types below"},
		{Name: "source", Type: "string", Doc: "host, or guest when the guest is what reported it"},
		{Name: "prev", Type: "string", Doc: "the previous event's hash; empty on the first"},
		{Name: "hash", Type: "string", Doc: "sha256 over this event with hash set to the empty string"},
	}
}

// Types is every event type, in the order a session produces them.
func Types() []EventType {
	return []EventType{
		{Type: TypeSessionStart, Source: SourceHost,
			Doc: "opens the file, and records what the sandbox is",
			Fields: []Field{
				{Name: "image", Type: "string", Doc: "image flavor"},
				{Name: "arch", Type: "string", Doc: "aarch64 or x86_64"},
				{Name: "kelyfos", Type: "string", Doc: "CLI version"},
				{Name: "argv", Type: "string array", Doc: "how the sandbox was launched, for reproduction"},
				{Name: "reason", Type: "string", Doc: "where the machine came from", When: "restore and fork"},
			}},
		{Type: TypeSessionReady, Source: SourceHost,
			Doc: "the guest announced itself on the ready channel",
			Fields: []Field{
				{Name: "boot_ms", Type: "integer", Doc: "host-measured boot-to-ready"},
				{Name: "kernel", Type: "string", Doc: "guest kernel release"},
				{Name: "supervisor", Type: "string", Doc: "supervisor version"},
				{Name: "overlay", Type: "boolean", Doc: "whether the writable overlay came up"},
				{Name: "image", Type: "string", Doc: "this agent's flavor", When: "in a team"},
				{Name: "via", Type: "string", Doc: "cold or fork — how this member was started", When: "in a team"},
				agentField(),
			}},
		{Type: TypeSessionEnd, Source: SourceHost,
			Doc: "closes the file",
			Fields: []Field{
				{Name: "reason", Type: "string", Doc: "shutdown, interrupted, vm_exited, command_exited, timeout, error"},
				{Name: "duration_ms", Type: "integer", Doc: "session length"},
			}},
		{Type: TypeCommandStart, Source: SourceHost,
			Doc: "a command was submitted, before it runs",
			Fields: []Field{
				{Name: "call", Type: "string", Doc: "correlates this command's three events"},
				{Name: "cmd", Type: "string array", Doc: "argv as submitted, including any /bin/sh -c wrapper"},
				{Name: "cwd", Type: "string", Doc: "working directory inside the guest"},
				{Name: "via", Type: "string", Doc: "which door asked: exec, mcp, or serve-mcp"},
				agentField(),
			}},
		{Type: TypeCommandOutput, Source: SourceHost,
			Doc: "a chunk of a command's output, coalesced at 8 KiB",
			Fields: []Field{
				{Name: "call", Type: "string", Doc: "the command this belongs to"},
				{Name: "stream", Type: "string", Doc: "stdout or stderr"},
				{Name: "data", Type: "string", Doc: "base64 — output is bytes, not text"},
				{Name: "bytes", Type: "integer", Doc: "decoded length"},
				agentField(),
			}},
		{Type: TypeCommandExit, Source: SourceHost,
			Doc: "how a command ended",
			Fields: []Field{
				{Name: "call", Type: "string", Doc: "the command this belongs to"},
				{Name: "code", Type: "integer", Doc: "exit status"},
				{Name: "signal", Type: "string", Doc: "Go's signal name, e.g. killed", When: "killed by a signal"},
				{Name: "duration_ms", Type: "integer", Doc: "how long it ran"},
				{Name: "error", Type: "object", Doc: "kind and message, when it did not run at all"},
				agentField(),
			}},
		{Type: TypeFileWrite, Source: SourceHost,
			Doc: "a file written through a tool, recorded by hash rather than content",
			Fields: []Field{
				{Name: "path", Type: "string", Doc: "path inside the guest"},
				{Name: "bytes", Type: "integer", Doc: "size written"},
				{Name: "sha256", Type: "string", Doc: "digest of the content"},
				{Name: "via", Type: "string", Doc: "which door the write came through: write_file or upload for a guest MCP tool, serve-mcp for an outside MCP client, shim for the E2B surface"},
				agentField(),
			}},
		{Type: TypeEgressAttempt, Source: SourceHost,
			Doc: "one outbound connection attempt, permitted or not",
			Fields: []Field{
				{Name: "host", Type: "string", Doc: "requested host", When: "the request parsed"},
				{Name: "port", Type: "integer", Doc: "requested port", When: "the request parsed"},
				{Name: "allowed", Type: "boolean", Doc: "whether policy permitted it"},
				{Name: "reason", Type: "string", Doc: "not_in_allowlist, port_not_allowed, bad_request, upstream_unreachable, tls_pinning_rejected_our_ca", When: "it did not go through"},
				{Name: "mode", Type: "string", Doc: "how much the proxy could read: tunnelled (a CONNECT it relayed unopened), terminated (a secret-bound domain it decrypted), or plain (ordinary HTTP, which it necessarily read in full)", When: "allowed"},
				{Name: "bytes_in", Type: "integer", Doc: "bytes read from upstream"},
				{Name: "bytes_out", Type: "integer", Doc: "bytes written upstream"},
				agentField(),
			}},
		{Type: TypeSecretUse, Source: SourceHost,
			Doc: "a bound credential was attached to a request — by name, never by value",
			Fields: []Field{
				{Name: "name", Type: "string", Doc: "the secret's environment-variable name"},
				{Name: "host", Type: "string", Doc: "the domain it was attached for"},
				agentField(),
			}},
		{Type: TypeResourceOOM, Source: SourceGuest,
			Doc: "the guest's OOM killer ran; the supervisor read it off /dev/kmsg and the host wrote it",
			Fields: []Field{
				{Name: "pid", Type: "integer", Doc: "the killed process"},
				{Name: "comm", Type: "string", Doc: "its name"},
				{Name: "rss_kib", Type: "integer", Doc: "how much it was holding"},
				{Name: "mem_mib", Type: "integer", Doc: "the machine's RAM cap, for comparison"},
				agentField(),
			}},
		{Type: TypeResourceTimeout, Source: SourceHost,
			Doc: "a time budget expired and ended the run",
			Fields: []Field{
				{Name: "budget", Type: "string", Doc: "max_runtime or idle_timeout — which one fired"},
				{Name: "budget_ms", Type: "integer", Doc: "the budget's size"},
				{Name: "elapsed_ms", Type: "integer", Doc: "how long the run lasted, or had been idle"},
				agentField(),
			}},
		{Type: TypeResourceSummary, Source: SourceHost,
			Doc: "the usage receipt, written once at teardown from host-side counters",
			Fields: []Field{
				{Name: "cpu_seconds", Type: "number", Doc: "CPU time consumed"},
				{Name: "peak_rss_kib", Type: "integer", Doc: "peak resident size of the VMM process"},
				{Name: "net_in_bytes", Type: "integer", Doc: "read from the TAP's own counters"},
				{Name: "net_out_bytes", Type: "integer", Doc: "written, same source"},
				{Name: "disk_read_bytes", Type: "integer", Doc: "from /proc/<pid>/io"},
				{Name: "disk_write_bytes", Type: "integer", Doc: "same"},
				{Name: "mem_mib", Type: "integer", Doc: "the cap it ran under"},
				{Name: "vcpu_count", Type: "integer", Doc: "the cap it ran under"},
				{Name: "cpu_quota_percent", Type: "integer", Doc: "the cap it ran under, when one was set"},
				agentField(),
			}},
		{Type: TypeTeamMessage, Source: SourceHost,
			Doc: "one inter-agent delivery, or one that could not be made",
			Fields: []Field{
				{Name: "agent", Type: "string", Doc: "the sender"},
				{Name: "peer", Type: "string", Doc: "the addressee"},
				{Name: "kind", Type: "string", Doc: "send, ask or reply"},
				{Name: "outcome", Type: "string", Doc: "delivered, unreachable, or timeout — timeout meaning an ask nobody answered in time, never a recv that found nothing"},
				{Name: "reason", Type: "string", Doc: "mailbox_full", When: "unreachable"},
				{Name: "bytes", Type: "integer", Doc: "body size"},
				{Name: "sha256", Type: "string", Doc: "digest of the body"},
				{Name: "data", Type: "string", Doc: "the body itself, as text — not base64, though the wire that carried it was (docs/protocol.md §5.6)", When: "record_payloads = true"},
			}},
		{Type: TypeTeamRefused, Source: SourceHost,
			Doc: "a message the edge list did not permit — its own type, because it is the interesting one",
			Fields: []Field{
				{Name: "agent", Type: "string", Doc: "the sender"},
				{Name: "peer", Type: "string", Doc: "the addressee it was not allowed to reach; absent on a reply refused for its correlation, which never named one", When: "the refusal had an addressee"},
				{Name: "kind", Type: "string", Doc: "send, ask or reply"},
				{Name: "outcome", Type: "string", Doc: "refused"},
				{Name: "reason", Type: "string", Doc: "no_edge, no_such_agent, missing_correlation, unknown_correlation"},
				{Name: "bytes", Type: "integer", Doc: "body size; zero for a refusal that carried no body, such as a reply to an unknown correlation"},
				{Name: "sha256", Type: "string", Doc: "digest of the body"},
				{Name: "data", Type: "string", Doc: "the body itself, as text — a refused message is captured like a delivered one", When: "record_payloads = true"},
			}},
		{Type: TypeTeamStore, Source: SourceHost,
			Doc: "one store access, permitted or not",
			Fields: []Field{
				{Name: "agent", Type: "string", Doc: "the caller"},
				{Name: "peer", Type: "string", Doc: "the key — a store access addresses a key, not an agent"},
				{Name: "kind", Type: "string", Doc: "get or put"},
				{Name: "outcome", Type: "string", Doc: "delivered or refused"},
				{Name: "reason", Type: "string", Doc: "denied, no_such_key, value_too_large, store_full", When: "refused"},
				{Name: "bytes", Type: "integer", Doc: "value size"},
			}},
		{Type: TypeTeamSpawn, Source: SourceHost,
			Doc: "a worker created or retired at runtime, or a request that the budget refused",
			Fields: []Field{
				{Name: "agent", Type: "string", Doc: "the spawner"},
				{Name: "peer", Type: "string", Doc: "the worker's name"},
				{Name: "kind", Type: "string", Doc: "spawn or despawn"},
				{Name: "outcome", Type: "string", Doc: "delivered or refused"},
				{Name: "reason", Type: "string", Doc: "no_spawn_budget, budget_exhausted, image_not_permitted", When: "refused"},
			}},
		{Type: TypeMCPHostCall, Source: SourceHost,
			Doc: "an outside MCP client asked kelyfos serve-mcp for a tool. These live in the " +
				"server's own session rather than in a sandbox's, because the calls that matter " +
				"most — the one that chose a machine's limits, and the ones that were refused — " +
				"belong to no sandbox at the moment they are made",
			Fields: []Field{
				{Name: "call", Type: "string", Doc: "correlates this call with its result"},
				{Name: "name", Type: "string", Doc: "the tool asked for"},
				{Name: "agent", Type: "string", Doc: "the sandbox the call names", When: "it names one"},
				{Name: "args", Type: "string", Doc: "the arguments, with anything carrying content replaced by its size"},
			}},
		{Type: TypeMCPHostResult, Source: SourceHost,
			Doc: "what that call came back with. A refused call is recorded exactly like a " +
				"permitted one — a policy ceiling nobody can see being enforced is a ceiling " +
				"nobody can audit",
			Fields: []Field{
				{Name: "call", Type: "string", Doc: "the call this answers"},
				{Name: "name", Type: "string", Doc: "the tool"},
				{Name: "agent", Type: "string", Doc: "the sandbox, including one this call created", When: "there is one"},
				{Name: "outcome", Type: "string", Doc: "ok or error"},
				{Name: "duration_ms", Type: "integer", Doc: "how long the call took"},
				{Name: "error", Type: "object", Doc: "kind and message", When: "the outcome is error"},
			}},
		{Type: TypePluginCall, Source: SourceGuest,
			Doc: "an agent called a tool belonging to a plugin running inside the guest. The " +
				"supervisor reports it and the host writes it, for the reason resource.oom is " +
				"reported the same way: the guest knows what happened and is not trusted to " +
				"record it",
			Fields: []Field{
				{Name: "name", Type: "string", Doc: "the plugin, as the policy file declared it"},
				{Name: "tool", Type: "string", Doc: "the plugin's own name for the tool, without the prefix"},
				{Name: "outcome", Type: "string", Doc: "ok or error"},
				{Name: "duration_ms", Type: "integer", Doc: "how long the plugin took"},
			}},
		{Type: TypePluginCrash, Source: SourceGuest,
			Doc: "a plugin's process ended. Its tools fail from then on and say so; the sandbox, " +
				"the other plugins and the supervisor are untouched. A plugin that died silently " +
				"and took its tools with it would otherwise look identical to one that never had " +
				"those tools",
			Fields: []Field{
				{Name: "name", Type: "string", Doc: "the plugin"},
				{Name: "reason", Type: "string", Doc: "what it exited with"},
			}},
	}
}

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
				{Name: "jailed", Type: "boolean", Doc: "whether the VMM ran inside the jailer — a chroot, a dropped uid, and only the devices it needs", When: "kelyfos run; every other entry point carries the posture on session.ready instead"},
				{Name: "cwd", Type: "string", Doc: "the directory it was launched from, which argv alone does not capture", When: "kelyfos run"},
				{Name: "reason", Type: "string", Doc: "where the machine came from", When: "restore, fork, the E2B shim, a serve-mcp server's own session, and anything raised through that server; kelyfos run and a plain team up record none"},
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
				{Name: "jailed", Type: "boolean", Doc: "whether the VMM ran inside the jailer — a chroot, a dropped uid, and only the devices it needs", When: "every path that opens a machine"},
				{Name: "profile", Type: "string", Doc: "what the guest's supervisor confined everything it spawned with: the flavor, the writable trees, the count of refused syscalls. Absent means no confinement — a machine restored from a snapshot taken before v0.9 has none, because restoring does not upgrade the guest inside it", When: "the guest reports one, which is every machine from v0.9"},
				agentField(),
			}},
		{Type: TypeSessionEnd, Source: SourceHost,
			Doc: "closes the file",
			Fields: []Field{
				{Name: "reason", Type: "string", Doc: "shutdown, interrupted, vm_exited, command_exited, timeout, error"},
				{Name: "duration_ms", Type: "integer", Doc: "session length"},
				{Name: "code", Type: "integer", Doc: "what kelyfos exited with, after the OOM adjustment", When: "kelyfos run knows"},
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
			Doc: "a bound credential was attached to a request and left the machine — by name, never by value",
			Fields: []Field{
				{Name: "name", Type: "string", Doc: "the secret's environment-variable name"},
				{Name: "host", Type: "string", Doc: "the domain it was attached for"},
				agentField(),
			}},
		{Type: TypeSecretWithheld, Source: SourceHost,
			Doc: "a credential was bound to this domain and deliberately not attached to a request. " +
				"The counterpart of secret.use, and the more useful of the two when something is wrong: " +
				"a credential that silently does not attach sends the request out unauthenticated, and " +
				"the only symptom is a failure from somewhere else",
			Fields: []Field{
				{Name: "name", Type: "string", Doc: "the secret's environment-variable name"},
				{Name: "host", Type: "string", Doc: "the domain the connection was bound to"},
				{Name: "reason", Type: "string", Doc: "why it was withheld: host_mismatch (the request " +
					"addressed a different host than the connection was opened to), path_not_covered " +
					"(outside the endpoint the credential is bound to), path_not_literal (a path carrying " +
					"an encoded slash or dot, or dot segments, which a server may re-segment into somewhere " +
					"else), or not_encrypted (a plaintext request, which never carries a credential)"},
				agentField(),
			}},
		{Type: TypeSecretScrubbed, Source: SourceHost,
			Doc: "a response echoed a bound credential back and the proxy replaced it before the " +
				"guest saw it. Recorded because a proxy that rewrites a byte stream and says nothing " +
				"is a proxy whose record understates what the host did",
			Fields: []Field{
				{Name: "name", Type: "string", Doc: "the secret's environment-variable name"},
				{Name: "host", Type: "string", Doc: "the domain whose response carried it back"},
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
				{Name: "kind", Type: "string", Doc: "get, put or delete — a delete is a put of nothing, and is its own word because the record has to show the store being made smaller"},
				{Name: "outcome", Type: "string", Doc: "delivered or refused"},
				{Name: "reason", Type: "string", Doc: "denied, no_such_key, value_too_large, key_too_long, too_many_keys, store_full", When: "refused"},
				{Name: "bytes", Type: "integer", Doc: "value size"},
			}},
		{Type: TypeTeamSpawn, Source: SourceHost,
			Doc: "a worker created or retired at runtime, or a request that the budget refused",
			Fields: []Field{
				{Name: "agent", Type: "string", Doc: "the spawner"},
				{Name: "peer", Type: "string", Doc: "the worker's name"},
				{Name: "kind", Type: "string", Doc: "spawn or despawn"},
				{Name: "outcome", Type: "string", Doc: "delivered or refused"},
				{Name: "reason", Type: "string", Doc: "on a refused spawn: no_spawn_budget, budget_exhausted, image_not_permitted, name_taken; on a refused despawn: not_a_spawned_worker", When: "refused"},
			}},
		{Type: TypeSessionPause, Source: SourceHost,
			Doc: "the machine was frozen under a name and stopped. The chain is not closed by it: " +
				"this is the same session, and closing it would make a machine that is coming " +
				"back look finished",
			Fields: []Field{
				{Name: "name", Type: "string", Doc: "the name it was stored under"},
				{Name: "duration_ms", Type: "integer", Doc: "how long the freeze took"},
			}},
		{Type: TypeSessionResume, Source: SourceHost,
			Doc: "a paused session was brought back",
			Fields: []Field{
				{Name: "name", Type: "string", Doc: "the session's name"},
				{Name: "boot_ms", Type: "integer", Doc: "how long the restore took, through the resync round trip"},
				{Name: "reason", Type: "string", Doc: "what differed between the frozen policy and the one in force", When: "they differ"},
			}},
		{Type: TypeShellStart, Source: SourceHost,
			Doc: "an interactive shell was opened in this sandbox. What was typed and shown is " +
				"NOT here: a shell is where somebody pastes a token to test something, and " +
				"recording that by default would make the honest thing the risky thing (F-D8)",
			Fields: []Field{
				{Name: "path", Type: "string", Doc: "where the terminal stream is being written", When: "--transcript was given"},
				{Name: "agent", Type: "string", Doc: "which team member's sandbox", When: "in a team"},
			}},
		{Type: TypeShellEnd, Source: SourceHost,
			Doc: "that shell ended, with what it exited with and how long it lasted",
			Fields: []Field{
				{Name: "code", Type: "integer", Doc: "the shell's exit status"},
				{Name: "signal", Type: "string", Doc: "the signal that ended it", When: "it was signalled"},
				{Name: "duration_ms", Type: "integer", Doc: "how long the shell was open"},
				{Name: "reason", Type: "string", Doc: "why it could not be opened", When: "it failed"},
				{Name: "agent", Type: "string", Doc: "which team member's sandbox", When: "in a team"},
			}},
		{Type: TypeForwardAccept, Source: SourceHost,
			Doc: "somebody connected to a forwarded port. The connection is carried over vsock " +
				"to the guest's own loopback, so nothing crossed the TAP and the firewall is " +
				"the same with a forward as without one (F-D7)",
			Fields: []Field{
				{Name: "port", Type: "integer", Doc: "the host port the connection arrived on"},
				{Name: "guest_port", Type: "integer", Doc: "the guest-local port it was carried to"},
				{Name: "peer", Type: "string", Doc: "who connected, as address:port"},
				{Name: "reason", Type: "string", Doc: "why it could not be carried", When: "the guest refused it"},
				{Name: "agent", Type: "string", Doc: "which team member's sandbox", When: "in a team"},
			}},
		{Type: TypeRunReview, Source: SourceHost,
			Doc: "somebody was shown what a sandbox did to a workspace and decided whether to " +
				"write it back. A declined review is recorded exactly like an accepted one: a " +
				"transcript that held only the accepted ones would be a record of agreement",
			Fields: []Field{
				{Name: "outcome", Type: "string", Doc: "accepted, declined, no_terminal, or no_manifest"},
				{Name: "path", Type: "string", Doc: "where the results went, or would have gone"},
				{Name: "added", Type: "integer", Doc: "files added"},
				{Name: "modified", Type: "integer", Doc: "files modified"},
				{Name: "deleted", Type: "integer", Doc: "files deleted"},
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
				{Name: "args", Type: "string", Doc: "the arguments, with anything carrying content replaced by its size"},
				{Name: "agent", Type: "string", Doc: "which member's plugin it was", When: "in a team"},
			}},
		{Type: TypePluginCrash, Source: SourceGuest,
			Doc: "a plugin's process ended. Its tools fail from then on and say so; the sandbox, " +
				"the other plugins and the supervisor are untouched. A plugin that died silently " +
				"and took its tools with it would otherwise look identical to one that never had " +
				"those tools",
			Fields: []Field{
				{Name: "name", Type: "string", Doc: "the plugin"},
				{Name: "reason", Type: "string", Doc: "what it exited with, or why it never started"},
				{Name: "agent", Type: "string", Doc: "which member's plugin it was", When: "in a team"},
			}},
	}
}

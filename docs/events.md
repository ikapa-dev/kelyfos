# KelyfOS flight recorder — event schema

**Status:** normative for `v: 1`. Written at task P2-4. The viewers in P3-8 and
P3-9 are built on this contract; the schema is the product and the viewers are
replaceable, so this document changes far more slowly than they do.

A session's flight recorder is a single append-only file of newline-delimited
JSON — one event per line, in the order the host observed them:

```
~/.cache/kelyfos/sessions/<sandbox-id>/events.jsonl
```

It lives outside the sandbox's run directory on purpose. The run directory is
deleted when the sandbox stops; the record of what happened must outlive the
thing it describes.

---

## 1. Why the host writes it

Every event is recorded by the **host**, never by the guest. That is not a
convenience — it is the whole basis for trusting the file. The guest runs
whatever an agent decides to run; a guest that could write its own audit trail
could also write a flattering one. The host sees enough to be useful without
asking: it launches the VM, it bridges MCP, and from P2-5 it is the only route
to the network.

The guest may *report* things on its events channel (`docs/protocol.md` §5.5),
and those arrive as events with `"source": "guest"`. They are still written by
the host, and a reader should weigh them accordingly.

## 2. Tamper evidence

Each event carries the hash of the one before it, so the file is a chain:

- `prev` — the `hash` of the previous event, or `""` for the first;
- `hash` — `sha256(canonical(event without its own hash field))`, hex-encoded.

Canonical form is the event serialized as JSON with `hash` set to the empty
string and empty optional fields omitted. Field order is the declaration order
of the `recorder.Event` struct in `internal/recorder/recorder.go`, which is
where an independent implementation must take it from: §3 pins the eight common
fields, and the type-specific fields that follow are in struct order rather than
in the order the tables below happen to list them.

**Verification does not re-serialize.** It recomputes the digest from the line
as written, with the value of `hash` replaced by `""` in place. For a chain this
build wrote, that is the same preimage — `hash` carries no `omitempty`, so
blanking it in the text is exactly what the writer hashed. The two differ for a
chain written by a build with a field this one does not know: re-serializing
would drop that field before re-hashing and report a legitimate record as
modified. Working from the bytes is what makes §3's "adding a field is not
breaking" true, and it was not true until v1.0.

`hash` is **mandatory and never empty**. Every line a recorder writes carries 64
hex characters there, and a verifier refuses a line that does not — otherwise the
cheapest forgery there is, a chain somebody typed with `"hash":""` on every line,
would verify: the digest of a line with an empty hash is empty, and an empty
digest matches an empty hash. That was true here until v1.0.

This makes the log **tamper-evident, not tamper-proof**. Anyone who can write
the file can rewrite it end to end and recompute every hash. What the chain
buys is that a *selective* edit — deleting one blocked-egress event, softening
one command — breaks the chain at the point of the edit, which is exactly the
edit someone covering their tracks wants to make: a deleted line leaves `seq`
disagreeing with its line number, and a re-hashed line leaves the next event's
`prev` disagreeing with it. `kelyfos log --verify` reports the first sequence
number where the chain breaks.

**A reader can run this themselves, on a file you send them.** `kelyfos log
--export` embeds the record in the report it writes, so `kelyfos verify
<report.html>` re-runs the chain over the record the page carries — offline,
with no key, no network and no trust root. §5 has the shape of it. Signing,
which turns "this record is internally consistent" into "and it was exported by
the holder of this key", is `kelyfos log --export --sign-key <key>`.

**The key is yours.** An ed25519 private key in PEM PKCS#8 — what
`openssl genpkey -algorithm ed25519` writes — because a signature is worth
exactly what knowing the key is worth, and a key this product minted for the
occasion would be worth nothing. A per-run ephemeral key was considered and
refused: it proves one process made both halves, which the chain already proves,
and a page saying "signed" beside a key nobody has ever seen invites a reader to
stop asking.

**What is signed is the record, not the page** — the chain head and a digest of
the embedded events. The page carries a generation timestamp, so signing it
would make two honest exports of one session disagree; signing the evidence means
a re-export produces the same signature.

**An unsigned report still verifies.** `kelyfos verify` reports a vocabulary
rather than a verdict: the chain intact or broken, crossed with unsigned, signed
by a key you named, or signed by a key only the file knows about. That last one
is stated carefully, because a signature whose key came out of the same file
proves only that whoever made the file had *a* key. `--key` checks it against one
you already hold, which is the only version of the question worth asking.

## 3. Common fields

Every event has these, in this order:

| Field | Type | Meaning |
| --- | --- | --- |
| `v` | integer | Schema version. `1`. |
| `seq` | integer | Position in the session, from 1, no gaps. |
| `ts` | string | RFC 3339 with milliseconds, UTC, host clock. |
| `sandbox` | string | Sandbox id this session belongs to. |
| `type` | string | Event type, from §4. |
| `source` | string | `host` or `guest`. See §1. |
| `prev` | string | Previous event's `hash`; `""` for the first. |
| `hash` | string | This event's digest. |

Type-specific fields follow, and are documented per type below. **A reader must
ignore fields it does not recognise** — adding a field is not a breaking change,
and `v` is bumped only when the meaning of an existing field changes.

That sentence was **false until v1.0**, and it is worth saying so rather than
quietly making it true. The chain's digest used to be recomputed by
re-serialising the *parsed* event, so a reader dropped any field it did not know
before re-hashing — and a chain written by a newer build came back from
`kelyfos log --verify` as `event N has been modified`. Tamper detection firing
on a legitimate record is the loudest wrong answer this product can give, and a
reader who saw it had every reason to believe their audit trail had been edited.
The digest is now recomputed from the bytes as written, so an unrecognised field
survives into the preimage and the sentence above is true. Chains written before
the fix verify unchanged: the preimage was always this line with the digest
emptied in place, so nothing about the format moved.

`sandbox` names the **session**, and a team is one session by design (E2-1), so
inside a team every event carries the team's id there rather than the id of the
machine it came from. The `agent` field is what says which machine, and inside a
team it appears on every type except `session.start`, `session.end`,
`team.topology` and `session.erasure`, which are about the team, or its whole
chain, as a whole rather than one machine in it. A reader that sees no `agent`
is looking at a single sandbox's session, or at one of those four.

A `kelyfos serve-mcp` process is a session in the same sense, and its machines
are sandboxes rather than agents: `agent` there carries the sandbox id a call
was about. It is the same question in both cases — which machine did this belong
to — which is why it is the same field and the same lane in an export (E4-4).

## 4. Event types

### `session.start`
Opens the file. Records what the sandbox is.

| Field | Type | Meaning |
| --- | --- | --- |
| `image` | string | Flavor, e.g. `base`. |
| `arch` | string | `aarch64` or `x86_64`. |
| `kelyfos` | string | CLI version. |
| `argv` | array of string | How the sandbox was launched, for reproduction. |
| `cwd` | string | The directory it was launched from, on `kelyfos run`. |
| `jailed` | boolean | Whether the VMM ran inside the jailer. On `kelyfos run` only — every other entry point carries the posture on `session.ready` instead. Present from v0.9. |
| `reason` | string | Where the machine came from, when the entry point recorded one — `kelyfos run` and a plain `kelyfos team up` record none. `forked from <snapshot>`, `restored from <name>`, `created through the E2B shim`, or a bare `serve-mcp` for a `kelyfos serve-mcp` process's own session. Raised *through* that server, the value names the session too: `created through serve-mcp session <id>`, `restored from <name> through serve-mcp session <id>`, `forked from <name> through serve-mcp session <id>`, and `raised through serve-mcp session <id>` for a team. The bare `serve-mcp` value is how `kelyfos log --list` and `kelyfos runs` tell a server's session from a machine's. |

`cwd` is there because `argv` alone does not reproduce a run: `--workspace .` is
relative, and the policy file is found by walking up from wherever the command
was typed. `kelyfos rerun` needs both, and §11 says what else it needs.

`jailed` is here rather than on `session.ready` because it is a *choice*, made
before the machine boots and knowable whether or not it ever does. The guest
profile is the opposite — an observation of a machine that is answering — so it
is on `session.ready`.

**That distinction is the rule for placing any field added to this schema**, not
just for those two:

> A fact knowable before the machine boots — a choice — may ride the event that
> opens the chain. A fact that had to be observed rides `session.ready`, because
> that is the first event that could carry it truthfully.

There is a second reason, and it is the one that decided it. `session.start`
opens one chain per *command*, and a `team up` of five agents is one chain with
five machines in it — so an opening event has no place to put five machines'
postures. `session.ready` is emitted once per machine. A field describing
*a machine* belongs there even when it could technically have been known
earlier.

### `session.ready`
The guest announced itself — or, on a restore, answered.

This is where both walls are recorded for *every* machine, and it is the only
event that can be: `session.start` opens one chain per command, and a `team up`
of five agents is one chain with five machines in it. `session.ready` is emitted
once per machine on `run`, `fork`, `snapshot restore`, `team up`, `serve-mcp`
and the shim. `kelyfos resume` is the exception: it appends `session.resume` to
the chain the machine was paused from and no second `session.ready`, so the
walls in that chain are the ones recorded before the pause.

**An absent `profile` is a fact, not a gap.** A machine restored from a snapshot
taken before v0.9 has a supervisor with no confinement in it, because restoring
a snapshot does not upgrade the guest inside it; the restore says so on the
terminal as well. The host walls — the jailer, the VMM's own syscall filter, the
egress policy, the cgroup — are unchanged by the age of a snapshot, which is why
such a restore is warned about rather than refused (D32).

| Field | Type | Meaning |
| --- | --- | --- |
| `boot_ms` | integer | Host-measured boot-to-ready. |
| `kernel` | string | Guest kernel release. |
| `supervisor` | string | Supervisor version. |
| `jailed` | boolean | Whether the VMM ran inside the jailer. Present from v0.9. |
| `profile` | string | What the guest's supervisor confines everything it spawns with: the flavor, the writable trees, how many syscalls it refuses. **Absent means unconfined.** |
| `agent` | string | Present inside a team: one of these per member. |
| `image` | string | Present inside a team: this member's flavor. |
| `via` | string | Present inside a team: `cold` or `fork` — how this member was started (F-D19). |
| `overlay` | boolean | Whether the writable overlay came up. |

### `session.end`
Closes the file.

| Field | Type | Meaning |
| --- | --- | --- |
| `reason` | string | `shutdown`, `interrupted`, `vm_exited`, `command_exited`, `timeout`, `error` — or `recorder failed at seq N: <error>`, which the recorder writes for itself; see below. |
| `duration_ms` | integer | Session length. |
| `code` | integer | What `kelyfos` exited with, when `kelyfos run` knows — after the OOM adjustment, so it is what the shell saw. |

`command_exited` is the `kelyfos run [flags] -- <command>` form (D23): the
sandbox's lifetime was that command's, and the command finished.

**The recorder fails closed.** An append can fail — the disk fills, or the
file is damaged and no longer parses — and until v1.1 that error was returned
to callers who discarded it: the sandbox went on running commands and making
egress while nothing was being recorded. The chain that came out of it
*verified*, because a refused append rolls its sequence number back and leaves
the previous hash alone, so the events written afterwards chain onto the ones
before the hole as though the hole were not there. Nothing distinguished that
record from a session in which the lost commands were never run (F13).

Now the first failure is final. No further event is recorded through that
recorder, and the run loop is told: the machine is brought down rather than
left running unrecorded. The recorder then writes one last `session.end` of
its own, with `reason` = `recorder failed at seq N: <error>` — `N` being the
sequence number of the event that could not be written, and `<error>` the
underlying failure, bounded to 160 bytes. When that line does reach the chain
it takes `N` as its own `seq`, so the chain has no gap: seq `N` is the place
where the lost event would have been, and what is there instead says so.

That line is the difference between a chain that stops for no stated reason
and one that says why it stops: without it, a truncated record and a session
that is still open are indistinguishable (§5). It is best effort in both
directions — a disk with no room for the lost event usually has none for this
either, and a chain that no longer parses cannot be appended to at all — so a
record that simply stops, with no `session.end` anywhere, remains a shape a
reader must be ready for.

### `command.start`
A command was submitted, before it runs.

| Field | Type | Meaning |
| --- | --- | --- |
| `call` | string | Correlates the start, output and exit of one command. |
| `cmd` | array of string | The argv actually sent. A shell wrapper is visible here because it changes what the command can do. |
| `cwd` | string | Working directory, if set. |
| `via` | string | Which door asked: `exec` (the CLI), `mcp` (a guest tool call), or `serve-mcp` (an outside MCP client). |
| `agent` | string | Present inside a team: which member ran it. |

### `command.output`
A chunk of output, in the order it was observed.

| Field | Type | Meaning |
| --- | --- | --- |
| `call` | string | The command this belongs to. |
| `stream` | string | `stdout` or `stderr`. |
| `data` | string | base64 of the raw bytes. |
| `bytes` | integer | Decoded length, so a reader can size a session without decoding. |
| `agent` | string | Present inside a team: which member produced it. |

### `command.exit`
One per `command.start`, when the guest returns an exit frame. If the supervisor
closes the connection without one, or sends a stream name the host does not
know, `kelyfos exec` reports the error and appends no `command.exit` — whatever
output had already arrived is still flushed to the chain, so a reader pairing
the two finds a `command.start` and its output with no exit, and has to handle
the gap.

| Field | Type | Meaning |
| --- | --- | --- |
| `call` | string | The command this belongs to. |
| `code` | integer | Exit status; `-1` when the command could not be run. |
| `signal` | string | Signal name, if one killed it. |
| `error` | object | `{kind, message}` when the command could not be run or was cut short. |
| `duration_ms` | integer | Wall-clock time. |
| `agent` | string | Present inside a team: which member ran it. |

### `file.write`
A file was written through a tool. The **content is not recorded** — a flight
recorder that copies every byte an agent writes is a second copy of the
workspace, and a much worse place to leave it.

**`write_file` and `upload` are recorded after the guest has answered**, on
every door. They used to be recorded from the *request*, so a write the guest
refused — a path outside the profile's writable trees, a body over the per-call
limit — went into the chain looking like one that happened, with a path, a size
and a digest of content that was never stored. The `serve-mcp` and `shim` doors
always got this right and `kelyfos mcp` now matches them: a refused write is not
a write, and recording one would put a line in the log for a file that does not
exist.

| Field | Type | Meaning |
| --- | --- | --- |
| `path` | string | Path inside the guest. |
| `bytes` | integer | Size written. |
| `sha256` | string | Digest of the content, so a later claim about what was written can be checked. |
| `via` | string | Which door the write came through: `write_file` or `upload` for a guest MCP tool, `serve-mcp` for an outside MCP client, `shim` for the E2B surface. |
| `agent` | string | Present inside a team: which member wrote it. |

### `egress.attempt`
One outbound connection attempt. Written from P2-5.

| Field | Type | Meaning |
| --- | --- | --- |
| `host` | string | Requested host. |
| `port` | integer | Requested port. |
| `allowed` | boolean | Whether policy permitted it. |
| `reason` | string | Why it did not go through. See below. |
| `mode` | string | How much the proxy could read: `tunnelled` (a `CONNECT` it relayed unopened), `terminated` (a secret-bound domain it decrypted), `plain` (ordinary HTTP, which it necessarily read in full), or `direct_tls` (an absolute-form `https://` request sent straight to the proxy with no `CONNECT`, fetched over a real TLS connection the proxy performed itself). **Required whenever `allowed` is true.** |
| `bytes_in`, `bytes_out` | integer | Transferred, when the connection closed. |
| `agent` | string | Present inside a team: which agent's proxy this was. |

`reason` is one of five, and only the first is a policy refusal:

| `reason` | Meaning |
| --- | --- |
| `not_in_allowlist` | The host is not permitted by this sandbox's `--allow`. |
| `port_not_allowed` | Permitted host, but not port 80 or 443. |
| `bad_request` | The proxy could not parse the request or its target, or could not mint a certificate for a secret-bound domain. `host` and `port` may be absent. |
| `upstream_unreachable` | Policy allowed it and the dial failed. |
| `tls_pinning_rejected_our_ca` | A secret-bound domain was terminated and the TLS handshake with the guest failed. Pinning is the common cause and the one worth naming — a pinned client refusing the run's CA is behaving correctly — but any handshake failure on a terminated domain lands here (`docs/networking.md` §6). |

`mode` exists because of decision D6, and answers exactly one question: how much
of this connection could the host read? `tunnelled` means nothing — a `CONNECT`
relayed unopened. `terminated` means everything, because a secret is bound to the
domain and the session was decrypted to attach it. `plain` also means
everything, because an ordinary HTTP request is parsed and re-issued by any
proxy that forwards it. `direct_tls` means everything too, and for a reason
`plain` cannot claim: a client can send an absolute-form request naming an
`https://` target straight to this proxy without ever sending a `CONNECT`, and
the proxy fetches it anyway, over a genuine, certificate-validated TLS
connection to the origin. Recording that as `plain` would say "nothing was
encrypted" about a request where something plainly was — the same
understatement `plain` itself was added to fix (F-D33), the other way round.
Four values rather than three, so that a reader looking for what the proxy saw
— and for whether a leg of the connection was actually encrypted — cannot be
misled by a word (`docs/networking.md` §6).

### `secret.use`
A credential was attached to a request **and left the machine**. Written from
P2-6.

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | Secret name, e.g. `GITHUB_TOKEN`. |
| `host` | string | Where it was sent — the domain the connection was opened and verified against, which is also the one the credential is bound to. |
| `agent` | string | Present inside a team: whose credential it was. |

The event is owed to the credential having left, not to an answer coming back.
A peer that reads the request and then resets the connection **has** the token,
so that is written down; a dial, DNS or TLS failure that never put a byte on the
wire is not. What separates them is whether the `Authorization` line was written
to the connection, which is a thing the proxy can observe rather than infer.

**The value is never recorded, in any field, in any form** — not truncated, not
hashed. A hash of a short credential is a credential. The whole point of
injecting at the proxy is that the value exists in one place; writing it to an
audit log would put it in two.

### `secret.withheld`
A credential was bound to this domain and deliberately **not** attached to a
request. Written from P6-4.

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | The secret's environment-variable name. |
| `host` | string | The domain the connection was opened and verified against. |
| `reason` | string | Why it was withheld. |
| `agent` | string | Present inside a team: whose credential it was. |

This is the counterpart of `secret.use`, and it is the more useful of the two
when something is wrong. A credential that silently does not attach sends the
request out unauthenticated, and the only symptom is a failure from somewhere
else — a 401 from a server that has no idea why. That failure mode has now been
found four separate times in this codebase, so it gets an event rather than a
comment.

`reason` is one of five:

| `reason` | Meaning |
| --- | --- |
| `host_mismatch` | The request addressed a different host than the connection was opened to. |
| `path_not_covered` | The credential is bound to an endpoint and the request was outside it. |
| `path_not_literal` | The path carried an encoded slash or dot, or dot segments — forms a server may re-segment into somewhere else, so it is not compared. |
| `not_encrypted` | A plaintext request. A credential is only ever attached on the terminated path. |
| `not_via_connect` | An absolute-form `https://` request reached the proxy directly, without a `CONNECT` — genuinely TLS-protected (`mode: direct_tls`), but credential injection is wired only into the `CONNECT`-and-terminate path, so nothing attaches it here either. |

**`host_mismatch` is worth understanding**, because it was a defect rather than
a rule. Inside a terminated session the guest writes its own `Host:` header, and
Go prefers that header over the connection's target when it writes the request
upstream. So a guest could open a tunnel to a domain a credential was bound to,
receive that domain's certificate, and then address the credentialed request to
any other name it chose. On a virtual-hosted or shared-edge origin that routes
on `Host`, the bound credential would be presented to a different site — and the
record named the target of the tunnel, so it said the wrong thing too. The
credential is now withheld, and the request itself still goes: `allow` decides
what may leave, and this decides only what a credential may be spent on.

**The value is never recorded here either** — and neither is the request path.
A path is a credential on more APIs than is comfortable
(`api.telegram.org/bot<TOKEN>/…` is the plainest example), and this record is
append-only, outlives the sandbox and is meant to be forwardable. What it says
is which secret, which domain, and why not.

### `secret.scrubbed`
A response echoed a bound credential back, and the proxy replaced it before the
guest saw it. Written from P6-5.

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | The secret's environment-variable name. |
| `host` | string | The domain whose response carried it back. |
| `agent` | string | Present inside a team: whose credential it was. |

One event per credential per *response*, not one per occurrence: a response that
quotes a token forty times is one fact. The scope is the response and not the
connection because the de-duplication is built fresh for every response the
proxy handles, and a terminated connection handles many — so a keep-alive
connection whose five responses each echo the same token produces five events,
which is the honest count: each one is a separate echo, not a repeat of the
first.

It is recorded because a proxy that rewrites a byte stream and says nothing is a
proxy whose record understates what the host did — the same reasoning that made
`mode` say how much of a connection the proxy could *read* (F-D33). `mode`
answers "how much could it see"; this answers "did it change anything".

### `team.message` and `team.refused`
One inter-agent message, or one the edge list did not permit. Written from E2-1.

| Field | Type | Meaning |
| --- | --- | --- |
| `agent` | string | The sender's name within the team. |
| `peer` | string | The intended recipient's name. |
| `kind` | string | `send`, `ask` or `reply`. |
| `outcome` | string | `delivered`, `refused`, `unreachable` or `timeout`. |
| `bytes` | integer | Payload length. |
| `sha256` | string | Digest of the payload. |
| `data` | string | The payload itself — **only** when the team enabled capture *and* the message was delivered. |
| `reason` | string | Why: `no_edge`, `no_such_agent`, `unknown_correlation` and `missing_correlation` on a `team.refused`; `mailbox_full` on a `team.message` with `outcome: unreachable`, which is a message the edge list permitted and the recipient was not reading. |

A refusal gets its own type rather than a flag, for the same reason a blocked
egress attempt does: it is the event someone reading the log is looking for.

`data` is absent by default. A team passing customer data between agents should
be able to prove what moved without keeping a second copy of it, and the digest
lets a later claim about a message be checked either way.

These events say what happened to a message, not what will happen to it. The
recorder is not a delivery buffer: delivery is at-most-once and nothing is ever
redelivered from the log (`docs/teams.md` §8.3).

### `team.store`
One access to the team store, permitted or not. Written from E2-3.

| Field | Type | Meaning |
| --- | --- | --- |
| `agent` | string | Who asked. |
| `peer` | string | The key — the store's equivalent of the other end. |
| `kind` | string | `get`, `put` or `delete` — a `put` of an empty value. |
| `outcome` | string | `delivered` or `refused`. |
| `reason` | string | `denied`, `no_such_key`, `value_too_large`, `key_too_long`, `too_many_keys`, `store_full`. |
| `bytes` | integer | Size of the value read or written. |

Values are never recorded. The store is shared state, not a second copy of it,
and a log that mirrored every write would be exactly that.

### `team.spawn`
A worker requested at runtime by an agent with a spawn budget, granted or
refused. Written from E2-5.

| Field | Type | Meaning |
| --- | --- | --- |
| `agent` | string | The spawner — the agent that asked. Absent on a `not_a_spawned_worker` despawn, because no agent asked for it. |
| `peer` | string | The worker's name, `<spawner>-spawn-N`. Absent on a refusal the host never got as far as naming — `no_spawn_budget`, `budget_exhausted`, `image_not_permitted` — and present on the two that are *about* a name, `name_taken` and `not_a_spawned_worker`. |
| `kind` | string | `spawn` or `despawn`. |
| `outcome` | string | `delivered` or `refused`. |
| `reason` | string | On a refused `spawn`: `no_spawn_budget`, `budget_exhausted`, `image_not_permitted`, `name_taken`. On a refused `despawn`: `not_a_spawned_worker`. |

A `despawn` is written when the worker's lifetime expires or the team comes
down, so the log says how long every machine in the team existed rather than
only that one was asked for.

### `resource.summary`
The usage receipt, written once at teardown. Written from E1-7.

| Field | Type | Meaning |
| --- | --- | --- |
| `cpu_seconds` | number | Host CPU time the VMM consumed. |
| `peak_rss_kib` | integer | High-water resident set **of the VMM process**. |
| `net_in_bytes`, `net_out_bytes` | integer | Bytes across the TAP, from the guest's point of view. |
| `disk_read_bytes`, `disk_write_bytes` | integer | Bytes the VMM moved to and from host storage. |
| `vcpu_count`, `mem_mib`, `cpu_quota_percent` | integer | The caps those figures were consumed under. |
| `blocked_packets` | integer | Packets the egress firewall's drop rule counted for this sandbox. Zero both for a sandbox that blocked nothing and for one with no network interface at all — the same non-distinction the rest of this event already makes for the figures above. |
| `agent` | string | Present inside a team: whose receipt this is. A team writes **one per member** — do not sum them and call it the session's. |

Every number is read on the host, from counters the kernel keeps about the
Firecracker process and the TAP attached to it. The guest is not asked, which is
the point: a guest that could write its own receipt could write a flattering one.

`peak_rss_kib` is the Firecracker process's own high-water mark, and it is not
a share of `mem_mib`. It covers the guest's memory *and* whatever the host
cached for the block devices the guest was writing, so a session that filled a
1 GiB workspace can report a peak well above the guest's RAM cap without the
guest having exceeded anything. The two are printed side by side rather than as
a fraction for exactly that reason.

The caps are carried alongside the consumption deliberately. A receipt that says
what was used without saying what was allowed is half a receipt, and joining the
two later means trusting that nothing changed in between.

### `resource.timeout`
A time budget expired and ended the run. Written from E1-6.

| Field | Type | Meaning |
| --- | --- | --- |
| `budget` | string | `max_runtime` or `idle_timeout` — which one fired. |
| `budget_ms` | integer | The budget's size. |
| `agent` | string | Present inside a team: which agent's budget expired. |
| `elapsed_ms` | integer | How long the run actually lasted, or how long it had been idle. |

The `session.end` that follows carries `reason: "timeout"`, and `kelyfos run`
exits 124.

### `resource.oom`
The guest's OOM killer ran. Written from E1-4, and the first event type with
`"source": "guest"` — the supervisor watches `/dev/kmsg`, reports what the
kernel said, and the host writes it (§1).

| Field | Type | Meaning |
| --- | --- | --- |
| `pid` | integer | The killed process, as the guest numbered it. |
| `comm` | string | Its name, from the kernel's own line. |
| `rss_kib` | integer | Its anonymous resident set at the moment it was killed. |
| `mem_mib` | integer | The machine's RAM cap, added by the host so the pair reads without cross-referencing. |
| `agent` | string | Present inside a team: which member ran out of memory. |

`rss_kib` is `anon-rss` and deliberately not `total-vm`: address space a process
reserved and never touched says nothing about the memory that ran out.

One of these means the `mem` cap was reached. The cap is the VM's hardware and
did not need help holding — what this event adds is that hitting it is legible
instead of a process that silently vanished. `kelyfos run` exits **137** when a
session saw one and would otherwise have exited 0.

### `mcp.host.call` and `mcp.host.result`
An outside MCP client asked `kelyfos serve-mcp` for a tool, and what it got.
Written from E4-4, and the pair mirrors `command.start` / `command.exit` because
it is the same shape of fact: something was asked for, and something came back.

| Field | Type | Meaning |
| --- | --- | --- |
| `call` | string | Correlates the two. |
| `name` | string | The tool. |
| `agent` | string | The sandbox the call named, or the one its answer created. Absent when it concerns no single machine. |
| `args` | string | On `mcp.host.call`: the arguments, with `content`, `stdin` and `data` replaced by their size. |
| `outcome` | string | On `mcp.host.result`: `ok` or `error`. |
| `duration_ms` | integer | On `mcp.host.result`: how long the call took. |
| `error` | object | On `mcp.host.result`: `kind` and `message`, when the outcome is `error`. |

These live in the **server's own session**, not in the sandbox each call was
about. The calls that matter most belong to no sandbox at the moment they are
made: the one that chose a machine's limits, before the machine exists, and
every call that was refused, which never gets one. Each sandbox created through
that door names the server's session in its own `session.start`, and `serve-mcp`
prints the id to stderr when it starts, so a reader can go from either end to
the other.

**Three argument names are recorded by size rather than by value**, and the
rest by value. `content`, `stdin` and `data` are replaced by their length
**whatever shape they arrive in** — a string, an object, an array, a number —
which is the rule `file.write` follows for the same reason. Measuring only
strings was a hole rather than a policy: the same content wrapped in an object
fell through and was written whole.

Every other argument is rendered as itself, with three bounds that exist so no
one call can make a record line its own readers cannot parse: a string is cut at
120 bytes, an array's whole rendering at 1 KiB — generous because the egress
allowlist arrives as an array and is recorded nowhere else — and the joined line
at 4 KiB. That is deliberate: an argument like `mem` or `image` is the decision
worth recording, and the three that are withheld are the ones that carry a
file. The summariser walks whatever
arguments it is given rather than knowing the tools, so an argument added later
appears without anyone remembering to add it here, and one carrying content
under those three names is withheld even on a tool that does not exist yet.

Without this pair the record would say *an agent ran a command in a sandbox* and
would not say *an agent decided to create a sandbox with these limits* — and the
second is the part a reader most wants when something has gone wrong. A refused
call is recorded exactly like a permitted one: a ceiling nobody can see being
enforced is a ceiling nobody can audit.

### `shell.start` and `shell.end`
An interactive shell was opened in a sandbox, and ended. Written from E5-3.

| Field | Type | Meaning |
| --- | --- | --- |
| `path` | string | Where the terminal stream is being written, when `--transcript` was given. |
| `code` | integer | On `shell.end`: the shell's exit status. |
| `signal` | string | On `shell.end`: the signal that ended it, when it was signalled. |
| `reason` | string | On `shell.end`: why the shell could not be opened. |
| `duration_ms` | integer | On `shell.end`: how long it was open. |
| `agent` | string | Present inside a team: whose sandbox. |

**What was typed and shown is not here.** The record says a shell was opened,
for how long, and how it ended — which is what an auditor needs to know that it
happened. The contents are stored only with `--transcript`, in a file beside the
log rather than inside the chain, because a hash-chained record is for facts
about what happened and a terminal stream is an artefact.

The default is off (F-D8), and not out of squeamishness: a shell is where
somebody pastes a token to test something, or types a password into a prompt
that does not echo but does arrive as keystrokes. Recording that by default
would make the honest thing — using the shell — the risky thing.

### `forward.accept`
Somebody connected to a forwarded port. Written from E5-5.

| Field | Type | Meaning |
| --- | --- | --- |
| `port` | integer | The host port the connection arrived on. |
| `guest_port` | integer | The guest-local port it was carried to. |
| `peer` | string | Who connected, as `address:port`. |
| `reason` | string | Why it could not be carried, when the guest refused it. |
| `agent` | string | Present inside a team: whose sandbox. |

**Per connection, not per packet and not per byte.** A connection is the unit
somebody would ask about — who reached this port, and when — and a per-packet
record would bury that in a log nobody reads.

A connection that could not be carried is written with the same type and a
`reason`: the accept happened, the carry did not. The usual reason is that
nothing was listening inside the sandbox yet, which is `forward.closed` in
[`denials.md`](denials.md).

Nothing here says anything crossed the network, because nothing did. The
transport is vsock and the guest dials its own loopback, so the nftables ruleset
is identical with a forward and without one (F-D7, `networking.md` §3).

### `run.review`
Somebody was shown what a sandbox did to a workspace and decided whether to
write it back. Written from E5-2.

| Field | Type | Meaning |
| --- | --- | --- |
| `outcome` | string | `accepted`, `declined`, `no_terminal`, or `no_manifest`. |
| `path` | string | Where the results went, or would have gone. |
| `added` / `modified` / `deleted` | integer | The counts the person was shown. |

**A declined review is recorded exactly like an accepted one.** It is the one
place this product asks a person to make a judgement, and a transcript holding
only the accepted ones would be a record of agreement rather than of what
happened. `no_terminal` is the same decision made by nobody: `--review` with
nothing to ask does not sync, does not silently divert, and says both.

### `session.pause` and `session.resume`
The machine was frozen under a name and stopped, and later brought back. Written
from E5-1.

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | The name the session is stored under. |
| `duration_ms` | integer | On `session.pause`: how long the freeze took. |
| `boot_ms` | integer | On `session.resume`: how long the restore took, measured through the resync round trip — the same thing `session.ready` measures. |
| `reason` | string | On `session.resume`: what differed between the frozen policy and the one in force, when they differ. |

**A pause does not close the chain.** There is no `session.end` for it, and the
resumed machine records into the session it was paused from, so one chain covers
the whole life of the machine — work before the pause, the pause, the resume, and
work after — and `--verify` covers all of it. Closing it would make a machine
that is coming back look finished, and the resume would then be appending after
an end.

### `plugin.call` and `plugin.crash`
A tool belonging to a `[[plugin]]` running inside the guest was called, and —
separately — a plugin's process ended. Written from E4-7, and both are
`"source": "guest"` for the reason `resource.oom` is: the supervisor knows what
happened and is not trusted to record it.

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | The plugin, as the policy file declared it. Never the name the plugin announces about itself. |
| `tool` | string | On `plugin.call`: the plugin's own name for the tool, without the prefix. |
| `args` | string | On `plugin.call`: the arguments, with `content`, `stdin` and `data` replaced by their size — the same rule and the same shape as `mcp.host.call`. |
| `outcome` | string | On `plugin.call`: `ok` or `error`. |
| `duration_ms` | integer | On `plugin.call`: how long the plugin took to answer. |
| `reason` | string | On `plugin.crash`: what it exited with. |
| `agent` | string | Present inside a team: which member's plugin it was. |

A plugin that dies silently and takes its tools with it would otherwise look
identical to a plugin that never had those tools. After a crash its tools stay
advertised and fail with the reason, so the transcript and the agent agree about
what happened.

### `session.policy`
What the machine was permitted, once per machine, immediately after its
`session.ready` — never on `session.start`, because a team's `session.start`
opens one chain for several machines and this describes one
(`docs/policy-record.md` §3, written before P7-2 built it). Inside a team it
carries `agent`, the same way `session.ready` does; outside one, it carries
none. Three fields are not new: `vcpu_count`, `mem_mib` and
`cpu_quota_percent` are the same fields `resource.oom` and `resource.summary`
already carry, reused for the declared cap rather than duplicated for a
fourth spelling of it.

| Field | Type | Meaning |
| --- | --- | --- |
| `vcpu_count` | integer | Cores the guest sees. Absent when nothing declared a cap for this machine (a bare team member with no `[team.agent.resources]`, say). |
| `mem_mib` | integer | Guest RAM cap, MiB. Same absence rule. |
| `cpu_quota_percent` | integer | Host CPU time, percent of one core. Absent when uncapped. |
| `disk_bytes` | integer | Ceiling on the packed workspace image. Present whenever `disk` (or a per-agent equivalent) is declared, whether or not a workspace is actually attached to this machine — the ceiling is what was declared, not only what ended up mattering. |
| `scratch_bytes` | integer | `scratch` — tmpfs size behind the overlay. |
| `net_mbps_rx` / `net_mbps_tx` | integer | Rate caps, decimal Mbps. Absent when unthrottled. |
| `disk_iops` / `disk_mbps` | integer | Block device caps. Absent when unthrottled. |
| `max_runtime_ms` / `idle_timeout_ms` | integer | Budgets, milliseconds. Absent when unbudgeted. |
| `allow` | string array | The resolved egress allowlist. Absent when the machine has no network interface at all. |
| `ports` | integer array | Ports the allowlist actually covers — `[80, 443]` whenever there is a network, since `egress.Policy.Ports` has no caller yet (P7-4) and that pair is its own runtime default. Same absence rule as `allow`. |
| `secrets` | object array | `name`, `host` and — when the binding names one — `path`. Never a value: checked by grepping a real chain for the value and finding nothing (this section's own acceptance evidence). |
| `workspace` | string | The host directory attached at `/work`, resolved to an absolute path. Absent when no workspace is attached. |
| `plugins` | string array | Configured plugin names — nothing about their path, command or arguments. Absent on a door that does not support `[[plugin]]` for this machine (every team member, today). |
| `forwards` | string array | `"<host-port>:<guest-port>"` per `[[forward]]` entry. Absent on a door that does not support forwards for this machine (every team member and every `serve-mcp`-created machine, today). |
| `rootfs_sha256` / `kernel_sha256` | string | The image manifest's own digests (`internal/sandbox/manifest.go`). |
| `tools` | string array | The outward verbs usable against this machine: `["exec", "shell", "diff", "snapshot save", "pause"]` for a CLI-facing machine, plus `"mcp"` when it has plugins configured; `["sandbox_exec", "sandbox_read_file", "sandbox_write_file", "sandbox_stop", "sandbox_snapshot"]` for one `serve-mcp` created. |
| `parent_session` | string | The session this machine's memory image came from, when it has one — a fork or a restore, CLI or `serve-mcp`. Read from the snapshot's own metadata (`SourceSession`), which is what lets a run's history be followed across two hops the way a snapshot *name* never could. |
| `traceparent` | string | An inbound W3C `traceparent`, verbatim and unparsed. Only ever present on a `serve-mcp`-created machine, and only when the caller supplied one. |

Some caps are genuinely absent on a door that does not enforce them today
rather than omitted by policy: `kelyfos snapshot restore`, `sandbox_restore`
and `sandbox_fork` apply none of `cpu_quota`, `scratch`, the rate caps or
either budget, so `session.policy` on those three doors correctly shows none
of them — the record is honest about an enforcement gap docs/policy-record.md
§4's own research found while wiring these doors, not silent about it.

### `team.topology`
The resolved shape of a team, written once at boot — after every agent's own
`session.ready`/`session.policy` pair, so every agent's own sandbox id is
actually known (`docs/policy-record.md` §3, written before P7-3 built it).
Carries no `agent` field of its own: it describes the team, not one machine,
the same scope `session.start` and `session.end` already use for a team. A
runtime spawn's later attach and detach are already covered by `team.spawn`
(above), so nothing here needs to anticipate one — this event is the roster at
the moment the team came up, not a live view of it.

| Field | Type | Meaning |
| --- | --- | --- |
| `agents` | object array | Every resolved agent: `name`, its own `sandbox` id — the handle `kelyfos diff` and `kelyfos shell` take — and `group`, the fork-template key it was forked from. `group` is absent when the agent booted cold. |
| `edges` | string array | The resolved, expanded `"from -> to"` pairs — a star written as one line in `kelyfos.toml` becomes every pair it expands to, the same list `kelyfos team ps` already shows. |
| `store_keys` | object array | Every `[[team.store.key]]` rule: `name`, `read` and `write`. Absent when the team's store is not enabled. |
| `cpu_quota_percent` | integer | The collective slice's cap — `[team.resources] cpu_quota`. The same field `resource.oom`, `resource.summary` and `session.policy` already carry, reused here for the team-wide number rather than one machine's. Absent when `[team.resources] cpu_quota` is not set — a team can still have a shared cgroup for another reason (a per-agent or per-spawn `cpu_quota`, which needs one too) with this field absent even so. |
| `record_payloads` | boolean | Whether `[team] record_payloads` is set. Always present on this event, unlike most other fields here: `false` is distinguishable from "not a team," the same reason `jailed` and `overlay` are recorded as pointers rather than left absent. |

### `session.erasure`
Appended by `kelyfos sessions erase` (`docs/retention.md`, D61) once, as the
new last event, after every field elsewhere in the chain known to carry
guest-influenced or operator-supplied content has been replaced with a
fingerprint of what was there — its own sha256 — and the whole chain
rehashed from the first event so it still verifies. Carries no `agent`
field: it is about the chain as a whole, the same scope `session.start`,
`session.end` and `team.topology` already use.

The redacted fields are `data`, `cmd`, `argv`, `args`, `cwd`, `path`, `host`,
`peer`, `comm`, `name`, `tool`, `allow`, `workspace`, `traceparent`,
`error.message` (since v1.1 — see `docs/retention.md` §5 for why it was
exempt before, and why that was wrong), and
`store_keys[].name` — every field on `Event` known to carry guest-influenced
or operator-supplied content, walked by reflection and checked field by
field rather than trusted to a hand-maintained list (`docs/retention.md` §5
has the complete list with the reasoning for each, including which fields
are deliberately exempt and why — a session id, an agent's own declared
name, and a handful of fixed enumerations are not content and survive
unchanged).

| Field | Type | Meaning |
| --- | --- | --- |
| `reason` | string | Why — the operator-supplied `-reason` the command requires, e.g. a GDPR Article 17 request. |
| `modified` | integer | How many events had a field replaced. Not how many fields — an event with more than one redacted field still counts once. Reused from `run.review`'s own `modified`, disambiguated by `type` the same way `cpu_quota_percent` already is across four other event types. |
| `redacted_fields` | integer | How many fields were replaced, across every event — the other half of `modified`, so an auditor has a number to compare against what a redaction over this chain should have touched. An event with three redactable fields set moves `modified` by one and this by three. |
| `sha256` | string | The chain head — the previous last event's own `hash` — immediately before this rewrite began, so a reader already holding an earlier export of this chain (`kelyfos verify --extract`, or a report's own embedded record) can confirm the erased chain is its honest successor rather than a fabrication. Reused from `file.write`'s own `sha256`, the same cross-type reuse `modified` and `cpu_quota_percent` already have. |

A redacted field reads `"(erased — sha256:<64 hex chars>)"` in place of what
was there — the same in-band-note shape `clipLargestField` already uses for
a clipped one, applied to a deliberate removal instead of an accidental
oversize. For a `[]string` field the digest is computed over a
length-prefixed encoding of the elements — each element's own byte length
as a fixed 8-byte big-endian integer, followed by the element's bytes,
concatenated across the whole slice — rather than the elements simply
joined with a delimiter first: `["a b", "c"]` and `["a", "b", "c"]` used to
fingerprint identically when joined with a space, because a fixed
delimiter can appear inside an element unless something upstream forbids
it, and nothing does. Length-prefixing is injective instead of merely
unlikely to collide: the encoded bytes for one slice split back into
elements exactly one way, so two slices that are not element-for-element
identical can never encode to the same bytes. Running erase again on an
already-erased chain recognises its own placeholder shape and refuses
rather than hashing the placeholder itself — a fingerprint set by one
erasure is never overwritten by a later one.

**The rewrite is lossless, and refuses a chain it cannot understand.** An
erasure rewrites every line, and until v1.1 it did so by parsing each one into
this build's own `Event` struct and marshalling it back — which silently
dropped every member the struct did not carry. An older `kelyfos` erasing a
chain a newer one wrote deleted part of the record, the result verified, and
nothing said so. That is the failure the digest-from-the-raw-bytes rule (§5)
exists to prevent on *reads*, and erase now inherits it: each line is rewritten
member by member, so anything not being redacted — including members this build
has never heard of, at the top level or inside an object — comes out exactly as
it went in, and the digest is taken over the bytes actually written. Before any
of that, an event carrying a `v` higher than this build writes is refused
outright: a schema version it has never seen is one whose fields it cannot
classify, so it cannot know what to redact.

`session.erasure` is not necessarily the last event a reader should use to
decide whether a session's own work finished — see §5's note on
`session.end` below: a session that closed cleanly and was later erased
still has a `session.end` earlier in the chain, and `kelyfos verify` looks
for one anywhere rather than only at the very end.

---

## 5. Reading the file

- `kelyfos log` replays a session in order.
- `kelyfos log --follow`, or `-f`, streams events as they are recorded. It is
  plain text and line-oriented on purpose — the greppable sibling of
  `kelyfos watch`, which draws a screen. `kelyfos logs` is the same command
  under the name people type.
- `kelyfos log --verify` checks the chain and reports the first break. On a
  chain that verifies it prints the chain head — the number a reader quotes to
  whoever receives the export — and, for a team or a `serve-mcp` session, names
  the agents or sandboxes it covered.
- `kelyfos log --list` lists recorded sessions, newest first, marking the ones
  that hold a team (`team of N`) and the ones belonging to a `kelyfos serve-mcp`
  process (`serve-mcp, N sandbox(es)`).
- `kelyfos log --json` prints the raw events instead of a readable replay — the
  form to parse.
- `kelyfos log --export <file>.html` renders the session as one self-contained
  HTML file — no scripts, no external requests — **carrying the record it was
  rendered from**, base64 of this file, in a `<pre id="kelyfos-chain">` element
  at the foot of the page. That is what makes the export verifiable by whoever
  receives it, and it costs roughly 4/3 of the record's size on top of the page.
- `kelyfos verify <report.html>` re-runs the chain over the record a report
  carries, and prints the chain head. It takes a raw `events.jsonl` too, so the
  sender and the receiver check the same thing with the same command.
  `--extract` writes the record back out; `--json` puts it on stdout with the
  verdict on stderr, so a redirect captures the record and nothing else.

  **What it checks, exactly.** The record: every digest, and the ordering.
  And the three values the page states *about* that record — the chain head, the
  event count and the session id, each marked in the page so it can be read back
  and compared. A page that states a head the record does not support is a failed
  check, not a footnote: the head is the one number a reader is told to compare
  against a head they were given separately, and a file able to change it quietly
  would turn that instruction into a trap. A missing marker fails too, because
  every export writes all three and deleting an `id` is the neatest way to switch
  a check off.

  **What it does not check** is the page's *rendering* of the events — the
  timeline, the cards, the lane view. Those are a drawing, the list of things to
  compare in them has no end, and a partial answer would invite a reader to treat
  the rest as checked. `kelyfos verify --replay` prints the record's own account
  instead, so a reader who wants the comparison can make it.

  Without KelyfOS at all, the record comes out of a report with two lines of
  shell — the report prints them itself:

  ```
  sed -n '/<pre id="kelyfos-chain">/,/<\/pre>/p' report.html | sed '1d;$d' | base64 -d > events.jsonl
  ```

A session that is still running has no `session.end`. That is not corruption:
a reader should present the session as open rather than truncated. This is
checked by looking for a `session.end` **anywhere** in the chain, not only
as the last event — `kelyfos sessions erase` appends `session.erasure` after
it, so a session that closed perfectly cleanly and was later erased still
has its `session.end` earlier in the chain, and reads as closed rather than
possibly cut short.

A `serve-mcp` session exports the same way, with **one lane per sandbox** —
the same machinery a team's transcript uses, because it is the same question.
A call naming no sandbox spans every lane, and a refused call is drawn like a
refused message.

A `team.store` event carries `kind` `get`, `put` or — since v1.0 — `delete`,
which is what writing an empty value does. The two are one call and different
events, and a record that called both `put` would leave a reader working out
which had happened from a byte count.

A refused `team.message` never carries `data`, whatever `record_payloads` says.
The option asks for the transcript to hold what was *said*; a message the broker
rejected was said to nobody, and keeping its body let an agent with no edges fill
the host's disk with the contents of messages that reached no one. The `sha256`
is still there, which is what lets a later claim about the message be checked
without the record holding a second copy of it.

**An ask and its reply are recorded by two different agents**, and either may
reach the chain first. The asking side cannot record its `team.message` until the
send has returned — until then nobody knows whether the message was delivered or
the mailbox was full — so the answering side can wake, reply and record in
between. The `ts` field is what orders them for a reader; `seq` orders the chain,
which is not the same question. Serialising the broker so one always landed first
would be paying for tidiness with the concurrency the record exists to describe.

**A team is one session**, so `--verify` over a team session verifies the whole
team: every member's commands, messages, store accesses and egress attempts are
lines in the same chain. The verification says how many agents it covered, so a
reader can compare it against the team they declared. `--export` additionally
renders a lane per agent with the message flow drawn between them (E2-7).

Two things the chain does **not** claim, stated because the difference matters
when this is used as evidence.

It proves no line was altered, and none removed from the beginning or the middle
— a `seq` that no longer matches its line number is caught, and so is a `prev`
that no longer matches. **It does not catch a record cut short at its end.**
Truncation there breaks nothing: the chain simply stops earlier, the last event
becomes the head, and the result is byte-for-byte what a shorter session would
have produced. It is indistinguishable from a session that is still running,
which is a real and ordinary state. What tells them apart is the chain head
compared against a head obtained from somewhere else — which is why
`kelyfos log --export` prints it — or a signature, which covers the chain head
and a digest of the whole record, so a signed export cut short no longer
verifies against its own signature. `kelyfos verify` also says when a record has
no `session.end`, and says it as an observation: the chain cannot tell an open
session from a truncated one.

One case of that is now narrower rather than closed. When the truncation is the
recorder's own — the disk filled, or the file stopped parsing — it writes a
final `session.end` with `reason` = `recorder failed at seq N: <error>` and
stops (§4, `session.end`), so a reader is told rather than left to infer. That
does not help against an attacker who cut the file short; nothing here can, and
the chain head is still what answers that.

It does not prove that every agent a policy declared actually wrote one.

`--session <agent-id>` redirects to the team's record while that sandbox still
exists — once the team is down the run directory is gone, and the team session
must be found by id or with `--list`.

## 6. The record is also the history

`kelyfos runs` lists what has run on this machine, newest first, and
`kelyfos rerun <id>` runs one of them again.

**Neither of them writes anything.** There is no run database, no index file and
no history log: `runs` reads the session records that were already being
written, one pass per session over the whole of each record. That is one
decision and it has one reason — a separate index would be a thing to keep in
step, to migrate, and eventually to find out of date, while the session logs are
already written, already chained, and already the thing anyone would check. The
acceptance states it as a count: one row per session directory, no more and no
fewer.

```
$ kelyfos runs
ID        WHEN              IMAGE  EXIT  TOOK    COMMAND
fc34cacd  2026-08-23 21:57  dev    3     837ms   kelyfos run -- make test
2dbb9208  2026-08-23 21:46  dev    —     23.1s   kelyfos run --allow github.com
41e476a0  2026-08-23 21:46  —      open  —       (attached) /bin/sh -c echo hello
```

`open` is a session with no `session.end` yet, and it is deliberately not shown
as `0`: "still running" and "succeeded" are the two states a reader most needs
to tell apart. A row marked `(attached)` is a chain that begins with a command
rather than a `session.start` — a machine somebody exec'd into, whose own launch
is recorded elsewhere. It is listed rather than hidden, because it happened.

### 6.1 What makes a rerun a rerun

Three things travel with a run, and `rerun` needs all three:

| | Where it comes from |
| --- | --- |
| the command | `argv` on `session.start` |
| the directory | `cwd` on `session.start` — `--workspace .` is relative, and the policy file is found by walking up |
| the policy | a copy of `kelyfos.toml`, frozen beside the record when the run started |

The frozen copy is the part that makes the word honest. A rerun that re-read
whatever `kelyfos.toml` says now would reproduce the command and not the run,
and it would do it silently — so the policy is frozen at session start, `rerun`
passes it with `--policy`, and it prints a provenance line naming all three
before it does anything:

```
kelyfos: rerunning session fc34cacd from 2026-08-23 21:57:06
    command   kelyfos run --policy …/sessions/fc34cacd/kelyfos.toml -- make test
    directory /home/you/project
    policy    …/sessions/fc34cacd/kelyfos.toml (frozen when that run started)
```

`--print` stops there. Otherwise the process is *replaced* rather than spawned,
so the rerun is this process: one exit status, one signal target, and nothing in
between for the two to get out of step.

## 7. Conformance

| Requirement | Task |
| --- | --- |
| Events written host-side, chained, with the types in §4 | P2-4 |
| `kelyfos runs` and `rerun` read the records and write nothing | E5-6 |
| `kelyfos log`, `--follow`, `--verify` | P2-4 |
| `egress.attempt` with `mode`, `secret.use` by name | P2-5, P2-6 |
| `resource.oom` reported by the guest, written by the host | E1-4 |
| `resource.timeout` naming the budget that fired | E1-6 |
| `resource.summary` usage receipt at teardown | E1-7 |
| `team.message` and `team.refused` for every inter-agent message | E2-1 |
| `team.store` for every store access, permitted or not | E2-3 |
| `team.spawn` for every worker requested, granted or refused | E2-5 |
| One chain per team, every member's events in it carrying `agent` | E2-7 |
| `--verify` over a team, `--export` with a lane per agent | E2-7 |
| `session.ready` per team member, saying `cold` or `fork` | E2-9 |
| HTML session export built only from this file | P3-8 |
| Live TUI built only from this file | P3-9 |
| `mcp.host.call` and `mcp.host.result` for every client tool call, refused or not | E4-4 |
| `--export` of a server session with a lane per sandbox | E4-4 |
| `plugin.call` per plugin tool call, `plugin.crash` when one ends | E4-7 |
| `session.pause` and `session.resume`, one chain across a pause | E5-1 |
| `run.review` for every decision, including the declined ones | E5-2 |
| `shell.start` / `shell.end` always, contents only with `--transcript` | E5-3 |
| `forward.accept` per connection, carried or refused | E5-5 |
| The export carries its record; `kelyfos verify` re-runs the chain offline | P6-6 |
| Signed exports, verifiable offline against a key the reader holds | P6-7 |
| `session.policy` per machine, alongside `session.ready`, at every door | P7-2 |

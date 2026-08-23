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
string and every field in the order this document lists, with empty optional
fields omitted. Verification re-serializes each parsed event the same way and
recomputes the digest.

This makes the log **tamper-evident, not tamper-proof**. Anyone who can write
the file can rewrite it end to end and recompute every hash. What the chain
buys is that a *selective* edit — deleting one blocked-egress event, softening
one command — breaks every hash after it, which is exactly the edit someone
covering their tracks wants to make. `kelyfos log --verify` reports the first
sequence number where the chain breaks.

Signing, which turns tamper-evidence into something a third party can check
offline, is P4-3.

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

`sandbox` names the **session**, and a team is one session by design (E2-1), so
inside a team every event carries the team's id there rather than the id of the
machine it came from. The `agent` field is what says which machine: it started
on the team message types and now appears on every host-side event a single
agent produced — `egress.attempt`, `secret.use`, `resource.timeout`. A reader
that sees no `agent` is looking at a single sandbox's session, or at an event
about the team as a whole.

## 4. Event types

### `session.start`
Opens the file. Records what the sandbox is.

| Field | Type | Meaning |
| --- | --- | --- |
| `image` | string | Flavor, e.g. `base`. |
| `arch` | string | `aarch64` or `x86_64`. |
| `kelyfos` | string | CLI version. |
| `argv` | array of string | How the sandbox was launched, for reproduction. |

### `session.ready`
The guest announced itself.

| Field | Type | Meaning |
| --- | --- | --- |
| `boot_ms` | integer | Host-measured boot-to-ready. |
| `kernel` | string | Guest kernel release. |
| `supervisor` | string | Supervisor version. |
| `overlay` | boolean | Whether the writable overlay came up. |

### `session.end`
Closes the file.

| Field | Type | Meaning |
| --- | --- | --- |
| `reason` | string | `shutdown`, `interrupted`, `vm_exited`, `command_exited`, `timeout`, `error`. |
| `duration_ms` | integer | Session length. |

`command_exited` is the `kelyfos run [flags] -- <command>` form (D23): the
sandbox's lifetime was that command's, and the command finished.

### `command.start`
A command was submitted, before it runs.

| Field | Type | Meaning |
| --- | --- | --- |
| `call` | string | Correlates the start, output and exit of one command. |
| `cmd` | array of string | The argv actually sent. A shell wrapper is visible here because it changes what the command can do. |
| `cwd` | string | Working directory, if set. |
| `via` | string | `exec` (the CLI) or `mcp` (a tool call). |

### `command.output`
A chunk of output, in the order it was observed.

| Field | Type | Meaning |
| --- | --- | --- |
| `call` | string | The command this belongs to. |
| `stream` | string | `stdout` or `stderr`. |
| `data` | string | base64 of the raw bytes. |
| `bytes` | integer | Decoded length, so a reader can size a session without decoding. |

### `command.exit`
Exactly one per `command.start`.

| Field | Type | Meaning |
| --- | --- | --- |
| `call` | string | The command this belongs to. |
| `code` | integer | Exit status; `-1` when the command could not be run. |
| `signal` | string | Signal name, if one killed it. |
| `error` | object | `{kind, message}` when the command could not be run or was cut short. |
| `duration_ms` | integer | Wall-clock time. |

### `file.write`
A file was written through a tool. The **content is not recorded** — a flight
recorder that copies every byte an agent writes is a second copy of the
workspace, and a much worse place to leave it.

| Field | Type | Meaning |
| --- | --- | --- |
| `path` | string | Path inside the guest. |
| `bytes` | integer | Size written. |
| `sha256` | string | Digest of the content, so a later claim about what was written can be checked. |
| `via` | string | Tool name: `write_file` or `upload`. |

### `egress.attempt`
One outbound connection attempt. Written from P2-5.

| Field | Type | Meaning |
| --- | --- | --- |
| `host` | string | Requested host. |
| `port` | integer | Requested port. |
| `allowed` | boolean | Whether policy permitted it. |
| `reason` | string | Why, when blocked: `not_in_allowlist`, `dns_blocked`, `no_nic`. |
| `mode` | string | `tunnelled` or `terminated`. **Required whenever `allowed` is true.** |
| `bytes_in`, `bytes_out` | integer | Transferred, when the connection closed. |
| `agent` | string | Present inside a team: which agent's proxy this was. |

`mode` exists because of decision D6. KelyfOS terminates TLS only for domains
with a secret bound to them, and tunnels everything else; recording which
happened per connection is how a user can prove exactly which traffic the proxy
was able to read.

### `secret.use`
A credential was attached to a request. Written from P2-6.

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | Secret name, e.g. `GITHUB_TOKEN`. |
| `host` | string | Where it was sent. |
| `agent` | string | Present inside a team: whose credential it was. |

**The value is never recorded, in any field, in any form** — not truncated, not
hashed. A hash of a short credential is a credential. The whole point of
injecting at the proxy is that the value exists in one place; writing it to an
audit log would put it in two.

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
| `data` | string | The payload itself — **only** when the team enabled capture. |
| `reason` | string | Why, on a refusal: `no_edge`, `no_such_agent`, `unknown_correlation`, `mailbox_full`. |

A refusal gets its own type rather than a flag, for the same reason a blocked
egress attempt does: it is the event someone reading the log is looking for.

`data` is absent by default. A team passing customer data between agents should
be able to prove what moved without keeping a second copy of it, and the digest
lets a later claim about a message be checked either way.

These events say what happened to a message, not what will happen to it. The
recorder is not a delivery buffer: delivery is at-most-once and nothing is ever
redelivered from the log (`docs/teams.md` §6.1).

### `team.store`
One access to the team store, permitted or not. Written from E2-3.

| Field | Type | Meaning |
| --- | --- | --- |
| `agent` | string | Who asked. |
| `peer` | string | The key — the store's equivalent of the other end. |
| `kind` | string | `get` or `put`. |
| `outcome` | string | `delivered` or `refused`. |
| `reason` | string | `denied`, `no_such_key`, `value_too_large`, `store_full`. |
| `bytes` | integer | Size of the value read or written. |

Values are never recorded. The store is shared state, not a second copy of it,
and a log that mirrored every write would be exactly that.

### `team.spawn`
A worker requested at runtime by an agent with a spawn budget, granted or
refused. Written from E2-5.

| Field | Type | Meaning |
| --- | --- | --- |
| `agent` | string | The spawner — the agent that asked. |
| `peer` | string | The worker's name, `<spawner>-spawn-N`. Absent on a refusal, because there is no worker. |
| `kind` | string | `spawn` or `despawn`. |
| `outcome` | string | `delivered` or `refused`. |
| `reason` | string | `no_spawn_budget`, `budget_exhausted`, `image_not_permitted`. |

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

`rss_kib` is `anon-rss` and deliberately not `total-vm`: address space a process
reserved and never touched says nothing about the memory that ran out.

One of these means the `mem` cap was reached. The cap is the VM's hardware and
did not need help holding — what this event adds is that hitting it is legible
instead of a process that silently vanished. `kelyfos run` exits **137** when a
session saw one and would otherwise have exited 0.

---

## 5. Reading the file

- `kelyfos log` replays a session in order.
- `kelyfos log --follow` streams events as they are recorded.
- `kelyfos log --verify` checks the chain and reports the first break.

A session that is still running has no `session.end`. That is not corruption:
a reader should present the session as open rather than truncated.

## 6. Conformance

| Requirement | Task |
| --- | --- |
| Events written host-side, chained, with the types in §4 | P2-4 |
| `kelyfos log`, `--follow`, `--verify` | P2-4 |
| `egress.attempt` with `mode`, `secret.use` by name | P2-5, P2-6 |
| `resource.oom` reported by the guest, written by the host | E1-4 |
| `resource.timeout` naming the budget that fired | E1-6 |
| `resource.summary` usage receipt at teardown | E1-7 |
| `team.message` and `team.refused` for every inter-agent message | E2-1 |
| `team.store` for every store access, permitted or not | E2-3 |
| `team.spawn` for every worker requested, granted or refused | E2-5 |
| HTML session export built only from this file | P3-8 |
| Live TUI built only from this file | P3-9 |
| Signed exports verifiable offline | P4-3 |

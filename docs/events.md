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
in the order the tables below happen to list them. Verification re-serializes
each parsed event the same way and recomputes the digest.

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
machine it came from. The `agent` field is what says which machine, and inside a
team it appears on every type except `session.start` and `session.end`, which
are about the team as a whole. A reader that sees no `agent` is looking at a
single sandbox's session, or at one of those two.

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
| `jailed` | boolean | Whether the VMM ran inside the jailer. Present from v0.9. |

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
postures. `session.ready` is emitted once per machine on every path there is.
A field describing *a machine* belongs there even when it could technically have
been known earlier.

### `session.ready`
The guest announced itself — or, on a restore, answered.

This is where both walls are recorded for *every* machine, and it is the only
event that can be: `session.start` opens one chain per command, and a `team up`
of five agents is one chain with five machines in it. `session.ready` is emitted
once per machine on every path there is — `run`, `fork`, `snapshot restore`,
`resume`, `team up`, `serve-mcp` and the shim.

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
| `via` | string | Present inside a team: `cold` or `fork` — how this member was started (F-D19). |
| `overlay` | boolean | Whether the writable overlay came up. |

### `session.end`
Closes the file.

| Field | Type | Meaning |
| --- | --- | --- |
| `reason` | string | `shutdown`, `interrupted`, `vm_exited`, `command_exited`, `timeout`, `error`. |
| `duration_ms` | integer | Session length. |
| `code` | integer | What `kelyfos` exited with, when `kelyfos run` knows — after the OOM adjustment, so it is what the shell saw. |

`command_exited` is the `kelyfos run [flags] -- <command>` form (D23): the
sandbox's lifetime was that command's, and the command finished.

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
Exactly one per `command.start`.

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
| `mode` | string | How much the proxy could read: `tunnelled` (a `CONNECT` it relayed unopened), `terminated` (a secret-bound domain it decrypted), or `plain` (ordinary HTTP, which it necessarily read in full). **Required whenever `allowed` is true.** |
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
proxy that forwards it. Three values rather than two, so that a reader looking
for what the proxy saw cannot be misled by a word (`docs/networking.md` §6).

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

`reason` is, today, one value:

| `reason` | Meaning |
| --- | --- |
| `host_mismatch` | The request addressed a different host than the connection was opened to. |

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
| `reason` | string | Why, on a refusal: `no_edge`, `no_such_agent`, `unknown_correlation`, `missing_correlation`, `mailbox_full`. |

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
| `args` | string | On `mcp.host.call`: the arguments, with anything carrying content replaced by its size. |
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

**The arguments never carry content.** `content` and `stdin` are replaced by
their size, which is the rule `file.write` follows for the same reason. The
summariser walks whatever arguments it is given rather than knowing the tools,
so an argument added later appears without anyone remembering to add it here,
and one carrying content is withheld even on a tool that does not exist yet.

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
| `args` | string | On `plugin.call`: the arguments, with anything carrying content replaced by its size — the same rule and the same shape as `mcp.host.call`. |
| `outcome` | string | On `plugin.call`: `ok` or `error`. |
| `duration_ms` | integer | On `plugin.call`: how long the plugin took to answer. |
| `reason` | string | On `plugin.crash`: what it exited with. |
| `agent` | string | Present inside a team: which member's plugin it was. |

A plugin that dies silently and takes its tools with it would otherwise look
identical to a plugin that never had those tools. After a crash its tools stay
advertised and fail with the reason, so the transcript and the agent agree about
what happened.

---

## 5. Reading the file

- `kelyfos log` replays a session in order.
- `kelyfos log --follow`, or `-f`, streams events as they are recorded. It is
  plain text and line-oriented on purpose — the greppable sibling of
  `kelyfos watch`, which draws a screen. `kelyfos logs` is the same command
  under the name people type.
- `kelyfos log --verify` checks the chain and reports the first break.
- `kelyfos log --list` lists recorded sessions, newest first, marking the ones
  that hold a team (`team of N`) and the ones belonging to a `kelyfos serve-mcp`
  process (`serve-mcp, N sandbox(es)`).
- `kelyfos log --json` prints the raw events instead of a readable replay — the
  form to parse.
- `kelyfos log --export <file>.html` renders the session as one self-contained
  HTML file — no scripts, no external requests.

A session that is still running has no `session.end`. That is not corruption:
a reader should present the session as open rather than truncated.

A `serve-mcp` session exports the same way, with **one lane per sandbox** —
the same machinery a team's transcript uses, because it is the same question.
A call naming no sandbox spans every lane, and a refused call is drawn like a
refused message.

**A team is one session**, so `--verify` over a team session verifies the whole
team: every member's commands, messages, store accesses and egress attempts are
lines in the same chain. The verification says how many agents it covered, so a
reader can compare it against the team they declared. `--export` additionally
renders a lane per agent with the message flow drawn between them (E2-7).

Two things the chain does **not** claim, stated because the difference matters
when this is used as evidence. It proves no line was altered or removed after it
was written; it does not prove that every agent a policy declared actually wrote
one. And `--session <agent-id>` redirects to the team's record while that
sandbox still exists — once the team is down the run directory is gone, and the
team session must be found by id or with `--list`.

## 6. The record is also the history

`kelyfos runs` lists what has run on this machine, newest first, and
`kelyfos rerun <id>` runs one of them again.

**Neither of them writes anything.** There is no run database, no index file and
no history log: `runs` reads the session records that were already being
written, one pass per session, taking only the two events it needs. That is one
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
| Signed exports verifiable offline | P4-3 |

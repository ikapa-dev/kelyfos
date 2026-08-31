# The policy record — the shapes, before the code

*Specification for P7-2 and P7-3 (Phase 7, v1.1), written before the code. D59
settled the one irreversible question — typed fields appended to `Event`, not
JSON in a string — so this document does not reopen it. What is left to decide
is everything a typed field needs before it can be hashed: its JSON key, its Go
type, its exact position in the frozen order, which door writes it, and — the
longer half — what it deliberately does not carry. Reviewed before P7-2 touches
`internal/recorder`, the way `docs/hardening.md` was at P5-0, for the same
reason: a schema argued about after it is hashed is a migration rather than an
argument.*

*Where this document and the code disagree once P7-2/P7-3 land, the code is
wrong and this page is the thing to argue with — the same rule
`docs/hardening.md` states for itself.*

---

## 1. The gap this closes

Thirty-four settings decide what a machine can touch — eleven `[resources]`
caps, an allowlist and the ports it covers, bound credentials, a workspace, a
spawn budget, store ACLs and an edge list — and every one is enforced on each
call and then thrown away when the run stops. A finished session's own record
cannot show its caps, its allowlist, its image digest or its topology, so the
question a reviewer asks first — *what was this allowed to reach?* — has no
answer in the file that answers everything else. D59 puts the declaration in
the chain so that question is answered by the same JSONL every other question
about a run is answered by, rather than by `kelyfos.toml`, which the user can
edit afterwards, or a team's own `run/teams/<session>.json`, which does not
outlive the run.

Two additive event types carry it: `session.policy`, once per machine, and
`team.topology`, once per team. Both are new types, not new fields bolted onto
`session.start` — §3 below is why.

## 2. D59's boundary, restated so P7-2 does not re-litigate it

Typed fields on `Event`, appended at the end, never inserted. It costs about
twenty fields of struct surface across the two types and buys three things a
compact-JSON-in-a-string field cannot: `tools/gendocs` generates a reference
row for each one, `TestSchemaFieldsExist` covers each one, and a consumer
filters without parsing twice. Nothing in this document reopens that question.

## 3. Placement: `session.policy` rides `session.ready`, not `session.start`

`docs/events.md` §4's `session.start` entry already states the rule for where
a new field belongs, and it settles this document's biggest structural
question by simply already existing:

> A fact knowable before the machine boots — a choice — may ride the event
> that opens the chain. A fact that had to be observed rides `session.ready`,
> because that is the first event that could carry it truthfully.
>
> There is a second reason... `session.start` opens one chain per *command*,
> and a `team up` of five agents is one chain with five machines in it — so an
> opening event has no place to put five machines' postures. `session.ready`
> is emitted once per machine. A field describing *a machine* belongs there
> even when it could technically have been known earlier.

Every field `session.policy` carries is a choice, knowable before the machine
boots. By the first rule it could ride `session.start`. But `session.policy`
describes *a machine* — its caps, its allowlist, its secrets — and `team up`'s
chain holds several machines, so by the second rule it cannot ride the team's
one `session.start`. `jailed` resolved the same tension by riding
`session.start` on `kelyfos run` alone and `session.ready` everywhere else — an
asymmetry the field-order test has to carry as a special case. `session.policy`
does not repeat that asymmetry: **it is its own event, emitted once per
machine, immediately after that machine's `session.ready`, at all eight doors
uniformly, including `run`.** One rule for every door is what makes the
door-enumerating test in §9 a single loop rather than one case for `run` and
another for everything else.

Inside a team, `session.policy` carries `agent`, the same way `session.ready`
does; outside one, it carries none, the same way `session.ready` does.

`team.topology` is the opposite scope: agents, edges, the store and the
collective slice describe the *team*, not one machine, so it is emitted once
per chain — the same scope `session.start` and `session.end` already carry
`agent`-less, per `docs/events.md` §3. It rides once, after the last agent's
`session.ready`/`session.policy` pair, when every agent's sandbox id is
actually known (§6).

## 4. The eight doors that open a chain with a machine in it

"Opens a chain" means: appends a `session.start`. **Nine call sites do that in
the current source, not eight.** `Event.WithPosture`'s eight call sites are a
*subset* of the nine, not the same set as originally claimed here — one
`session.start` writer has no machine behind it at all, and is its own
subsection below (§4.1) rather than a ninth row in this table. The eight below
are the ones with a machine, and are the ones `session.policy` attaches to:

| # | Door | `session.start` site | `WithPosture` site |
| --- | --- | --- | --- |
| 1 | `kelyfos run` | `host/run.go:570` | `host/run.go:624` |
| 2 | `kelyfos team up` — every *declared* agent, cold or forked (**not** a runtime-spawned worker; §4.2 is a currently-real gap, not a design choice) | `host/team.go:276` (once per team) | `host/team.go:509` (once per declared agent) |
| 3 | `kelyfos fork` | `host/fork.go:161` | `host/fork.go:246` |
| 4 | `kelyfos snapshot restore` | `host/snapshot.go:189` | `host/snapshot.go:282` |
| 5 | `kelyfos shim` (the E2B-compatible surface) | `shim/shim.go:332` | `shim/shim.go:358` |
| 6 | `serve-mcp`'s `sandbox_run` tool | `host/servemcptools.go:439` | `host/servemcptools.go:470` |
| 7 | `serve-mcp`'s `sandbox_restore` tool | `host/servemcpstate.go:190` | `host/servemcpstate.go:215` |
| 8 | `serve-mcp`'s `sandbox_fork` tool | `host/servemcpstate.go:368` | `host/servemcpstate.go:401` |

This is also the set `internal/sandbox/jail.go:123`'s `requireJail` comment
names by CLI verb — "`run`, `team up`, `fork`, `snapshot restore`, `serve-mcp`
and `shim` all build a sandbox through this package" — with `serve-mcp`'s three
tool paths counted individually here because each is a separate place a
`session.policy` has to be constructed, the same way each is a separate
`WithPosture` call site today.

### 4.1 The ninth site: `serve-mcp`'s own audit chain has no machine

`host/servemcpaudit.go:92-106`'s `openAudit` mints an id, calls
`recorder.Open`, and appends `TypeSessionStart` with
`Reason: recorder.ReasonServeMCP` — a full chain by the criterion above.
`closeAudit` closes it with a `session.end`. This is the *server's own*
session, not a sandbox's: "a `kelyfos serve-mcp` process is a session in the
same sense a `kelyfos run` is" (the function's own comment), tracking
`mcp.host.call`/`.result` across every tool call the process serves, whether
or not any of them ever creates a machine. It has no `[resources]` caps, no
allowlist, no image — nothing `session.policy` describes — so it correctly
gets none.

`Reason == recorder.ReasonServeMCP` is the existing, already-relied-on marker
for telling this chain apart from a machine's: `host/log.go:164` (`kelyfos
runs`), `host/runs.go:265` (`kindOf`, labels it `"serve-mcp"` rather than a
flavor), and `internal/report/report.go:212` (the exported report shows "per
sandbox" rather than one image) all switch on it today. **The door-enumerating
test in §9.3 must use the same marker to exempt this site**, or it will fail
on the very first real `serve-mcp` session — a `session.start` this chain
legitimately writes with no `session.policy` to match.

### 4.2 A real gap this spec found, not a design choice: runtime-spawned workers get no posture at all today

`broker.OnSpawn` (`host/team.go:358-391`) is what boots a worker a *running*
agent asks for at runtime — as opposed to the declared agents door 2's table
row covers. It computes real caps (`plan.spawnResources(req.Spawner)` at
`host/team.go:363`) and calls `bootAgent` to build the machine. Checked end to
end: neither `OnSpawn` nor `bootAgent` (`host/team.go:736` onward) contains a
single `rec.Append` call. `host/team.go:507`, inside the loop over the
*initially planned* roster, is the **only** `TypeSessionReady`/`WithPosture`
site in the file — a spawned worker never reaches it. So today, a
runtime-spawned worker gets a `team.spawn` event (from the broker) and real,
enforced caps, and **no `session.ready`, no `jailed`/`profile`, and nothing
for a `session.policy` to attach to** — the exact P5-1 shape (a wall that is
in fact around a session with nothing in the record saying so) that this
whole phase exists to close, reappearing in a path P5-1 itself never reached.

This is not scoped out. **P7-2 must extend the spawn path** — `OnSpawn`/
`bootAgent` — to write `session.ready` (with `WithPosture`, closing the
existing gap) and `session.policy` (this phase's new field) for a spawned
worker, using the same `plan.spawnResources(req.Spawner)` result already
computed at the call site. `team.topology` does not need a matching change:
it is written once, at team boot (§3), and a spawned worker's later arrival
and departure are already covered by the existing `team.spawn` event D59's
own text names as sufficient ("`team.spawn` already records attach and
detach, so the graph replays over time with nothing new").

**Four things that do *not* open a chain at all, on purpose, so a future
tenth site does not get invented by accident:**

- **`kelyfos exec`** (`host/exec.go`) calls `sandbox.Load` and dials an
  already-running machine. It writes into a chain that is already open
  (`command.start`/`.output`/`.exit`) and never a `session.start`.
- **`kelyfos shell`** likewise attaches; `shell.start`/`shell.end` are the
  events it writes, into an existing chain.
- **`kelyfos resume`** calls `sandbox.Restore` — a real new VMM process — but
  writes `session.resume` into the *same* chain the machine was paused from
  (`host/sessions.go:531`), specifically so "one chain covers the whole life
  of the machine rather than one per resume." §8.4 covers why it still gets
  no `session.policy` of its own.
- **`kelyfos bench`** (`host/bench.go`) calls both `sandbox.New` and
  `sandbox.Restore` to measure boot time and never opens a recorder at all —
  no `session.start`, no chain, nothing for `session.policy` to attach to.

## 5. `session.policy` — field by field

**Three** fields are not new: `mem_mib`, `vcpu_count` and `cpu_quota_percent`
already exist on `Event` (`internal/recorder/recorder.go:150,174,175`, used
today by `resource.oom` and `resource.summary`) and carry the exact same
meaning here — the cap, not a measurement of it — so `session.policy` reuses
them rather than adding a fourth spelling of "the RAM ceiling" to the struct.
The remaining nineteen rows below are new, and their `#` column is their
**normative** position in the frozen append order — see §9.2.

| # | JSON key | Go field | Go type | Meaning | Present when |
| --- | --- | --- | --- | --- | --- |
| *(existing)* | `vcpu_count` | `VcpuCount` | `int` | `cpus` — cores the guest sees | always |
| *(existing)* | `mem_mib` | `MemMiB` | `int` | `mem` — guest RAM cap, MiB | always |
| *(existing)* | `cpu_quota_percent` | `CPUQuota` | `int` | `cpu_quota` — host CPU time, percent of one core; 0 when uncapped | always |
| 1 | `disk_bytes` | `DiskBytes` | `int64` | `disk` — ceiling on the packed workspace image | a workspace is attached |
| 2 | `scratch_bytes` | `ScratchBytes` | `int64` | `scratch` — tmpfs size behind the overlay | always |
| 3 | `net_mbps_rx` | `NetMbpsRx` | `int` | inbound rate cap, decimal Mbps; 0 when unthrottled | network is attached |
| 4 | `net_mbps_tx` | `NetMbpsTx` | `int` | outbound rate cap, same units | network is attached |
| 5 | `disk_iops` | `DiskIOPS` | `int` | block device operations/sec cap; 0 when unthrottled | always |
| 6 | `disk_mbps` | `DiskMbps` | `int` | block device bytes/sec cap; 0 when unthrottled | always |
| 7 | `max_runtime_ms` | `MaxRuntimeMS` | `int64` | wall-clock budget, milliseconds; 0 when unbudgeted | always |
| 8 | `idle_timeout_ms` | `IdleTimeoutMS` | `int64` | idle budget, milliseconds; 0 when unbudgeted | always |
| 9 | `allow` | `Allow` | `[]string` | the resolved egress allowlist | network is attached |
| 10 | `ports` | `Ports` | `[]int` | ports the allowlist actually covers — `[80, 443]` when unset and `allow` is non-empty (`egress.Policy.Ports`'s own default, P7-4) | network is attached |
| 11 | `secrets` | `Secrets` | `[]EvSecret` | bound credentials, by name, host and path scope — never a value (§8.1) | one or more are bound |
| 12 | `workspace` | `Workspace` | `string` | resolved host directory attached at `/work` | a workspace is attached |
| 13 | `plugins` | `Plugins` | `[]string` | configured plugin names (§8.2) | one or more `[[plugin]]` entries |
| 14 | `forwards` | `Forwards` | `[]string` | `"<host-port>:<guest-port>"` per `[[forward]]` entry | one or more are configured |
| 15 | `rootfs_sha256` | `RootfsSHA256` | `string` | the image manifest's `rootfs_sha256` | always |
| 16 | `kernel_sha256` | `KernelSHA256` | `string` | the image manifest's `kernel_sha256` | always |
| 17 | `tools` | `Tools` | `[]string` | the outward verbs usable against this machine (§8.3) | always |
| 18 | `parent_session` | `ParentSession` | `string` | the session id this machine was forked or restored from | fork, snapshot restore, `sandbox_restore`, `sandbox_fork` |
| 19 | `traceparent` | `Traceparent` | `string` | inbound W3C `traceparent`, verbatim, unparsed | `serve-mcp`, when the caller supplied one |

`rootfs_sha256`/`kernel_sha256` name the manifest's own JSON keys
(`internal/sandbox/manifest.go:19,21`) rather than inventing a second spelling
of "the image digest."

## 6. `team.topology` — field by field

One event, written once a team is fully up (`host/team.go`, after the loop
that appends every agent's `session.ready`/`session.policy` pair — see §3),
carrying no `agent` field, the same scope `session.start`/`session.end`
already use for a team.

`#` continues §5's normative append order (§9.2) — `team.topology`'s new
fields are appended immediately after `session.policy`'s nineteenth.

| # | JSON key | Go field | Go type | Meaning |
| --- | --- | --- | --- | --- |
| 20 | `agents` | `Agents` | `[]EvAgent` | every resolved agent: name, its own sandbox id, its fork-template group |
| 21 | `edges` | `Edges` | `[]string` | the resolved, expanded pairs — reuses the exact `"from -> to"` strings `host/teamplan.go:126,142` already computes as `plan.edgeText`, post-glob-expansion |
| 22 | `store_keys` | `StoreKeys` | `[]EvStoreKey` | every `[[team.store.key]]` rule: its name/glob, its read list, its write list |
| *(existing)* | `cpu_quota_percent` | `CPUQuota` | `int` | the collective slice's cap — `[team.resources] cpu_quota`; 0 when the team has no shared cgroup |
| 23 | `record_payloads` | `RecordPayloads` | `*bool` | whether `[team] record_payloads` is set — a pointer, like `Jailed` and `Overlay`, so `false` is distinguishable from "not a team" |

`cpu_quota_percent` is reused a second time here, on a different event type,
carrying the team-wide number rather than one machine's — the same field
already means "the cap in force" on three other types, and a chain reader
already has to read `type` to know which cap a `cpu_quota_percent` belongs to.

## 7. New nested types

Three small structs, the same shape `EvError` already established for a
struct-valued field:

```go
// EvSecret is one bound credential on a session.policy — never its value.
type EvSecret struct {
    Name string `json:"name"`
    Host string `json:"host"`
    Path string `json:"path,omitempty"`
}

// EvAgent is one resolved team member on a team.topology.
type EvAgent struct {
    Name    string `json:"name"`
    Sandbox string `json:"sandbox"`
    // Group is the fork-template key (host/teamtemplate.go's templateKey,
    // already a content hash, never a filesystem path) shared by every agent
    // forked from the same in-memory template. Empty means this agent booted
    // cold.
    Group string `json:"group,omitempty"`
}

// EvStoreKey is one [[team.store.key]] rule on a team.topology.
type EvStoreKey struct {
    Name  string   `json:"name"`
    Read  []string `json:"read,omitempty"`
    Write []string `json:"write,omitempty"`
}
```

`eachStringField` (`internal/recorder/recorder.go`) already walks a
pointed-to struct's string fields when clipping `*EvError`, so `EvSecret`
inside a `[]EvSecret` gets the same treatment for free *once the slice itself
is reachable* — which it is not, by reflection alone. §9.1 is why that matters
and what to do about it.

## 8. What this deliberately omits, and why

The longer half, as the task asks for.

### 8.1 No secret value, by any path

`Name` and `Host` mirror what `secret.use` already writes for the same
credential (`internal/recorder/schema.go:139`, `:140`). `Path` is genuinely
new — there is no existing event field it mirrors — and comes from
`egress.Secret.Scope.Path` (`internal/egress/scope.go:24-30`), the same value
`secret.withheld`'s `path_not_covered` reason already checks against.

What is deliberately absent is the value and the scheme. `egress.Secret.value`
(`internal/egress/secret.go:18`) is unexported, but it is not true that
nothing can reach it: `Header()` (`internal/egress/secret.go:22`) returns it,
prefixed with the scheme, for the one legitimate purpose — attaching it to an
outbound request. The reason it cannot end up in `session.policy` is simpler
and does not depend on Go's visibility rules holding: **`EvSecret` has no
field for it to flow into**, the same "nowhere to put it" property every other
secret-adjacent event on this schema already has. `Scheme` (`Bearer` or
`Basic`) is the one field of `egress.Secret` this document silently drops —
named here rather than left implicit, since a field that is not obviously
sensitive still deserves a stated reason: the scheme is implied by which
header shape a domain's requests carry today and is not itself part of "what
was this allowed to reach," which is the question `session.policy` answers.

A secret bound and never used still appears in `session.policy`, by name and
host, which is D59's whole point: a policy ceiling nobody can see being
enforced is a ceiling nobody can audit. It appears with no value and no
scheme, which is every other rule in this product about what a record may
hold.

### 8.2 Plugin path, command and args are not recorded

`plugins` is names only. A plugin's `path` is a host filesystem location the
same way `workspace` is — but `workspace` has a direct precedent
(`session.start`'s existing `cwd` field already records a host path, for
reproduction) and a plugin's `path`/`command`/`args` do not. Recording a
second host-filesystem detail with no existing precedent, for a feature this
phase does not otherwise touch (P7-4 is about `[[plugin]]` being silently
inert in a team, not about widening what the record holds), is deferred rather
than decided here. `kelyfos.toml` already has the full plugin declaration, on
disk, beside the record.

### 8.3 `tools` is a fixed vocabulary, not a live capability query

There is no existing "tool surface" type to reuse — this is the one field in
this document with no direct code precedent, so the choice is stated plainly
rather than implied, and checked here against every command's actual flags
rather than assumed from its name. The rule for membership: a verb belongs
only if it takes `--sandbox <id>` (or the MCP equivalent) and acts on an
*existing* machine — a verb that creates one, or that names a snapshot rather
than a sandbox, is a door (§4), not a member of a running machine's `tools`.

`tools` is drawn from two fixed lists, chosen by which kind of door created
the machine, and does not vary per policy today (nothing in `kelyfos.toml`
can currently narrow it further):

- **CLI-facing machines** (`run`, `team up`, `fork`, `snapshot restore`,
  `shim`): `["exec", "shell", "diff", "snapshot save", "pause"]`
  (`host/main.go:64-114`'s case list, checked against each subcommand's own
  flags: `exec` — `host/exec.go:26`; `shell` — `host/shell.go:34`; `diff` —
  `host/review.go:26`; `snapshot save` — `host/snapshot.go:47`; `pause` —
  `host/sessions.go:84`; all five take `--sandbox`, defaulting to "the only
  running one"), plus `"mcp"` when `[[plugin]]` is configured for that
  machine (guest-side MCP passthrough). `snapshot save` is named with its
  subcommand because `kelyfos snapshot restore` is a door (row 4), not a
  member of this list, and `snapshot` alone would not say which half is
  meant. **Not** `fork` — `kelyfos fork -name <snapshot>`
  (`host/fork.go:22`) restores *from* a snapshot; it is door 3, and takes no
  running machine's id at all. **Not** `forward` — there is no `case
  "forward"` in `host/main.go`; `[[forward]]` is a boot-time config section,
  not a verb.
- **`serve-mcp`-facing machines**: the tool names that take a sandbox id and
  act on an existing one — `["sandbox_exec", "sandbox_read_file",
  "sandbox_write_file", "sandbox_stop", "sandbox_snapshot"]`
  (`host/servemcptools.go:29-131`). **Not** `sandbox_run` or `sandbox_list`
  (create or enumerate, name no single existing machine), and — checked
  against their actual input schemas and not assumed from the name — **not**
  `sandbox_restore` or `sandbox_fork` either: both take `name`, the *snapshot*
  to restore from (`host/servemcptools.go:142`, `:159`), and return a new
  sandbox id rather than act on one. They are the MCP halves of doors 7 and 8,
  the same way `sandbox_run` is door 6's.

Recording today's fixed set makes it explicit rather than assumed, and gives
a future policy that *does* narrow it (a per-agent tool allowlist, say) a
field to write into without a schema change.

### 8.4 `resume` gets no `session.policy` of its own

`kelyfos resume` continues an existing chain under "the same memory, the same
disks, and the policy it was paused under" (`host/sessions.go:412`) —
`frozenFitsCurrent` (`host/sessions.go:462`) refuses a resume that would
exceed the ceiling in force now, so the machine's effective policy at resume
is never anything other than what its original `session.policy` already
declared. Recording a second, identical `session.policy` at every resume
would not be wrong, only redundant on every field — and `TypeSessionResume`
already carries what a reader of a resume actually wants to know: whether
`kelyfos.toml` drifted, in its existing `reason` field ("what differed
between the frozen policy and the one in force"). A resume that changed
nothing gets no new event; a resume where the file on disk moved gets the
one sentence that says so. Re-deriving the *chain's own* declared policy —
the one from `session.policy`, not the file on disk — is a `kelyfos log`
question, not a new field.

### 8.5 No per-call re-declaration

`session.policy` is written once per machine, at the door. `kelyfos exec`,
`kelyfos shell`, `kelyfos mcp` and every other command that runs *against* an
already-open machine write into the same chain without repeating any part of
its policy — the same way `session.ready`'s `jailed`/`profile` are not
repeated on every `command.start`.

### 8.6 No image provenance beyond the two digests

`rootfs_sha256` and `kernel_sha256` are what let a chain be checked against a
specific build; `Manifest`'s other fields (`buildroot`, `linux`, `built`,
human-readable `kernel`/`rootfs` filenames) describe how the image was made,
not what a sandbox was permitted, and are one `image.json` lookup away from
the two digests this document does add. Restating the whole manifest in every
`session.policy` would make the record a second copy of a file that already
exists beside the image.

### 8.7 `traceparent` is opaque

Stored as the header value, verbatim, unparsed into `trace-id`/`parent-id`/
`trace-flags`. Decomposing it is a P7-11 (OTLP export) concern if it turns
out to be one; nothing here needs the pieces, and a field that holds an
unvalidated string cannot itself be a place a malformed header breaks
`Append`.

### 8.8 No tombstone or retention field, yet

D61 (P7-5) adds a retention floor, a prune command, and an erasure path that
"writes a replacement record preserving chain integrity while keeping a
content fingerprint." Whatever field-level shape that needs is P7-5's own
decision, made when its mechanism is designed against real code, not
predicted here. This document is scoped to the two event types D59 names —
`session.policy` and `team.topology` — which is also what its filename says.
Pinning tombstone field names now, ahead of P7-5's own design pass, would
risk exactly the "migration rather than an argument" this whole document
exists to avoid, on a mechanism that has not been designed yet. P7-5 remains
free to append further fields after P7-3's, in whatever order its own design
review settles — appending is always safe (§9.2); nothing here constrains it.

## 9. What P7-2 and P7-3 must still do, in the same commit as the fields

Not this document's job to build, but its job to make sure nothing here gets
implemented forgetting the two traps the survey already found (Progress Log,
2026-08-27, the entry that opened D63):

### 9.1 Every new slice field needs `clipToBudget` extended, in the SAME commit

`eachStringField` (`internal/recorder/recorder.go`) walks `Event` by
reflection over **string-kinded fields only**. Every field this document adds
that is a slice — `Allow`, `Ports`, `Secrets`, `Plugins`, `Forwards` (§5),
`Agents`, `Edges`, `StoreKeys` (§6) — is invisible to it, the same way `Cmd`
already was before it got a hand-written entry in `clippableFields`. An
oversized one today would send
`fitUnderMaxLine`'s loop through nothing to shrink, `Append` would fail
closed, and the event vanishes from the record with no trace — the exact
failure S16 was written to prevent. `Ports` is bounded and small in practice
(a handful of integers) and unlikely to ever need clipping on its own, but it
is still, mechanically, a slice reflection does not see, and a fixture should
say so explicitly rather than leave it untested by omission. A hostile
fixture — a 64 KiB `secrets` list, a `plugins` array with a thousand
30-character names — proving each of the eight actually clips is part of
P7-2/P7-3's own done criteria, not a follow-up.

Two names in this section moved in v1.1.1 and the rule did not.
`clipLargestField` became `clipToBudget` and `largestStringField` became
`eachStringField` when P7-15 replaced "halve the largest field, up to eight
times" with "reduce every field standing above the ceiling the budget allows"
(D80); the slice list itself moved out to `clippableFields`, which is the
function a new slice field is added to. The line numbers this section used to
carry are gone rather than corrected: they had already drifted by roughly eight
hundred lines before anybody noticed, which is what a line number in prose does.

### 9.2 Field order is normative, not a proposal

The `#` column in §5 and §6 **is** the position each new field appends at —
positions 1–19 for `session.policy`, 20–23 for `team.topology`, in exactly
that sequence. This is not a suggestion P7-2 is free to resequence: this
document exists specifically so the field's actual position in the frozen
order is settled before anything is hashed, per P7-0's own task text, and the
opening premise this page states for itself — "a schema argued about after it
is hashed is a migration rather than an argument" — would be undercut by
hedging the one number that argument is about. The rule that is genuinely
load-bearing, and the one to cite when checking this later, is
**append at the end, never insert, never reorder**
(`TestTheEventFieldOrderIsFrozen`, `internal/recorder/fieldorder_test.go:28`):
P7-2 writes positions 1–19 into `Event` in that order, in the same commit that
updates the test's `want` slice, and P7-3 appends 20–23 after them. If
implementing P7-2 turns up a genuine reason to want a different sequence, that
is a deviation from this document and gets a decision-log row under §8 rule 5
before it lands — the same rule any other change of approach gets — not a
silent resequencing.

### 9.3 `schema.go`, the door-enumerating test, and `docs/events.md`

Two new `EventType` rows in `internal/recorder/schema.go` (which
`TestSchemaCoversEveryType` and `tools/gendocs` both read), and one test that
enumerates the **nine** `session.start` sites in §4 and §4.1 and asserts,
for each: a matching `session.policy` when it has a machine (the eight in
§4's table), or `Reason == recorder.ReasonServeMCP` and no `session.policy`
when it does not (§4.1's one). The test must fail when a tenth site writes
`session.start` with neither — the same shape `WithPosture` exists to
enforce, for the reason P5-1's gap (`jailed` set at one door, silent at
seven) is a landmine entry in the agent brief this document's author was
given, and the same shape that already needed correcting once in this
document (§4.1). §4.2's runtime-spawn gap is a separate assertion the same
test suite needs: a `broker.OnSpawn`-created worker (`host/team.go:358`)
must reach `session.ready`/`WithPosture`/`session.policy` the same as a
declared agent does, which today it structurally cannot, because nothing on
that path calls the recorder at all — this is code P7-2 has to add to
`OnSpawn`/`bootAgent`, not only a test.

`docs/reference/events.md` regenerates from `schema.go` automatically
(`make docs`); `docs/events.md`'s own per-type prose tables do not — they are
still hand-maintained (`docs/README.md`'s own inventory says so), so the two
new `### session.policy` / `### team.topology` sections there are a manual
edit P7-2/P7-3 has to remember, not something `make docs` supplies.

---

*Doc kind: concept, written before the code, the way `docs/hardening.md`,
`docs/qol.md` and `docs/mcp-surface.md` were before P5, E5 and E4. Once
P7-2/P7-3 land, this page's §5–§7 become the changelog for how the reference
got its shape rather than a prediction of it, and `docs/events.md` — not this
page — is where a reader goes for the fields as they actually shipped.*

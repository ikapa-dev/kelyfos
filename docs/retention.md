# Retention, pruning and erasure

*P7-5 (Phase 7, v1.1), D61. Unlike `docs/policy-record.md` this was not
written before the code — P7-0's own scope note said so explicitly: "whatever
field-level shape [retention] needs is P7-5's own decision, made when its
mechanism is designed against real code, not predicted here." This page is
that decision, recorded once the mechanism existed rather than before it.*

## 1. The gap this closes

`~/.cache/kelyfos/sessions/` holds the flight recorder's own history — every
session this machine has ever run, kept forever. The fork-template cache
next to it has a bound and sweeps itself, oldest-used first
(`host/teamtemplate.go`); the session history had neither a bound, a sweep,
nor a setting, and nothing warned when it grew.

That is not only a disk problem. KelyfOS shipped the tamper-evident half of
an audit story in v1.0 — a hash-chained record nothing can edit
undetectably — with no retention policy at all, which is half a compliance
story told confidently. Two obligations pull in opposite directions on the
same file:

- **EU AI Act Article 12** requires automatic, tamper-evident recording for
  the systems it covers, with a retention floor — twelve months from session
  close for Annex III (high-risk) systems, six for a general-purpose one —
  and Recitals 99–100 extend the boundary to every agent in a chain
  performing a high-risk function, which is a per-agent record, which D59
  already supplies.
- **GDPR Article 17** gives a data subject the right to have their data
  erased, on request.

A record that must be *kept* and a request to *delete what is in it* look
like a contradiction until the record separates two different claims: the
**structural** one (a session happened, at this time, with these agents, in
this many steps, in this order) and the **content** one (what was said,
written, or run). Article 12 needs the first. Article 17 targets the second.
KelyfOS is unusually well placed to split them because `file.write` already
does, for a different reason: it has recorded a file's own digest rather
than its content since before this phase, so a reader can prove a write
happened and match it against a later claim without the record ever holding
what was written. P7-5 applies the same pattern retroactively, to fields
that were recording content directly.

## 2. The retention floor — `[sessions] retention_days`

```toml
[sessions]
retention_days = 365
```

A **floor**, not a target: `kelyfos sessions prune` never deletes a
recorded session younger than this, however it is invoked — there is no
flag that overrides it. Absent, or written as `0` (`internal/config`'s own
convention: zero means not set, the same as every other numeric key in the
file), it defaults to **180 days**, the EU AI Act's own floor for a
general-purpose system. A project subject to the Annex III floor instead
writes `retention_days = 365`.

The floor is read from a policy file the same way `run`, `fork` and
`snapshot restore` already resolve one: `--policy` names a file, and naming
one that is not there is an error; with nothing named, `kelyfos sessions
prune` walks up from the working directory the way `git` does. The session
history under `~/.cache/kelyfos/sessions/` is not scoped to one project —
many `kelyfos.toml` files can contribute sessions to the same host cache —
so which policy's floor applies is a property of *where prune is run from*,
not of any one session.

## 3. `kelyfos sessions prune`

```
kelyfos sessions prune [-dry-run] [-policy <file>]
```

Deletes whole session directories — never a partial edit — that are older
than the floor. Age is `events.jsonl`'s own mtime, not a `session.end`
timestamp read out of the chain: cheap (no chain has to be parsed to decide
what to prune), and it treats a cleanly closed session and an
orphaned/crashed one alike, where a crashed session may have no
`session.end` to read at all (`docs/events.md`: "a session that is still
running has no `session.end`... the chain cannot tell those apart"). This
is the same choice `pruneTemplates` already made for the fork-template
cache, kept consistent rather than inventing a second aging rule.

**events.jsonl's own mtime, not the session directory's.** The first cut of
this task aged sessions by the directory's own mtime, and that was wrong:
appending to an existing file does not advance its parent directory's own
mtime on POSIX — only creating or removing a directory *entry* does — so a
session's directory keeps the mtime it had the moment it was first created
and never moves again, however long the session runs or however many
events land in it afterward. Prune was therefore aging every session from
its own *start*, silently contradicting this very page's own framing
("twelve months from session close") the whole time. `events.jsonl` is the
one file every write to a session touches, including the last one, so its
own mtime is genuinely last-write at the same cost — no chain parse — the
directory-mtime approach was chosen for. One consequence is worth stating
rather than leaving to be found: `kelyfos sessions erase` also writes
`events.jsonl`, so running it resets this clock by up to the retention
floor, the same as any other write to the chain would. That is not a
special case to work around — an erasure genuinely is the most recent thing
that happened to the chain — but it is worth knowing if a prune schedule
and an erasure schedule are ever compared against each other.

Four guards apply before age is even considered, and none respect
`-dry-run` differently — a session either is prunable or it is not:

- **A currently paused session's own chain is never pruned**, however old.
  `kelyfos pause` freezes a machine under a name and a later `kelyfos
  resume` writes `session.resume` into the *same* chain the machine was
  paused from — "one chain covers the whole life of the machine rather than
  one per resume" (`docs/events.md`). Deleting that chain out from under a
  paused session would either break the resume or make it silently start a
  fresh one. Checked by cross-referencing every paused session's own
  metadata (`NamedMeta.Session`) against the session id under
  consideration.
- **A session with a live-looking run directory is never pruned.** A
  leftover run directory after a crash is a false positive prune would
  rather have than the alternative — touching a chain something might still
  be writing to. This only ever sees an ordinary sandbox, whose own id
  names its run directory.
- **A session any live sandbox's own `RecordSession()` names is never
  pruned** (`sandbox.RunningSessions()`). This is what makes a **team**'s
  own top-level chain visible — opened under an id `sandbox.NewID()` mints
  that is never any sandbox's own id, so the guard above never sees it, but
  a live member sandbox's own state does name it.
- **A session with a live `kelyfos serve-mcp` marker is never pruned.** A
  `serve-mcp` process's own audit chain is opened the same un-sandboxed way
  a team's is, but no sandbox it creates ever names the audit session as
  its own `RecordSession()` either, so the guard above cannot see it — this
  was found live, by a whole-phase read-back (P7-13): a long-lived,
  low-traffic `serve-mcp` process's own audit chain, silently deleted by
  prune while the process kept running, no error anywhere. `openAudit`
  creates an empty marker file under `~/.cache/kelyfos/audit-live/` the
  moment the session exists and `closeAudit` removes it on a clean
  shutdown; prune (and erase, see §5) both check for it. **The same
  leftover-after-a-crash tradeoff the run-directory guard already accepts
  applies here too, and is worth naming plainly: `kelyfos serve-mcp` does
  not currently exit on `SIGTERM` alone while its stdin pipe is held open
  the way a real MCP client normally holds it (a signal handler runs, but
  a blocking read on inherited stdin is not interrupted by it) — so a
  supervisor stopping it with a plain `kill` rather than closing its input
  stream is likely to end up sending `SIGKILL`, which leaves the marker
  behind permanently.** There is no command to clear a stale marker today;
  the only recovery is deleting the file by hand under
  `~/.cache/kelyfos/audit-live/`.

`-dry-run` reports exactly what a real run would delete, with no side
effect. Without it, `kelyfos sessions prune` deletes and reports what it
deleted — size, and age — the same way `kelyfos sessions rm` already says
what it discarded rather than leaving "removed" to sound thinner than it
is.

## 4. The size warning

`kelyfos doctor` gained a **session records** check, printed the same way
every other check is, but it is a `warn`, not a `FAIL`, and a warning never
moves `doctor`'s own exit code. That distinction exists because this check
is not like its neighbours: `disk space` and `jailer` and the rest all ask
"can this machine currently run KelyfOS," and a script that stops on their
FAIL is doing the right thing. Session-records size answers a different
question — "does this machine's past history need pruning" — and
`kelyfos doctor`'s own exit code used to conflate the two, so a CI job that
treated any nonzero exit as "this environment is broken" would stop for a
reason that has nothing to do with whether the environment works. The bound
(1 GiB) is a constant, like `templateCacheBytes`, rather than a setting:
crossing it changes nothing about what KelyfOS does, only what `doctor`
says.

## 5. `kelyfos sessions erase` — the replacement record

```
kelyfos sessions erase -reason "<why>" <id>
```

Flags may go on either side of `<id>`, the same as `kelyfos verify` already
allows — `parseAround` (`host/flags.go`) is the one implementation both
commands share, so they cannot disagree about which order works. An
earlier draft of this command required `-reason` before `<id>` and failed
with a confusing "-reason is required" when it was not, because Go's
`flag` package stops looking for flags at the first positional argument;
using the same helper `kelyfos verify` already had removes the restriction
rather than merely explaining it better.

This is the erasure path, and it does not delete a session — that is what
`prune` is for, and it is bound by the retention floor for exactly the
reason erase is not: erase answers Article 17 without touching the
Article 12 obligation at all, because it removes *content*, not the
*record that content happened*.

**What it does.** Every field on the chain known to carry
guest-influenced or operator-supplied content is replaced, wherever it is
non-empty, with a fingerprint of what was there: its own sha256, in the
same in-band-note shape `clipToBudget` already uses for a clipped
field (`"(erased — sha256:…)"`). That list, as of this task's review round,
is: `data` (command output, a team message's payload), `cmd` and `argv`
(a command's own argv, and the host process's own — what a trailing
`-- <command>` carries, e.g. the docs' own canonical example,
`kelyfos run --workspace . --allow github.com -- claude`), `args` and
`tool` (an MCP or plugin call's argument summary and tool name — the tool
name is copied verbatim from an outside client's own frame before
anything validates it is a real tool, so it is exactly as capable of
carrying arbitrary text as `args` is), `cwd` (the host launch directory
recorded on `session.start` and `command.start` — a directory named after
a client leaks that name into the record forever without this), `path`
(a file's path inside the guest, guest-chosen), `host` (a connection's
target domain) and `peer` (who connected — an IP address on
`forward.accept`, or a guest's own verbatim, unvalidated `to` string on a
refused `team.message`/`team.refused`), `comm` (the name of a process the
guest's OOM killer reported, from the kernel's own line, guest content by
construction), `name` (an MCP tool name, a plugin name, or a paused
session's own chosen name), `allow` (the resolved egress allowlist — a
domain can be as identifying as the traffic to it), `workspace` (the host
directory a machine's `/work` was attached to, a filesystem path), a
`traceparent` (an inbound W3C trace header, taken verbatim and unparsed
from an outside MCP client, so nothing here has ever validated its
shape), `store_keys[].name` (a team store ACL rule's own key name —
the same value space `team.store`'s own `peer` field already redacts when
a key is actually accessed, kept consistent between declaration and use),
and `error.message` (see below — it is redacted since v1.1, and was not
before). Everything else about each event — its type, timestamp, agent,
`error.kind` (with the caveat below), byte counts, exit codes, resource
figures — survives unchanged. A new
`session.erasure` event is appended recording that this ran, why (an
operator-supplied `-reason`, required — an erasure with no stated reason
would be exactly the kind of unaccountable action this product's whole
design argues against), how many events were touched, and the chain head
immediately before the rewrite began (§5.3 below).

**The `[]string` fingerprint rule (S5).** A field like `cmd` or `argv` is a
list, not a single string, and its fingerprint has to be computed over
*something* that represents the whole list — this task's first draft
simply joined the elements with a space before hashing, which is
collision-prone by construction: `["a b", "c"]` and `["a", "b", "c"]`
join to the identical string `"a b c"` and would fingerprint identically,
so a fingerprint could not actually distinguish what was erased. The
fingerprint is computed over a length-prefixed encoding instead — each
element's own byte length as a fixed 8-byte big-endian integer, immediately
followed by the element's own bytes, concatenated across the whole slice,
then hashed as one value. That encoding is injective: it can only be split
back into elements one way, so two slices that are not element-for-element
identical can never produce the same bytes to hash, whatever the elements
themselves contain — no delimiter choice can make that guarantee, since any
fixed delimiter can appear inside an element unless something upstream
forbids it, and nothing here does.

**How that list is kept honest.** A hand-maintained list of which fields
carry content is precisely the failure class this project has now hit
four times in one week, on four different lists: `clipToBudget`
naming six fields and missing `Tools`; `internal/digest` missing
`session.policy`; `internal/digest` missing `team.topology`; and this
task's own first draft naming four fields (`data`, `args`, `cmd`, `argv`)
and leaving eleven more — `cwd`, `path`, `peer`, `comm`, `workspace`,
`host`, `name`, `allow`, and every field inside `agents`, `edges` and
`store_keys` — fully unredacted, found by an adversarial review that put a
marker in every string and `[]string` field `Event` has and ran a real
erasure over each one in turn. The fix is the same one `clipToBudget`
already uses for its own list: walk `Event` by reflection instead of
trusting memory. `internal/recorder/erase.go`'s `eraseExempt` is the
single, explicit table of every field left alone and why — a session id,
an agent's own declared name (the structural claim of *who did this*,
which Article 12 needs kept even when *what they did* is redacted), a
digest that already does not hold what it fingerprints, or one of a small
set of values the code itself chose rather than text an operator typed or
a guest produced. `TestEraseCoversEveryContentField`
(`internal/recorder/erase_test.go`) is what makes the table honest: it
puts a marker in every field reachable from `Event` — including
`*EvError`'s two fields and the three struct slices' own fields — runs a
real erasure, and fails with the field's own name if the marker survives
a field the table does not name. A field added to `Event` next month is
covered, or the test that added it fails, on the day it lands.

**The rewrite is lossless, and refuses a chain from a newer build.** Until
v1.1 the rewrite went read → redact → hash → re-marshal, and the read was
`json.Unmarshal` into this build's own `Event`: every member the struct did
not carry was dropped on the way through. An older `kelyfos` erasing a chain
a newer one wrote deleted part of the record, the rewritten chain verified,
and `modified` did not reflect it — the exact failure `digestOfLine` exists
to prevent on reads, where a digest is recomputed from the bytes as written
so an older build never calls a legitimate record modified.

Erase inherits that property now. Each line is held as its own members, in
the order the line carries them, and only the members a redaction actually
changes are written back; everything else comes out byte-for-byte, including
members this build has never heard of, members inside objects whose own
struct it only partly knows, and values a struct round trip would have
normalised away. The digest is taken over the bytes actually written.

And before any of it: an event carrying a `v` higher than this build writes
is refused, naming the event and both versions. A schema version this binary
has never seen is one whose fields it cannot classify as content or not, so
it cannot know what to redact — and guessing is not available to the one
operation whose whole promise is that it removed exactly what it said it
removed. Adding a *field* does not move `v` (`docs/events.md` says adding one
is not breaking), which is why the lossless rewrite above is the part that
carries the ordinary case; this covers the case where `v` really did move.

It refuses a chain whose file does not end in a newline. A line cut at
exactly its last byte is a complete JSON object with no terminator, so
`kelyfos verify` reads it happily and reports the chain intact — the missing
newline is the only trace that a writer was cut short, and the recorder itself
refuses to append to such a file for exactly that reason. An erasure rewrites
every line and terminates every one of them, so without this refusal it would
be the one operation that turns "this record was cut short" into "this record
is complete", while writing a `session.erasure` event that says how much was
redacted and nothing about the truncation. The remedy is one byte and destroys
nothing — appending the missing newline changes no event and no digest, and
the chain can then be erased normally — so refusing keeps the decision with a
person rather than having a tool make it silently. No chain KelyfOS wrote can
be refused this way: the recorder writes each line and its newline in one
call, and an erasure terminates every line it emits.

It refuses one more shape, found by fuzzing the rewrite (`FuzzEraseRoundTrip`,
`internal/recorder/fuzz_test.go`): a line carrying a member whose name differs
from a field's own name only in case — `"Cmd"` where the schema says `cmd`. Go's
JSON decoder matches a member to a field case-insensitively when there is no
exact match, so such a member *is* decoded, *is* redacted, and the fingerprint
was written back under the canonical name — appending a member and leaving the
original, content intact, in the line beside its own fingerprint. `erase`
reported the event redacted and the content was still in the file. Every line
KelyfOS writes uses the canonical names, so the only chains this refuses are
hand-edited ones or ones written by something else against `docs/events.md`;
they still verify, because verification works on the raw bytes, so refusing
loses no evidence. The message names the member.

**Two counts, not one.** `modified` is how many events were touched;
`redacted_fields` is how many fields were replaced across all of them. An
event with three redactable fields set moves the first by one and the second
by three. The second exists so an auditor has a number to compare against
what a redaction over a given chain should have touched — the comparison that
catches a field quietly falling out of coverage, which is the failure this
section's own history is made of.

**Why the chain still verifies afterward.** Every event's `hash` covers
`prev`, and `prev` is the previous event's `hash`, so a content change to
one event changes the digest of every event chained after it whether or
not that later event's own content moved — the same property that makes
the chain tamper-evident in the first place makes an in-place edit
impossible without a full rebuild. `kelyfos sessions erase` does not try
to avoid this; it embraces it. The whole chain's `seq`, `prev` and `hash`
are recomputed from the first event, which is what makes the result a
**replacement record** rather than a patched one — D61's own phrase. The
session's event count, order and every untouched field survive exactly;
only the digests differ from what they were before, because the content
they were computed over is different now, honestly.

### 5.1 Rewritten in place, not renamed over — a live writer's own record

The first cut of this mechanism wrote the rewritten chain to a temp file
and renamed it over `events.jsonl`, the same crash-safety pattern the
fork-template cache already uses. That is wrong for this file specifically,
and an adversarial review reproduced why on real, running code: a
`Recorder` that already had this session's chain open — a team's own
process, say — keeps its file descriptor pointing at whatever inode
`events.jsonl` named at the moment it opened the file. A rename replaces
the *directory entry*, not that inode; the writer's fd, and everything it
appends through it afterward, keeps landing on the old, now-unlinked
inode, which nothing else can ever read again once the writer's own fd
closes. The writer's next `Append` neither errors nor warns — its own
`catchUp` compares the file's size against what it last saw, on that same
stale fd, sees no change, and proceeds as if nothing happened. Three
events the review appended after the erasure never reached a readable
file, and `kelyfos verify` reported the truncated chain as clean, because
nothing about it was inconsistent — it was simply short by exactly the
events that vanished.

`Erase` now rewrites the same inode in place instead: the new content is
written with `WriteAt` at offset 0 on the same locked file descriptor
already used to read and verify the chain, then the file is truncated to
the new length (only ever shrinking it — a redacted field's fingerprint is
often much shorter than what it replaced) and synced. Every file
descriptor still pointing at this file — including one opened before this
call started — sees the new bytes the moment the lock releases, because
there is only ever one inode to see. The write happens before the
truncate specifically so that a process killed between the two leaves the
new content whole with stale bytes trailing it, which `kelyfos verify`
can detect as a broken chain, rather than a truncate landing first and a
crash before the write leaving nothing at all.

That alone is not sufficient: a live writer's own cached position in the
file — how many bytes of it this process has already accounted for — is a
byte offset into the file as it looked *before* the rewrite, and a
redacted field's fingerprint is essentially never the same length as the
content it replaced, so that offset is no longer guaranteed to land on a
line boundary, let alone the same event, once the rewrite has happened.
`Recorder.catchUp` (`internal/recorder/recorder.go`) closed the other
half of this: instead of trusting its own remembered offset and reading
only what looks new past it, it now re-derives the chain's true end from
the whole file whenever the file's size no longer matches what it last
saw — which is exactly what happens the instant `Erase` releases the lock
it was blocking on. A concurrent writer therefore neither loses events
nor needs to be told an erasure happened; its next `Append` simply
continues the (now-rewritten) chain correctly.

### 5.2 Running it twice

`redactString` and `redactStrings` recognise their own placeholder shape —
`(erased — sha256:<64 hex characters>)` — and treat a field that already
matches it as already-redacted rather than hashing the placeholder text
itself. Without this, a second `erase` on an already-erased session
(an accidental re-run, or a script retrying on a transient failure) would
compute the sha256 of the note `"(erased — sha256:…)"` rather than the
content it stood in for, silently and permanently replacing the real
fingerprint — the one thing this whole mechanism exists to keep — with
the hash of a string of English text. The refusal a chain with nothing
left to redact already gets ("nothing to erase") now correctly fires on
the second run instead of on neither.

### 5.3 The pre-erasure anchor

`session.erasure`'s own `sha256` field carries the chain head — the last
event's own `hash` — immediately before the rewrite began. Without it,
`session.erasure` is honest *by convention*: anyone using this product's
own tooling gets an honest record, but the field carries nothing that
distinguishes a genuine erasure from wholesale tampering dressed up to
look like one. Hand-edit an event's `data` to reverse its meaning, rehash
the chain from event 1 with no erasure event recorded at all, and
`kelyfos verify` passes — identically to a real erasure, because both
produce an internally consistent chain and the chain alone cannot tell
honest redaction from malicious rewriting.

The anchor is what turns that into a claim a third party can check rather
than one they have to take on trust: `kelyfos verify --extract` (or a
report's own embedded record) taken *before* an erasure gives a reader the
pre-erasure chain head independently of the erasure itself, and comparing
it against `session.erasure`'s own `sha256` on the rewritten chain proves
the erased chain is the honest successor of exactly the chain they
already hold — not a fabrication with no erasure event at all, and not an
erasure that silently dropped more than it claims to have touched. No new
`Event` field: `sha256` is already `file.write`'s own field, reused the
same way `modified` and `cpu_quota_percent` already are across other
event types.

**What it refuses, and why.** A chain that does not already verify —
rewriting a broken chain would erase the evidence that it was broken,
which is the one thing an erasure path must never do. An empty chain, one
with nothing to redact (including a chain every redactable field of which
is already a fingerprint from an earlier erasure — §5.2), or a chain with
no `session.end` anywhere in it — the shape of a session that may still be
open, or a process that may still be writing to it, and erasing either
would risk exactly the concurrent-writer race §5.1 exists to close.
A currently paused session, or one with a live-looking run directory —
`hasLiveRunDir` catches an ordinary sandbox, whose own id names its run
directory. It cannot catch a running **team** or a running
**`kelyfos serve-mcp`** process's own audit session: both open their
chain under an id `sandbox.NewID()` mints that is never any sandbox's own
id, so `RunDirOf(that id)` never exists even while every sandbox writing
into that exact chain is alive. `sandbox.RunningSessions()` closes this
for a team specifically — every live sandbox's own `RecordSession()`,
whichever sandbox actually holds the run directory — with a specific,
named refusal at the CLI layer. A live serve-mcp audit session is closed
the same explicit way (P7-13): `openAudit`/`closeAudit` maintain a marker
file (§3 above has the full account, including its own leftover-after-an-
unclean-kill tradeoff), and erase refuses with a specific, named message
the moment it sees one — the no-`session.end`-anywhere check inside
`Erase` itself remains underneath as a second, independent layer for the
same case, since neither guard alone can see everything the other misses.

**`error.message`, and why it used to be exempt.** Until v1.1 this field
was left alone, on the stated ground that it was "generally a
system-generated string (a timeout, a signal name) with no established
precedent for holding raw guest content the way `data`, `args` and `cmd`
do". That was wrong when it was written. The precedent was two files
away: `sandbox_exec` builds its tool result out of the guest's stdout, and
`host/servemcpaudit.go` stored the first line of that result here — so
every failed command in a `serve-mcp` session left a line of its own
output in a field an erasure did not touch. `host/exec.go` copies the
guest supervisor's error string the same way, and that one carries an
agent-chosen path.

Both halves are closed. The audit lane no longer copies any of a tool
result into a message field: it records the shape of the failure instead —
the exit status the guest process returned, which the chain already keeps
unredacted on `command.exit`, or the size of the content it declined to
hold, which is the rule the argument summariser already applies. And
`error.message` is redacted like `args` and `cmd`, so whatever a future
writer of that field puts there is covered without anyone having to
remember. Either fix alone would have drifted: an exemption is what tells
the next writer of a field that it is a safe place to put a string.
`error.kind` — the fixed enumeration an auditor reads — is still exempt.

**`error.kind` is exempt on a fact now, and it used to be exempt on a
condition.** It is meant to be a fixed enumeration — `bad_request`, `not_found`,
`denied`, `timeout`, `killed`, `io`, `internal` — and an auditor reads it as one,
which is why an erasure keeps it: it says *what kind of thing went wrong*
without saying what was in it. For one release the host did not enforce that.
`host/exec.go` copied the guest supervisor's `kind` verbatim off the wire,
nothing checked it against the protocol's own set, and guest-chosen text in that
field survived an erasure. The page said so rather than promising the property.

It is enforced at the edge now, which is where the note said the fix belonged.
Every frame the host decodes from a guest goes through `Sanitize`, and an error
whose `kind` is not one of the seven is clamped to `internal`, with the guest's
own string moved into `message` — which *is* redacted.

**Three limits on that, because the sentence is easy to write one step too
strong.** First, the moved string does not always reach the record: on the
`kelyfos exec` path the chain's `command.exit` carries the kind and not the
message, so what the guest sent is dropped rather than relocated. It is still
printed on the operator's terminal. Second, `kind` is a *guest*-supplied field
only on the guest paths; the host writes it too — a `mcp.host.result` carries
`tool`, which is the host's own word and is not one of the seven. Read
`error.kind` as "a short host-controlled category", not as "one of exactly seven
strings". Third, an erasure rewrites a chain *off disk* and does not re-sanitise
it, so a chain written by a build from before this was enforced keeps whatever
kind it recorded, through the erasure, exactly as this page used to warn.

A second route deserves the same honesty. `error.message` is redacted now, so
an **erased** chain is clean whatever writes it — but an un-erased one can
still carry guest bytes there by a route the audit lane's own fix does not
cover: `host/servemcptools.go` records `err.Error()` from `sandbox.Exec`, and
one of those errors embeds the guest-chosen stream name. `proto.SafeText`
bounds its character class, not its length. The record holds it until an
erasure removes it.

**What is deliberately out of scope.** Per-agent or
per-event scoping — "erase only what agent X said," rather than a whole
session — is a decision deferred until something asks for it:
nothing has asked for it yet, and a session is usually the right unit for
an Article 17 request in the first place, since it is one interaction.
**A copy that already left this record is out of reach by construction,
not by omission**: `kelyfos sessions erase` rewrites the one file this
product calls the record of a session, and nothing else. A report already
exported before the erasure ran (`kelyfos log --export`, signed or not)
embeds the original, unredacted chain in the page itself, and this
command has no way to know such a page exists, let alone reach it — the
same is true of any copy made outside KelyfOS entirely (a backup of
`~/.cache/kelyfos`, a chain someone piped elsewhere). Erasing the record
this product keeps does not reach back through every door content may
already have left by. None of these omissions are silent: this section
says so, the way `docs/policy-record.md` §8 says what it omits and why.

## 6. What a reader checks

`kelyfos verify` after an erasure reports the chain intact, the same as
before — that is the point, not a special case. It also still says the
session ended cleanly when it genuinely did: `session.erasure` is appended
*after* `session.end`, so a check that only looked at the very last event
used to report a perfectly-closed, later-erased session the same way it
reports a session cut short mid-run. `kelyfos verify` now looks for
`session.end` anywhere in the chain rather than only as the last event,
which is correct on every chain that is not erased and correct on the ones
that are. `kelyfos log` replays an erased session exactly like any other,
showing the fingerprint text where content used to be rather than failing
or skipping the event. Grepping the raw `events.jsonl` for the original
content finds nothing, the same acceptance check this product already
applies to a bound secret's value (`docs/policy-record.md` §1's own
"checked by grepping the raw file for the value and finding nothing").

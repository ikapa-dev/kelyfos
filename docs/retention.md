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
than the floor. Age is the directory's own mtime, not a `session.end`
timestamp read out of the chain: cheap (no chain has to be parsed to decide
what to prune), and it treats a cleanly closed session and an
orphaned/crashed one alike, where a crashed session may have no
`session.end` to read at all (`docs/events.md`: "a session that is still
running has no `session.end`... the chain cannot tell those apart"). This
is the same choice `pruneTemplates` already made for the fork-template
cache, kept consistent rather than inventing a second aging rule.

Two guards apply before age is even considered, and neither respects
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
  be writing to.

`-dry-run` reports exactly what a real run would delete, with no side
effect. Without it, `kelyfos sessions prune` deletes and reports what it
deleted — size, and age — the same way `kelyfos sessions rm` already says
what it discarded rather than leaving "removed" to sound thinner than it
is.

## 4. The size warning

`kelyfos doctor` gained a **session records** check: the same FAIL/fix
shape `disk space` already uses, not a new severity tier. Nothing deletes a
session automatically — that is what makes this a warning and not a
sweep — so the check exists to make the situation visible before it is a
problem, the same way `disk space` does for the cache root generally. The
bound (1 GiB) is a constant, like `templateCacheBytes`, rather than a
setting: crossing it changes nothing about what KelyfOS does, only what
`doctor` says.

## 5. `kelyfos sessions erase` — the replacement record

```
kelyfos sessions erase -reason "<why>" <id>
```

`-reason` has to come before `<id>`: Go's `flag` package stops looking for
flags at the first positional argument, so `erase <id> -reason ...` would
silently read `-reason` and its value as two more positional arguments
rather than the flag.

This is the erasure path, and it does not delete a session — that is what
`prune` is for, and it is bound by the retention floor for exactly the
reason erase is not: erase answers Article 17 without touching the
Article 12 obligation at all, because it removes *content*, not the
*record that content happened*.

**What it does.** Every field on the chain known to carry
guest-influenced or operator-supplied content — `data` (command output, a
team message's payload), `args` (an MCP call's argument summary), `cmd` (a
command's own argv) and `argv` (the host process's own argv — what a
trailing `-- <command>` carries, e.g. the docs' own canonical example,
`kelyfos run --workspace . --allow github.com -- claude`) — is replaced,
wherever it is non-empty, with a fingerprint of what was there: its own
sha256, in the same in-band-note shape `clipLargestField` already uses for
a clipped field (`"(erased — sha256:…)"`). Everything else about each
event — its type, timestamp, agent, byte counts, exit codes, resource
figures — survives unchanged. A new `session.erasure` event is appended
recording that this ran, why (an operator-supplied `-reason`, required —
an erasure with no stated reason would be exactly the kind of
unaccountable action this product's whole design argues against), and how
many events were touched.

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

**What it refuses, and why.** A chain that does not already verify —
rewriting a broken chain would erase the evidence that it was broken,
which is the one thing an erasure path must never do. An empty chain, or
one with nothing to redact — an erasure event that changed nothing but
claimed something happened would be worse than no event at all. A
currently paused session, or one with a live-looking run directory — the
same two guards `prune` applies, for the same reasons.

**What is deliberately out of scope.** `EvError.Message` is not redacted:
it is generally a system-generated string (a timeout, a signal name) with
no established precedent for holding raw guest content the way `data`,
`args` and `cmd` do, and widening the redacted-field list is a decision to
make against a real request for it, not to predict here. Per-agent or
per-event scoping — "erase only what agent X said," rather than a whole
session — is the same kind of decision, deferred for the same reason:
nothing has asked for it yet, and a session is usually the right unit for
an Article 17 request in the first place, since it is one interaction.
Neither omission is silent: this section says so, the way
`docs/policy-record.md` §8 says what it omits and why.

## 6. What a reader checks

`kelyfos verify` after an erasure reports the chain intact, the same as
before — that is the point, not a special case. `kelyfos log` replays an
erased session exactly like any other, showing the fingerprint text where
content used to be rather than failing or skipping the event. Grepping the
raw `events.jsonl` for the original content finds nothing, the same
acceptance check this product already applies to a bound secret's value
(`docs/policy-record.md` §1's own "checked by grepping the raw file for the
value and finding nothing").

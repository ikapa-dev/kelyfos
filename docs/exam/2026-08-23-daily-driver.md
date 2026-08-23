# The daily driver, examined from the documents alone

*E5's exit requirement, run the way E3-5 and the E4 exam ran it: the
documentation is the only source, and the question is not "is this page
accurate" but "can somebody get the thing done from it".*

*Date: 2026-08-23. Corpus: `docs/qol.md`, `docs/denials.md`, `docs/events.md`,
`docs/networking.md`, `docs/protocol.md`, the six generated pages, the cookbook,
and both README files. Method: two tasks attempted from the documents, then a
mechanical sweep of every claim in them that a machine can check.*

---

## Why this exists, again

E3-5 established that generation gives *consistency*, not truth. The E4 exam
extended it: the pages a generator cannot reach go stale, and the part no page
describes is the part nothing checks. This exam found the third form of the same
thing, and it is the one that costs a reader the most.

**A feature can be completely and correctly documented and still be unusable,
because the sentence a reader needs is about something else.**

## Tasks

**Task A — "stop for the day and pick this machine up tomorrow."** Completed
from the documents. `docs/qol.md` §1 explains what a paused session is and why
the policy travels with it; recipe 12 is the whole thing as a script. No
findings.

**Task B — "look at the web app my agent is building."** *Not completed.* The
reader found `-p host:guest` in `reference/cli.md`, understood from
`networking.md` §3.1 that it does not touch the firewall, and got as far as

```
kelyfos run --image dev -p 8080:80
kelyfos exec 'python3 -m http.server 80'
```

which never returns. Nothing in the documentation shows how to start a
long-running process inside a sandbox, and `-p` is the one feature that requires
it. The refusal a reader eventually sees — `forward.closed`, "start the server in
the guest before connecting" — is correct and does not help: they *were* trying
to start the server.

## Findings

| # | What | Where | Fixed |
| --- | --- | --- | --- |
| 1 | No runnable `-p` example anywhere, and nothing shows how to start a long-running process in a guest without hanging on it | cookbook | recipe 14 |
| 2 | The named-session store layout named a `session` file that does not exist, and omitted `named.json` which does | `qol.md` §1.1 | corrected |
| 3 | The diff example showed a line count for a deleted file, which the manifest cannot supply | `qol.md` §2.2 | corrected |
| 4 | Two different minus signs in one column of `kelyfos diff` — ASCII for bytes, U+2212 for lines | `internal/sandbox/diff.go` | fixed |
| 5 | `llms-full.txt` described as "about 48,000 tokens" in one place and "about 54,000" in another; it is about 93,000 | `docs/README.md` | corrected |
| 6 | "79 comments across 37 Go files" cite a document; it is 139 across 61 | `docs/README.md` | corrected |
| 7 | "Eleven recipes" in four places, after two were added | `docs/README.md`, `README.md`, `integrating.md` | corrected |

Finding 1 is the one worth the exam. The others are drift of the kind the E4
exam predicted: **numbers written into prose go stale silently, and a page that
is regenerated is not the same as a page that is checked.** Every count in
finding 5–7 had passed every mechanical gate in CI, because no gate knows that
a sentence contains a number that is about something countable.

## What was checked mechanically, and passed

- **106 cross-references** of the form `<doc>.md §N`, in prose and in Go
  comments, all resolve to a section that exists. This is the check that would
  have caught a renumbering, and `events.md` gained a section in this epic.
- **Every `kelyfos <command>` named anywhere in the prose** is a command the
  binary dispatches. One false positive: "kelyfos says so" in a comment.
- **Every documented `kelyfos.toml` key parses**, and every key the parser takes
  is documented — the two directions the schema tests already hold.
- **The exact refusal strings** quoted in `resources.md` and `denials.md` are the
  strings the product prints, including the bracketed ID and the fix line.
- **The `--p-bind` warning** matches what `qol.md` §4.3 specified, to the word.
- **`kelyfos runs` output** matches the shape `events.md` §6 shows, including
  `open` for a session with no end and `(attached)` for a chain that begins with
  a command.

## The lesson, stated so it can be checked next time

The E4 exam's lesson was that the part no page describes is the part nothing
checks. This one adds: **the part every page describes correctly can still be
the part nobody can do**, and the way to find it is to attempt the task rather
than to audit the page.

The mechanical half of this exam is now cheap to repeat — the cross-reference
sweep and the command sweep are a dozen lines of Python — and the counts in
finding 5–7 argue for something more: a number in prose about a countable thing
should either be generated or not written. That is a candidate for the next
epic rather than a change made at a tag.

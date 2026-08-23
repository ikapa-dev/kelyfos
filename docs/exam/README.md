# The documentation exam

E3-5 asks whether the documentation is good enough to build from, and answers it
the only way that means anything: by giving a fresh agent the documentation and
nothing else, and watching.

**The rules.** A fresh session on a machine carrying the `kelyfos` binary and
both image flavors built from the commit under test. It gets `llms-full.txt` and
the binary's own `--help` and error output. It does not get the source tree, the
`docs/` directory, `README.md`, the plan files, the git history, or the web.
The task: boot a three-agent team, run a task containing at least one
`team_ask` round-trip, and export the transcript.

Every failure the exam finds becomes a documentation fix. The exam is re-run
until it passes.

## Runs

### 2026-08-23, commit `65be6c6`, `kelyfos v0.5-17-g65be6c6` — **pass, first try**

| | |
| --- | --- |
| [`2026-08-23-transcript.md`](2026-08-23-transcript.md) | the working transcript, written as it went |
| [`orchestrate.sh`](orchestrate.sh) | what it built |
| [`probe.sh`](probe.sh) | what it wrote to break things on purpose, after the task was already done |
| [`team-transcript.html`](team-transcript.html) | the export its orchestrator produced |

It worked on the first run and took about 35 minutes, of which roughly ten were
reading, five writing, three running — and seventeen deliberately breaking
things, because the happy path had cost so little. Ten defects came out of it.
Nine were documentation and are fixed; the rest are product work and are
recorded in `PLAN-FEATURES.html` (F-D32) rather than quietly fixed inside a
documentation epic.

The most valuable one is worth stating here, because it is the failure this
whole epic was built to prevent and it happened anyway: the **generated**
reference said a team message's `data` field was base64. It is plain text. The
hand-written `events.md` in the same file said so correctly, so the two
contradicted each other — and the wrong one was the page carrying the banner
promising CI would catch exactly this. It could not: CI checks that the
reference matches its source table, and the source table was wrong. A generator
guarantees consistency, not truth. The exam is what checks truth.

### 2026-08-23, Epic E4's exit — [`2026-08-23-mcp-surface.md`](2026-08-23-mcp-surface.md)

Two readers, given the documentation and nothing else, asked to drive KelyfOS
from an MCP client and to ship a plugin that runs inside a sandbox. Both said
no: neither could finish from the documents. Twenty-two findings, and the
lesson that outlived them — **the pages a generator cannot reach go stale, and
the part no page describes is the part nothing checks.**

### 2026-08-23, Epic E5's exit — [`2026-08-23-daily-driver.md`](2026-08-23-daily-driver.md)

Two tasks attempted from the documents — pause and resume a machine, and look at
a web app inside a sandbox — plus a mechanical sweep of every claim a machine can
check. The first task completed; the second did not, and the reason is the
lesson: **a feature can be completely and correctly documented and still be
unusable, because the sentence a reader needs is about something else.** Nothing
showed how to start a long-running process inside a guest, which is what `-p`
exists for. Seven findings, all fixed before the tag.

These files are evidence and are not run by anything. `dev/cookbook.sh` does not
look here.

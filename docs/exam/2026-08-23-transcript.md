# KelyfOS documentation exam — working transcript

**The rule.** The only documentation I read was `~/exam/llms-full.txt` plus what the
binary told me at runtime (`kelyfos help`, `<cmd> --help`, error messages). I did **not**
open the KelyfOS source tree at `/Users/ioanniskapageridis/dev/labs/KelyfOS` — no Go
source, no `README.md`, no `docs/`, no `PLAN*.html`, no git history — and I did not search
the web. No violations to disclose.

**Outcome: pass, first try.** The orchestrator worked on its first run and is reproducible.
The documentation is genuinely buildable-from. The defects below are real but none of them
blocked me; most would bite someone who deviated from the cookbook.

---

## Step 0 — check the machine

    limactl shell kelyfos-dev -- bash -lc 'cd ~/exam && export PATH=$HOME/exam/bin:$PATH && pwd && ls -la && wc -l llms-full.txt'

`~/exam` = `/home/ioanniskapageridis.guest/exam`, containing only `bin/` and
`llms-full.txt` (5017 lines, 229 KB).

    kelyfos version   ->  kelyfos v0.5-17-g65be6c6
    kelyfos doctor    ->  all checks passed — this machine can run KelyfOS

`doctor` identifies the platform as `Lima VM (macOS host), aarch64`, KVM API 12,
Firecracker v1.16.1, guest image `dev` built 2026-08-23. Remember that platform line — it
matters for gap 6.

---

## Step 1 — find the relevant documentation

    grep -n "^#" llms-full.txt

`llms-full.txt` is a concatenation of ~11 documents. Three sections carried the task:

- Cookbook **"## 5. Three agents, an ask round-trip, and a refused edge"** (line 3213) —
  a complete, working script for almost exactly the task I was set.
- **"# CLI reference"** (line 4189) — `kelyfos team up`, `kelyfos log`.
- **"# MCP tools"** (line 4616) — the `team_ask` / `team_reply` argument shapes.

For the export requirement the CLI reference gives, under `## kelyfos log`:

> | `--export` | string | — | write a self-contained HTML report to this path |

and `teams.md` §8.1 confirms the team shape:

> `kelyfos log --export team.html` renders that same chain as **one lane per agent**, in
> boot order, with a message between two agents drawn as a bar spanning exactly the
> columns it connects — an ask points forward, a reply points back, a refusal is flagged
> and still drawn.

**Conclusion.** I did not have to invent an orchestrator. The recipe tagged
`<!-- recipe: three-agent-team -->` already boots master + worker-1 + worker-2, performs a
`team_ask` round trip and ends at `kelyfos log`. My script is that recipe, plus
`record_payloads = true` so bodies land in the record, plus a real `--export`.

This is worth saying plainly: **the single best thing in this documentation set is that
cookbook recipe.** It is the reason this exam passed in minutes rather than hours.

---

## Step 2 — write the orchestrator

Written to `~/exam/orchestrate.sh` (122 lines). The policy file it generates:

    [team]
    name = "exam"
    record_payloads = true

    [[team.agent]]
    name  = "master"
    image = "dev"

    [[team.agent]]
    name  = "worker"
    image = "dev"
    count = 2

    [[team.edge]]
    from = "master"
    to   = "worker-*"

    [team.store]
    enabled = true

Two decisions I had to take from prose rather than from the recipe:

1. **One edge block is enough for a two-way ask.** The config reference says of
   `[[team.edge]]`: "`bidirectional` | boolean | **true** | whether the far end may
   initiate too; a reply to an ask never needs an edge". So `master -> worker-*` also
   licenses `worker-1 -> master`, which is what the required ask depends on. Confirmed at
   runtime: `kelyfos team ps` printed all four edges.

2. **`record_payloads = true`.** Default is false, and `teams.md` §8 says "metadata and a
   hash, never the body". Left at the default, the exported transcript would prove a
   message of 39 bytes moved without showing what it said — true to the design, but a
   thin artifact for this exam.

---

## Step 3 — run it

    limactl shell kelyfos-dev -- bash -lc 'cd ~/exam && ./orchestrate.sh'

**It worked on the first attempt.** Exit 0. Abridged output:

    == booting the team ==
    team exam: 3 agents, 4 edges
      master       c9d8ba39 ready in 2495 ms
      worker-1     91d99655 ready in 2519 ms
      worker-2     1446af3c ready in 2529 ms
    team up in 2529 ms  (3 cold)

    AGENT     SANDBOX   BOOT  CPU/CAP  MEM/CAP      DISK WRITTEN  EGRESS  REACHES
    master    c9d8ba39  cold  2.7s/2c  37 MiB/512M  0 B           none    worker-1 worker-2
    worker-1  91d99655  cold  2.7s/2c  37 MiB/512M  0 B           none    master
    worker-2  1446af3c  cold  2.8s/2c  37 MiB/512M  0 B           none    master

    == who can master reach ==
    worker-1 worker-2

    == master hands worker-1 a task ==
    delivered to worker-1
    == worker-1 takes it ==
    count the regular files in /etc

    == worker-1 asks the master a question and BLOCKS on the answer ==
      master received: only regular files, or directories too?
      correlate tag:   93f3d11a90cbf622
    answered
      worker-1's blocked ask returned: regular files only

    == worker-1 does the work and publishes it to the team store ==
    11
    stored findings/worker-1
    counted, regular files only

    == an edge that was never declared is refused ==
    no_edge: this team has no edge from worker-1 to worker-2

    == the record ==
    12:01:04.470  team            master -> worker-1  send · 31 bytes · cb01d0da3d5d
    12:01:10.515  team            worker-1 ?> master  ask · 39 bytes · 3ea6fab5e638
    12:01:16.566  team            master <- worker-1  reply · 18 bytes · 00f60dc5ee1b
    12:01:35.579  team store      worker-1 put findings/worker-1  delivered
    12:01:38.597  team store      master get findings/worker-1  delivered
    12:01:41.614  team REFUSED    worker-1 -> worker-2  send · 4 bytes · 32c655bb8433 (no_edge)

    session 9c60808f: chain intact, 17 events verified across 3 agents (master, worker-1, worker-2)

    wrote /home/ioanniskapageridis.guest/exam/team-transcript.html (17 events, 14351 bytes)

All three requirements met: three agents booted; `worker-1` called `team_ask` and blocked
until `master` called `team_reply` with the matching `correlate` tag; the transcript was
exported to a file.

### Re-run, to prove it is reproducible

Second run, exit 0, session `bbdd2d88`, 17 events, chain intact, export 14384 bytes. The
boot path changed on its own:

    team exam: 3 agents, 4 edges
      template     dev, forking 3 from a cached template
      master       38c1bc81 ready in 344 ms  (forked)
      worker-1     64f5eb01 ready in 320 ms  (forked)
      worker-2     6323caf5 ready in 321 ms  (forked)
    team up in 345 ms  (3 forked from 1 cached template(s), 0 cold)

This is `teams.md` §7 behaving exactly as written — "**Cold-first, fork-warm.** With no
cached template, every agent boots cold ... The template is built afterwards, in the
background, while the team is already working; the next `team up` of the same shape forks
its no-egress workers from it." 2529 ms cold, then 345 ms forked. The documentation
predicted this and it happened. Credit where due.

---

## Step 4 — verify the exported transcript

    kelyfos log --json  |  filter type startswith "team"

The raw events confirm the schema, and reveal the first defect (gap 1):

    {"seq":5,"type":"team.message","data":"count the regular files in /etc","bytes":31,
     "sha256":"cb01d0da...","agent":"master","peer":"worker-1","kind":"send","outcome":"delivered"}
    {"seq":6,"type":"team.message","data":"only regular files, or directories too?","bytes":39,
     "agent":"worker-1","peer":"master","kind":"ask","outcome":"delivered"}
    {"seq":7,"type":"team.message","data":"regular files only","bytes":18,
     "agent":"master","peer":"worker-1","kind":"reply","outcome":"delivered"}
    {"seq":13,"type":"team.refused","reason":"no_edge","data":"psst","bytes":4,
     "agent":"worker-1","peer":"worker-2","kind":"send","outcome":"refused"}

The HTML export checks out against every claim §8.1 makes:

    grep -o -E "(src|href)=\"[^\"]*\"" team-transcript.html   -> no matches (genuinely self-contained)
    grep -c "count the regular files in /etc" team-transcript.html -> 2
    lane / master / worker-1 / worker-2 / no_edge / ask / reply all present

Title is `KelyfOS session 9c60808f`, dark theme, inlined CSS, no external fetches.

---

## Step 5 — probe the failure modes

Since the happy path passed first time, I spent the remaining budget deliberately breaking
things, to test whether the documentation describes what actually happens. Script:
`~/exam/probe.sh`, run against a live three-agent team.

| Probe | Result | Docs correct? |
| --- | --- | --- |
| `kelyfos mcp` / `exec` with no `--sandbox`, team up | `kelyfos: 3 sandboxes are running; pick one with --sandbox: [1e622bda 4f8162c3 8086e3b4]` | yes |
| `team_recv` empty window | `timeout: nothing arrived within 2s`, `isError: true` | yes, exactly |
| `team_send` to a non-existent agent | `no_such_agent: nobody is not in this team` | yes, exactly |
| `tools/list` on a worker with no spawn budget | 13 tools, `team_spawn` absent | yes, exactly |
| `log --session <agent sandbox id>` while up | `kelyfos: 4f8162c3 is agent "worker-1" in team session fa3e834b; showing the team's record` | yes, verbatim |
| `team_reply` with a bogus `correlate` | `denied: no question is outstanding with that correlation` | **no — gap 2** |
| blocking `team_ask`, channel closed early | **silence** | **no — gap 3** |
| documented config refusals (F-D20, `[team.resources] mem`) | refused with good prose | yes, but **gap 5** on the line number |

---

# Where the documentation let me down

Ordered by how much damage each would do to someone building from these docs.

## 1. `data` is documented as base64. It is not — it is plain text. (factually wrong)

The generated CLI/event reference, under `## team.message`:

> | `data` | string | base64 body *(record_payloads = true)* |

The actual event, from `kelyfos log --json`:

    "data": "count the regular files in /etc", "bytes": 31

Plain UTF-8, not base64. Anyone who trusts the reference writes a `base64.b64decode()` that
throws — and note this is the page that carries the banner "Generated by `make docs`. Do
not edit ... CI fails when this file disagrees with the source (F-D4)", so it is the page a
reader is most entitled to trust.

The narrative `events.md` gets it right — "`data` | string | The payload itself — **only**
when the team enabled capture" — so **the two documents in this same file contradict each
other**, and the wrong one is the generated one.

**Two further errors in the same reference table, `## team.refused`:**

- The table lists no `data` field at all, yet a refused message carries one:
  `{"type":"team.refused","reason":"no_edge","data":"psst",...}`.
- `bytes` is documented as "body size", but on an `unknown_correlation` refusal of a
  4-byte body (`"nope"`) the event recorded `"bytes": 0`. The `peer` field, documented as
  "the addressee it was not allowed to reach", is absent entirely on that event — the
  readable replay renders it as `master <-   reply` with a hole where the name goes.

## 2. The error a bad `correlate` returns is `denied`, which the error table says means something else

`teams.md` §3.8 "Errors are explicit" gives the vocabulary an agent receives:

> | `denied` | Store access this agent does not have, or a spawn it may not make. |

and both event references list `unknown_correlation` as a refusal reason. So a reader
expects a bad correlate to surface as `unknown_correlation`. What the agent actually gets:

    denied: no question is outstanding with that correlation

The *record* does say `unknown_correlation` — I checked: `{"seq":6,"type":"team.refused",
"reason":"unknown_correlation","agent":"master","kind":"reply","outcome":"refused"}`. So
there are two vocabularies, an agent-facing one and a record-facing one, they disagree for
this case, and §3.8 documents only the record's while presenting itself as the agent's.
Its `denied` row is wrong: `denied` also covers correlation failures.

This matters because §3.8's whole point is that a model should branch on the error kind.

## 3. A blocking tool whose channel closes early fails *silently* — and nothing warns you

This is the one I would fix first, because it is the trap the docs come closest to
describing and still leave you in.

The cookbook says, twice, in prose:

> Driving them by hand needs one helper, because MCP over stdio is newline-delimited
> JSON-RPC and a blocking tool answers when the other side acts, not when the request is
> sent.

That explains *why* the `call()` helper takes a "seconds to hold the channel open"
argument. It never says **what you see if you get it wrong**, and the answer is: nothing at
all. I issued a `team_ask` with `timeout_ms: 20000` and closed stdin after 1 s. Full output:

    kelyfos: attached to sandbox 4f8162c3
    {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25",...}}

No response to `id:2`. No error, no timeout, no non-zero exit. A builder writing their own
client — which is precisely what the "Building on KelyfOS" chapter invites — sees a tool
that returns nothing and concludes `team_ask` is broken.

Worse, the ask **was delivered and is recorded as such**: `{"seq":5,"type":"team.message",
"kind":"ask","outcome":"delivered"}`. And no event is ever written for the fact that it went
unanswered. `teams.md` §8.3 reassures the reader that "The recorder logs *outcomes*" and
that "a message appearing in the log is not evidence it was received — that is what the
outcome field is for" — but here the outcome field says `delivered` for a question nobody
ever answered, and the ask's actual outcome is recorded nowhere. Auditing that record, you
cannot tell the exchange failed.

Relatedly: `team_recv` timing out produced **no event whatsoever** (the record jumps from
seq 5 straight to seq 6). Yet both event references list `timeout` as a possible `outcome`
of `team.message`. Nothing in the docs says which timeouts are recorded and which are not.

**What the docs should say:** hold the channel open for at least the tool's own
`timeout_ms`; a closed transport is a silent drop, not an error; and here is which timeouts
reach the record.

## 4. The one file you need to build any orchestrator is mentioned once, inside a code block, with no schema

To call `kelyfos mcp --sandbox <id>` you need to map an agent *name* to a sandbox *id*.
`kelyfos team ps` prints them in an ASCII table and has **no flags** (confirmed: `kelyfos
team up --help` and the reference both) — so there is no machine-readable form. The only
other route is this, and this is its **sole appearance in 5017 lines**:

    a=json.load(open('$HOME/.cache/kelyfos/run/team.json'))['agents']

    $ grep -n "team\.json" llms-full.txt
    3274:a=json.load(open('$HOME/.cache/kelyfos/run/team.json'))['agents']

No prose introduces it, no section documents its schema, and it is not in the reference
alongside the flags and the toml keys. It appears as an argument to `json.load` inside a
bash function, in a recipe. Yet it is load-bearing for every team orchestrator anyone will
ever write.

I dumped it to find out what is actually in it:

    {"name":"probe","pid":387093,"session":"fa3e834b","started_at":"2026-08-23T15:04:26...",
     "agents":[{"name":"master","sandbox":"8086e3b4","via":"fork"}, ...],
     "edges":["master -> worker-1","master -> worker-2","worker-1 -> master","worker-2 -> master"]}

That is a genuinely useful, stable-looking interface — `session` in particular saves you
guessing at `--session` — and none of it is written down. The docs' own "Not written down
yet" section admits the neighbouring omission ("`KELYFOS_SANDBOX`, `KELYFOS_CACHE` and
`KELYFOS_CGROUP_ROOT` are read by the CLI and named nowhere") but does not list this one.

Either document `team.json`, or give `kelyfos team ps` a `--json` flag and point the
cookbook at it.

## 5. A refused config key reports the wrong line number

The config reference opens with a promise:

> Anything not listed here is an error naming the line — the file never skips a key it
> does not recognise.

For *unknown* keys this is exactly true — I checked two and both were spot on
(`nonsense_key` on line 10 reported `:10`; `nonsense_top` on line 5 reported `:5`).

But for a key that is *refused on purpose*, the line is wrong. Given this file:

         4  [[team.agent]]
         5  name = "b"
        ...
        12  [team.agent.resources]
        15  idle_timeout = "5m"

the error is:

    kelyfos: /tmp/.../kelyfos.toml:8: idle_timeout is not available per agent yet (F-D20)

Line 8 is the *second* `[[team.agent]]` header, not line 15 where the key is. It reports
the enclosing table header. In a long team file that is a materially unhelpful pointer.
(The `[team.resources] mem` refusal, by contrast, pointed at the right line.)

Credit: the message text itself is excellent, and the docs even predict the related
circularity — "Note the pair of refusals is currently circular: writing it under
`[team.resources]` tells you to move it to `[team.agent.resources]`, which then refuses
it." Known and disclosed. Only the line number is a surprise.

## 6. The performance numbers are off by ~20x on the platform `doctor` explicitly supports

`teams.md` §7:

> on the reference environment a cold boot is 109–134 ms and writing a 384 MiB memory
> image is 927 ms ... after it, a fork is 57–61 ms there

Measured here: cold boot **2495–2529 ms**, fork **320–344 ms**. Roughly 20x and 6x.

"On the reference environment" is an honest hedge and the *ratio* the docs care about held
perfectly (forking beat cold booting, as claimed). But `kelyfos doctor` prints
`platform  Lima VM (macOS host)` and passes every check, so this is a first-class supported
configuration, and a reader sizing a `--ready-timeout` or an SLA from those numbers will be
wrong by an order of magnitude. One sentence naming what the reference environment is, or a
second row for a macOS/Lima host, would fix it.

## 7. Minor: the cookbook's own MCP handshake uses a protocol version the server does not speak

The recipe sends:

    "protocolVersion":"2025-06-18"

The guest answers:

    "protocolVersion":"2025-11-25"

Harmless — MCP negotiates, and the recipe works — but the docs' canonical example is
pinned to a version the shipped server has moved past, which will read as a bug to anyone
comparing the two strings.

## 8. Minor: §8.1 reads as though the default `--session` stops working after `team down`

> After `team down` the run directories are gone, so the team session is found by its own
> id or with `kelyfos log --list`.

I read this as a warning that bare `kelyfos log --export` would fail after teardown, and
nearly wrote session-id plumbing I did not need. In fact "the most recent" still resolves
fine after `team down` — my script calls `kelyfos log --export` with no `--session` twice
and it works. The sentence is about *finding* a session that is no longer the most recent;
it reads like a constraint on the default. Worth a clause.

---

## What went right, since a report of only defects would misrepresent this

- The three-agent cookbook recipe ran essentially as written. That is rare.
- Every CLI flag in the reference exists, with the documented type and default. I diffed
  `kelyfos log --help` and `kelyfos team up --help` against the tables: exact match.
- Every MCP tool in the reference exists with the documented parameter names. `exec` took
  `command` exactly as specified; `tools/list` returned the documented 13 and correctly
  omitted `team_spawn` for an agent with no budget, as F-D18 promises.
- The refusal semantics are exactly as documented: `no_edge` on the undeclared worker→worker
  edge, `no_such_agent` for an unknown name, `timeout` as an *error* rather than an empty
  result from `team_recv` — all three matched their documented text nearly word for word.
- `log --verify` produced precisely the sentence §8.1 advertises, down to the shape:
  `session 9c60808f: chain intact, 17 events verified across 3 agents (master, worker-1, worker-2)`.
- The cold-first/fork-warm boot story in §7 is real and observable between two runs.
- The `--export` HTML is genuinely self-contained: zero external `src`/`href`.

---

## Addendum — two more defects, found reading the exported HTML itself

Extracted the text of `team-transcript.html` to check it against §8.1's description. The
export is good: it really does render one column per agent in boot order, with the bodies
inline, a verified-chain badge, per-agent usage receipts and the refusal drawn rather than
hidden. Two things are wrong.

## 9. The reply arrow points the wrong way in the Timeline view (contradicts §8.1)

`teams.md` §8.1 promises:

> an ask points forward, a **reply points back**, a refusal is flagged and still drawn

The same reply event is rendered two different ways in the same file. In **Team lanes**:

    12:05:50.168   master ← worker-1     reply · 18 bytes · sha256 00f60dc5ee1b

In **Timeline**, a few hundred lines down:

    12:05:50.168   master → worker-1     reply · 18 bytes · sha256 00f60dc5ee1b

The lanes view honours the documented rule; the Timeline view draws the reply pointing
forward, identically to a `send`. Since `master → worker-1` is also exactly how the
preceding `send` is drawn, the Timeline gives a reader no way to tell the direction of
the conversation. The lanes view is right and the Timeline is wrong.

## 10. The image name is empty for a team session

The summary card renders `image  · aarch64` with a hole, and the readable replay agrees:

    12:05:34.493  session start   image= arch=aarch64 kelyfos=v0.5-17-g65be6c6

`image=` is blank, even though all three agents declared `image = "dev"` and each
`session.ready` event carries `image dev` correctly. The export's header card also shows
`boot ms 0` for the same reason — there is no single boot for a team.

This is cosmetic, but it undercuts a claim the docs make twice, e.g. in "Common mistakes":

> The point is that the flavor in your audit trail is a checked fact rather than a label
> somebody typed.

For a team, the flavor is missing from the top-level audit record. It is recoverable from
the per-agent `session.ready` events, so nothing is lost — but the session header, which is
the first thing a reader looks at, is blank where it claims to be authoritative.

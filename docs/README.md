# KelyfOS documentation

Everything KelyfOS has written down, and an honest account of what it has not.

Two kinds of reader are expected here. A person reads for the shape of a design
and the reason behind it. A language model reads to write correct code on the
first attempt, which needs exact names, exact defaults and exact error strings.
Those need different things from a sentence, so every document below says which
kind it is, and this page says where each one is still thin.

The rule the directory is built on (F-D4): **the reference half is generated
from the source and CI fails on drift; hand-written prose is reserved for
concepts and recipes.** [`reference/`](reference/) is the generated half — every
command, flag, toml key, MCP tool, event type and exit code, extracted by
`make docs` and checked on every commit. The pages beside it are the
hand-written half, and this page says where each is still thin.

## Start here

| If you are… | Read, in order |
| --- | --- |
| trying it for the first time | the repository [`README.md`](../README.md) quickstart, then [`threat-model.md`](threat-model.md) before trusting it with anything |
| an LLM or an agent framework | [`../llms.txt`](../llms.txt) — an index per the llmstxt.org spec — or [`../llms-full.txt`](../llms-full.txt), which is every page below in one file, about 48,000 tokens |
| deciding how much machine an agent gets | [`resources.md`](resources.md) |
| running several agents together | [`teams.md`](teams.md) |
| auditing what an agent did | [`events.md`](events.md) |
| keeping an agent off the network | [`networking.md`](networking.md) |
| building KelyfOS into something else | [`protocol.md`](protocol.md), then [`e2b-shim.md`](e2b-shim.md) |
| judging whether to trust it | [`threat-model.md`](threat-model.md) |

## The map

| Document | Kind | What it answers |
| --- | --- | --- |
| [`reference/`](reference/) | **generated** | Every command, flag, `kelyfos.toml` key, MCP tool, event type and exit code, with types and defaults. Extracted from the source; CI fails on drift. |
| [`protocol.md`](protocol.md) | mixed | How the host and the guest talk: Firecracker's hybrid vsock, the port map, newline-delimited JSON framing, and every channel's message shape. |
| [`events.md`](events.md) | mixed | What the flight recorder writes: the common fields, the hash chain, and every event type with its payload. |
| [`networking.md`](networking.md) | mixed | Why a sandbox has no NIC by default, what `--allow` builds, the nftables template, and why the guest has no DNS. |
| [`resources.md`](resources.md) | mixed | Every resource cap: units, precedence, what enforces it, and what happens when it is reached. |
| [`teams.md`](teams.md) | mixed | The `[team]` schema, the host broker and its edge rules, the team store, the collective budget, and how a team boots. |
| [`threat-model.md`](threat-model.md) | concept | What KelyfOS defends against and — the longer half — what it does not. |
| [`e2b-shim.md`](e2b-shim.md) | mixed | The E2B-compatible REST subset: what it implements, what it does not, and why. |
| [`../llms.txt`](../llms.txt) | **generated** | The index a machine reads first: every page above as a link with a one-line description, per the llmstxt.org spec. |
| [`../llms-full.txt`](../llms-full.txt) | **generated** | Every page above concatenated, each with its source URL. About 48,000 tokens — a quarter of a 200k context window. |
| [`launch/hn-post.md`](launch/hn-post.md) | not documentation | The launch post draft. Unposted, and the maintainer's to send. |

The plan files at the repository root — [`PLAN.html`](../PLAN.html) for phases 0–4
and [`PLAN-FEATURES.html`](../PLAN-FEATURES.html) for the epics after them — are
**not** documentation. They are the build record: every task, every decision with
its rationale, and a progress log with the command output behind each claim. The
documents above cite them constantly (`D6`, `F-D19`, `E2-1`), and those citations
resolve there. [`STATUS.md`](../STATUS.md) is the current position in one page.

## What the kinds mean

**Concept.** Hand-written, and about a design or a trade-off. Nothing in the
source can confirm or refute it. Kept honest by review, and by the fact that the
code cites it back: 79 comments across 37 Go files name a document and a section,
so a section number here is load-bearing rather than decorative.

**Reference.** Statements of fact that also exist in the source — a port number,
a toml key, a default, an event field, an error string. Every one of these can
drift, and a drifted reference is worse than a missing one, because a model will
write confidently against it. Most of this half now lives in
[`reference/`](reference/), generated and CI-checked; what is left in the prose
below is the part no generator reaches, and it is named per document.

**Mixed.** Every document above except the threat model. The inventory names
which half of each is reference, so it is clear what a generator will eventually
own and what will always be someone's prose.

## The inventory

What each document is made of, and where it is thin. Compiled at E3-0 by reading
every document against the code it describes. The prose errors it turned up have
since been corrected, so what remains under *thin* is what is genuinely missing
rather than wrong — with one exception, called out where it appears:
`mode: tunnelled` on a plain-HTTP request understates what the proxy read, and
the documents now say so rather than repeating the claim.

### `protocol.md` — the wire

*Concept:* why the host side of vsock is a Unix socket and not a vsock one; why a
closed handshake must be retried; why the team channel runs guest→host; why the
MCP bridge must be a byte copier; what a snapshot's vsock reset does.
*Reference:* the port map, the `CONNECT`/`OK` strings, the framing limits, the
error-kind vocabulary, and every channel's field tables.
*Thin:* the kernel command line (`kelyfos.proxy`, `.workspace`, `.agent`,
`.spawn`, `.scratch`) is nowhere described as a set; the guest's default
environment is referred to and never listed; §6 defines MCP framing and not one
MCP tool; no timeout in the system is written down except the heartbeat.

### `events.md` — the audit record

*Concept:* why the host writes every event and the guest writes none; what
tamper-evidence buys and what it does not; why a refused message is its own type.
*Reference:* the common-field table, every per-type payload table, and the
canonical form the hash is computed over.
*Thin:* nothing material. The per-type field tables are the reference half and
E3-1 will take them over; until then they are hand-maintained and were last
checked against the emitters at E3-0.

### `networking.md` — egress

*Concept:* the deny-all posture, why the base chains are `policy accept`, why the
guest gets no DNS at all (D16), and what that costs.
*Reference:* the nftables template, the addressing, the boot arguments, the proxy
environment variables, the allowlist matching rule.
*Thin:* snapshot restore's re-pairing of a frozen NIC to a fresh TAP (D22) is
absent — the addressing is reproduced from the snapshot rather than re-derived,
the proxy re-binds the exact recorded port, and the host TAP's MAC is pinned so a
restored guest's stale ARP entry still resolves. None of that is written down.
The TLS-termination mechanism itself — the per-run CA, its 24-hour leaves, the
leaf cache — is still only named.

### `resources.md` — the caps

*Concept:* `cpus` caps parallelism while `cpu_quota` caps consumption — the
clearest passage in the directory; why refusing beats clamping; why a tmpfs cap is
an exception to host-side enforcement (F-D13); why a team's quotas may
oversubscribe.
*Reference:* the units table, the cap-to-mechanism table, the worked example, and
the two proof scripts.
*Thin:* a `[resources]` ceiling silently doubles as the default — writing
`cpus = 2` also chooses two — and the document frames the section purely as
ceilings; `[resources] cpus` is not checked for positivity; the per-agent
`max_runtime` path in a team behaves differently from the single-run one and only
the latter is described.

### `teams.md` — several agents at once

*Concept:* why there is no guest-to-guest network path at all; why a store rather
than shared memory or a shared disk; why the topology is fixed for a run;
cold-first, fork-warm and the measurements behind it (F-D25, F-D26).
*Reference:* the toml schema, the `team_*` tool list, the event types, the
template-cache key and its 2 GiB bound, the boot paths.
*Thin:* F-D20 and F-D21 refuse `idle_timeout` by pointing at each other, and
neither refusal mentions the other, so a user who follows the first message hits
the second; `[team.agent.spawn.resources]` accepts two keys nothing enforces
(F-D27); `team ps` has no sample output; the store's `not_found` is described as
"not a refusal" and is recorded as one.

### `threat-model.md` — what to trust

Concept throughout, deliberately, and the document the README sends a first-time
reader to.
*Thin:* nothing known. Brought to v0.5 at E3-0 — resource caps and what each
kind of cap is actually worth, teams as a deliberate data path between sandboxes,
the shim's unauthenticated port, and the two guarantees a shim sandbox does not
get.

### `e2b-shim.md` — the compatibility subset

*Concept:* why a subset rather than a clone, and why command execution is
deliberately out. *Reference:* the endpoint table.
*Thin:* request and response shapes, status codes and the 64 MiB upload limit
are undocumented — the endpoint table says what exists and not what it looks
like. The `E2B_API_KEY` value it tells you to export disagrees with the one
`kelyfos shim --help` prints.

## Not written down yet

The parts of the product with no documentation at all. Code-derived rather than
remembered, and the input to E3-1 — most of it disappears the moment the
reference is generated rather than typed.

Commands, flags, toml keys, MCP tools, event types and exit codes were all on
this list at E3-0 and are now in [`reference/`](reference/), extracted rather
than typed. What is still missing is what no generator reaches:

**The wire protocol's remaining corners.** The kernel command line as a set, the
guest's default environment, and every timeout in the system except the
heartbeat. `protocol.md` is hand-written and stays that way — it is a
specification, not a description.

**Snapshot restore's networking.** How a frozen NIC is re-paired to a fresh TAP
(D22) is in the code and in no document.

**Environment variables.** `KELYFOS_SANDBOX`, `KELYFOS_CACHE` and
`KELYFOS_CGROUP_ROOT` are read by the CLI and named nowhere. `KELYFOS_SANDBOX`
is the one an integrator needs, and E3-4 is its home.

**Recipes.** There is no cookbook and no integration guide. Those are E3-3 and
E3-4, and until they exist neither `llms.txt` nor `llms-full.txt` can offer a
worked example — which is the gap a machine reader will feel first.

## How these documents are kept true

1. **Generated where possible.** `make docs` regenerates
   [`reference/`](reference/) from the source and CI fails on any diff (F-D4,
   E3-1). A flag that exists cannot be missing from the reference, and a flag in
   the reference cannot be one that no longer exists. Three of the five pages are
   read straight out of the running product — the CLI's own `-h`, the
   supervisor's own `tools/list` — and the other two out of tables the product
   depends on, so there is no copy of the truth that only the documentation
   reads.
2. **Executed where possible.** Every cookbook recipe is a script CI runs from a
   fresh clone, so a recipe that stops working fails the build (E3-3).
3. **Examined by a reader with no other source.** A fresh agent is given the
   documentation and nothing else and asked to build something real; every
   failure becomes a documentation fix (E3-5).
4. **Shipped with the feature.** From E3 onward no epic closes until the
   generated reference, `llms-full.txt` and the recipes cover what it added
   (F-D9).

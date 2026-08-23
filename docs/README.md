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
command, flag, toml key, MCP tool, event type, exit code and refusal, extracted
by `make docs` and checked on every commit. The pages beside it are the
hand-written half, and this page says where each is still thin.

## Start here

| If you are… | Read, in order |
| --- | --- |
| trying it for the first time | the repository [`README.md`](../README.md) quickstart, then [`threat-model.md`](threat-model.md) before trusting it with anything |
| an LLM or an agent framework | [`../llms.txt`](../llms.txt) — an index per the llmstxt.org spec — or [`../llms-full.txt`](../llms-full.txt), which is every page below in one file, about 48,000 tokens |
| deciding how much machine an agent gets | [`resources.md`](resources.md) |
| running several agents together | [`teams.md`](teams.md) |
| auditing what an agent did | [`events.md`](events.md) |
| stuck on something KelyfOS refused | [`denials.md`](denials.md), then [`reference/denials.md`](reference/denials.md) for the exact one |
| keeping an agent off the network | [`networking.md`](networking.md) |
| after something that works, right now | [`cookbook.md`](cookbook.md) — eleven recipes, each one runnable as it stands |
| putting KelyfOS inside something else | [`integrating.md`](integrating.md) |
| building KelyfOS into something else | [`protocol.md`](protocol.md), then [`e2b-shim.md`](e2b-shim.md) |
| driving KelyfOS from an MCP client | [`mcp-surface.md`](mcp-surface.md) — `serve-mcp` and `[[plugin]]`, and [recipe 9](cookbook.md) for the configuration |
| judging whether to trust it | [`threat-model.md`](threat-model.md) |

## The map

| Document | Kind | What it answers |
| --- | --- | --- |
| [`reference/`](reference/) | **generated** | Every command, flag, `kelyfos.toml` key, MCP tool, event type, exit code and refusal, with types and defaults. Extracted from the source; CI fails on drift. |
| [`protocol.md`](protocol.md) | mixed | How the host and the guest talk: Firecracker's hybrid vsock, the port map, newline-delimited JSON framing, and every channel's message shape. |
| [`events.md`](events.md) | mixed | What the flight recorder writes: the common fields, the hash chain, every event type with its payload, and why `kelyfos runs` is the record read back rather than a second one. |
| [`networking.md`](networking.md) | mixed | Why a sandbox has no NIC by default, what `--allow` builds, the nftables template, and why the guest has no DNS. |
| [`resources.md`](resources.md) | mixed | Every resource cap: units, precedence, what enforces it, and what happens when it is reached. |
| [`teams.md`](teams.md) | mixed | The `[team]` schema, the host broker and its edge rules, the team store, the collective budget, and how a team boots. |
| [`denials.md`](denials.md) | mixed | Why every refusal names its own fix, what the ID in brackets is for, and what deliberately is not in the catalog. |
| [`qol.md`](qol.md) | concept | The v0.8 specification, written before the code: named sessions and their store, the workspace manifest, the PTY channel, and why inbound forwarding does not touch the firewall. |
| [`mcp-surface.md`](mcp-surface.md) | concept | MCP in both directions: `serve-mcp` as a tool for any client, and `[[plugin]]` servers inside the guest. Specification, written before the code. |
| [`threat-model.md`](threat-model.md) | concept | What KelyfOS defends against and — the longer half — what it does not. |
| [`cookbook.md`](cookbook.md) | recipes | Eleven complete, copy-pasteable recipes. Every one is a script CI extracts and runs on a real machine. |
| [`integrating.md`](integrating.md) | mixed | For building on KelyfOS: the four ways in, orchestrator patterns, and a long list of the mistakes people actually make. |
| [`e2b-shim.md`](e2b-shim.md) | mixed | The E2B-compatible REST subset: what it implements, what it does not, and why. |
| [`../llms.txt`](../llms.txt) | **generated** | The index a machine reads first: every page above as a link with a one-line description, per the llmstxt.org spec. |
| [`../llms-full.txt`](../llms-full.txt) | **generated** | Every page above concatenated, each with its source URL. About 54,000 tokens — a quarter of a 200k context window. |
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
tamper-evidence buys and what it does not; why a refused message is its own type;
why the run history is the records read back and never a second index, and what
a rerun has to carry to deserve the name.
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

### `denials.md` — why a refusal names its fix

*Concept:* why a refusal is three parts and not one; why the ID is stable when
the prose is not; why a failure is deliberately not a refusal; why a fix line may
name the edit and never make it (F-D5).
*Reference:* none of it — the catalog itself is generated to
[`reference/denials.md`](reference/denials.md), and this page links to it rather
than repeating it, which is the arrangement E3-1 exists to make possible.
*Thin:* nothing material. The catalog covers every refusal the product makes,
which is checked by the build rather than by reading (`make docs` fails when an
entry is raised nowhere), and E5-5 added its own the moment forwarding existed.

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

### `cookbook.md` — eleven things that work

*Recipes:* one sandbox; an allowlist and an injected credential; a workspace
round-trip; snapshot and fork; a three-agent team with an ask round-trip and a
refused edge; reading and verifying the record, including watching one altered
byte break the chain; driving a sandbox from the E2B SDK; an orchestrator built
on the official MCP Python SDK; the configuration that points Claude Code and
VS Code at `serve-mcp`, checked by running exactly what each file names; and the
same SDK driving the host rather than a guest, ending in the record the server
kept of its own calls; and both MCP directions at once, with a plugin written out
in full, ending in the two transcripts that hold what each side did.
*Thin:* nothing hidden — every script is extracted and executed by
`dev/cookbook.sh` and by the `cookbook` workflow, so a recipe that stops working
fails rather than misleading anyone.

### `integrating.md` — for building on it

*Concept:* which of the four ways in to choose and what each one costs you;
why `run -- <command>` is the shape to build on; what KelyfOS will not do for
you. *Reference:* the error messages in the common-mistakes section, quoted so
that searching for one lands here.
*Thin:* it prints no JavaScript client, because nothing in this repository
executes one and a transcribed snippet is the failure F-D4 exists to prevent.
What it gives instead is the client configuration, which is verified, and the
wire shape, which the cookbook demonstrates.

### `mcp-surface.md` — MCP in both directions

*Concept throughout.* It was written before the code, the way `teams.md` was at
E2-0, and has been reconciled with what got built: the policy-ceiling invariant
and what it rules out, the outward tool list, the session and concurrency model,
the plugins drive and its manifest, the namespacing rule with the evidence behind
it, and the audit lane in each direction.
*Thin:* the tool schemas and the event fields are in
[`reference/`](reference/), generated from the product; this page explains why
they are that shape. Where it and the code disagree, the code is right and the
page is a bug — the E4 exit exam found four such places and they are listed in
[`exam/2026-08-23-mcp-surface.md`](exam/2026-08-23-mcp-surface.md).

### `qol.md` — the v0.8 specification

*Concept throughout, and written before the code exists*, the way `teams.md` was
at E2-0 and `mcp-surface.md` was at E4-0: the four pieces of Epic E5 whose shape
has to be agreed in advance — the named-session store and its frozen policy, the
workspace manifest two commands share, the PTY channel as an additive protocol
revision, and the vsock transport that lets inbound forwarding exist without a
single nftables rule.
*Thin:* it describes nothing that runs yet, and says so. The four features that
are wrappers over existing machinery are not in it, because there is nothing to
decide about them.

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

**A JavaScript client that has been run.** [`integrating.md`](integrating.md)
covers the configuration route and the wire format, and deliberately prints no
TypeScript SDK code, because nothing here executes any. Closing that means
adding Node to the cookbook's environment, which is a real cost for one recipe
and has not been paid.

## How these documents are kept true

1. **Generated where possible.** `make docs` regenerates
   [`reference/`](reference/) from the source and CI fails on any diff (F-D4,
   E3-1). A flag that exists cannot be missing from the reference, and a flag in
   the reference cannot be one that no longer exists. Three of the five pages are
   read straight out of the running product — the CLI's own `-h`, the
   supervisor's own `tools/list` — and the other two out of tables the product
   depends on, so there is no copy of the truth that only the documentation
   reads.
2. **Executed where possible.** Every recipe in
   [`cookbook.md`](cookbook.md) is a script, extracted rather than transcribed,
   run on a real machine by the `cookbook` workflow (E3-3). Every commit checks
   that they still extract and are still valid shell; the weekly run checks that
   they still work.
3. **Examined by a reader with no other source.** A fresh agent is given the
   documentation and nothing else and asked to build something real; every
   failure becomes a documentation fix (E3-5).
4. **Shipped with the feature.** From E3 onward no epic closes until the
   generated reference, `llms-full.txt` and the recipes cover what it added
   (F-D9).

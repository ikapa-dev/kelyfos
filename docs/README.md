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
| an LLM or an agent framework | [`../llms.txt`](../llms.txt) — an index per the llmstxt.org spec — or [`../llms-full.txt`](../llms-full.txt), which is every page below in one file — `llms.txt` states its current size |
| deciding how much machine an agent gets | [`resources.md`](resources.md) |
| running several agents together | [`teams.md`](teams.md) |
| auditing what an agent did | [`events.md`](events.md) |
| auditing what a run was *permitted* to do, not only what it did | [`policy-record.md`](policy-record.md) |
| deciding how long records are kept, or erasing what one holds | [`retention.md`](retention.md) |
| feeding a run into Jaeger, Tempo or an OTel Collector | [`otlp.md`](otlp.md) — `kelyfos log --export-otlp` |
| stuck on something KelyfOS refused | [`denials.md`](denials.md), then [`reference/denials.md`](reference/denials.md) for the exact one |
| running something long and walking away | [`denials.md`](denials.md) on `--notify`, and [`events.md`](events.md) §6 for the history afterwards |
| keeping an agent off the network | [`networking.md`](networking.md) |
| after something that works, right now | [`cookbook.md`](cookbook.md) — twenty recipes, each one runnable as it stands |
| putting KelyfOS inside something else | [`integrating.md`](integrating.md) |
| building KelyfOS into something else | [`protocol.md`](protocol.md), then [`e2b-shim.md`](e2b-shim.md) |
| driving KelyfOS from an MCP client | [`mcp-surface.md`](mcp-surface.md) — `serve-mcp` and `[[plugin]]`, and [recipe 9](cookbook.md) for the configuration |
| judging whether to trust it | [`threat-model.md`](threat-model.md), then [`hardening.md`](hardening.md) for what v0.9 added |
| what the VMM process itself may ask the host kernel for | [`host-seccomp.md`](host-seccomp.md) — every syscall the filter permits, read out of a running machine |

## The map

| Document | Kind | What it answers |
| --- | --- | --- |
| [`compatibility.md`](compatibility.md) | hand | **The promise that makes this a 1.0**: which surfaces do not move, which are explicitly allowed to, what a major, minor and patch mean here and what they attach to, and how something is deprecated before it is removed. |
| [`reference/`](reference/) | **generated** | Every command, flag, `kelyfos.toml` key, MCP tool, event type, exit code, refusal and guest confinement profile, with types and defaults. Extracted from the source; CI fails on drift. |
| [`protocol.md`](protocol.md) | mixed | How the host and the guest talk: Firecracker's hybrid vsock, the port map, newline-delimited JSON framing, and every channel's message shape. |
| [`events.md`](events.md) | mixed | What the flight recorder writes: the common fields, the hash chain, every event type with its payload, how an exported report carries its own record so its reader can re-run the chain, and why `kelyfos runs` is the record read back rather than a second one. |
| [`networking.md`](networking.md) | mixed | Why a sandbox has no NIC by default, what `--allow` builds, the nftables template, and why the guest has no DNS. |
| [`resources.md`](resources.md) | mixed | Every resource cap: units, precedence, what enforces it, and what happens when it is reached. |
| [`teams.md`](teams.md) | mixed | The `[team]` schema, the host broker and its edge rules, the team store, the collective budget, and how a team boots. |
| [`denials.md`](denials.md) | mixed | Why every refusal names its own fix, what the ID in brackets is for, what deliberately is not in the catalog, and how `--notify` reaches somebody who stopped watching. |
| [`qol.md`](qol.md) | concept | The v0.8 specification, written before the code: named sessions and their store, the workspace manifest, the PTY channel, and why inbound forwarding does not touch the firewall. |
| [`policy-record.md`](policy-record.md) | concept | The Phase 7 policy-record specification, written before the code: every field `session.policy` and `team.topology` add, its position in the frozen hash order, which of the eight doors writes it, and what it deliberately omits. |
| [`retention.md`](retention.md) | mixed | P7-5 (D61): the `[sessions] retention_days` floor, `kelyfos sessions prune`, the size warning, and `kelyfos sessions erase` — the replacement-record pattern that lets an EU AI Act Article 12 retention floor and a GDPR Article 17 erasure request coexist by separating a chain's structure from its content. |
| [`otlp.md`](otlp.md) | mixed | P7-11: how `kelyfos log --export-otlp` maps a session's chain to OTLP-JSON spans, why that mapping is versioned apart from the flight recorder and never an input to `kelyfos verify`, what is deliberately not mapped, and why the IETF `agent-audit-trail` draft's own mapping is ready rather than shipped. |
| [`mcp-surface.md`](mcp-surface.md) | concept | MCP in both directions: `serve-mcp` as a tool for any client, and `[[plugin]]` servers inside the guest. Specification, written before the code. |
| [`hardening.md`](hardening.md) | concept | The v0.9 specification, written before the code: what a compromised agent reaches today, what the jailer and the guest profiles take away, and what remains reachable afterwards. |
| [`host-seccomp.md`](host-seccomp.md) | mixed | The syscall filter around the VMM process: which one is in force and why that is settled, how it is proved from the kernel's own copy rather than from the absence of a flag, and every syscall it permits. |
| [`threat-model.md`](threat-model.md) | concept | What KelyfOS defends against and — the longer half — what it does not. |
| [`cookbook.md`](cookbook.md) | recipes | Twenty complete, copy-pasteable recipes. Every one is a script CI extracts and runs on a real machine. |
| [`integrating.md`](integrating.md) | mixed | For building on KelyfOS: the four ways in, orchestrator patterns, and a long list of the mistakes people actually make. |
| [`e2b-shim.md`](e2b-shim.md) | mixed | The E2B-compatible REST subset: what it implements, what it does not, and why. |
| [`../llms.txt`](../llms.txt) | **generated** | The index a machine reads first: every page above as a link with a one-line description, per the llmstxt.org spec. |
| [`../llms-full.txt`](../llms-full.txt) | **generated** | Every page above concatenated, each with its source URL. Its size is *estimated* by `make docs` and printed in `llms.txt`, rather than repeated here — because a hand-typed count is exactly the kind of number that goes stale quietly, and this one had: it said 101,000 while the generator said 108,000. |
| [`launch/hn-post.md`](launch/hn-post.md) | not documentation | The launch post draft. Unposted, and the maintainer's to send. |

The plan files at the repository root — [`PLAN.html`](../PLAN.html) for phases 0–6
and [`PLAN-FEATURES.html`](../PLAN-FEATURES.html) for epics E1–E5 — are
**not** documentation. They are the build record: every task, every decision with
its rationale, and a progress log with the command output behind each claim. The
documents above cite them constantly (`D6`, `F-D19`, `E2-1`), and those citations
resolve there. [`STATUS.md`](../STATUS.md) is the current position in one page.

## What the kinds mean

**Concept.** Hand-written, and about a design or a trade-off. Nothing in the
source can confirm or refute it. Kept honest by review, and by the fact that the
code cites it back: 111 comments across 62 Go files name a document and a
section, so a section number here is load-bearing rather than decorative. That
count is `grep -rn -E '[a-z-]+\.md §' --include='*.go' .`, given as a rule
because a hand-typed number on this page has gone stale before.

**Reference.** Statements of fact that also exist in the source — a port number,
a toml key, a default, an event field, an error string. Every one of these can
drift, and a drifted reference is worse than a missing one, because a model will
write confidently against it. Most of this half now lives in
[`reference/`](reference/), generated and CI-checked; what is left in the prose
below is the part no generator reaches, and it is named per document.

**Mixed.** Both halves in one document — the label the map gives a document
that is neither *concept*, *hand*, *recipes*, *generated* nor *not
documentation*. The inventory names which half of
each is reference, so it is clear what a generator will eventually own and what
will always be someone's prose.

**Hand, recipes and not documentation.** The map's three remaining labels.
*Hand* is [`compatibility.md`](compatibility.md), hand-written like a concept
document but normative rather than explanatory — a promise about what moves, not
an account of why. *Recipes* is [`cookbook.md`](cookbook.md), which is extracted
scripts with prose around them rather than prose with examples in it. *Not
documentation* is the launch post, which is neither.

## The inventory

What each document is made of, and where it is thin. Compiled at E3-0 by reading
every document against the code it describes. The prose errors it turned up have
since been corrected, so what remains under *thin* is what is genuinely missing
rather than wrong — with one exception, called out where it appears:
`mode: tunnelled` on a plain-HTTP request understates what the proxy read, and
the documents now say so rather than repeating the claim.

### `compatibility.md` — the promise

*Concept:* what each of the three version constants attaches to and why they are
not kept in lockstep; why a denial identifier is inside the promise and a guest
confinement profile is deliberately outside it; why a security fix that must
narrow a surface is not a patch; and why the MCP revision is somebody else's to
number.
*Reference:* none of it — §2 cites the page that pins each surface rather than
re-listing it, so six of the seven cannot go stale by the mechanism that already
keeps the reference honest (F-D4). The seventh is the host↔guest protocol, whose
page is hand-written and checked by no drift gate; the promise says so itself
rather than letting the citation imply otherwise.
*Thin:* it is normative from v1.0 and this repository is at v0.9, so nothing in
it binds yet. §4's deprecation mechanism has not been used: `vcpus`, which
`kelyfos run` describes as an alias kept so v0.3 command lines keep working, is
still accepted in silence by both the flag and `kelyfos.toml`.

### `protocol.md` — the wire

*Concept:* why the host side of vsock is a Unix socket and not a vsock one; why a
closed handshake must be retried; why the team channel runs guest→host; why the
MCP bridge must be a byte copier; what a snapshot's vsock reset does.
*Reference:* the port map, the `CONNECT`/`OK` strings, the framing limits, the
error-kind vocabulary, and every channel's field tables.
*Thin:* the kernel command line (`kelyfos.proxy`, `.workspace`, `.agent`,
`.spawn`, `.scratch`) is nowhere described as a set; the guest's default
environment is referred to and never listed; §6 defines MCP framing and not one
MCP tool.

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
ceilings; the per-agent `max_runtime` path in a team behaves differently from the
single-run one and only the latter is described.

### `denials.md` — why a refusal names its fix

*Concept:* why a refusal is three parts and not one; why the ID is stable when
the prose is not; why a failure is deliberately not a refusal; why a fix line may
name the edit and never make it (F-D5); why a notification is best effort, is
data rather than script, and is off until asked for.
*Reference:* none of it — the catalog itself is generated to
[`reference/denials.md`](reference/denials.md), and this page links to it rather
than repeating it, which is the arrangement E3-1 exists to make possible.
*Thin:* the catalog covers every refusal that carries an ID, and the build checks
that each entry is raised somewhere (`make docs` fails when one is not). What it
does not cover is the refusals raised while reading `kelyfos.toml` or validating
a team plan: those name their own file and line instead of an ID, deliberately,
because the thing to look at is the line you wrote — but it means "every refusal"
was too strong, and `denial.Of` does not recognise them.

### `teams.md` — several agents at once

*Concept:* why there is no guest-to-guest network path at all; why a store rather
than shared memory or a shared disk; why the topology is fixed for a run;
cold-first, fork-warm and the measurements behind it (F-D25, F-D26).
*Reference:* the toml schema, the `team_*` tool list, the event types, the
template-cache key and its 2 GiB bound, the boot paths.
*Thin:* F-D20 and F-D21 refuse `idle_timeout` by pointing at each other, and
neither refusal mentions the other, so a user who follows the first message hits
the second; `team ps` has no sample output; the store's `not_found` is described as
"not a refusal" and is recorded as one.

### `cookbook.md` — twenty things that work

*Recipes:* one sandbox; an allowlist and an injected credential; a workspace
round-trip; snapshot and fork; a three-agent team with an ask round-trip and a
refused edge; reading and verifying the record, including watching one altered
byte break the chain and checking an exported report the way its recipient
would; driving a sandbox from the E2B SDK; an orchestrator built
on the official MCP Python SDK; the configuration that points Claude Code and
VS Code at `serve-mcp`, checked by running exactly what each file names;
`kelyfos connect` writing that same configuration into the client's own file and
`--check` proving it by completing a real handshake; and the
same SDK driving the host rather than a guest, ending in the record the server
kept of its own calls; and both MCP directions at once, with a plugin written out
in full, ending in the two transcripts that hold what each side did; pausing a
machine and picking the same one up with its scratch intact, under the policy it
was frozen with; seeing what an agent changed before keeping it, including what
`--review` does when there is nobody to ask; reaching a server inside a
sandbox that has no network, including how to start a long-running process
through `kelyfos exec` without hanging on it; a team's declared topology,
drawn with nothing booted and then confirmed to match the same team once it
is actually running (`team graph`, `team ps --graph`); exporting the same
chain as OTLP-JSON, with its span names and shape checked out of the file
rather than eyeballed; and exporting a report against a team that has not
stopped, `--refresh` rewriting it atomically on a clock so an open browser
tab follows along through its own `<meta http-equiv="refresh">` — checked
for the one property that matters, that the process doing the rewriting
holds no socket at all.
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
*Thin:* written before its code, and the code has since answered it — §1.1 and
§2.2 carry "corrected after the epic" notes where the built thing differed from
the plan. The four features that are wrappers over existing machinery are not in
it, because there was nothing to decide about them.

### `policy-record.md` — the Phase 7 specification

*Concept, written before the code*, the way `qol.md` was at E5-0 and
`hardening.md` was at P5-0: why `session.policy` rides `session.ready` rather
than `session.start` (and how that reuses the rule `events.md`'s own
`session.start` entry already states), the eight doors that open a chain
audited against the current source, the field tables for both new event
types, and — the longer half — what deliberately did not make the cut and
why.
*Reference:* none — every field it names is generated to
[`reference/events.md`](reference/events.md) once P7-2/P7-3 land.
*Thin:* written before its code exists; nothing to report yet.

### `retention.md` — retention, pruning and erasure

*Mixed, and written after the code rather than before it* — P7-0's own scope
note left this decision for P7-5 to make against a real mechanism, unlike
`policy-record.md`'s. *Concept:* why a retention floor and an erasure
request are not actually in tension once the record's structure and its
content are separated; why age is measured by directory mtime rather than a
`session.end` timestamp; why the two guards (a paused session, a live-looking
run directory) apply identically to `prune` and `erase`; what `erase`
deliberately does not redact and why.
*Reference:* the `[sessions] retention_days` key is in
[`reference/config.md`](reference/config.md); the `session.erasure` event is
in [`reference/events.md`](reference/events.md). `kelyfos sessions prune`
and `erase`'s own flags are not in [`reference/cli.md`](reference/cli.md) —
like `sessions rm`, they are subcommands of `kelyfos sessions` rather than
top-level commands, and the generator's discovery only reaches the
top-level usage block; `-h` on each, and this page, are where their flags
are written down.
*Thin:* written once, against the code that already existed; nothing to
report yet.

### `otlp.md` — mapping the chain to a standard, without adopting it

*Mixed, written after the code, the same way `retention.md` was*: this is a
projection off an already-frozen record, so there was no field to specify
ahead of a real mapping. *Concept:* why the OTLP export is versioned apart
from the flight recorder and never an input to `kelyfos verify` (D59); which
`gen_ai.*` attributes this mapping uses and which two it deliberately skips
(`gen_ai.provider.name`, `gen_ai.tool.type`) because KelyfOS has no honest
value for either; how an inbound W3C `traceparent` on `session.policy`
continues an existing trace instead of starting a new one; why the IETF
`agent-audit-trail` draft's own mapping is ready — the same `digest.Walk` plus
per-agent/per-command grouping this package already does — rather than
shipped, and what specifically about that draft (a `trust_level` scale and an
`action_type` enum with no KelyfOS equivalent) makes shipping it now a
guess rather than a mapping.
*Reference:* none — `--export-otlp` itself is a flag on `kelyfos log`, in
[`reference/cli.md`](reference/cli.md); the shape it writes is OTLP's own,
not this project's, so there is nothing of this project's own schema for a
generator to extract.
*Thin:* written once, against the code that already existed; nothing to
report yet.

### `hardening.md` — the v0.9 specification

*Concept:* what a compromised agent can reach today, stated before anything is
built so the README sentence at the end of the phase can be checked against it;
why every entry point goes through the jailer or none does; why the host
seccomp filter is to be proved rather than written; why a profile that cannot be
applied refuses rather than degrades; and a longer §5 on what is still reachable
afterwards.
*Reference:* none — every mechanism it names is documented where it is
implemented.
*Thin:* it was written before its code, and the code has since answered it: §3
and §4 carry "written after P5-2/P5-3" notes where the built thing went further
than the specification asked, and §4.4 records a protection nobody asked for.
The sentence it exists to replace was replaced at P5-4, in both places the README
carried it.

### `host-seccomp.md` — the wall around the VMM process

*Mixed:* which filter is in force and the single argument that settles it — that
KelyfOS passes neither `--no-seccomp` nor `--seccomp-filter`, kept true by a test
rather than by care; how the mode is read from `/proc` on every thread of the
VMM and a machine without it refused; and the full permitted set for each of the
three thread filters, produced by pulling the installed program back out of the
kernel and interpreting it.
*Reference:* `dev/expect/host-seccomp-<arch>.txt` is the machine-checked copy the
acceptance diffs a live VMM against; this page is written from it.
*Thin:* the conditions on argument-conditioned syscalls are quoted from
Firecracker's published filter rather than read out of the program — the probe
reports that a condition exists, not what it is. Nothing turns on the difference
today, and the page says so where it matters.

### `threat-model.md` — what to trust

Concept throughout, deliberately, and the document the README sends a first-time
reader to.
*Thin:* nothing known. Brought to v0.9 at P5-4, where §3 gained the two layers
this release adds and §4 — the longer half — gained what each of them does *not*
do: a chroot is not a boundary, the VMM shares your uid, the guest profile is a
refusal list and not an allowlist, and an older image or snapshot has neither.
It was brought to v0.5 at E3-0 before that, for resource caps, teams as a
deliberate data path, and the shim's unauthenticated port.

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

**The wire protocol's remaining corners.** The kernel command line as a set and
the guest's default environment. `protocol.md` is hand-written and stays that
way — it is a specification, not a description.

**Snapshot restore's networking.** How a frozen NIC is re-paired to a fresh TAP
(D22) is in the code and in no document.

**Environment variables.** `KELYFOS_CACHE`, `KELYFOS_CGROUP_ROOT` and
`KELYFOS_CONNECT_HOME` — the last of which relocates where `kelyfos connect`
writes per-user client configuration, for tests and for anybody generating a
configuration for a machine that is not this one — are read by the CLI and named
nowhere. `KELYFOS_SANDBOX` is covered in [`integrating.md`](integrating.md) and
the cookbook, but has no entry in the generated reference; E3-4 is its home.

**A JavaScript client that has been run.** [`integrating.md`](integrating.md)
covers the configuration route and the wire format, and deliberately prints no
TypeScript SDK code, because nothing here executes any. Closing that means
adding Node to the cookbook's environment, which is a real cost for one recipe
and has not been paid.

## How these documents are kept true

1. **Generated where possible.** `make docs` regenerates
   [`reference/`](reference/) from the source and CI fails on any diff (F-D4,
   E3-1). A flag that exists cannot be missing from the reference, and a flag in
   the reference cannot be one that no longer exists. Three of the seven pages are
   read straight out of the running product — the CLI's own `-h`, the
   supervisor's own `tools/list`, and its `--dump-profile` — and the other four
   out of tables the product depends on, so there is no copy of the truth that only the documentation
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

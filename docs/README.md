# KelyfOS documentation

Everything KelyfOS has written down, and an honest account of what it has not.

Two kinds of reader are expected here. A person reads for the shape of a design
and the reason behind it. A language model reads to write correct code on the
first attempt, which needs exact names, exact defaults and exact error strings.
Those need different things from a sentence, so every document below says which
kind it is, and this page says where each one is still thin.

The rule the directory is built on (F-D4): **the reference half is generated
from the source and CI fails on drift; hand-written prose is reserved for
concepts and recipes.** That machinery arrives with E3-1 and E3-3. Until it
does, everything here is hand-written, and its gaps are listed on this page
rather than left to be discovered.

## Start here

| If you are… | Read, in order |
| --- | --- |
| trying it for the first time | the repository [`README.md`](../README.md) quickstart, then [`threat-model.md`](threat-model.md) before trusting it with anything |
| an LLM or an agent framework | this page and the map below. `llms.txt` / `llms-full.txt` at the repository root — the whole product in one file — arrive with E3-2. |
| deciding how much machine an agent gets | [`resources.md`](resources.md) |
| running several agents together | [`teams.md`](teams.md) |
| auditing what an agent did | [`events.md`](events.md) |
| keeping an agent off the network | [`networking.md`](networking.md) |
| building KelyfOS into something else | [`protocol.md`](protocol.md), then [`e2b-shim.md`](e2b-shim.md) |
| judging whether to trust it | [`threat-model.md`](threat-model.md) |

## The map

| Document | Kind | What it answers |
| --- | --- | --- |
| [`protocol.md`](protocol.md) | mixed | How the host and the guest talk: Firecracker's hybrid vsock, the port map, newline-delimited JSON framing, and every channel's message shape. |
| [`events.md`](events.md) | mixed | What the flight recorder writes: the common fields, the hash chain, and every event type with its payload. |
| [`networking.md`](networking.md) | mixed | Why a sandbox has no NIC by default, what `--allow` builds, the nftables template, and why the guest has no DNS. |
| [`resources.md`](resources.md) | mixed | Every resource cap: units, precedence, what enforces it, and what happens when it is reached. |
| [`teams.md`](teams.md) | mixed | The `[team]` schema, the host broker and its edge rules, the team store, the collective budget, and how a team boots. |
| [`threat-model.md`](threat-model.md) | concept | What KelyfOS defends against and — the longer half — what it does not. |
| [`e2b-shim.md`](e2b-shim.md) | mixed | The E2B-compatible REST subset: what it implements, what it does not, and why. |
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
write confidently against it. E3-1 moves this half into generated files behind a
CI drift gate.

**Mixed.** Every document above except the threat model. The inventory names
which half of each is reference, so it is clear what a generator will eventually
own and what will always be someone's prose.

## The inventory

What each document is made of, and where it is thin. Compiled at E3-0 by reading
every document against the code it describes.

### `protocol.md` — the wire

*Concept:* why the host side of vsock is a Unix socket and not a vsock one; why a
closed handshake must be retried; why the team channel runs guest→host; why the
MCP bridge must be a byte copier; what a snapshot's vsock reset does.
*Reference:* the port map, the `CONNECT`/`OK` strings, the framing limits, the
error-kind vocabulary, and every channel's field tables.
*Thin:* the team channel's `spawn` op and almost all of its response fields are
absent, including the `agent` name the host returns and the guest is required to
prefer; §1.6 and §5.1 both omit `team` from their channel lists; the kernel
command line (`kelyfos.proxy`, `.workspace`, `.agent`, `.spawn`, `.scratch`) is
nowhere described as a set; the guest's default environment is referred to and
never listed; §6 defines MCP framing and not one MCP tool; §8's conformance table
has no row for the team channel.

### `events.md` — the audit record

*Concept:* why the host writes every event and the guest writes none; what
tamper-evidence buys and what it does not; why a refused message is its own type.
*Reference:* the common-field table, every per-type payload table, and the
canonical form the hash is computed over.
*Thin:* the `egress.attempt` reason vocabulary lists two values the code never
emits and omits four it does; §2 describes the canonical field order as this
document's order when it is the Go struct's, which is what an independent
verifier would have to reproduce; the list of types carrying an `agent` field is
shorter than reality; `kelyfos log --json` is missing from §5.

### `networking.md` — egress

*Concept:* the deny-all posture, why the base chains are `policy accept`, why the
guest gets no DNS at all (D16), and what that costs.
*Reference:* the nftables template, the addressing, the boot arguments, the proxy
environment variables, the allowlist matching rule.
*Thin:* the oldest document here, and the only one untouched since the task that
wrote it. Its diagram gives the wrong address range. The TLS termination the rest
of the document leans on is one clause; the five CA-bundle variables the guest is
given are absent; snapshot restore's re-pairing of a frozen NIC to a fresh TAP
(D22) is absent; per-agent allowlists inside a team are absent. D6 made
documenting the certificate-pinning limitation *here* a binding condition, and it
is documented in `threat-model.md` instead.

### `resources.md` — the caps

*Concept:* `cpus` caps parallelism while `cpu_quota` caps consumption — the
clearest passage in the directory; why refusing beats clamping; why a tmpfs cap is
an exception to host-side enforcement (F-D13); why a team's quotas may
oversubscribe.
*Reference:* the units table, the cap-to-mechanism table, the worked example, and
the two proof scripts.
*Thin:* `disk` is described as the size of the `/work` device and is really a
ceiling on the packed image, which matters because the device is 2× the directory
or 1 GiB whatever `disk` says; `--mem 512` and `mem = 512` do not mean the same
thing and the asymmetry is unstated; a `[resources]` ceiling silently doubles as
the default; §"What is live today" still says parts are being built above a table
in which everything is enforced; the F-D20 lift condition it names has been met.

### `teams.md` — several agents at once

*Concept:* why there is no guest-to-guest network path at all; why a store rather
than shared memory or a shared disk; why the topology is fixed for a run;
cold-first, fork-warm and the measurements behind it (F-D25, F-D26).
*Reference:* the toml schema, the `team_*` tool list, the event types, the
template-cache key and its 2 GiB bound, the boot paths.
*Thin:* it counts the guest's team tools as six and there are eight; the wait
argument is `timeout_ms` in milliseconds, not `timeout`; `team_recv` is said to
return nothing on an empty window and actually returns a `timeout` error; a
spawned worker's total absence of egress, secrets and workspace is never stated;
F-D20 and F-D21 refuse `idle_timeout` by pointing at each other, and neither
refusal mentions the other.

### `threat-model.md` — what to trust

Concept throughout, deliberately, and the document the README sends a first-time
reader to.
*Thin:* stamped "current as of v0.2", two releases ago. Its denial-of-service
section says there is no rate limiting and no cgroup enforcement, both of which
v0.4 added. The team broker, the team store, spawn budgets and per-agent policy
have no paragraph. The shim's unauthenticated local port has none either. Its
section on snapshots and fork templates *is* current.

### `e2b-shim.md` — the compatibility subset

*Concept:* why a subset rather than a clone, and why command execution is
deliberately out. *Reference:* the endpoint table.
*Thin:* it predates resource caps and teams, and its claim that a shim sandbox
gets "the same guarantees as any other KelyfOS sandbox" is the one outright false
sentence the inventory found — a shim sandbox has no flight recorder and no
`kelyfos.toml` caps. Request and response shapes, status codes and the 64 MiB
upload limit are undocumented.

## Not written down yet

The parts of the product with no documentation at all. Code-derived rather than
remembered, and the input to E3-1 — most of it disappears the moment the
reference is generated rather than typed.

**Commands.** `kelyfos version` and `kelyfos help` appear in no document.

**Flags.** `--arch`, `--image-dir`, `--console`, `--verbose-boot`,
`--ready-timeout`, `--no-sync-back`, `--sandbox`, `--cwd`, `--shell`, `--stdin`,
`--timeout`, `--json`, `--runs`, `--restore` — and `--idle-timeout`, whose toml
key is documented while its flag is not. No document lists any one command's
flags in full.

**Toml keys.** `sandbox.arch`, `resources.net_mbps_tx` and `resources.disk_iops`
are accepted and undocumented.

**MCP tools.** There is no reference for the fourteen tools a guest exposes.
`teams.md` describes the team half in prose; `exec`, `read_file`, `write_file`,
`list_dir`, `upload` and `download` are named in `README.md` and specified
nowhere — no parameters, no types, no output shapes.

**Exit codes.** `124` and `137` are documented. `126`, `127`, `2`, and the two
meanings of `1` — a failed `doctor` check, a broken chain from `log --verify` —
are not.

**Environment variables.** `KELYFOS_SANDBOX`, `KELYFOS_CACHE` and
`KELYFOS_CGROUP_ROOT` are read by the CLI and named in no document.

**Recipes.** There is no cookbook, no integration guide and no `llms.txt`. Those
are E3-3, E3-4 and E3-2.

## How these documents are kept true

1. **Generated where possible.** `make docs` regenerates the reference from the
   source and CI fails on any diff (F-D4, E3-1). A flag that exists cannot be
   missing from the reference, and a flag in the reference cannot be one that no
   longer exists.
2. **Executed where possible.** Every cookbook recipe is a script CI runs from a
   fresh clone, so a recipe that stops working fails the build (E3-3).
3. **Examined by a reader with no other source.** A fresh agent is given the
   documentation and nothing else and asked to build something real; every
   failure becomes a documentation fix (E3-5).
4. **Shipped with the feature.** From E3 onward no epic closes until the
   generated reference, `llms-full.txt` and the recipes cover what it added
   (F-D9).

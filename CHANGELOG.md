# Changelog

**This file is the source, not a mirror.** The release workflow cuts a release's
notes from the section below that matches its tag, and refuses to publish a tag
that has no section (D50). Nothing regenerates this file and nothing copies it
somewhere else, because a second copy of the truth that nothing keeps honest is
the failure the generated reference exists to prevent.

Versioning follows [`docs/compatibility.md`](docs/compatibility.md), which is
normative from v1.0 and says what a major, a minor and a patch may each do.
Releases before v1.0 predate that promise and made none.

Dates are the tag's, not the merge's. Timings are measured on the bare-KVM
reference described in the README and re-measured per release.

---

## Unreleased — v1.0

The promise release. Not yet tagged; what follows lands with it.

### Added
- **A compatibility promise** — [`docs/compatibility.md`](docs/compatibility.md):
  what stabilises, what deliberately does not, and a deprecation mechanism that
  did not exist. Guest confinement profiles are explicitly allowed to narrow in a
  minor release, because a profile that cannot be tightened without a major
  release is a profile nobody tightens.
- **Signed exports.** `kelyfos log --export --sign-key` signs a report with an
  ed25519 key of yours; `kelyfos verify --key` checks it against a key the reader
  already holds rather than one the file supplied itself.
- **`kelyfos verify`** — re-runs the hash chain over an exported report offline,
  on a machine with no sandbox and no guest. The record travels inside the HTML.
- **`kelyfos connect <client>`** writes six clients' own MCP configuration in
  their own formats and locations; `--check` starts the server it just configured
  and completes a real MCP handshake.
- **A macOS build of the CLI.** `doctor` owns the Lima layer, `verify` checks a
  report somebody sent you, and every command that needs a guest refuses with the
  way in. It is a smaller program than the Linux one and says so.
- **The release is a workflow**, not a laptop: both architectures from the tag's
  own commit, `SHA256SUMS` regenerated from scratch and checked in both
  directions, provenance and SBOM attestations, and an SBOM per architecture
  covering all three places an image comes from.
- **`CHANGELOG.md`, [`docs/upgrading.md`](docs/upgrading.md)**, and issue and
  pull-request templates.

### Fixed
- **The audit chain stopped reporting legitimate records as tampered with.**
  Verification now works from the bytes as written rather than by re-marshalling,
  so a reader tolerates a field it has never heard of, and a record with no
  digests is refused instead of passing.
- **A guest-authored directory entry could decide where the host wrote.** The
  workspace block device is a guest→host surface the threat model did not list.
  Every entry is now validated and the image refused whole if one carries a name
  the host cannot use, and extraction goes through `openat2` with
  `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`, so a name that got past the check
  still cannot leave the tree. Reported by an external security audit.
- **`write_file` and `upload` could write anywhere the guest asked**, including
  the block devices the confinement profile deliberately withholds, because the
  supervisor is PID 1 and the profile does not confine it. Both are now held to
  the same three lists the profile is built from.
- **`--review` no longer destroys an edit made while somebody was reading it.**
  The workspace is re-fingerprinted immediately before the rename and diverted on
  a mismatch, and the previous tree is kept until the next successful run.
- **A credential bound with a path now binds one endpoint** rather than expanding
  to subdomains, and is withheld — with a `secret.withheld` event saying which and
  why — from a request whose `Host` header disagrees with the host the guest asked
  to connect to.
- Exhaustion clamps: a timeout ceiling, key-count and key-size accounting in the
  team store with a delete that makes it smaller, a bounded output total per
  command, and a refusal that records a digest rather than a body.

### Documentation
- **Every hand-written document re-read against the code that implements it.**
  174 confirmed findings across 21 documents, 157 corrected. The record is
  [`dev/docs-audit-2026-08-25.md`](dev/docs-audit-2026-08-25.md). It also found
  eighteen defects in the code.

---

## v0.9 — 2026-08-24
### the boundary is the hardware, and everything around it is locked too

The hardening release. Every release before it said "not hardened yet", and that
was true: KelyfOS relied on the boundary Firecracker gives it and added nothing
of its own around the VMM process or inside the guest.

### Added
- **The VMM runs inside the jailer** — a chroot holding only this sandbox's
  files, a dropped uid, `no_new_privs`, only the device nodes it needs, and the
  run's cgroup where the policy set a quota. Every entry point or none: `run`,
  `team up`, `fork`, `snapshot restore`, `serve-mcp` and the shim all go through
  one refusal.
- **Firecracker's own seccomp filter is read out of `/proc` on every one of its
  threads** at boot and the VMM refused if it is absent — rather than assumed
  from the absence of a `--no-seccomp` flag.
- **Everything the guest's supervisor spawns is confined by Landlock** and a
  seccomp refusal list, per flavor, generated into
  [`docs/reference/profiles.md`](docs/reference/profiles.md) from the code that
  enforces it.
- **The record names which walls were around each machine**, so a transcript
  cannot make an unconfined run look like a confined one.

### Breaking changes
1. **A guest command that writes outside `/work`, `/tmp`, `/run` and `$HOME` is
   refused.** It succeeded before. One of this project's own cookbook recipes did
   exactly that — `mkdir /prepared` at the filesystem root — and now prepares in
   `/tmp`. There is no way to permit that and still refuse `/etc`: a Landlock rule
   covers a tree, so granting the root grants everything under it.
2. **A snapshot taken before v0.9 restores into the guest it captured, which
   confines nothing it spawns.** Warned about rather than refused — the host walls
   are properties of the run you are starting now and all still apply, so refusing
   would make old snapshots unusable to buy nothing. See
   [`docs/upgrading.md`](docs/upgrading.md).
3. **Attaching a debugger to a process already running inside a guest fails**
   with `Operation not permitted`, on every flavor including `dev`. Each confined
   process gets its own Landlock domain and Landlock refuses `ptrace` between
   siblings. Launching a program *under* a debugger still works, because a child
   inherits its parent's domain.

---

## v0.8 — 2026-08-23
### the daily driver feels like one

### Added
- **`kelyfos pause` and `kelyfos resume`** — stop for the day and pick up the
  same machine tomorrow, not a copy of its files.
- **`--review`** shows what changed in the workspace before you keep it.
- **A real terminal** — `kelyfos shell`, with a pty, resizes and signals.
- **Port forwarding** — `kelyfos run -p 8080:80` and `[[forward]]` in
  `kelyfos.toml` reach a server inside the sandbox.
- **Every refusal names its own fix**, with a stable identifier scripts can
  branch on, generated into [`docs/reference/denials.md`](docs/reference/denials.md).
- **`kelyfos runs`** lists what has run here, and `kelyfos rerun` runs one again.
- **A desktop notification** when a run finishes and you have walked away.

---

## v0.7 — 2026-08-23
### any MCP client can drive it; any MCP server can run inside it

### Added
- **`kelyfos serve-mcp`** — KelyfOS itself as an MCP server, so any client can
  boot, run, snapshot and fork sandboxes as tools. The policy is the ceiling and
  no tool can raise it.
- **`[[plugin]]` servers inside the guest**, with namespaced tools. A plugin that
  dies costs its own tools and nothing else.
- **Prepare once, fork many** — snapshot a machine you have set up, then bring it
  back repeatedly.
- The MCP channel carries whole files: its frame limit is 16 MiB rather than the
  1 MiB the rest of the protocol uses.
- A restore is held to the policy, and snapshots record how large a machine they
  came from.

---

## v0.6 — 2026-08-23
### any LLM can build on KelyfOS from the docs alone

### Added
- **The reference is generated from the source and CI fails when it drifts** —
  every command, flag, `kelyfos.toml` key, MCP tool, event and exit code.
- **The cookbook's recipes are executed**, not illustrated: CI extracts each one
  and runs it on a real machine.
- **`llms.txt` and `llms-full.txt`** for machine readers, per the llmstxt.org
  spec.

### Documentation
- The first documentation inventory read every document against the code and
  found real drift, including a normative document that had gone two epics
  without being touched. It also found four defects that were product work rather
  than documentation, recorded rather than fixed.

---

## v0.5 — 2026-08-23
### agent teams as code

### Added
- **`[team]` in `kelyfos.toml`** declares agents and the edges between them;
  `kelyfos team up` boots the graph. Master/workers, a pipeline, a mesh.
- **A broker** carries messages along declared edges only, and refuses the rest
  with a recorded `team.refused`.
- **A team store**, shared by default and narrowed per key.
- **One team, one transcript** — every member's events in one chain.
- **Resource budgets that compose**: per-agent caps inside a team-wide ceiling.

---

## v0.4 — 2026-08-23
### the user decides how much machine the agent gets

### Added
- **`[resources]` in `kelyfos.toml`** — `cpus`, `cpu_quota`, `mem`, `disk`,
  `scratch`, `net_mbps_rx`/`tx`, `disk_iops`, `disk_mbps`, `max_runtime`,
  `idle_timeout`. Every cap is imposed on the host, because a limit the guest
  applies to itself is advisory at best.
- **`[resources]` are ceilings, not defaults.** `--cpus 8` against `cpus = 2`
  refuses at boot and names the line it came from rather than quietly clamping.
- **`bash dev/prove-caps.sh`** drives each cap past its limit and checks it held.

---

## v0.3 — 2026-08-22
### a sandbox an agent can only reach through tools

The first announced release. `v0.3-rc1` was tagged the same day and is the same
tree.

### Added
- **One command hands an agent a sandbox**: `kelyfos run --workspace . --allow
  github.com -- claude`.
- **Egress is off, not filtered.** No `--allow` means no network interface
  exists at all.
- **Secrets never enter the guest.** The host's proxy attaches them on the way
  out; `env` inside the sandbox shows nothing.
- **A host-written, hash-chained audit record**, with `kelyfos log --verify`, a
  standalone HTML export, and a live `kelyfos watch`.
- **Snapshots and forks.**

---

## v0.2 — 2026-08-22
### a toolbox, not a computer

Tagged at the end of phase 2; no release was published. The guest supervisor
exposes itself as MCP tools — `exec`, `read_file`, `write_file`, `list_dir`,
`upload`, `download` — over vsock, and there is no shell login and no SSH.

---

## v0.1 — 2026-08-22
### it boots

Tagged at the end of phase 1; no release was published. A minimal bootable
Buildroot guest with a supervisor on vsock.

---

## v0.0 — 2026-08-22
### environment and scaffold

Tagged at the end of phase 0; no release was published. The pinned toolchain,
the repository layout, and an acceptance test that passed.

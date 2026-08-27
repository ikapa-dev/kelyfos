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

## Unreleased

### Fixed
- **A single oversized, guest-influenced field could make the flight recorder
  permanently unreadable from that line on.** The record is a hash chain read
  with a bufio.Scanner capped at 8 MiB, and nothing bounded what a caller could
  put in a line before it reached that cap. Two doors did: the egress proxy
  validated a CONNECT target's characters but never its length, and the MCP
  bridge base64-encoded a whole command's stdout or stderr into one
  `command.output` event with no chunking at all. Both are closed now — the
  proxy rejects a host over 253 bytes (RFC 1035) before it is ever considered
  for recording, and exec output crossing the MCP bridge is chunked the same
  way `kelyfos exec` already chunks it. `Append` itself also refuses,
  unconditionally, to write a line its own readers could not read back,
  whatever field made it that large and whatever door produced it.
- **`kelyfos snapshot restore` could run a restored guest's egress unaudited
  for the whole restore.** It wired the proxy's audit hooks only after
  `sandbox.Restore` returned — but `Restore` resumes the guest and lets it
  round-trip over the control port (clock/entropy resync, the seccomp check)
  well before it returns, and `InstallTrustAnchor` ran after that, itself a
  control-port round trip with a read deadline a hostile guest controls the
  far end of. Every egress attempt, secret use and withheld-credential
  decision in that window went unrecorded: the proxy still enforced its
  allowlist, but nothing told the flight recorder about it. The audit hooks
  are now wired — with the sandbox id already known, same as the other four
  places in this product that build a proxy — before `sandbox.Restore` is
  ever called, so nothing the guest does from the moment it resumes goes
  unaudited.
- **A path-scoped credential (`Scope.Path`, endpoint locking) could be
  attached to a request whose literal, on-the-wire bytes an origin server
  would route outside the bound path.** The check compared the *decoded*
  request path against the bound prefix, but Go sends the *escaped* path
  upstream verbatim, and the two can be made to differ in ways a real server
  re-segments and Go's own parser has no opinion on at all: a `;`
  matrix-parameter a Tomcat/Jetty container strips before routing, a raw
  backslash IIS/.NET treats as a separator, an overlong UTF-8 encoding of `/`
  a lenient legacy decoder accepts. The old check enumerated only the two
  encodings Go's own parser treats specially (`%2f`, `%2e`), which is not the
  same claim as "safe on every origin this could be bound to". It is now an
  allowlist: the escaped path may contain only unreserved characters, `/`,
  and the one vetted exception (`%20`, for an ordinary encoded space in a
  path segment) — anything else, including any other percent-encoding,
  withholds the credential instead of trying to reason about what a
  particular server would do with it.
- **An exported report's own tamper-evidence markers could be defeated by an edit that a
  verifier's own doc comment already said should be refused.** `marked()` reads each of the six
  values a page states about itself (chain head, event count, session, and — the sharpest case —
  the signing key's fingerprint, the exact check P6-19 added so a swapped signing key could not
  hide behind a fingerprint the reader trusts) by looking for one `<code id="...">` or, failing
  that, one `<span id="...">`. On finding the `<code>` count ambiguous (2+), it fell through to
  check `<span>` instead of refusing outright — so an editor could show a fake value in a visible,
  duplicated `<code>` tag and hide the true value in a lone `<span>` for the same id, and
  `marked()` would hand back the true value, agreeing with the record while the page a human
  reads shows the fake one. `kelyfos verify` now refuses to answer for a marker that is ambiguous
  across *either* tag kind, matching what `marked()`'s comment already promised.
- **Four lower-severity gaps, each a guest able to spend host resources or a record able to say
  something false.** The egress proxy accepted an unbounded number of connections, never set a
  read deadline on one, and let `http.ReadRequest` consume an unbounded header block before
  giving up — a guest could hold connections open forever or force unbounded memory per
  connection while it parsed; a concurrency cap, a read deadline, and a header-size bound close all
  three — the bound is a releasable limiting reader rather than a plain `io.LimitReader`, since the
  latter would keep charging a request's body against the same budget as its headers and silently
  truncate any legitimate upload once the two together crossed the limit (found in review) — and
  the host's own denial-deduplication map is now bounded the
  same way against a guest trying unboundedly many disallowed hostnames. The team wire bounded a
  request's id and body but never its store key, so an oversized key reached `internal/team`'s
  store unchecked; `Store.Put`'s own length check also ran after its access check, so an oversized
  key denied for an unrelated reason was recorded in full before its length was ever examined —
  the wire now refuses an oversized key outright, and `Get` and `Put` both check length before
  anything else. A guest file named with a quote character was not refused, and the comment
  claiming quoting already covered it was wrong: a quote is not whitespace and closes the
  double-quoted debugfs command early; `validName` now refuses it. And an absolute-form
  `https://` request sent straight to the proxy without a `CONNECT` was recorded as
  `mode: plain` / `not_encrypted` even though it is a real, certificate-validated TLS fetch —
  a new mode and withheld reason say what actually happened instead.
- **A symlink planted inside a tree the sandbox may write let `write_file` and `upload` reach
  anywhere on the host, including the raw block devices behind the guest's own read-only root and
  workspace.** `writableFor` was a pure lexical check — `filepath.Clean` plus a prefix comparison
  against the writable trees — and the write itself was a bare `os.WriteFile`/`os.MkdirAll` on
  whatever path the agent supplied, so neither ever asked what a path component actually pointed
  at. Creating a symlink costs a confined exec nothing beyond what it already has —
  `LANDLOCK_ACCESS_FS_MAKE_SYM` is granted on every tree write is — so `ln -s /dev/vda /work/escape`
  followed by `write_file("/work/escape", …)` reached the disk without the tool ever naming it.
  Both call sites now walk the path component by component with `Lstat` and refuse if any
  component — including a pre-existing symlink at the final one — is a symlink, once as part of the
  writability decision and again immediately before the write itself, since a symlink can be
  planted in the gap between the two.
- **The egress proxy allowed a connection based on a hostname string and never checked where that
  hostname actually resolved to, so an allowlisted domain that is DNS-hijacked, or simply taken
  over, could be pointed at `169.254.169.254` — a cloud instance's metadata endpoint, on port 80,
  already in the proxy's always-allowed port set — and an ordinary guest CONNECT to that
  already-allowed name would be tunnelled straight there.** `allowsHost` and `secretsFor` only ever
  looked at the string a guest's CONNECT or request line named; nothing in `tunnel`, terminate's
  upstream leg, or `forwardHTTP` ever looked at the address DNS actually sent the connection to.
  All three now dial through a `net.Dialer.Control` hook that runs once per address a resolver
  returns, immediately before the connect syscall for that address, refusing loopback, link-local
  (169.254.0.0/16 included) and other private/reserved space — skipped only when the host being
  dialled is already a literal IP address, since nothing is resolved there for DNS to have
  hijacked, which is also why this changes nothing for the many tests in this package that dial
  real loopback test servers by address. The refusal is recorded in the flight recorder the same
  way any other egress denial is, as a new `unsafe_resolved_address` reason with an
  `egress.resolved_addr` catalog entry naming the address and explaining why retrying will not help.
- **A guest OOM kill or a plugin call/crash on a restored, forked or resumed sandbox left no trace
  in the flight recorder.** `sandbox.Options.OnGuestEvent` is what turns a guest's report into a
  recorder line, and `sandbox.go`'s `serveEvents` drops the frame outright, silently, when it is
  nil. That was correct for a fresh `sandbox.New` boot and for a team member forked from a
  template — `host/team.go`'s `memberOptions` already solved exactly this problem once, per its
  own comment — but every other door that resumes a machine with `sandbox.Restore` built a bare
  `sandbox.Options{}` with no handler at all: `kelyfos fork`, `kelyfos snapshot restore`,
  `kelyfos resume`, and `serve-mcp`'s `sandbox_restore` and `sandbox_fork` tools. `memberOptions`'s
  inline closure is now `guestEventRecorder`, one function shared by all six call sites. Three of
  them also had to open their recorder before calling `sandbox.Restore` rather than after: the
  guest starts reporting the instant the machine resumes, and a recorder opened only once every
  fork in a batch had finished, or only long enough to append a single resume event and close
  again, missed whatever the guest said in between.
- **`kelyfos snapshot restore` read no policy file at all, unlike `run` and `fork` (which enforce
  `[resources]` ceilings) and unlike `serve-mcp`'s `sandbox_restore` — the identical operation
  through the MCP door, which already calls `checkSnapshotFits` and `restoreAllow` before
  restoring.** A restored machine got no ceiling, no allowlist narrowing and no secrets from
  `kelyfos.toml`, a gap `docs/compatibility.md` and `docs/resources.md` already disclosed by name
  but the asymmetry with the MCP door was undocumented. `snapshot restore` now takes `-policy`,
  resolved by `loadPolicyAt` exactly the way `run` and `fork` resolve it — a named file that does
  not exist is an error, and with nothing named it walks up from the working directory and applies
  whatever `kelyfos.toml` it finds. Found or named, a restore is held to it the same three ways
  `sandbox_restore` already holds one to it: `checkSnapshotCeiling` refuses a frozen machine whose
  recorded vcpu or memory is over the ceiling (Firecracker takes both from the state file, so
  there is nothing to clamp — only allow or refuse), `restoreAllowCeiling` refuses reaching a
  domain the policy does not permit, and `restoreSecrets` defaults `--secret` from the policy's
  own `secrets` when none are typed, dropping rather than erroring on the ones this particular
  restore cannot reach. This is a real default-behaviour change: a working directory with a
  `kelyfos.toml` above it — this repository's own included — now gets its restores held to it by
  default, the way its `run`s and `fork`s already were.

---

## v1.0 — 2026-08-25

The promise release. Everything below is in it.

Built by `.github/workflows/release.yml` from this tag's own commit — the first
release this project did not assemble by hand. `v1.0-rc1` and `v1.0-rc2` came
first, deliberately: rc1's build failed at the SBOM attestation, which is a step
no release had ever run, and rc2 is the one the quickstart numbers above were
measured against. This tag is byte-identical to rc2 in everything that builds;
what changed between them is documentation.

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

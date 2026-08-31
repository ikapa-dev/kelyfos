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

## v1.1.2 — 2026-08-31

A patch release with one defect in it, found by downloading the published
release and reading the artifacts rather than the code that produced them.
Nothing in the product moves: no CLI surface, no `kelyfos.toml` key, no record
format, no guest image, and no section 2 surface of
[`docs/compatibility.md`](docs/compatibility.md) — the SBOM has never been one.
What changes is the bill of materials the release publishes.

`sbom-aarch64.cdx.json` and `sbom-x86_64.cdx.json` were **the same bytes** in
v1.1 and in v1.1.1, and neither said which product, which version or which
architecture it described. Underneath that sat a larger one: the merge that
produces them decoded Buildroot's output through a struct modelling seven fields
and wrote that struct back out, so every licence, CPE, source-tarball hash and
patch record Buildroot had computed was deleted on the way through — 333 KB of
input published as 11 KB — and the host build of a package silently replaced the
target build of it.

### Fixed
- **The two architectures' SBOMs were byte-identical, and neither named the
  product, the version or the architecture it described.** `-arch` was validated
  non-empty, printed to the terminal and discarded; `-version` reached nothing
  but the same progress line; and the merge copied Buildroot's metadata verbatim,
  so the document a stranger downloads from a KelyfOS release declared its
  subject to be `buildroot 2025.02.17`. The consequence was not cosmetic:
  `release.yml` cuts two SBOM attestations on purpose, one per architecture,
  because *"an attestation that pointed at both sets of artifacts would be
  claiming that either SBOM describes either image"* — and with one document
  under two names, both attestations said exactly that. The document now carries
  a `metadata.component` naming KelyfOS, its version and its architecture, and
  the serial number is a digest of the whole document, so the two files differ
  and each identifies itself.
- **The architecture is read out of the binaries instead of copied from a flag.**
  Every binary the merge opens reports its own `GOOS` and `GOARCH` through
  `debug/buildinfo`; `-arch` is now an assertion checked against all of them, and
  a mismatch writes no document at all. The binaries know what they were built
  for; the flag was a claim.
- **The merge deleted most of what it merged.** Every Buildroot component lost
  its `licenses`, its `cpe`, its `externalReferences` — which is where the
  SHA-256 of each source tarball lives — its patch pedigree and its `BR_TYPE`
  property, and the document lost Buildroot's dependency graph. A bill of
  materials without licences is not one, and a component without a CPE is one no
  scanner can match a CVE against. Components this tool did not author now pass
  through as the bytes they arrived as: 49 components carry licences where none
  did, 30 carry a CPE, and 40 carry a source hash.
- **The host build of a package replaced the target build of it.** Components
  were deduplicated on name and version, and `libzlib` and `host-libzlib` are one
  name at one version. The v1.1.1 SBOM lists the *host* OpenSSL, zlib, libffi and
  python3 — the ones on the build machine — and not the ones in the guest image,
  and which of each pair survived was decided by the order Buildroot happened to
  emit them in. Deduplication is on `bom-ref` now, which is the identifier
  CycloneDX gives a component for this reason and the one its dependency graph
  refers to.
- **The document said CycloneDX 1.5 while carrying a 1.6 generator's output.**
  Harmless only for as long as the 1.6-only fields were being deleted: the
  document validates as 1.5 today and would fail in 42 places once its components
  survive. It declares 1.6 now, carries the matching `$schema`, and the merge
  refuses a Buildroot input whose own `specVersion` is not the one it writes.

## v1.1.1 — 2026-08-31

A patch release with one fix in it. The flight recorder's own last-line-of-defense
against an oversized event could not converge when the size was spread across
several fields, so it dropped the event instead of clipping it — and a dropped
event latches the recorder and takes the machine down with it. Reachable from
`kelyfos mcp` by an ordinary tool call.

Nothing about the record's format changes. `MaxLine` is the same 8 MiB, the field
order is the same frozen order, the digest is computed the same way, and a chain
written by v1.1 verifies byte for byte under v1.1.1.

### Fixed
- **An oversized `command.start` from the `kelyfos mcp` bridge was dropped from
  the record rather than clipped, and took the recording and the sandbox with
  it.** `Append`'s size guard reduced one field per attempt, by half, up to eight
  attempts. That converges for one oversized field and cannot converge when the
  bulk is spread across several: an event carrying 16 MiB across sixteen fields
  is no closer to the limit after eight halvings of the largest, so the `Append`
  failed closed — and an event `Append` refuses vanishes from the record instead
  of being kept in truncated form, which is exactly the failure the guard exists
  to prevent. Because `Append` failing also latches the recorder (every later
  event refused, `Broken` closed), the run loop then brings the machine down.
  `host/mcpobserve.go` can build such an event from a single `tools/call` for
  `exec`: `call`, `cmd` and `cwd` all come out of that one frame with no length
  bound on any of them, and the frame may be 16 MiB. The guard now reduces every
  field standing above the ceiling the budget allows, in one pass, so the event
  is recorded clipped whatever the size is spread across. (P7-15, D80)
- **One `Append` of a very large event allocated gigabytes.** The same
  non-convergence meant the loop re-marshalled the whole event on every attempt:
  one `Append` of an event holding 340 MiB across its fields allocated 4.3 GiB
  and left a 4.4 GiB resident set, which is what OOM-killed `internal/recorder`'s
  own fuzz worker once its corpus grew (D69). The reduction now runs before the
  first marshal, so the cost is bounded by `MaxLine` rather than by what the
  caller built: the same `Append` allocates 80 MiB, and the 215-entry corpus that
  reproduced the kill replays in a full 60-second fuzz run at a 392 MiB peak.
- **`internal/recorder`'s fuzz target no longer tolerates the failure it was
  written to catch.** `FuzzAppendFieldValues` discarded the error from every
  `Append` and took its expected event count from `Verify`; because a latched
  recorder leaves a chain that is *short* rather than broken, and a short chain
  verifies, it watched `Append` drop the oversized event on every run and
  reported nothing. It now requires every `Append` to succeed and the chain to
  hold all four events.

### Changed
- **More of an oversized field survives being clipped, and several oversized
  fields are now each clipped rather than one repeatedly.** As a fraction of the
  8 MiB line limit, for a 20 MiB `data`: ordinary output went from 62.8% kept to
  99.9%, and output full of `<` — which JSON escaping expands six-for-one, so a
  shell transcript reaches it constantly — from 15.6% to 74.7%. An event with
  four oversized fields comes back with four clip notes instead of one field
  reduced to a sixteenth, and each note now names the field's true original size
  rather than the size it had partway through being reduced. This is a change to the text of a clipped value, not
  to the schema: the field, its position and the digest over it are unchanged,
  and `docs/compatibility.md` §2 pins those rather than the contents of a value
  this file already replaces with a note. Anything parsing the
  `...(clipped from N to M bytes)` note will still find it, on more fields than
  before.

## v1.1 — 2026-08-31

The declared shape of a run. v1.0 could say what a sandbox did; this one says
what it was *allowed* to do, in the same record and under the same hash chain —
the policy in force at every door that opens a chain, a team's resolved topology
written at boot, and both readable back with `kelyfos log`, `kelyfos watch`,
`kelyfos team graph` and `--json` on all of them.

It also carries the remediation of an independent security review of
2026-08-28: twenty-one findings, and the seven more that an adversarial
verification pass then found inside those fixes. Every one is below under
**Fixed**, and every one was reviewed by somebody who did not write it.


### Added
- **`kelyfos team graph`**: renders a team's topology straight from
  `kelyfos.toml`, with nothing booted — the same plan-time checks
  `kelyfos team up` runs before it boots anything, including the refusal a
  `[[plugin]]`/`[[forward]]` beside `[team]` already gets. The picture: every
  agent, the resolved edges, the domains and secrets each agent reaches, and
  the store's rules — including the access every key with no matching
  `[[team.store.key]]` rule has by default. `kelyfos team ps --graph` draws
  the identical picture for a running team, read from that team's own
  recorded `team.topology` and `session.policy` events rather than from the
  file. `kelyfos watch` gains two panes alongside the existing one — a map
  (`2`/`m`) and an agent sheet (`3`/`s`, caps beside live counters) — both
  read off the same fold, and the map's "refused since boot" section covers
  every real `team.refused`/`team.store`/`team.spawn` reason, each with the
  fix line `internal/denial`'s catalog already writes for it where one
  exists. Both graph commands also say, explicitly, what a recorded
  `team.topology` cannot tell them: a worker spawned at runtime after boot,
  and whether an empty store rule list means the store is off or open to the
  whole team (P7-7).
- **`--json` on `kelyfos team ps`, `kelyfos team graph` and `kelyfos watch`**:
  the extensibility surface for a view this phase did not think of, and
  cheaper than a plugin system. Before this, only `bench`, `log` and `verify`
  could be piped. `kelyfos team ps --json` returns the identical shape the
  `team_ps` MCP tool has always returned as `structuredContent`. `kelyfos team
  graph --json` and `kelyfos team ps --graph --json` return the resolved
  topology as data instead of a drawing — agents, edges, resources, access and
  the indirect-reach pairs the terminal view already draws in prose. `kelyfos
  watch --json` prints one snapshot of `internal/digest`'s own fold — every
  counter, the session header, the policy and topology events verbatim, bounded
  the same way the live view already is — and exits, instead of opening the
  TUI; it carries no timeline, which `kelyfos log --json` already is. Documented
  in `docs/teams.md` §8.5 (P7-10).
- **`kelyfos log --export-otlp`**: maps a session's chain to an OTLP-JSON
  trace export — `invoke_agent` per agent (or the sole implicit agent of a
  non-team session), `execute_tool` per command, every egress attempt or
  refusal as a span event on the agent it belongs to. Versioned apart from
  the flight recorder and never an input to `kelyfos verify` (D59): the
  `gen_ai.*` semantic conventions this targets are still marked
  "Development" with no stabilisation timeline, so a future revision of them
  changes only this mapping, never a hashed byte. An inbound W3C
  `traceparent` on `session.policy` continues that trace instead of starting
  a new one (`docs/otlp.md`, P7-11).
- **`kelyfos log --export` against a session that has not ended, and
  `--refresh` to keep it current.** The export always rendered whatever the
  flight recorder held; what was new is `--refresh`, which rewrites the same
  destination on a timer (`--refresh-every`, default 2s), atomically, for as
  long as the session runs, and adds a `<meta http-equiv="refresh">` tag so a
  browser tab already open on the file reloads itself and shows the latest
  rewrite. No socket anywhere in that path — a CLI process rewriting a file
  and a browser polling it — so it is the honest answer to "live" for anyone
  who does not want a listener, and it exists whether or not `kelyfos view`
  (P7-12) does. The loop stops on its own once `session.end` appears in the
  chain (that final write drops the refresh tag, since nothing more is
  coming) or on Ctrl-C (P7-9).
- **Several teams may run on one host at once, and `--team` says which one a
  command means.** `kelyfos team up` used to refuse with *"a team is already
  running"*; it no longer does. Each team mints its own session, writes its own
  state, gets its own cgroup parent, and holds its own machines, workspaces,
  proxies and record — nothing is shared and nothing is queued. `kelyfos team
  ps` and `kelyfos team down` take `--team <name|session>`; with one team up
  neither needs it and nothing about them has changed, and with several they
  print what is running rather than guess, which is the rule `--sandbox` has
  always had for `kelyfos exec` one level up. Two teams may share a name, which
  is what two checkouts of one project do, so the selector takes a session id as
  well, and `kelyfos team up` now prints its own session on the line after
  `team up in N ms` so you have one to give. `kelyfos watch`'s team lane and the
  `team_*` MCP tools need no selector: the lane reads the session it is already
  tailing, the tools are about the team that server raised, and a team raised
  elsewhere is named in the refusal rather than acted on. See
  [`docs/teams.md`](docs/teams.md) §5.1 and cookbook recipe 22 (P7-16, D79).

### Fixed
- **Two teams on one host collided over host-level state, and one team's
  teardown could stop the other team's machines.** Every team wrote the same
  `~/.cache/kelyfos/run/team.json`, and `kelyfos team up` guarded it with a
  `stat` taken tens of seconds before the matching write — so two teams started
  within that window both passed the guard, booted, and the second's write
  replaced the first's state. After that `kelyfos team ps` described the wrong
  team, `kelyfos team down` signalled the wrong process, and the first team's
  own teardown deleted the second team's file. Worse and separately: a team's
  parent cgroup was named for the team's *name*, so two checkouts of one project
  shared `kelyfos-team-<name>.slice` — the second team's cap overwrote the
  first's, and the second team's teardown ran `systemctl --user stop` on the
  slice, which stops every scope in it, including the first team's Firecrackers.
  On the direct cgroup path the same name meant one directory: `cpu.max`
  rewritten under a running team, and a removal aimed at a parent a live team
  was still accounted in. Both are now keyed to the team's own session — one
  state file per team at `run/teams/<session>.json`, published by rename so a
  concurrent `team ps` can never read one half-written, and a cgroup parent of
  `kelyfos-team-<name>_<session>`. Found by two independent adversarial reviews
  hitting it unprompted in separate worktrees on one development machine
  (P7-16, D70, D79).
- **A path-scoped credential could attach one segment wider than its bound
  prefix when the scope carried a doubled trailing slash.** `covered()` trims
  exactly one `/` before comparing, so `--secret TOKEN@host/repos//` — a typo,
  not a contrived input — approved `/repos/`, which an origin that strips
  matrix parameters (Tomcat, Jetty) resolves to `/repos`. A scope path is now
  refused where it is typed unless it is already in normal form (no `.`/`..`
  segments, no doubled slashes), with the form to write instead; and `covers` withholds the credential on any scope
  that is not, so a scope built past the parser cannot approve what the prefix
  does not literally cover. Found by `FuzzScopeCovers` on 2026-08-27 and
  deferred (D67); fixed when `make ci-act` started finding it in four seconds
  (P7-14).
- **`kelyfos connect` refuses a project-local configuration path whose symlink
  leaves both the project and your home directory.** Following a leaf symlink is
  what keeps a dotfiles-managed configuration working, and four of the six
  clients write a **project-local** file — `.mcp.json`, `.cursor/mcp.json`,
  `.vscode/mcp.json`, `.junie/mcp/mcp.json` — any of which a repository can
  commit as a symlink. Following that one would put the entry wherever the
  repository pointed. A path you named under your own home may still resolve
  anywhere, because your home is yours and a dotfiles repository at
  `/srv/dotfiles` is an ordinary layout; only the project-local half is bounded,
  and it is bounded to the two places you are answering for. The refusal names
  the file, the destination and the two things that work (**D75**).
- **The guest-side fixes in this release need a rebuilt image, and a stale one
  gives you none of them.** Four of them live in the supervisor, which ships
  inside `rootfs.ext4`: the confinement wrapper that a binary named
  `kelyfos-confine` used to step around, the Landlock ruleset that now governs
  device creation, the guarded `write_file`/`upload` open, and the vsock peer
  check. Upgrading the `kelyfos` CLI alone leaves a machine booting the image it
  already had, and nothing says so — `kelyfos run` does not compare the
  supervisor's version against the CLI's. Rebuild with `make image FLAVOR=dev`
  (and `FLAVOR=base` for that flavor), or fetch the release artifacts.
  `dev/accept-profile.sh` is what tells you which one you have: against the
  pre-fix image its F8 block fails, and against a rebuilt one the suite is 35 of
  35. **`FLAVOR` is load-bearing** — the default is `base` and the output
  directory carries no flavor, so a bare `make image` overwrites whichever image
  is there with a base one.
- **A failed upstream dial told the guest which address an allowlisted name
  resolved to.** The `403` for a name that resolves somewhere reserved stopped
  naming the address earlier in this release — a guest that is told that has
  been handed the result of a DNS lookup it has no resolver of its own to
  perform, one name at a time. The `502` two lines below it still wrote Go's own
  dial error, which carries the address by construction, and it is the easier
  one to reach: the name only has to resolve somewhere that does not answer. The
  body now names the host the guest asked for and nothing else; the address goes
  to the flight recorder, in the same `resolved_addr` field the `403` path uses.
- **A knock on the proxy's port from elsewhere on the machine was counted as the
  sandbox's blocked egress.** A `foreign_peer` refusal is a fact about the host —
  something that is not the guest connected to the port that carries your
  credentials — and `kelyfos watch`, the digest and the exported report were
  adding it to the sandbox's own `egress blocked` figure, so a session in which
  the guest attempted nothing could report three blocked attempts. It is the
  same distinction the nftables receipt already drew, where the F9 rule's counter
  is deliberately not part of the guest's `blocked_packets`. The event stays in
  the timeline, where it is worth reading.
- **Two terminal paths printed guest-chosen text unsanitised.** `kelyfos log`'s
  fallback for an event type the build has no renderer for printed the raw chain
  line — the case that arises when an older binary replays a newer chain, which
  is supported. And `kelyfos watch`'s two headers printed the session's image,
  architecture and end reason straight off the chain, where `kelyfos view`
  sanitises the same three in the same header.
- **`kelyfos connect` replaced a dotfiles-managed client configuration instead
  of writing through it.** The atomic temp-file-and-rename this release
  introduced is right for a file another program may be editing, and it changed
  one thing nobody looked at: `os.WriteFile` follows a leaf symlink and a rename
  replaces one. A `~/.codex/config.toml` or `~/.gemini/settings.json` that stow,
  chezmoi or a hand-made link points into a repository became a plain file, the
  version-controlled copy stopped being what the client reads, and the next
  `stow -R` would put the link back over the entry that had just been written.
  The write now resolves a leaf link and replaces the file it names, atomically,
  in that file's own directory — including when the link is dangling, which is
  what a fresh machine looks like before the dotfiles repository is cloned.
  **And the mode rule is decided by the path you named as well as by where it
  resolves**, whichever is stricter: a link out of `$HOME` made the file read as
  project-local and get `0644`, which is this release's own `0600` rule inverted
  at the one path it exists to protect (P7-17/B1).
- **`kelyfos serve-mcp --policy` did not check the policy file it was given, and
  it is the file every MCP client is pointed at.** The ownership and writability
  rules a discovered `kelyfos.toml` gets were applied in one function that
  `kelyfos run`, `team up`, `fork`, `snapshot restore` and the rest go through —
  and `serve-mcp` had a near-copy of that function which did the missing-file
  refusal and then read the file with nothing in front of it. `kelyfos connect`
  writes `serve-mcp --policy <path>` into every client configuration it touches,
  so the door most people enter by was the door with no check on it. The frozen
  policy a `kelyfos resume` runs under had the same gap. Both now go through the
  one function, and nothing else in the repository reads a policy file.
- **A policy refusal could be silently ignored by `pause` and `resume`.**
  `kelyfos sessions pause` froze *no* policy at all when the file was refused —
  so the resume that followed had no ceiling to restore — and `kelyfos resume`
  read the refusal as "this project has no policy", which skipped the check that
  a paused machine's frozen ceiling still fits the project's current one. A
  refused policy is now an error that stops the operation.
- **A `[[team.agent]] workspace` outside the policy file's own tree was
  accepted.** `kelyfos run` has refused an out-of-tree `[sandbox] workspace`
  since v1.1, because that directory is written back over when the run ends; an
  agent's workspace is written back the same way at `kelyfos team down` and was
  not checked. It is now refused at plan time, so `kelyfos team up`, `kelyfos
  team graph` and the `team_up` MCP tool all get it. `kelyfos team up` has no
  `--workspace` flag to override it with, and the refusal says so — move the
  directory inside the project, or run that agent on its own with
  `kelyfos run --workspace`.
- **Two more doors that failed open when the flight recorder did.** The wiring
  that stops a machine nobody is recording reached every loop that holds one
  open and left two places that have no such loop. `kelyfos serve-mcp` keeps a
  chain of its **own** — every `mcp.host.call` and `mcp.host.result` — and
  nothing watched it, so a full disk left the server answering tool calls with
  the whole outward lane silently refused: an agent creating machines, running
  commands and spending credentials, and a record saying none of it happened. It
  now refuses every tool call once its chain has stopped, naming the event that
  was lost, and says so on stderr the moment it happens rather than at the next
  call. The sandboxes it already created keep their own chains and their own
  watchers. And `kelyfos shim` had no watcher at all, so an E2B-shim sandbox
  whose recorder failed kept running exactly as the finding describes; each shim
  sandbox now gets the same per-box watcher, and a machine it stops answers the
  next SDK call naming it with a `404`. Both teardowns also make the second
  attempt at the "why the record stops here" line that every other door in the
  CLI already made (P7-17/A2, F13).
- **A sandbox whose flight recorder had failed kept running, unrecorded.** The
  recorder latches on its first failed append and refuses everything after it,
  so the record stopped — but nothing outside the recorder watched that, so the
  machine went on executing commands and making egress with nobody told, which
  is the harm the finding describes rather than a narrowing of it. Every loop
  that keeps a machine alive now watches it: `kelyfos run`'s two, `kelyfos team
  up`'s — one recorder covers a whole rig — `kelyfos sessions resume`'s and
  `kelyfos snapshot restore`'s, and, since `serve-mcp` has no such loop, a
  per-sandbox watcher started where the machine is registered. When it
  fires the machine is stopped and the operator is told which event was lost and
  why; `kelyfos run` exits `1` and the session ends `recorder_failed`, and under
  `serve-mcp` and the shim the next call naming that sandbox says the recorder
  failed rather than that no such sandbox exists. **A `serve-mcp` whose own
  chain has failed still answers `sandbox_list`, `sandbox_stop` and `team_down`**
  (**D76**): a stop *is* recorded, in the sandbox's own chain, and refusing it
  would leave an agent that has just been told its calls are unrecorded unable
  to stop or even find the machines it started. Everything that starts work is
  refused. The operator's terminal names how many sandboxes are still running
  and which. Every teardown also makes one more
  attempt to get the "why the record stops here" line onto the chain, because by
  then the machine is down and whatever was holding the disk may have let go
  (P7-17/F13(b)).
- **A snapshot name was checked on the MCP path and not on the CLI path.**
  `validSnapshotName` — a character allowlist, a length bound and a leading-dot
  refusal — was called by every MCP tool before it built a path and by none of
  `kelyfos snapshot save`, `kelyfos snapshot restore`, `kelyfos fork` or
  `kelyfos bench`. Both paths are driven by the local user's own flags, so no
  privilege boundary was crossed; it is closed because a rule enforced at some
  call sites is a rule the next call site misses. The check now lives in
  `snapshotDir`, which every call site already went through, with a
  `filepath.Rel` assertion after the join as belt and braces (P7-17/F7).
- **`kelyfos connect` created MCP client configuration files world-readable.**
  `~/.codex/config.toml` and `~/.gemini/settings.json` are files that commonly
  grow an API key later, and `os.WriteFile` only applies its mode on creation —
  so where `kelyfos connect` was the first thing to create one, which is the
  common case for a fresh setup, the client that later wrote a credential into
  it kept the `0644` it found. A file under `$HOME` is now created `0600` inside
  directories created `0700`; project-local files (`.mcp.json`,
  `.cursor/mcp.json`, `.vscode/mcp.json`, `.junie/mcp/mcp.json`) keep the
  umask-derived mode because they are meant to be committed. The rule is by path
  prefix rather than by client name, so a client added later inherits it, and an
  existing file is never widened — whatever mode is already stricter wins. The
  write is now atomic as well (temp file beside the target, fsync, rename),
  which it needed to be regardless: it is a read-modify-write of a file another
  program may have open (P7-17/F5).
- **A web page you visited could write files into a running shim sandbox and
  boot microVMs.** `kelyfos shim` serves on `127.0.0.1:3000` with no
  authentication by default, which is the exact configuration a browser can
  reach, and its middleware chain had no `Origin`, `Sec-Fetch-Site`, `Host` or
  CSRF check. `POST /files` takes `multipart/form-data`, a CORS-"simple"
  request needing no preflight, so a plain `<form>` in any page wrote a file
  into the live sandbox — `/work/.git/hooks/pre-commit`, say — and `POST
  /sandboxes` discarded its decode error, so a cross-origin post with no
  parseable body at all booted a machine. The responses are not readable
  cross-origin; the writes landed anyway. Every route now refuses, **before**
  the token check, a `Sec-Fetch-Site` that is neither `same-origin` nor `none`,
  the *presence* of an `Origin` header, and a `Host` header that does not name
  the bound address — the last being the only one that catches DNS rebinding,
  since a rebound page is same-origin with itself. `localhost` and any IP
  literal on the bound port are accepted; a name is not. No SDK sends any of
  those headers. `POST /sandboxes` now answers `400` to a body that is not
  JSON, reads it to a ceiling of 64 KiB, and still treats an absent body as
  "the defaults" (P7-17/F2).
- **The team channel's request frame reached the host, and the hash chain, with
  no sanitiser at all.** `proto.TeamRequest` is decoded straight off the guest's
  team vsock channel and carries the identity-like fields the Trojan Source
  widening exists for — a store key and another agent's name — which
  `internal/team/record.go` puts into the event the broker records. Two other
  frames had their `id` left out of an otherwise complete `Sanitize`, and the
  shell channel's exit frame had its `signal` left out beside an `error` that
  was cleaned. Every frame the host decodes off a guest channel now implements
  the interface, and a test asserts that list is complete rather than checking
  whichever types somebody remembered — the fuzz harness that should have
  caught this listed `TeamRequest` and then skipped it, because its guard only
  asserted on types that already implemented the interface (P7-17/F20).
- **Guest-chosen strings reached the operator's terminal without
  `proto.SafeText`.** A process name, a plugin name, a crash message, the
  kernel and supervisor strings on the boot line, and a command's captured
  output are all bytes the guest chose, and eight print sites across
  `kelyfos run`, `kelyfos exec`, `kelyfos log` and `kelyfos watch` printed them
  raw — so `comm = "\x1b[2J\x1b[3J…"` cleared the screen and the scrollback
  mid-run and could repaint a fake prompt, and `kelyfos run` recorded the same
  bytes into the hash chain, where they came back on every later replay. They
  are now sanitised at the edge, in `proto.Reader.Read`, before the value is
  either shown or recorded; the three replay surfaces sanitise again on the way
  out, because a chain on disk may predate this — once per event rather than
  once per field, because the per-field version missed nineteen of them,
  `agent` included, which is the `[who]` prefix on nearly every line. Command output keeps `\n`,
  `\t` and SGR colour and loses everything else, including OSC (window titles
  and hyperlinks), the CSI erase and cursor-movement sequences, and a bare
  `\r`. The predicate is now `unicode.IsPrint` rather than an ASCII control
  range, which also covers the Trojan Source characters — `U+202E` and the
  bidirectional isolates — in the terminal and in the exported HTML report
  alike (P7-17/F20, F1).
- **An `egress.attempt` refused because a foreign local process connected to
  the proxy printed as `egress BLOCKED :0`.** The refusal records the address
  that knocked in `peer` and nothing rendered it, so the one fact worth
  recording was visible only by reading the chain. `kelyfos log`,
  `kelyfos watch`, `kelyfos view` and the exported report now all name it, and
  `kelyfos view` prints the reason for a blocked egress as well (P7-17/F20).
- **A workspace image could come back short, or carrying a symlink chain that
  leaves the workspace, and be written over your project anyway.** `debugfs
  dump` opens its destination `O_CREAT|O_TRUNC` and copies block by block, and
  it reports a failed command on stderr while still exiting 0 — so a read error
  or a full staging disk part way through left a file that *exists* and is
  short, and "nothing was staged" was the whole per-file check. Every file, and
  every symlink target, is now compared against the size its own inode records,
  and a mismatch refuses the whole extraction. A symlink is judged by where its
  entire chain lands, resolved through the image's own entry set and with case
  folded, rather than one link at a time — three links that each look like they
  stay inside can compose into one that does not, and the filesystem your
  project lives on may not agree with the image about spelling. A directory
  whose name carries whitespace (`notes `, `my notes`) used to come back created
  and empty, with its contents gone and nothing saying so; the enumeration now
  quotes the name it asks about and refuses an image that will not list a
  directory at all. The dump also stages on the same disk as the images rather
  than in the system temp directory, which on most Linux hosts is RAM the guest
  can fill from inside.
- **A refused write-back deleted the workspace image, which was the only copy of
  what the sandbox did.** On the resume path the image was removed by a `defer`
  registered before the sync-back, so it ran on the error return too. It is now
  removed only after a write-back that actually happened, and a refusal names
  the path the image is still at. `kelyfos diff`, which reads a disk the guest
  is still writing to, reads the image a second time before reporting one of
  these refusals, so an ordinary busy agent no longer looks like a hostile
  image.
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
- **`count` under `[[team.agent]]` had no upper bound, unlike every sibling numeric field, so
  `count = 999999999999` in a `kelyfos.toml` crashed the whole `kelyfos` process with an
  unrecoverable Go OOM abort — from parsing the policy file alone, before any topology, budget or
  scratch check ran.** `host/teamplan.go`'s `expandCount` allocates `make([]string, 0, count)` per
  agent group as the very first thing `planTeam` does with a parsed count, so a large enough number
  was never a slow boot or a refused plan — it was a slice the allocator could not satisfy and an
  abort no `recover` catches. `count` is now capped at 64 in `internal/config/team.go`, refused at
  parse time with the same clear error `count < 1` already gets, rather than left to fail wherever
  the number was first used. 64 is headroom over anything this project's own examples or
  `max_sandboxes`'s default of 4 suggest a real team needs — `docs/teams.md` documents the ceiling
  next to `count`. `FuzzConfigParse` gained the finding's own reproduction as a seed and an
  invariant checking every parsed `Count` against the ceiling, alongside a dedicated unit test for
  the boundary itself.
- **The guest-facing team and events channels' accept loops had no connection cap and no read
  deadline, unlike the egress proxy's identical accept loop, fixed for exactly this shape by S5a —
  the fix was never mirrored to these two sibling listeners.** Both are unix sockets any process
  inside the guest can dial directly over vsock, not only through the supervisor's own
  well-behaved clients, and `serveTeam`/`serveEvents` spawned one goroutine per `Accept` with
  nothing bounding how many could be outstanding or how long one could sit open having sent
  nothing at all — enough silent connections and no connection, including a real one, could ever
  be served again. Both loops now acquire a 128-connection semaphore before `Accept`, the same cap
  and the same before-not-after placement `internal/egress/proxy.go` uses, and set a 10-second read
  deadline on an accepted connection that is cleared the moment its first frame parses — a
  connection already mid-conversation is never punished for an idle gap before its next request,
  which on the team channel can legitimately be arbitrarily long.
  `TestSilentTeamConnectionsAreCappedAndReclaimed` and `TestSilentEventsConnectionsAreCappedAndReclaimed`
  fill each cap with connections that never write and prove a legitimate connection queued behind
  it is still served once the deadline reclaims a slot, rather than stuck for good.
- **An oversized or malformed MCP frame — one over the 16 MiB channel limit, or one carrying a
  literal, unescaped newline — used to kill the whole session over a single bad frame, and could
  lose even the one reply meant to explain why.** `mcpSession.serve`'s read loop answered any
  non-EOF read error with a best-effort, id-less parse error and unconditionally closed the
  connection; for an oversized frame, `bufio.Scanner` gives up having buffered exactly the frame
  limit and no more, so the rest of that same line was still unread on the wire when the close
  raced it — the close could interleave with, or be cut short by, those unread bytes, and the
  reply was not guaranteed to arrive. Every call still in flight on the connection was lost with
  it, for a defect in one frame that had nothing to do with them. The session now recovers instead
  of closing: on `proto.ErrLineTooLong` it drains the rest of the oversized line first (a new
  `proto.Reader.DrainOverlongLine`, reading straight off the connection since the scanner's own
  buffer holds nothing past its limit) so the reply is never racing unread bytes, and on a frame
  that decoded to a complete, newline-terminated line but failed `json.Unmarshal` (the embedded-
  newline case, now reported as `*proto.MalformedFrame`) there was never anything to drain — the
  stream was already back at a clean boundary. Both cases reply and keep serving. Getting the
  first case right needed `proto.Reader` itself to stop reusing a `bufio.Scanner` after any error:
  one does not resume cleanly — the very next `Scan()` hands back its already-buffered, oversized
  data as if it were a normal final token, which is what a caller actually observed instead of the
  `ErrLineTooLong` it expected — so a successful drain now rebuilds the scanner in place
  (`resetScanner`) before resuming. The host bridge's own observer had the identical flaw one
  level up: `tee` in `host/mcpobserve.go` drove the client→guest and guest→client copies through a
  `bufio.Scanner` of its own for the flight recorder's sake, so the same oversized-line give-up
  closed the pipe the real byte copy reads from — silently dropping every byte sent afterward on
  that connection, from either side, regardless of how gracefully the guest handled the frame.
  `tee` now relays an oversized line's remainder raw and rebuilds its own scanner to resume
  observing what comes after, rather than ending the copy. `kelyfos mcp` also no longer exits 0
  when the bridge closes with a call still outstanding: `answerOutstanding` already wrote the
  client a synthetic error and a stderr line saying so, but returned nil regardless, so the one
  thing a wrapper script or supervisor process checks — `$?` — said success; it now returns a
  non-zero `exitError`. Verified against a real sandbox's MCP channel with both a frame just over
  `proto.MaxMCPLine` and a frame with a literal embedded newline: the session now answers each and
  keeps serving normal calls afterward, including a `write_file` whose event still lands in the
  flight recorder, rather than the bridge exiting silently.
- **`kelyfos exec` silently mangled an argument containing invalid UTF-8 bytes.**
  `proto.ExecRequest.Cmd` was a plain `[]string` JSON field, unlike `Stdin`, which
  docs/protocol.md §3 already requires base64 for because "every field whose value is raw bytes
  is base64": `encoding/json` marshals a Go string as UTF-8 and silently replaces any byte
  sequence that is not valid UTF-8 with U+FFFD, so an argv entry built from arbitrary bytes — a
  filename, a fetched credential, anything not guaranteed to be text — arrived in the guest
  corrupted, with no error anywhere on either side. `cmd` now gets the same treatment `stdin`
  already had: each argv element is base64-encoded by the host before the request is sent
  (`proto.EncodeCmd`) and decoded by the supervisor before it reaches `exec.Command`
  (`proto.DecodeCmd`), an invalid element failing the request with `error.kind = "bad_request"`
  rather than being silently accepted. The array structure is unchanged — only each element's
  encoding — so argv boundaries stay visible on the wire. Every place that builds an
  `ExecRequest` (`kelyfos exec`, `sandbox.Exec`, the guest's own `exec` MCP tool) and the one
  place that decodes it (`runCommand`) were updated in lockstep, since this is a wire-protocol
  change. Verified live against a rebuilt guest image: an argument built from the four bytes
  `0x80 0x81 0x82 0x83` — not valid UTF-8 on their own — now round-trips through `kelyfos exec`
  byte-for-byte instead of coming back as four U+FFFD replacement characters.
- **A TOML array element containing a comma inside its own quotes broke parsing of the whole
  policy file.** `parseArray` (internal/config/config.go) split the raw bracket contents on every
  `,` with `strings.Split` before `parseString` ever saw an element, so `args = ["x", "--y=a,b"]`
  under `[[plugin]]` — or the same shape under `[sandbox]`/`[[team.agent]]` allow and secrets,
  spawn images, or store read/write — tore the second element in two at the internal comma and
  failed with a misleading "expected a quoted string" error instead of loading. The split is now
  a quote-aware scan (`splitTopLevel`): it walks the bracket contents tracking whether the cursor
  is inside a `"..."` string, honoring `\"` as an escaped quote that does not close it, and only
  splits on a comma seen outside quotes. Verified with the finding's own repro — a `kelyfos.toml`
  with `[[plugin]] args = ["x", "--y=a,b"]` — which now loads with the two-element array intact.
- **`resource.summary`, the usage receipt written once at teardown, was emitted from only two of
  the places a session actually ends.** `kelyfos run` and a team member's own `stop` sampled and
  wrote one; `kelyfos serve-mcp`'s per-sandbox `close()` (which also covers the two early-boot-
  failure paths in `servemcptools.go` that route through it), `kelyfos resume`, and `kelyfos
  snapshot restore` did not, so a session ending through any of those three doors left a
  `session.start`/`session.ready`/`session.end` chain with no receipt of what it actually spent in
  between. Each now samples and appends the same event immediately before its own `Shutdown`,
  following the pattern the two working sites already used. Separately,
  `internal/sandbox/network.go`'s `BlockedPackets` — the egress firewall's own nftables drop
  counter — had no caller anywhere in the product; it is now read into a new `blocked_packets`
  field on every `resource.summary` event (zero for a sandbox with no network interface at all,
  same as one that blocked nothing), through one small helper shared by every teardown path rather
  than a nil check repeated at each. Verified live in the Lima VM: a `kelyfos serve-mcp` session's
  sandbox now writes a `resource.summary` ahead of its `session.end`, and a `kelyfos run --allow`
  session that made a connection attempt outside its allowlist now reports a nonzero
  `blocked_packets` on that same event. `kelyfos bench`'s throwaway boot-timing VMs and the
  fork-template cache's own build-and-snapshot machine (`host/teamtemplate.go`) were left alone —
  neither opens a flight recorder session at all, by design, so instrumenting them is a bigger
  change than this pass covers. The third sub-item of this finding — giving `kelyfos.toml` parse
  errors and team-plan check errors their own `denial` catalog IDs — was left alone too: both
  already carry the file and line that produced them, and `docs/reference/denials.md`'s own banner
  already states, on purpose, that refusals from those two paths are excluded because "the thing to
  go and look at is the line you wrote" — reversing that is a product decision, not a gap.
- **`Append`'s own size backstop only looked at six of the event struct's fields, though its
  comment claimed to cover "whatever field made it that large."** `clipLargestField`
  (internal/recorder/recorder.go) named `Data`, `Args`, `Host`, `Path`, `Name` and `Cmd` by hand;
  an oversized value anywhere else — `EvError.Message`, `Reason`, `Tool`, and every other string
  field on `Event` — was invisible to it, so `fitUnderMaxLine`'s clip loop found nothing to clip,
  exhausted its attempt budget, and `Append` refused the whole event: the event vanished from the
  record instead of being clipped and kept, the same failure mode S1 closed for `Data` and `Host`
  specifically. No current caller can put an oversized value in one of the missed fields, so this
  was latent rather than reachable, but the backstop's whole point is to hold even for a door this
  code does not yet know about. `clipLargestField` now finds its candidate by walking the struct
  with reflection (`largestStringField`) instead of a hand-maintained list — every string field,
  plus the fields of `*EvError` — so a field added to `Event` next month is covered the day it
  lands rather than the day someone reads this function and remembers to add it. `Cmd` keeps its
  separate `[]string` handling, since reflection over string-kinded fields does not see it.
  `FuzzAppendFieldValues` now drives one event through `setAllStringFields`, its own independent
  reflective walk, so a future field reachable by that walk but missed by `clipLargestField`'s own
  walk fails the fuzz run rather than needing a code read to find. Verified with the finding's own
  repro — a 9 MiB `EvError.Message` on an otherwise-empty event — which failed closed before this
  fix (confirmed by temporarily disabling the new code path) and now clips and keeps the event,
  verifying like any other clipped field.
- **`shim.Policy.Secrets` held `[]egress.Secret` — values, not pointers — the one container in the
  product that broke the pattern every other secret-holding container follows.** `Secret.String()`
  deliberately has a pointer receiver so it can redact: a `*Secret` formats as
  `Secret{NAME@domain scheme=Bearer}`, but a bare `Secret` value is outside that method's receiver
  set, so a stray `%v`/`%+v` on it falls back to reflecting over the struct fields — including the
  unexported `value` holding the plaintext credential — and prints it. Nothing formats
  `shim.Policy` as a whole today, so the gap was dormant, but it stood next to `egress.Policy.Secrets`
  and every other secret container in this codebase, all of which already carry `[]*egress.Secret`
  for exactly this reason. `shim.Policy.Secrets` is now `[]*egress.Secret` too; `host/shim.go`'s
  population of it (`shimCmd`, from `--secret` and the policy file) appends the already-owned
  pointer instead of dereferencing it, and `shim/shim.go`'s use of the field when building the
  sandbox's `egress.Policy` collapses to a plain slice assignment now that the two field types
  match. `TestPolicySecretsNeverFormatTheirValue` (shim/policy_secrets_test.go) pins it: it builds a
  `Policy` with a real parsed secret and asserts `%v`/`%+v` on the `Policy`, on `Policy.Secrets`, and
  on a `Secrets` element never contain the token, the same shape `TestSecretValueNeverFormats`
  already pins for a bare `Secret`.
- **`kelyfos runs --all` treated a locked-down or otherwise unreadable session directory as if it
  had never existed, in silence.** `readRun` (host/runs.go) passed every `os.Open` error, not just
  the "no such session" case, through the same bare `false` its caller reads as "nothing here" —
  so a permission-denied directory (or any other read error) vanished from the listing exactly like
  a directory that genuinely was not a session, with nothing distinguishing the two. docs/events.md
  §6 states the listing's guarantee as a count, "one row per session directory, no more and no
  fewer," which a silent drop breaks. `readRun` now returns its error separately from its found/not-
  found bool: `os.IsNotExist` still means "no session, say nothing," the same as before, but any
  other error — permission denied, an I/O error — is reported by `readRuns` as a
  `kelyfos: could not read session <id>: <err>` line on stderr instead of being folded into
  "missing." Verified live in the Lima VM with the finding's own repro: two session directories, one
  `chmod 000`'d — `kelyfos runs --all` now lists the readable one and warns about the other, where
  the prior binary listed only the readable one with no warning at all.
- **The host and supervisor MCP argument summarisers were two independent, byte-for-byte duplicated
  implementations — `summariseArgs` (host/servemcpaudit.go) and `summarisePluginArgs`
  (supervisor/pluginhost.go), each with its own copy of the `maxArgBytes`/`maxArgsBytes`/
  `maxArrayBytes` constants and its own copy of `clipUTF8`.** They were in exact lock-step by
  discipline rather than by construction: the shared low-level `proto.SafeText` the pair both call
  is genuinely unified, but nothing stopped a future edit to one copy's redaction or bounding rules
  from landing without the other, which would have made a supervisor-recorded plugin call redact
  differently from a host-recorded tool call with no way to notice. The shared logic — key sorting,
  `contentKeys` handling, the compact/clip rendering, the `maxArgsBytes` line budget, and `clipUTF8`
  itself — now lives once, in a new `internal/argsummary` package both binaries import; only what is
  genuinely caller-specific stayed local (host's `clipField`, which also bounds the tool name and
  sandbox id fields `summariseArgs` never touched). `contentKeys` and the three size constants are
  identical between the two callers, so those moved whole rather than being kept as two decisions
  that happened to agree. Both `summariseArgs` and `summarisePluginArgs` are now one-line wrappers
  over `argsummary.Summarise`; every existing test in both packages, and both fuzz targets, pass
  unchanged against the shared implementation, and `internal/argsummary` carries its own test suite
  covering the same guarantees directly.
- **`dev/demo-team.sh`'s teardown check false-failed on a shared host.** Step 6 asked `pgrep
  firecracker` a host-wide question — whether *any* Firecracker process exists anywhere on the
  machine — after tearing down its own five (or six, with the step-5 spawn) sandboxes, so any
  unrelated Firecracker session running alongside it on a shared dev box reported a teardown leak
  even though the demo's own VMs came down cleanly (F18, reproduced live during the security
  review that found it). The script already tracks each agent's sandbox ID in `$M`/`$W1`-`$W4` (and
  the step-5 spawn in `$NEW`) to report per-agent PASS/FAIL earlier in the run, so those are reused
  rather than adding new tracking: before `team down` runs, it now reads each sandbox's own
  `firecracker.pid` from `$RUN_ROOT/firecracker/<sandbox-id>/root/` — the same jail run-directory
  `internal/sandbox.jailRunDir` builds — and after teardown it asserts specifically that none of
  those PIDs are still alive, rather than asking whether Firecracker is running anywhere on the
  host.
- **`kelyfos snapshot restore` could write its `resource.summary` receipt after the `session.end`
  that is supposed to close the chain.** F14's fix wired `resource.summary` into a `defer`
  registered right after `sandbox.Restore` succeeds, but the CA-install-error, interrupted
  (Ctrl-C), and `vm_exited` exits still appended `session.end` inline, immediately before their
  own `return` — code that runs *after* that defer was registered, so on every one of those three
  paths the defer necessarily unwound afterward, writing `resource.summary` behind an event
  `docs/events.md` documents as the one that closes the file. `session.end` is now written from its
  own `defer`, registered before the resource-summary one so defers unwind last-registered-first
  and it fires second, the same ordering `run.go`'s own `reason`/`session.end` defer already keeps
  against its usage defer; the three sites set a `reason` variable instead of appending inline.
  Verified live in the Lima VM: a restored sandbox's `-json` log now shows `resource.summary`
  immediately ahead of `session.end` on both the interrupted and the `vm_exited` path.
- **`TestSnapshotRestoreRealVMWiresAuditBeforeResume` asserted through a binary the guest image
  doesn't carry, and silently discarded the exit code that would have said so (F20) — not a gap in
  S2/P6-4's restore-audit fix.** `guestEgressAttempt` drove the guest with `curl`, and its own doc
  comment claimed curl is what the base and dev image flavors both carry;
  `image/flavors/base/buildroot.fragment` says the opposite — base is "BusyBox and musl and nothing
  else. No TLS client" — curl is dev-only (`BR2_PACKAGE_LIBCURL_CURL`, in the dev fragment), and
  `requireRealSandbox` never asks for the dev flavor specifically. On a base-flavor guest, which is
  what this VM normally builds, the guest's shell answered "curl: not found" with `EXIT=127`, no
  request was ever made, and the exit status was thrown away, so a missing binary looked identical
  from the caller's side to a connection error. `fixed_order_captures_the_attempt` failed on both
  its assertions as a result, while `old_order_missed_the_attempt` passed regardless — it only
  checks for the ABSENCE of `egress.attempt`/`secret.withheld`, which is guaranteed whether or not a
  real attempt was made, so the guard subtest meant to prove its sibling meaningful reported green
  in exactly the situation where neither subtest proved anything. `guestEgressAttempt` now drives
  the guest with BusyBox wget, which both flavors carry, and returns its exit code instead of
  dropping it; both subtests now assert that code is not 127, failing loudly and by name rather than
  proceeding on a false premise. That alone only closes one way to no-op, so both subtests also
  count real hits on the upstream test server and assert the count moved: `forwardHTTP`
  (`internal/egress/proxy.go`) reaches it over a genuine `RoundTrip` whether or not
  `OnEvent`/`OnSecret`/`OnWithheld` are wired, so a rising count proves a request truly landed there
  — independent of the recorder chain the old-order subtest is busy saying is silent. Root-caused by
  the repository owner's review of PR #6, who re-ran the fixed ordering by hand against the same
  base image with wget in place of curl and got the correct events in the correct order, confirming
  S2/P6-4 works correctly on real hardware and this was always a test bug.

- **A request whose header block is larger than the egress proxy will parse is now refused with
  `431` and recorded as `header_too_large`, instead of being buffered whole.** Inside a
  TLS-terminated tunnel — the connections opened to a domain a `--secret` is bound to — every
  request after the first was parsed with no header ceiling of any kind, and Go supplies none
  either: a 16 MiB header line parses into memory without complaint. One guest, one long header
  line, times the 128 connection slots, is an out-of-memory the sandbox can trigger at will, on
  the one connection kind that is holding a credential while it buffers. The 1 MiB budget and the
  10-second header deadline that the first request on a connection always had are now applied to
  every request on that leg, reset per request and released before the body so a transfer is never
  charged against a header's budget. **New refusal reason:** `header_too_large` appears in
  `egress.attempt` events and in `kelyfos log`. It is deliberately not `bad_request` — that reason
  says the proxy could not parse a request, and this one says it refused to, which is a different
  thing for whoever reads the record. The connection's own summary still reports `allowed` with
  `mode: terminated`, because it describes the connection, which policy did permit and which the
  proxy did decrypt.

### Changed
- **A team's state file moved, and the documentation that told you to read it
  now points at `kelyfos team ps --json`.** `~/.cache/kelyfos/run/team.json` is
  gone; each team writes `~/.cache/kelyfos/run/teams/<session>.json`. That path
  is internal layout rather than a surface this project promises to keep still
  (`docs/compatibility.md` §2), and `kelyfos team ps --json` — added earlier in
  this same release — returns the same roster in the shape `team_ps` already
  guaranteed. [`docs/integrating.md`](docs/integrating.md) and cookbook recipes
  5 and 20 read the file directly and now ask the command line instead, and
  every team recipe's own teardown names the team it raised rather than saying
  "the team". A capped team's cgroup parent is likewise renamed on both paths —
  the systemd slice from `kelyfos-team-<name>.slice` to
  `kelyfos-team-<name>_<session>.slice`, and the direct one (under
  `KELYFOS_CGROUP_ROOT`, or as root) from `<root>/kelyfos-team-<name>` to
  `<root>/kelyfos-team-<name>_<session>`; `kelyfos team ps` prints the resolved
  path, so nothing needs to reconstruct the name. What to do about either is in
  [`docs/upgrading.md`](docs/upgrading.md) §7 (P7-16, D79).
- **The proxy waits ten minutes for an origin's first byte, not thirty
  seconds.** Both egress transports set `ResponseHeaderTimeout`, which neither
  Go's default nor a zero value supplies — without it an allowlisted origin that
  accepts, completes TLS and then says nothing holds a goroutine, a socket and,
  on the terminated leg, your credential. It shipped earlier in this release at
  thirty seconds, which is below the time a non-streaming completion from a
  model API legitimately takes to begin its reply: that request failed with
  `net/http: timeout awaiting response headers` on the one leg that carries a
  credential. The value is now the ten-minute cumulative idle budget the
  terminated leg already enforces, on both transports, and it is written down in
  [`docs/networking.md`](docs/networking.md) rather than living in a struct
  literal. Measured either way against an origin taking 35 seconds to answer:
  `30s -> timeout awaiting response headers` after 30s, `10m -> 200 OK` after
  35s. It still bounds only the wait for the first byte of the response head;
  the body is the ten-second rolling stall bound's, and the hour ceiling on the
  whole connection is unchanged (**D74**).
- **`kelyfos shim` now requires a credential, and mints one if you do not.**
  Unauthenticated was the default for three phases, with `KELYFOS_SHIM_TOKEN` as
  an opt-in. It is now the other way round: with that variable unset the shim
  generates 256 bits from `crypto/rand` at start, prints them once with the
  `export` line and a `curl` line, and every route requires
  `Authorization: Bearer <token>`, compared in constant time, answering `401`
  without it. **Running with no credential now takes `--insecure-no-token`** —
  an opt-out is a choice the operator can see, and an opt-in is a step nobody
  takes. **This breaks any client that was reaching the shim without one**,
  including the E2B Python SDK, which cannot carry a bearer token at all: its
  control plane sends `X-API-KEY` and its file routes send
  `Authorization: Basic base64("<user>:")` derived from the sandbox user (`e2b`
  2.45.1). Drive it with `--insecure-no-token` on loopback;
  `docs/cookbook.md`'s recipe does, and says why (P7-17/F2).
- **A `kelyfos.toml` found by walking up must be owned by you, and no policy
  file may be writable by anybody else.** `kelyfos` finds a policy file the way
  `git` finds a repository, and that file names a host directory to pack into
  the guest and sync back over, host directories to expose read-only to it, the
  domains it may reach, and which of your environment variables are attached to
  requests — with no check on who wrote it. A discovered file owned by another
  user is now refused by name, with `--policy` named as the way to use it
  deliberately; `--policy` skips the ownership rule and not the writability one,
  because naming a file does not make a file anybody can rewrite safe. A symlink
  is checked on both ends. World-writable is refused unconditionally; the group
  bit is refused only when the file's group is not your own user-private group,
  so a `umask 0002` machine — where `cat > kelyfos.toml` produces `0664` — is
  unaffected. **This can break a working setup**: a `kelyfos.toml` under a
  directory owned by another account, one left mode `0666`, or one whose group
  is a shared group with other members now stops the run instead of configuring
  it. The fix is in the message (`chmod go-w`, or `--policy`).
- **A `[[plugin]] path` outside the policy file's own directory tree is
  refused** unless `--plugin-path` names the same directory — a new repeatable
  flag on `kelyfos run` and `kelyfos serve-mcp`. A plugin directory is packed
  into a read-only device and mounted inside the guest, so everything in it is
  readable by whatever the agent runs; a `kelyfos.toml` naming
  `plugin.path = "/home/you/.ssh"` hands the agent a key. The check lives in
  `packPlugins`, so both doors that build the plugins device get it. **This can
  break a working setup**: a shared plugin directory beside several projects
  now needs the flag, and `docs/cookbook.md` §14 is a recipe for exactly that
  arrangement (P7-17/F21).
- **A `workspace` a policy file names outside its own directory tree is
  refused** unless `--workspace` names the same value on the command line. That
  directory is packed into the guest and written back over the host directory
  when the run ends, and a policy file describes its own project — a cloned
  repository does not get to name your home directory. Passing the flag is the
  escape hatch and makes the path your decision rather than the file's. Symlinks
  are resolved on both sides before the comparison.
- **Every run now says what its policy file reaches before anything boots**:
  the file's path, the workspace, every `[[plugin]] path`, and every secret by
  name with the domain it is bound to. Secret values are never read for this and
  never printed. Replaces the bare `policy: <path>` line on `kelyfos run`,
  `kelyfos team up`, `kelyfos sessions resume` and `kelyfos snapshot restore`
  (P7-17/F21).
- **`kelyfos shim` refuses to serve a non-loopback `--addr` unless
  `KELYFOS_SHIM_TOKEN` is set.** `--addr` accepted any address, and a shim
  bound off loopback with no credential is reachable from the LAN by a surface
  whose routes boot microVMs and write files into a live sandbox —
  `docs/e2b-shim.md` and `docs/threat-model.md` both said so while the code let
  it happen silently. The check reads the listener's own address, after the
  bind, so `--addr :0` and `--addr localhost:3000` are resolved before it is
  applied, and the refusal names the address and the fix. **A loopback bind is
  unchanged** — that is the default and every setup the documentation
  describes. Set `KELYFOS_SHIM_TOKEN` to keep an off-loopback bind working;
  every route then requires `Authorization: Bearer <token>`, compared in
  constant time (P7-17/F2).
- **A running sandbox is readable only by the `kelyfos` that started it.** The
  host's own record of a machine — `sandbox.json` and the marker a pause leaves
  — used to live in the sandbox's run directory, which *is* the chroot the
  jailer builds for Firecracker, owned by the uid the VMM is dropped to. Every
  later `kelyfos` process reads that file before doing anything: it names the
  host directory a resume renames the guest's tree over, the socket `exec` and
  `shell` dial, the image `snapshot save` copies into the next guest's
  snapshot, and the addressing the restored egress proxy binds and accepts
  from. Both files moved one level up, out of the chroot, and every path and
  address in them is now checked against something the reading process can
  derive for itself rather than believed.

  The break is two-way and there is no compatible middle, because a fallback
  that still read the copy inside the chroot would be the hole: a new binary
  cannot see a sandbox an older one started, and an older one cannot see a
  sandbox a new one started. Stop your running sandboxes before upgrading, or
  leave them to finish. While both versions are installed, `kelyfos sessions
  prune` and `sessions erase` lose the id-to-session mapping for machines
  started by the other one — their other liveness guards still hold — so do not
  run either until only one version is left. Nothing on disk needs migrating.
  [`docs/upgrading.md`](docs/upgrading.md) §5 has the detail (D72).
- **A `kelyfos.toml` combining `[team]` with `[[plugin]]` or `[[forward]]` is now refused by `kelyfos
  team up` (and `serve-mcp`'s `team_up`), at plan time, instead of silently booting a team where
  neither did anything.** Both keys are file-level and always parsed next to an ordinary `[team]`
  section, but `packPlugins` and `resolveForwards` — the two functions that actually launch a plugin
  or open a forward — are only ever called from the single-sandbox doors (`kelyfos run`,
  `serve-mcp`'s own sandbox), never from a team boot. A file naming either alongside `[team]` used to
  load without complaint and produce a team with no plugin tools advertised and no forwarded port
  listening; it is now refused by name, with the line, and with the fix (drop the block, or run that
  plugin or forward outside `[team]`). Ruled not a breaking change (D66): the combination never
  worked, so nothing that depended on its effect can be broken by this — only the earlier silence
  about it. `[[plugin]]` and `[[forward]]` continue to work exactly as before outside `[team]`.

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
  the host cannot use, and extraction goes through an `os.Root`, so a name that
  got past the check still cannot leave the tree. Reported by an external
  security audit. *(This entry named `openat2` with `RESOLVE_BENEATH` and
  `RESOLVE_NO_SYMLINKS` until v1.1. The behaviour v1.0 shipped is unchanged and
  the mechanism was described wrongly: Go's `os.Root` calls `openat2` nowhere —
  `openat2Trap` is declared in GOROOT and never called — and walks the path one
  component at a time with `openat(O_NOFOLLOW)`, resolving each link itself. The
  guarantee it gives is stricter than `RESOLVE_BENEATH` in one respect: an
  absolute link is refused even when it points back inside the tree. Corrected
  at P7-17.)*
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
  a documentation audit of 2026-08-25. It also found
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

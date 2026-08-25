# The v1.0 documentation audit — findings

**Taken:** 2026-08-25, against `5a6aa78`. **Task:** P6-15. **Status:** the record of
what was found. The corrections are the commit after this one, deliberately, so that
what was wrong survives the fixing of it.

Every hand-written document was read against **the code that implements it**, not
against the other documents — the version that reads documents against each other
reports a tidy directory and finds nothing, because the documents agree with each
other and the code is the thing they have drifted from.

The generated set (`docs/reference/*`, `llms.txt`, `llms-full.txt`) is excluded: a
hand edit there is reverted by the next `make docs` and turns the pipeline red.
A finding against a generated page is a finding against its generator.

## Method, and what the numbers are worth

21 documents. 202 candidate findings; each was then handed to a separate
reader whose instruction was to **refute** it — quote the line, read the code, and
report the candidate as unreal if the document was right. **174 survived that
pass and 28 were refuted**, which is a 14% false-positive rate on the first pass and
the reason the second pass exists. The refutations were not retained; only the
survivors are recorded here, each with the file and line that proves it.

A finding here is not an opinion about wording. Each one names a sentence, what the
code actually does, and where to look.

| kind | count | what it means |
| --- | --- | --- |
| `FALSE` | 44 | the document states something the code does not do |
| `STALE` | 41 | it was true when written and the code moved |
| `IMPRECISE` | 54 | true as far as it goes, and misleading in the case that matters |
| `MISSING` | 35 | behaviour that exists and is documented nowhere |
| **total** | **174** | |

| document | findings | of which false or stale |
| --- | --- | --- |
| `docs/protocol.md` | 18 | 9 |
| `docs/events.md` | 17 | 8 |
| `README.md` | 15 | 7 |
| `docs/threat-model.md` | 15 | 6 |
| `docs/mcp-surface.md` | 15 | 8 |
| `docs/integrating.md` | 15 | 6 |
| `docs/hardening.md` | 11 | 6 |
| `docs/README.md` | 9 | 6 |
| `docs/resources.md` | 8 | 3 |
| `docs/teams.md` | 8 | 5 |
| `docs/cookbook.md` | 8 | 4 |
| `docs/networking.md` | 6 | 2 |
| `docs/qol.md` | 5 | 1 |
| `docs/compatibility.md` | 5 | 3 |
| `docs/denials.md` | 4 | 2 |
| `docs/e2b-shim.md` | 4 | 1 |
| `SECURITY.md` | 4 | 4 |
| `CONTRIBUTING.md` | 4 | 1 |
| `.github/workflows/release.yml` | 1 | 1 |
| `Makefile` | 1 | 1 |
| `docs/media/demo.cast` | 1 | 1 |

---

## The findings

### `.github/workflows/release.yml`

**.github/workflows/release.yml:100 — `STALE`**

> rm -f dist/kelyfos-linux-* # the publish job builds the pair it ships

Code defect rather than doc drift. `make release-cli` builds four binaries, not a pair: the two Linux CLIs and the two macOS CLIs. This line removes only the Linux ones, so both matrix jobs upload `kelyfos-darwin-x86_64` and `kelyfos-darwin-aarch64` inside their `image-<arch>` artifacts, and the publish job's `download-artifact … merge-multiple: true` has two artifacts carrying the same two filenames. The shipped bytes end up correct only because the publish job's own `make release-cli` overwrites them afterwards.

*Proof:* Makefile:210-231 (four binaries); .github/workflows/release.yml:109-114 (upload dist/), 132-136 (merge-multiple), 141-142 (rebuild)


### `CONTRIBUTING.md`

**CONTRIBUTING.md:96 — `STALE`**

> What is *not* pinned: the host build packages `apt` installs, and the build is not reproducible yet — that work is P6-9.

P6-9 landed on 2026-08-25 (commit 50c9445). The four determinism knobs are on — BR2_REPRODUCIBLE, SOURCE_DATE_EPOCH taken from the commit rather than the clock, a fixed ext4 UUID and hash seed, gzip -n — and .github/workflows/repro-check.yml now rebuilds and diffs per artifact on a monthly schedule. It has been run: two full aarch64 dev builds from nothing produced byte-identical Image, rootfs.ext4 and image.json, and the two Linux CLI binaries are identical when built from two different source paths. The apt half of the sentence is still correct (dev/install-build-deps.sh:22 installs unversioned packages), but 'not reproducible yet — that work is P6-9' describes a task that is finished. CONTRIBUTING.md was last touched on 2026-08-24 at P6-2, one day before P6-8 through P6-14 landed.

*Proof:* Makefile:19 (export SOURCE_DATE_EPOCH, "P6-9, D38"); .github/workflows/repro-check.yml:55-74 (the CLI comparison) and :123-143 (the per-artifact image comparison); commit 50c9445

**CONTRIBUTING.md:94 — `IMPRECISE`**

> Bumping one means changing the version and its checksum in the same commit, with the reason in the progress log.

True for three of the four components the previous sentence names, not for Firecracker. versions.mk pins FIRECRACKER_VERSION ?= v1.16.1 with no accompanying digest, deliberately: the release tarballs publish their own .sha256.txt, which dev/install-firecracker.sh fetches and checks at install time. A contributor bumping Firecracker who follows this sentence looks for a checksum that does not exist. Buildroot, Linux and Go do each have a SHA256 line, so the rule holds for them.

*Proof:* versions.mk:41-44 (Firecracker: version only, "Release tarballs ship their own .sha256.txt"); dev/install-firecracker.sh:40-50 (fetches and verifies it at install time)

**CONTRIBUTING.md:79 — `MISSING`**

> The Linux layer is required — Firecracker runs on Linux/KVM only:

True for the guest image and for running a sandbox, but since P6-12 (commit d016223) the CLI has a second target: host/lima_darwin.go and host/layer_darwin.go are //go:build darwin, host/platform_other.go is //go:build !linux, and Makefile:223-230 cross-builds kelyfos-darwin-{x86_64,aarch64} for the release. Nothing in .github/workflows ever sets GOOS=darwin — grep finds no occurrence — so `go vet ./...` and `go test ./...` in CI never compile those files, and the only thing that does is `make release-cli`, which runs at tag time in release.yml. A contributor can break the macOS build in a PR, see green, and have it surface during a release. The guide describes only the Linux path and never says the second one exists.

*Proof:* host/lima_darwin.go:1 and host/layer_darwin.go:1 (//go:build darwin); host/platform_other.go:1 (//go:build !linux); Makefile:223-230 (darwin cross-build); .github/workflows/release.yml:98,142 (make release-cli — the only darwin compile in CI)

**CONTRIBUTING.md:89 — `MISSING`**

> Bare `make` prints the target list and builds nothing — the default goal is `help`.

Accurate (Makefile:88), but it is the document's only statement about make targets and the section never reaches the ones a change has to pass. CI's `checks` job requires the tree to be gofmt-clean, `go vet ./...` to pass, `go test -count=1 ./...` to pass, `make fuzz FUZZTIME=10s` to find nothing, the hostile-input corpus to hold with KELYFOS_HOSTILE=required, tools/check-plan.py to accept PLAN.html, and every cookbook recipe to extract and parse. `make test` exists (Makefile:354-356) and is never mentioned; neither is gofmt, which is the first thing that fails and the one a contributor is most likely to trip.

*Proof:* .github/workflows/ci.yml:136-141 (gofmt gate), :143-149 (vet and unit tests), :159-160 (fuzz), :188-193 (hostile corpus), :195-196 (check-plan.py), :225-233 (cookbook); Makefile:354-356


### `Makefile`

**Makefile:188 — `STALE`**

> they are not bit-for-bit what `image` makes here, because the build is not # reproducible yet (P6-9), and they are not signed (P6-11).

Both halves are now out of date, and the script this comment sits above already says so. P6-9 (commit 50c9445) measured the rebuild and found the aarch64 dev image byte-identical across two from-nothing builds; P6-11 (commit c6d065c) added attestations — release.yml runs actions/attest@v4 over dist/SHA256SUMS and once per architecture over the SBOMs, which is SLSA v1.0 Build Level 2 provenance verifiable with `gh attestation verify`. dev/fetch-image.sh was rewritten to say exactly this ('measured rather than claimed', 'Provenance is a separate statement and there is one'), while the Makefile comment that introduces the same target was not updated with it. Reported here rather than against a document because it is a claim in the build entry point, not on a generated page.

*Proof:* dev/fetch-image.sh:7-16 (the corrected wording); .github/workflows/release.yml:184-208 (actions/attest@v4); .github/workflows/repro-check.yml:123-143; commits 50c9445 and c6d065c


### `README.md`

**README.md:15 — `FALSE`**

> five agents up in **412 ms** — > x86_64 on a bare-KVM CI runner, ten runs each, by a benchmark workflow in this > repository rather than by hand.

The benchmark workflow never boots a team. `.github/workflows/bench.yml` has exactly two measurement steps — `kelyfos bench --runs 10` for cold boot and `kelyfos bench --restore bench` for restore — and the word "team" does not appear in it. The five-agent figures come from `dev/demo-team.sh`, run by caps.yml, which scrapes the first `team up in <N> ms` line out of one cold run and one warm run. So "ten runs each" is true of the boot and restore numbers and false of the 412 ms, and "by a benchmark workflow" is the wrong workflow.

*Proof:* .github/workflows/bench.yml:103,119 (no team step anywhere in the file); dev/demo-team.sh:122 (`ms()` takes `sed -n '1,1p'`), 139, 162; .github/workflows/caps.yml:114-119

**README.md:160 — `FALSE`**

> The downloads above are built from this source at the release tag, by [`.github/workflows/release.yml`](.github/workflows/release.yml) — both architectures in one workflow run, from the tag's own commit, with `SHA256SUMS` regenerated from scratch over exactly the files attached.

The downloads above are v0.9 (README:83 says so: "against the v0.9 release, which is what the commands below actually download", and dev/fetch-image.sh:23 defaults TAG=latest). release.yml did not exist when v0.9 was tagged, so no artifact a reader downloads today was built by it. The README's own next sentence concedes this, which makes the two statements contradict each other rather than qualify each other.

*Proof:* dev/fetch-image.sh:23,40-42; .github/workflows/release.yml:20-21 (`on: push: tags: ["v*"]`) added 2026-08-25, v0.9 tagged 2026-08-24

**README.md:200 — `FALSE`**

> **Release artifacts carry a provenance attestation**: a statement, signed by GitHub, saying which workflow and which commit produced these exact bytes. One command checks it, and it needs nothing from this project: ```sh gh attestation verify kelyfos-linux-x86_64 --repo p4r4n0rm4l/KelyfOS ```

No released artifact carries one. The attestation steps live only in `.github/workflows/release.yml` (`actions/attest@v4` at lines 186, 199, 206), and that file was first committed on 2026-08-25 (c6d065c "P6-11"), while the newest and only current tag is v0.9 from 2026-08-24. The workflow's own header states the position: "Every release this project has cut was assembled by hand, and the v0.9 artifacts prove it". `gh attestation verify kelyfos-linux-x86_64` against the published release fails today, and so does the claim two lines later that "Each architecture's SBOM is attested too".

*Proof:* .github/workflows/release.yml:3-8 and 186; `git log --format='%ci' -- .github/workflows/release.yml` → 2026-08-25; `git log -1 --format='%ci' v0.9` → 2026-08-24

**README.md:448 — `FALSE`**

> Guest-chosen modes do not survive onto your filesystem.

They largely do. `safeMode` keeps the guest's permission bits and only clears world-write and forces the owner bits on: `p := m.Perm() &^ 0o002` then `p | 0o700` (dirs) or `p | 0o600` (files). `copyThrough` then explicitly re-applies them after the copy, with the comment "the executable bit is the half of the guest's intent worth keeping". What does not survive is setuid/setgid/sticky (dropped by `.Perm()`) and world-write — not "modes".

*Proof:* internal/sandbox/extract.go:263-269 (safeMode), internal/sandbox/extract.go:425-427 (root.Chmod)

**README.md:261 — `STALE`**

> Writing that file by hand is what `kelyfos connect <client>` is for; until it ships, [`docs/integrating.md`](docs/integrating.md) has the per-client shapes.

It has shipped. `connect` is a dispatched subcommand with `--remove`, `--check`, `--project`, `--policy`, `--bin` and `--list`, and README's own table at line 365 lists it as an existing command. The clause "until it ships" was written before P6-13 (da9ebb2, 2026-08-25) and was not removed.

*Proof:* host/main.go:100 (`case "connect"`), host/connect.go:96-107

**README.md:394 — `STALE`**

> [`docs/cookbook.md`](docs/cookbook.md) | fourteen recipes that work

There are fifteen. `docs/cookbook.md` carries fifteen `<!-- recipe: … -->` markers (one-sandbox … forward-a-port, including the separately-numbered `connect-a-client`), its own opening line says "Fifteen recipes", and `tools/cookbook`'s `checkCount` fails the build if that stated number and the marker count disagree — so fifteen is the enforced figure and the README is the only place that says fourteen.

*Proof:* tools/cookbook/main.go:163-177 (checkCount); docs/cookbook.md:3 and the 15 markers at lines 32,82,142,204,291,423,592,653,735,881,969,1082,1281,1355,1413

**README.md:487 — `STALE`**

> The host build packages are not pinned, and reproducible builds are still open.

Reproducibility stopped being open one commit before this page was last touched. `.github/workflows/repro-check.yml` builds the same commit twice and diffs per artifact, and README's own table at lines 176-179 already reports both CLI binaries and the aarch64/dev image as byte-identical. The sentence was written at P6-1 (930ff74, 2026-08-24) and P6-9 (50c9445, 2026-08-25) did not update it, so the same page says both things.

*Proof:* .github/workflows/repro-check.yml:39-95; `git log -S "reproducible builds are still open" -- README.md` → 930ff74 only

**README.md:99 — `IMPRECISE`**

> limactl start --name kelyfos-dev dev/lima.yaml limactl shell kelyfos-dev # everything below runs in here

Line 55 of the same page says "you never type `limactl`", and the code treats a hand-made instance as unmanaged: `limaDrifted` finds no marker file and reports "this instance was not created by `kelyfos doctor`, so what it was made from is unknown", with the fix being `kelyfos doctor --recreate` — which stops, deletes and re-provisions the VM the reader just built. Following the quickstart puts a macOS reader straight into that state.

*Proof:* host/lima_darwin.go:33 (instanceName = "kelyfos-dev"), 68-80 (limaDrifted's no-marker branch)

**README.md:264 — `IMPRECISE`**

> The agent then sees six tools — `exec`, `read_file`, `write_file`, `list_dir`, `upload`, `download` — and nothing else.

Those six are the guest-side tools, but the sentence lands directly after the `serve-mcp` JSON block and the `.mcp.json` / `kelyfos connect` paragraphs, so it reads as a description of what a client configured that way sees. A `serve-mcp` client sees twelve host-side tools instead: sandbox_run, sandbox_exec, sandbox_read_file, sandbox_write_file, sandbox_stop, sandbox_list, sandbox_snapshot, sandbox_restore, sandbox_fork, team_up, team_ps, team_down — none of them named here. The six are reached through `kelyfos mcp` or the `run … -- <agent>` form.

*Proof:* host/servemcptools.go:31,49,70,85,101,111,118,133,150 and host/servemcpteam.go:33,42,50 vs supervisor/tools.go:31,49,62,75,85,99

**README.md:304 — `IMPRECISE`**

> Sandboxes created through `serve-mcp`, `fork`, `snapshot restore` and the E2B shim do not carry one yet.

The exclusion list reads as exhaustive and is missing the pause/resume path. `run` skips the receipt when the run ended in a pause — the append is guarded by `pausedAs == ""` — and `resume` appends only a `session.resume` event, never a `resource.summary`. A machine that is paused and later resumed therefore never produces one, so the preceding claim that "a `kelyfos run` session … ends with a `resource.summary` event" does not hold for it either.

*Proof:* host/run.go:542-553 (`if u, err := sb.State.Sample(); err == nil && pausedAs == ""`); host/sessions.go:463-466 (resume appends only TypeSessionResume)

**README.md:409 — `IMPRECISE`**

> Every figure above is measured on the bare-KVM reference — a stock `ubuntu-latest` GitHub runner with KVM — by `make bench`, which is a workflow in this repository.

bench.yml never invokes `make bench`; it runs `./bin/kelyfos bench` directly. More substantially, "every figure above" is wrong: the 412 ms and 286 ms team figures three paragraphs down come from `dev/demo-team.sh` under caps.yml, and `make bench` only shells out to `kelyfos bench --runs … --arch … --image …`, which measures one sandbox.

*Proof:* .github/workflows/bench.yml:103,119; Makefile:288-289; .github/workflows/caps.yml:114-119

**README.md:432 — `IMPRECISE`**

> One of them was incomplete until v1.0, and the sentence above was true of the guest and not of the host.

There is no v1.0. The tag list ends at v0.9 (2026-08-24) and PLAN.html has Phase 6 — "v1.0, the promise" — still open. The workspace fix this paragraph describes landed on main at 8bda078 on 2026-08-25, after v0.9 was cut, so the release the quickstart downloads (README:83) still extracts workspaces the old way. The page's own status line at line 13 says "Status: v0.9".

*Proof:* `git tag` ends at v0.9; `git log --format='%ci' -- internal/sandbox/extract.go` → 2026-08-25 (8bda078, P6-24); README.md:13,83

**README.md:54 — `MISSING`**

> **On macOS there is a Linux layer, and kelyfos looks after it.** There is a macOS build of the CLI, and you never type `limactl`:

The macOS binary exists — `make release-cli` cross-builds `dist/kelyfos-darwin-{x86_64,aarch64}` — but the README never says how to get one onto a Mac. The only installer, `dev/install-kelyfos.sh`, keys on `uname -m` alone and downloads `kelyfos-linux-$ARCH`; run on macOS it installs a Linux ELF as `bin/kelyfos` and then fails at its own `kelyfos version` step. `brew install lima` (line 58) is the only install command the macOS block gives, and it installs Lima, not kelyfos.

*Proof:* Makefile:223-230 (GOOS=darwin builds); dev/install-kelyfos.sh:14-18 and 30-45 (no darwin branch)

**README.md:59 — `MISSING`**

> kelyfos doctor --setup # provision the layer and start it

The hardware requirement is never stated on this page. The layer needs Apple M3 or newer and macOS 15+ for Virtualization.framework nested virtualisation; without it `/dev/kvm` never appears in the Lima guest and the instance's own probe fails at start. doctor's fix text and lima.yaml both say so; the README does not, so a reader on an M1/M2 Mac follows the macOS block to a failure it does not predict.

*Proof:* host/doctor.go:178-182 ("On Apple Silicon (M3 or newer, macOS 15+)"); dev/lima.yaml:3-5, 51-53, 96-98 (probe hint)

**README.md:446 — `MISSING`**

> inside the guest | every process the supervisor spawns — `exec`, a plugin, the shell — is confined by Landlock (writes only `/work`, `/tmp`, `/run`, `$HOME`, `/dev/pts` and `/dev/shm`, plus seven named device nodes) and a seccomp refusal list of 28 syscalls.

The trees, the seven device nodes and the 28 syscalls all check out exactly. What the row omits is a second enforcement point added by P6-24: the supervisor is PID 1 and is not itself confined by the profile, so `write_file` and `upload` used to be able to write anywhere, including `/dev/vda` and `/dev/vdb`. `writableFor` now holds the supervisor's own file tools to the same three lists the profile is built from; reads are deliberately left unrestricted. The row's "every process the supervisor spawns" excludes the tools running inside PID 1, which is where that hole was.

*Proof:* supervisor/writable.go:9-36 (rationale) and 42-62 (writableFor, checked against writableEverywhere/writableDeviceTrees/writableDevices); supervisor/profile.go:66,83-89


### `SECURITY.md`

**SECURITY.md:126 — `FALSE`**

> A report that the artifacts are unsigned tells us something we say ourselves, in four places.

It is now said in exactly one place: this sentence. Grepping the whole documentation set for "not yet signed", "unsigned", "checksummed" and "reproducib" across README.md, docs/hardening.md, docs/threat-model.md and SECURITY.md returns the claim only from SECURITY.md:123-126; README.md:466 and docs/hardening.md:313 now describe measured reproducibility and shipped attestations instead.

*Proof:* .github/workflows/release.yml:170-209; README.md:203-208 ("That is SLSA v1.0 Build Level 2")

**SECURITY.md:64 — `STALE`**

> This is a `v0.x` project moving toward `v1.0`, and the support commitment above is deliberately minimal until the compatibility promise exists to say more.

The compatibility promise exists — docs/compatibility.md was added at P6-14 and is normative from v1.0. SECURITY.md still frames it as absent and does not link to it, even though §3 of that page makes a directly security-relevant commitment ("A security fix that must narrow a surface is not a patch") that a reporter reading this file would want.

*Proof:* docs/compatibility.md:1-3; git commit ca506b3 ("P6-14: the compatibility promise") adds docs/compatibility.md

**SECURITY.md:110 — `STALE`**

> The credential binding is a *suffix* match, so `--secret T@github.com` also covers `api.github.com` — bind narrowly.

Suffix matching is now only the default. A secret spec is `NAME@host[:bearer|basic][/path]`, and naming a path binds the credential to one endpoint on one host exactly — the suffix rule is turned off, and a wildcard host with a path is refused outright: "a path binds one host exactly, so %q cannot also be a wildcard". The advice "bind narrowly" omits the mechanism that actually narrows.

*Proof:* internal/egress/secret.go:232-239 (`Covers`), internal/egress/scope.go:25-27, internal/egress/secret.go:123-128; internal/config/schema.go:155-157 documents the `/path` form

**SECURITY.md:123 — `STALE`**

> - **The supply chain, for now.** Release artifacts are checksummed but not yet signed or attested, and the build is not yet reproducible.

All three halves of this shipped in the current phase. The release workflow runs three `actions/attest@v4` steps — one build-provenance attestation over every asset and one SBOM attestation per architecture — after `make release-sbom` produces a CycloneDX SBOM per arch, and reproducibility is measured by its own workflow rather than open. README.md:466 now says "reproducibility is measured per artifact rather than claimed". SECURITY.md is the only document left carrying the old sentence.

*Proof:* .github/workflows/release.yml:186, .github/workflows/release.yml:199, .github/workflows/release.yml:206 (attest steps); .github/workflows/release.yml:99 (`make release-sbom`); .github/workflows/repro-check.yml


### `docs/README.md`

**docs/README.md:82 — `FALSE`**

> **Mixed.** Every document above except the threat model. The inventory names which half of each is reference, so it is clear what a generator will eventually own and what will always be someone's prose.

The map directly above contradicts this. Five documents are not mixed: compatibility.md is "hand" (line 41), qol.md "concept" (49), mcp-surface.md "concept" (50), hardening.md "concept" (51), cookbook.md "recipes" (54) — plus threat-model.md "concept" (53). "What the kinds mean" also defines only three of the six labels the map actually uses; "hand", "recipes" and "not documentation" are never defined.

*Proof:* docs/README.md:41, docs/README.md:49-51, docs/README.md:54 (the Kind column of its own map)

**docs/README.md:30 — `STALE`**

> | after something that works, right now | [`cookbook.md`](cookbook.md) — fourteen recipes, each one runnable as it stands |

There are fifteen extracted recipes. The extractor keys on `<!-- recipe: name -->` markers and docs/cookbook.md carries fifteen of them; recipe 9b (`connect-a-client`, "Attach a client with one command") was added at P6-13 and is extracted and run like the rest. The same stale count appears twice more: line 54 "Fourteen complete, copy-pasteable recipes" and line 174 "### `cookbook.md` — fourteen things that work". The inventory's recipe list at lines 175-190 also never mentions `kelyfos connect`.

*Proof:* docs/cookbook.md:881 (`<!-- recipe: connect-a-client -->`, the fifteenth marker); dev/cookbook.sh:45 and .github/workflows/ci.yml:229 (`tools/cookbook -in docs/cookbook.md`, one script per marker)

**docs/README.md:34 — `STALE`**

> | judging whether to trust it | [`threat-model.md`](threat-model.md), then [`hardening.md`](hardening.md) for what v0.9 is adding |

v0.9 is the shipped release — it is the newest git tag and README.md:13 states "Status: v0.9". hardening.md is described elsewhere on this same page as a specification "written before its code" that "the code has since answered" (lines 242-244). Sending a reader to it "for what v0.9 is adding" describes work that landed at P5-2 through P5-4.

*Proof:* git tag → v0.9 is the latest; README.md:13,18; docs/README.md:242-246

**docs/README.md:61 — `STALE`**

> The plan files at the repository root — [`PLAN.html`](../PLAN.html) for phases 0–4 and [`PLAN-FEATURES.html`](../PLAN-FEATURES.html) for the epics after them — are **not** documentation.

PLAN.html covers phases 0 through 6, not 0–4. It contains headings for Phase 0 through Phase 6 and 153 occurrences of `P6-`, including the task that created docs/compatibility.md. PLAN-FEATURES.html holds Epics E1–E5, which were interleaved with rather than wholly after the phases.

*Proof:* PLAN.html (headings "Phase 0"…"Phase 6"; 153 `P6-` references); git commit ca506b3 modifies PLAN.html for P6-14

**docs/README.md:105 — `STALE`**

> §6 defines MCP framing and not one MCP tool; no timeout in the system is written down except the heartbeat.

Plugin timeouts were written down when the E4 exam's inward finding 9 was fixed: docs/mcp-surface.md now carries a table row "Time to answer `initialize` | **20 s**" and "Time to answer one tool call | **120 s**". `exec --timeout`, `--max-runtime` and `--idle-timeout` are also in the generated CLI reference and carry exit code 124. The same sentence is repeated at lines 294-295 ("and every timeout in the system except the heartbeat").

*Proof:* docs/mcp-surface.md:587-588; internal/exitcode/exitcode.go:52 (`a time budget expired — --max-runtime, --idle-timeout, or exec --timeout`)

**docs/README.md:142 — `STALE`**

> `[resources] cpus` is not checked for positivity;

It has been checked since P6-3. `[resources] cpus` is parsed by `parseCount`, which returns "<file>:<line>: cpus cannot be negative" for a negative value. The fix is documented in the function's own comment: "`cpus` was the one that was not, so `cpus = -1` parsed cleanly and became the ceiling every flag is compared against ... Found by FuzzConfigParse (P6-3)."

*Proof:* internal/config/config.go:206 (cpus → parseCount), internal/config/config.go:306-315 (the negative check)

**docs/README.md:72 — `IMPRECISE`**

> code cites it back: 139 comments across 61 Go files name a document and a section, so a section number here is load-bearing rather than decorative.

Neither number matches the tree. Go lines matching a document name followed by a section sign: 111, across 62 files (56 files excluding tests). Go lines naming a `docs/*.md` at all: 179 across 83 files (161 across 69 excluding tests). No counting rule I could construct yields 139/61. This is the same hand-typed number the page itself warns about eleven lines earlier at line 58.

*Proof:* grep -rn -E "[a-z-]+\.md §" --include="*.go" . → 111 lines / 62 files; grep -rn -E "docs/[a-z-]+\.md" --include="*.go" . → 179 lines / 83 files

**docs/README.md:86 — `MISSING`**

> ## The inventory What each document is made of, and where it is thin.

The inventory has an entry for all fourteen other hand-written documents and none for compatibility.md, which the map added at line 41. The page promises the coverage twice — line 8-9 ("every document below says which kind it is, and this page says where each one is still thin") and line 15-16 ("The pages beside it are the hand-written half, and this page says where each is still thin") — so the newest normative document is the one page with no account of what it is made of or where it is thin.

*Proof:* docs/README.md:95-281 (fourteen `### ` entries: protocol, events, networking, resources, denials, teams, cookbook, integrating, mcp-surface, qol, hardening, host-seccomp, threat-model, e2b-shim); docs/README.md:41 (compatibility.md in the map)

**docs/README.md:301 — `MISSING`**

> **Environment variables.** `KELYFOS_CACHE` and `KELYFOS_CGROUP_ROOT` are read by the CLI and named nowhere.

A third one joined them at P6-13 and is likewise named in no document: `KELYFOS_CONNECT_HOME`, read by `connectHome()` to relocate where `kelyfos connect` writes per-user client configuration ("The override exists for tests and for anybody generating a configuration for a machine that is not this one"). Grepping the documentation for it returns nothing.

*Proof:* host/connect.go:53-63


### `docs/compatibility.md`

**docs/compatibility.md:11 — `FALSE`**

> Seven surfaces already have a machine-readable source of truth and a CI-enforced generated page, so this promise **cites** rather than re-lists — and cannot go stale by the mechanism that already keeps the reference honest (F-D4).

The arithmetic does not close. There are seven generated pages (cli, config, denials, events, exit-codes, tools, profiles) but they are not the seven surfaces §2 lists: profiles.md is generated and is explicitly excluded from the promise by §3, while §2's protocol row has no generated page at all. So only six of the seven promised surfaces are protected by the drift gate, and the seventh promised surface — the protocol — can go stale by exactly the mechanism this sentence says it cannot.

*Proof:* tools/gendocs/main.go:74-92; docs/reference/README.md:10-18 (the seven pages, including profiles.md); docs/compatibility.md:85-90 (profiles excluded)

**docs/compatibility.md:55 — `FALSE`**

> Each of these has a generated page, produced from the code that implements it, which CI fails on drift.

Six of the seven rows have a generated page. The seventh — `| the host↔guest protocol | protocol.md | internal/proto |` (line 67) — points at a hand-written document. gendocs writes exactly eight files: README.md, cli.md, config.md, denials.md, events.md, exit-codes.md, tools.md, profiles.md. There is no protocol page, docs/protocol.md carries no `Generated by make docs` banner, and CI's drift gate covers only `docs/reference llms.txt llms-full.txt`. Nothing in CI compares protocol.md against internal/proto.

*Proof:* tools/gendocs/main.go:74-92 (the files map); .github/workflows/ci.yml:207-216 (`generated="docs/reference llms.txt llms-full.txt"`); docs/protocol.md:1 (no banner)

**docs/compatibility.md:97 — `FALSE`**

> — which is why every supported client carries the tool, version and date it was checked against.

Three of the six client entries carry no version. `cursor` says "verified against Cursor on 2026-08-24", `vscode` says "verified against VS Code on 2026-08-24", and `junie` says "verified against JetBrains Junie on 2026-08-24". Only claude-code (v2.1.241), codex (0.149.1) and gemini (v0.56.0) name a version.

*Proof:* host/connect_clients.go:55, host/connect_clients.go:64, host/connect_clients.go:85

**docs/compatibility.md:20 — `IMPRECISE`**

> Three independent version constants exist, and their relationship has never been stated. It is stated here.

At least four more exist, two of which are on-disk format versions that travel with a file a consumer reads: `manifestSchema = 1` stamped into the workspace manifest as `"schema"` ("It travels with the file so a manifest written by an older kelyfos can be recognised rather than misread"), the image manifest's own `Schema int json:"schema"`, the guest supervisor's own `Version` — which SECURITY.md:37-38 tells a reporter to quote separately from `kelyfos version` — and `EnvdVersion = "0.1.0"` in the shim. The page says nothing about whether either manifest format is stable.

*Proof:* internal/sandbox/diff.go:25-28; internal/sandbox/manifest.go:15; supervisor/main.go:33; shim/shim.go:37

**docs/compatibility.md:100 — `IMPRECISE`**

> - **Anything under `dev/`.** Scripts for people working *on* KelyfOS, not with it.

`dev/` is the documented install path for people using KelyfOS, and the product itself sends an ordinary user there. The quickstart tells a first-time reader to run `bash dev/install-firecracker.sh`, `bash dev/install-kelyfos.sh` and `bash dev/fetch-image.sh`; and postureWarning — printed on every run booting a pre-v0.9 image — says "update the image: `bash dev/fetch-image.sh`". Declaring all of `dev/` outside the promise puts the install path and a runtime remediation instruction outside it too.

*Proof:* internal/sandbox/posture.go:47 (the warning text) reached from internal/sandbox/sandbox.go:558; README.md:107-109


### `docs/cookbook.md`

**docs/cookbook.md:1468 — `FALSE`**

> One shell detail worth copying rather than rediscovering: these truncate output with `sed -n '1,Np'` rather than `head -N`.

One recipe does not: docs/cookbook.md:950, in `connect-a-client`, is `kelyfos connect generic | head -20` on the host under `set -euo pipefail`. printGeneric prints exactly twenty lines today (2 + blank + 13 lines of MarshalIndent'd JSON + blank + 3), so the recipe survives with nothing to spare — it is precisely the case the next sentence describes: "a recipe written with `head` passes while its output is short and starts failing… the day it is not".

*Proof:* docs/cookbook.md:950; host/connect.go:279-297 (printGeneric emits 20 lines)

**docs/cookbook.md:1478 — `FALSE`**

> Every `head -N` in `dev/` and in the workflows is now `sed -n '1,Np'`.

dev/install-build-deps.sh was fixed (it now uses `sed -n '1,1p'`), but the sweeping claim is not true: fourteen `head -N` remain under dev/ and in the workflows, several in exactly the producer|head shape the paragraph warns about — `firecracker --version | head -1`, `strace -V 2>&1 | head -1`, `ls -t … | head -1`, and `find ~/.cache/kelyfos/run -mindepth 1 | head -20` inside ci.yml's smoke test.

*Proof:* dev/accept-seccomp.sh:88,109,122,141; dev/accept-profile.sh:64,103,201,218; dev/prove-caps.sh:27; dev/prove-team.sh:27; dev/accept-e1.sh:23; dev/accept-jail.sh:145,170; .github/workflows/ci.yml:402

**docs/cookbook.md:589 — `STALE`**

> What the shim does not do is authenticate anybody, so treat the port the way you would any unauthenticated local API.

It can now. Handler() wraps every route in `authenticated`, which reads KELYFOS_SHIM_TOKEN: when that is set, every request must carry a matching `Authorization: Bearer …` (compared with subtle.ConstantTimeCompare) or gets 401 "this shim requires a bearer token". Unauthenticated is the default, not the whole story — and the cookbook is the page a reader would look at to find out the option exists.

*Proof:* shim/shim.go:133-176 (tokenEnv, authenticated, the 401)

**docs/cookbook.md:730 — `STALE`**

> This matters most on macOS, where there is no `kelyfos` on the host at all — KelyfOS needs Linux with `/dev/kvm`, so the binary lives inside the VM and the entry has to reach into it.

There is a kelyfos on the macOS host: `make dist` cross-builds dist/kelyfos-darwin-x86_64 and -aarch64, and that binary runs doctor, verify, version and help natively — it is how a Mac user provisions the Lima layer without typing limactl. What is true is narrower: the darwin build refuses every command that needs a guest, serve-mcp included, so the MCP entry must reach into the VM. The reason given is stale, not the advice.

*Proof:* host/platform_other.go:31-36 (worksOnDarwin = doctor, verify, version, help) and Makefile:223-230 (the darwin builds)

**docs/cookbook.md:6 — `IMPRECISE`**

> `bash dev/cookbook.sh` extracts every script below and runs it on a real machine, and CI runs the same thing — so a recipe that stops working fails the build rather than failing a stranger who trusted it (F-D4, E3-3).

CI does not run the recipes on any commit. cookbook.yml has only `workflow_dispatch` and a `schedule` cron (Tuesdays 05:17 UTC) — no push and no pull_request trigger — and its own header says so: "What every commit does get, in ci.yml's `checks`, is that every recipe still extracts and is still valid shell. What this adds is that they still work… a recipe cannot rot for longer than seven days." The per-commit gate is `go run ./tools/cookbook` plus `bash -n` on each extracted script. A broken recipe fails no build for up to a week, and never blocks a PR.

*Proof:* .github/workflows/cookbook.yml:20-34 (triggers) and .github/workflows/ci.yml:221-233 (the per-commit gate is extraction + `bash -n` only)

**docs/cookbook.md:12 — `IMPRECISE`**

> The [quickstart](../README.md#quickstart) is four commands, and `kelyfos doctor` will tell you which of the four you still owe it.

Neither half lines up. The quickstart's Linux block is six commands (three install scripts, two to write the sudoers file, then doctor), and `kelyfos doctor` runs nine checks — platform, /dev/kvm, firecracker, /dev/net/tun, egress tooling, jailer, workspace tooling, guest image, disk space. It checks the jailer, which is not among "the four", and it has no check at all for "the `kelyfos` binary on your `PATH`", which is — and dev/install-kelyfos.sh installs to `<repo>/bin/kelyfos`, not onto PATH, so that is the one of the four a reader is most likely still to owe.

*Proof:* host/doctor.go:135-145 (the nine checks); dev/install-kelyfos.sh:12,41 (DEST=$here/bin); README.md:107-118 (six commands)

**docs/cookbook.md:176 — `IMPRECISE`**

> The old directory is renamed away and the reconstructed one is renamed into place, so a file the agent deleted is really gone

"Renamed away" now has a destination the reader is not told about, and it is beside their project: Commit renames the old directory to `<dir>.kelyfos-previous` and deliberately leaves it there — "The previous copy stays, until the next successful run clears it on the line above" — so after this recipe the host has a `project.kelyfos-previous` sibling, and the file the agent deleted is still in it. docs/qol.md §1 documents this; the recipe that teaches the swap does not, and it is the recipe whose script cd's back into the directory afterwards.

*Proof:* internal/sandbox/workspace.go:244-266 (old := w.HostDir + ".kelyfos-previous"; the copy is kept)

**docs/cookbook.md:318 — `MISSING`**

> to = "worker-*" # a star: no worker may reach another worker

The comment is true, and the half it leaves out is what the rest of the recipe depends on: `[[team.edge]]` sets Bidirectional: true when the section opens, so this one line permits master→worker-1, master→worker-2 AND worker-1→master, worker-2→master. That is why line 365's `call worker-1 team_ask '{"to":"master"…}'` works — Ask goes through deliver, which checks topo.Allows(from,to) like any send, and would refuse it with `no_edge` on a genuinely one-way edge. The recorded run shows it: "3 agents, 4 edges". A reader copying this file believing they wrote a one-way graph has written a two-way one.

*Proof:* internal/config/team.go:191 (TeamEdge{Bidirectional: true}); internal/team/topology.go:113-117 and internal/team/broker.go:268-284,365-372


### `docs/denials.md`

**docs/denials.md:157 — `FALSE`**

> Plain HTTP carries it through untouched, because there the refusal *is* the response, and so does a secret-bound domain, where the proxy terminates TLS and answers inside it.

No refusal is ever answered inside a terminated TLS session. The allowlist and port checks run on the CONNECT itself, before the proxy decides whether to terminate: handle() writes the 403 with the rendered refusal and returns, and only a CONNECT that passed both checks reaches the secretsFor()/terminate() branch. Inside terminate() the only things written to the guest are 500 (no CA) and 502 (upstream failure) — neither is a catalogued refusal. And a secret-bound domain is by construction in --allow (secret.unbound refuses the other case at startup), so a refusal on that domain is delivered exactly like every other CONNECT refusal: a 403 the client usually discards, which is the opposite of what this sentence promises.

*Proof:* internal/egress/proxy.go:236-256 (allowsHost/allowsPort → writeStatus 403, then the CONNECT/terminate branch below them); internal/egress/terminate.go:24-137

**docs/denials.md:11 — `STALE`**

> So every refusal KelyfOS makes names its own fix:

The page enumerates the exceptions to this — catalogued refusals carry all three parts, kelyfos.toml and team-plan refusals name their own file and line instead, and the ptrace case is the one refusal the product never sees. P6-24 added a class that fits none of them. write_file's confinement refusal ("<path> is outside the trees a sandbox may write (/work, /tmp, /run, /root). The confinement profile withholds everything else…") and the workspace-image refusal ("the workspace image contains an entry this host will not use: …") are policy decisions KelyfOS makes and reports to a user, with no ID, no fix line and no file:line. The second is the one people will meet: a socket, fifo or device node left anywhere in the workspace makes the whole extraction refuse, and the run prints "kelyfos: workspace sync-back failed: …" with nothing to type.

*Proof:* internal/sandbox/extract.go:79-83 and 214-218; supervisor/writable.go:63-67 (raised at supervisor/tools.go:402-404); host/run.go sync-back error path

**docs/denials.md:109 — `IMPRECISE`**

> `notify-send` on Linux, `osascript` on macOS, and the terminal bell when neither is there — which needs nothing installed. The run says which one it found, in its own header, because a notification that never arrives is indistinguishable from one that was never asked for.

The bell needs nothing installed but it does need a terminal: Send writes the BEL only when stderr is a character device, and silently does nothing otherwise. So on a machine with neither notifier, a run whose output is redirected — which is the "you started it and stopped watching" case this whole section exists for — gets no notification at all, while the header still prints "notify terminal bell only — neither notify-send nor osascript is on this machine". In that case the header says which mechanism would be used, not that anything arrived.

*Proof:* internal/notify/notify.go:102-108 and 136-139; host/run.go:712-716

**docs/denials.md:146 — `IMPRECISE`**

> Team refusals cross the broker as a `team.Error`, whose `Message` is the same rendered text — ID, fix line and all — so an agent reading the error it was handed has the fix in front of it too.

True only for the five catalogued team refusals (team.edge, team.spawn_none/_budget/_image, team.store). The broker and the store raise other refusals with the same Kind "denied" whose Message is a bare sentence with no ID and no fix line: "this team cannot spawn workers", "this team has no store", "a store value may be at most %d bytes; this one is %d", "a store key may be at most %d bytes; this one is %d", "this team's store is limited to %d keys; write an empty value to remove one", "this team's store is limited to %d bytes". An agent that reads a team.Error expecting an ID and a fix line gets neither for any of these.

*Proof:* internal/team/store.go:153-160 and 187-203; internal/team/broker.go:227, 335, 342


### `docs/e2b-shim.md`

**docs/e2b-shim.md:43 — `FALSE`**

> **The policy file applies here.** The shim reads `kelyfos.toml` the way `kelyfos run` does — with one gap, stated here rather than discovered:

There are four gaps, not one. Besides the time budgets, `kelyfos shim` never reads `workspace`, `[[plugin]]` or `[[forward]]` — all three of which `kelyfos run` acts on. A shim sandbox silently gets no plugin device (so the guest advertises none of the project's plugin tools) and no forwarded ports. serve-mcp announces its workspace gap out loud (F-D49); the shim announces nothing.

*Proof:* host/shim.go:56-113 (consumes only Image, Arch, Allow, Secrets and the [resources] caps), vs host/run.go:202-206 (workspace), host/run.go:384 (packPlugins), host/run.go:264 (resolveForwards); host/servemcp.go:297-307 shows the workspace gap being declared on the other door

**docs/e2b-shim.md:87 — `IMPRECISE`**

> | Health | `GET /health` | envd liveness. |

The handler ignores every sandbox and always answers 204 — it is the shim process's own liveness, not envd's and not any guest's. A client polling /health before using the file endpoints gets 204 when no sandbox exists at all, and the file call then fails with 400 "no sandbox has been created through this shim".

*Proof:* shim/shim.go:192-194 (`w.WriteHeader(http.StatusNoContent)`, no lookup), shim/shim.go:426-439 (only())

**docs/e2b-shim.md:84 — `MISSING`**

> | Create | `POST /sandboxes` | Boots a microVM and waits for it to be ready. |

The request's `templateID` is decoded, ignored for the boot, and echoed back in the 201 as though it were honoured. Every sandbox boots `s.Policy.Flavor` — the operator's `--image` or the policy's. `Sandbox.create(template="python")` therefore gets a machine running `dev` and a response saying templateID "python". The page says a client cannot ask for another machine (line 49); it does not say the ask is answered with a false echo.

*Proof:* shim/shim.go:206-243 (req.TemplateID decoded; opts.Flavor = s.Policy.Flavor at shim/shim.go:283; response TemplateID = req.TemplateID)

**docs/e2b-shim.md:89 — `MISSING`**

> | Write file | `POST /files?path=…` | Multipart or octet-stream, binary-safe. |

Binary-safe, but silently truncating: the body is read through io.LimitReader(r.Body, 64<<20) and a multipart part through the same limit, with no error on overflow. A 100 MiB upload returns 200 with a `file.write` event whose bytes and SHA-256 describe the first 64 MiB, and the guest holds a truncated file. Neither the limit nor the truncation is documented.

*Proof:* shim/shim.go:494 (`io.ReadAll(io.LimitReader(r.Body, 64<<20))`), shim/shim.go:572 (same for multipart), shim/shim.go:512-525 (success + file.write on the truncated body)


### `docs/events.md`

**docs/events.md:183 — `FALSE`**

> `session.ready` is emitted once per machine on every path there is — `run`, `fork`, `snapshot restore`, `resume`, `team up`, `serve-mcp` and the shim.

`kelyfos resume` writes no `session.ready` at all. resumeCmd opens the paused machine's chain and appends exactly one event, `session.resume`; grep for TypeSessionReady across host/ and shim/ returns run.go, fork.go, snapshot.go, team.go, servemcpstate.go, servemcptools.go and shim/shim.go — never sessions.go. The consequence is bigger than a missing row: line 178 says session.ready is "where both walls are recorded for *every* machine", and a resumed machine records neither `jailed` nor `profile` anywhere in its chain.

*Proof:* host/sessions.go:464 (the only Append on the resume path; no WithPosture, no session.ready)

**docs/events.md:250 — `FALSE`**

> A file was written through a tool. The **content is not recorded**

For `via: write_file` and `via: upload` the event is written from the *request*, before the guest has answered, so a write the guest refused is still recorded as a write with a path, a size and a digest of content that was never stored. write_file is now confined to the profile's writable trees and returns an error for anything outside them, and nothing corrects the chain afterwards — fromGuest only handles `exec` results and returns early for every other tool. The `serve-mcp` door does the opposite and says why: "A refused write is not a write, and recording one would put a line in the log for a file that does not exist."

*Proof:* host/mcpobserve.go:113 and :120 (recorded on the way in), host/mcpobserve.go:141 (results for anything but exec are dropped), supervisor/tools.go:402 (the write can be refused), host/servemcpfiles.go:71-75 (the other door refuses to record it)

**docs/events.md:509 — `FALSE`**

> **The arguments never carry content.** `content` and `stdin` are replaced by their size, which is the rule `file.write` follows for the same reason.

Two drifts. The redaction list is three keys, not two — `data` was added so the host summariser matches the guest's. And the replacement only fires when the value is a *string*: a content key whose value is an object falls through to compactValue's default branch, which json.Marshals it whole with no truncation, so `{"content":{"x":"<1 MiB>"}}` lands in the chain in full. The summariser runs on the raw arguments of any call, including a tool that does not exist, so a client controls both the key's type and its size.

*Proof:* host/servemcpaudit.go:41 (three keys), :69-74 (the size substitution is guarded on `v.(string)`), :100-106 (default branch marshals the value entire)

**docs/events.md:705 — `FALSE`**

> Three things the chain does **not** claim, stated because the difference matters when this is used as evidence.

Only two follow — truncation at the end, and that every declared agent wrote a line. The paragraph was rewritten from "Two things" to "Three things" and the third was never added; the second item also has an unrelated sentence about `--session <agent-id>` fused onto it mid-line. A reader counting to three goes looking for a limitation that is not stated. There are real candidates in the code: nothing checks `ts` ordering, `v`, or that every line names the same sandbox.

*Proof:* internal/recorder/recorder.go:398-443 (Verify checks seq, prev and the digest — and nothing else)

**docs/events.md:729 — `FALSE`**

> `runs` reads the session records that were already being written, one pass per session, taking only the two events it needs.

readRun calls recorder.Read, which parses every line of the file into a slice held in memory, and then walks all of it — collecting agent names, the first command.start and the event count as well as session.start and session.end. The cost is linear in events and so is the memory. runs.go's own comment ("reading only the two events that matter, so a long session with a hundred thousand events costs the same as a short one") is wrong in the same way.

*Proof:* host/runs.go:180 (recorder.Read of the whole file), host/runs.go:187-211 (the loop reads every event), internal/recorder/recorder.go:482-497

**docs/events.md:401 — `STALE`**

> | `kind` | string | `get` or `put`. |

A third kind, `delete`, is written whenever a put carries an empty value — which §5 line 679 of this same document states correctly. The §4 table a reader parses against was not updated.

*Proof:* internal/team/store.go:87 (KindDelete = "delete") and :176 (recorded on an empty-value put)

**docs/events.md:403 — `STALE`**

> | `reason` | string | `denied`, `no_such_key`, `value_too_large`, `store_full`. |

Two refusal reasons are missing: `key_too_long` (a key over MaxKeyBytes) and `too_many_keys` (the MaxStoreKeys ceiling). Both were added with the store's key limits and both reach the record. internal/recorder/schema.go:229 carries the same stale list, so the generated reference is wrong too — that half is a finding against tools/gendocs's source, schema.go.

*Proof:* internal/team/store.go:158 (key_too_long) and :186 (too_many_keys); the doc's four all appear at :122, :134, :152, :200

**docs/events.md:714 — `STALE`**

> The only thing that tells them apart is the chain head compared against a head obtained from somewhere else — which is why `kelyfos log --export` prints it, and why signing it is P6-7.

P6-7 has landed and this document documents it forty lines earlier (§2, `--sign-key`), so "signing it is P6-7" reads as pending work for something that exists. It is also no longer the *only* thing: the signature preimage covers the chain head **and** a sha256 of the whole record, so truncating a signed export invalidates the signature; and `kelyfos verify` now states "the record has no session.end" as an observation on any record that does not end cleanly.

*Proof:* internal/report/sign.go:46-49 (preimage = head + digest of the whole chain), host/verify.go:115-117 and :163-169 (the session.end observation)

**docs/events.md:65 — `IMPRECISE`**

> What the chain buys is that a *selective* edit — deleting one blocked-egress event, softening one command — breaks every hash after it

No hash after the edit breaks. Every following line's digest still covers its own bytes and still matches. What breaks is the linkage at the edit point: a deleted line makes `seq` disagree with the line number, and a re-hashed line makes the next event's `prev` disagree — and Verify stops at the first of those, so nothing after it is even examined. The detection claim is right; the mechanism as stated is not.

*Proof:* internal/recorder/recorder.go:413-415 (seq vs line), :416-419 (prev), :431-435 (per-line digest, self-contained)

**docs/events.md:151 — `IMPRECISE`**

> | `jailed` | boolean | Whether the VMM ran inside the jailer. Present from v0.9. |

On session.start it is present only for `kelyfos run`. Every other entry point — fork, snapshot restore, team up, serve-mcp, the shim — leaves it off session.start and carries the posture on session.ready instead (WithPosture). schema.go:63 states the qualification ("kelyfos run; every other entry point carries the posture on session.ready instead"); this table states it flatly, so a reader treats an absent `jailed` on a forked machine's session.start as "not jailed".

*Proof:* host/run.go:570 (the only session.start that sets Jailed) against host/fork.go:218-219, host/snapshot.go:168-169, host/team.go:221-222, host/servemcpaudit.go:140-141, shim/shim.go:334-336

**docs/events.md:238 — `IMPRECISE`**

> Exactly one per `command.start`.

Only when the guest returns an exit frame. If the supervisor closes the connection without one, or sends a stream name the host does not know, `kelyfos exec` returns an error and appends nothing — the chain keeps a command.start with no matching command.exit. A reader pairing the two has to handle the gap, which this sentence tells them they need not.

*Proof:* host/exec.go:121 (EOF path returns before any command.exit), host/exec.go:164 (unknown stream, same), against the append at host/exec.go:139-147

**docs/events.md:380 — `IMPRECISE`**

> | `data` | string | The payload itself — **only** when the team enabled capture. |

Capture is necessary but not sufficient: the body is kept only when the outcome is `delivered`. A refused message never carries it (§5 line 684 says so), and neither does an `unreachable` one (mailbox_full) nor a `timeout` — both of which are `team.message`, not `team.refused`, so a reader who only read §5 still expects a body there.

*Proof:* internal/team/broker.go:411-414 (`if b.capture && outcome == OutcomeDelivered`)

**docs/events.md:381 — `IMPRECISE`**

> | `reason` | string | Why, on a refusal: `no_edge`, `no_such_agent`, `unknown_correlation`, `missing_correlation`, `mailbox_full`. |

Four of the five are refusals; `mailbox_full` is not. It is recorded on a `team.message` with `outcome: unreachable`, never on a `team.refused` — describe() only flips the type to team.refused when the outcome is `refused`. A reader filtering the chain for `team.refused` to find every undelivered message misses exactly the full-mailbox case.

*Proof:* internal/team/broker.go:386-388 (mailbox_full recorded with OutcomeUnreachable), :405-408 (type becomes team.refused only for OutcomeRefused)

**docs/events.md:142 — `MISSING`**

> Opens the file. Records what the sandbox is.

The session.start table omits `reason`, which five entry points write and two commands read back. It carries "forked from <snapshot>", "restored from <name>", "created through the E2B shim", a team's own reason, or the constant `serve-mcp` — and `serve-mcp` is how `kelyfos log --list` and `kelyfos runs` tell a server's session from a machine's. §5's "serve-mcp, N sandbox(es)" marking depends on a field this schema never documents.

*Proof:* host/fork.go:219, host/snapshot.go:169, shim/shim.go:336, host/servemcpaudit.go:141, host/team.go:222 (writers); host/log.go:163 and host/runs.go:236 (readers)

**docs/events.md:200 — `MISSING`**

> | `via` | string | Present inside a team: `cold` or `fork` — how this member was started (F-D19). |

The session.ready table omits `image`, which a team writes on every member's ready event and which the replay renders beside `via`. internal/recorder/schema.go:74 documents it ("this agent's flavor", in a team); this table does not.

*Proof:* host/team.go:453 (Image on the per-agent session.ready), host/log.go:468-469 (printed from it)

**docs/events.md:528 — `MISSING`**

> | `signal` | string | On `shell.end`: the signal that ended it, when it was signalled. |

`shell.end` also carries `reason` — why the shell could not be opened — which this table does not list. schema.go:270 documents it; the hand-written table stops at signal and duration_ms.

*Proof:* host/shell.go:112 (`Reason: exit.Error` on the shell.end append)

**docs/events.md:631 — `MISSING`**

> - `kelyfos log --verify` checks the chain and reports the first break.

It also prints the chain head, on every successful verify, and for a team or a serve-mcp session names the agents or sandboxes it covered. The head is the number §5 tells a reader to quote out of band to whoever receives the export, so the command that produces it locally is worth naming: §2 and §5 only credit `--export` and `kelyfos verify` with printing it.

*Proof:* host/log.go:281 (deferred `chain head %s`), :286-295 (the agents/sandboxes line)


### `docs/hardening.md`

**docs/hardening.md:108 — `FALSE`**

> The API socket resolves to `<chroot>/run/firecracker.socket`.

KelyfOS passes its own `--api-sock` to the jailed VMM, so the socket is at `<chroot>/fc.sock`, not `<chroot>/run/firecracker.socket`. `Start` builds `argv = jailArgv(..., []string{"--api-sock", inJail("fc.sock"), "--config-file", inJail("config.json")})`, and `inJail(name)` returns `"/" + name`. The host's own handle on the same file is `State.APIPath = filepath.Join(runDir, "fc.sock")`. `<chroot>/run/firecracker.socket` is only the jailer's default when no `--api-sock` is given, which is never the case here.

*Proof:* internal/sandbox/sandbox.go:465 (`--api-sock`, inJail("fc.sock")); internal/sandbox/jail.go:150 (inJail); internal/sandbox/sandbox.go:271 (APIPath)

**docs/hardening.md:279 — `FALSE`**

> kernel offers root minus twenty-eight names

Twenty-eight is the length of the policy list, not of any filter that ships. `dev` — the only flavor the release builds — takes `ptrace` back out (`p.AllowPtrace = true`, and both `seccompProgram` and `Refused` skip it), and on aarch64 `settimeofday` has no number and is dropped from the compiled filter. So the shipped image refuses 27 syscalls on x86_64 dev and 26 on aarch64 dev; only `base` on x86_64 refuses twenty-eight. The generated page produced from the same code says "Refused, 27 syscalls" for `dev`.

*Proof:* supervisor/profile_policy.go:21-53 (28 names); supervisor/profile.go:113 (dev drops ptrace); supervisor/profile.go:319-321 and 366-368 (skip); supervisor/profile_arm64.go:16-44 (no settimeofday); .github/workflows/release.yml:63 (flavor: dev)

**docs/hardening.md:57 — `STALE`**

> | the root filesystem | read-only, with a tmpfs overlay — writes outside `/work` die with the sandbox |

Since P5-3 a write outside the profile's writable set does not survive until shutdown — it is refused immediately. The ruleset grants only `readRights` beneath `/` and write rights beneath the named trees, so `/bin`, `/usr`, `/etc` and `/lib` are no longer writable through the overlay for anything the supervisor spawns. profile.go's own header says so: "/bin, /usr, /etc and /lib are writable through the tmpfs overlay today, and after this they are not." §1 is presented as "the honest inventory" of what an agent can reach "today" and carries none of the *Written after P5-x* annotations the rest of the document uses.

*Proof:* supervisor/profile.go:203-218 (readRights beneath /, writeRights only beneath p.Write); supervisor/profile.go:21-26

**docs/hardening.md:83 — `STALE`**

> a real protection this project has been getting for free and has never checked.

It is checked now, on every run and every restore. `confirmSeccomp` reads `Seccomp:` from `/proc/<tid>/status` for every thread of the VMM and refuses the machine with `[seccomp.not_in_force]` if any thread is not in filter mode; it is called from `WaitReady` and from `Restore`. §3's later annotation records this, but §1.2 still states the opposite in the present tense.

*Proof:* internal/sandbox/seccomp.go:59-90 and 97-124; internal/sandbox/sandbox.go:540-542 (WaitReady); internal/sandbox/sandbox.go:1203-1205 (Restore)

**docs/hardening.md:91 — `STALE`**

> It has never been used.

The jailer is used for every sandbox unless `--no-jail` is passed, and `requireJail` refuses to build a sandbox on a machine that cannot run `sudo -n jailer` before anything is created. §2.3's decision was implemented in P5-1; this sentence was not reversed.

*Proof:* internal/sandbox/sandbox.go:248-251 (requireJail in New); internal/sandbox/sandbox.go:309; internal/sandbox/jail.go:127-138

**docs/hardening.md:317 — `STALE`**

> Measured: the two CLI binaries are identical when built from two *different* source paths

`make release-cli` now builds four CLI binaries — `kelyfos-linux-{x86_64,aarch64}` and, since the macOS work, `kelyfos-darwin-{x86_64,aarch64}` — and all four ship in the release and are covered by SHA256SUMS. The repro-check job compares only `dist/kelyfos-linux-*`, so the two macOS binaries a stranger downloads have never been measured for reproducibility.

*Proof:* .github/workflows/repro-check.yml:59 and 65 (`cp dist/kelyfos-linux-*`, `for f in first/kelyfos-linux-*`); Makefile:210-231 (four binaries built)

**docs/hardening.md:211 — `IMPRECISE`**

> is refused from v0.9 where it succeeded before

The writable set is larger than the four trees this sentence names. `/dev/pts` and `/dev/shm` are granted the full `writeRights` — `/dev/shm` is a general-purpose tmpfs the kernel sizes at half the guest's RAM — and seven device nodes (`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty`, `/dev/ptmx`) get read/write/truncate. `DumpProfile` carries a comment about exactly this omission having made the generated page "wrong by omission"; the same omission is still here.

*Proof:* supervisor/profile.go:82-90 (writableDevices, writableDeviceTrees); supervisor/profile.go:219-236 (both granted); supervisor/profile.go:406-411 (the same defect, fixed in the dump)

**docs/hardening.md:324 — `IMPRECISE`**

> **An SBOM ships with every release**, one per architecture, covering all three places an image comes from: Buildroot's packages, the guest supervisor, and the host CLI.

The SBOM reads exactly two binaries: the guest supervisor and `dist/kelyfos-linux-$(ARCH)`. The macOS CLI for the same architecture ships in the release and is in no SBOM — yet it is a subject of that architecture's SBOM attestation, because the attestation's subject glob is `dist/*aarch64*` / `dist/*x86_64*`, which matches `kelyfos-darwin-<arch>`. So one shipped artifact per architecture is attested as being described by an SBOM that never read it.

*Proof:* Makefile:251-255 (`-binary` twice: supervisor and kelyfos-linux-$(ARCH)); Makefile:223-229 (darwin binaries into dist/); .github/workflows/release.yml:200-201 and 207-208 (subject-path globs)

**docs/hardening.md:105 — `MISSING`**

> | `--new-pid-ns` | its own PID namespace |

The jailer's PID namespace is deliberately not used. `jailArgv` never passes `--new-pid-ns`, with a comment explaining why: it makes the jailer fork and the parent return, so the process KelyfOS waits on exits as soon as the machine starts. The jailed VMM therefore shares the host's PID namespace and can see the host's process list. §2.1 lists the flag among what the jailer does, and §5's inventory of what remains reachable never says the PID namespace is off — so nothing in the document tells a reader this layer is absent.

*Proof:* internal/sandbox/jail.go:156-182, in particular the comment at 165-171 ("--new-pid-ns is deliberately not passed") and the argv built at 158-164

**docs/hardening.md:263 — `MISSING`**

> ## 5. What remains reachable afterwards — the longer half

The inventory omits the supervisor itself. Landlock and seccomp are reached only from the re-exec'd `--confine` helper, so PID 1 is not confined by the profile it applies to everything it spawns: a tool running inside the supervisor has the whole filesystem in front of it. `write_file` is now checked against the same three lists by hand (`writableFor`), and reads are deliberately not restricted at all. None of that appears anywhere in this document, although it is the one place where the confinement described in §4 does not apply.

*Proof:* supervisor/writable.go:9-36 ("The supervisor is PID 1 and it is not confined by the profile it applies to everything it spawns"); supervisor/confine.go:45-61 (applyLandlock/applySeccomp reached only from runConfined)

**docs/hardening.md:281 — `MISSING`**

> Landlock also cannot restrict `chdir`, `stat`, `chmod`, `chown`, `access` or `fcntl` at all, by its own documentation

The list of what the filesystem layer does not cover omits one item that is a deliberate choice here rather than a Landlock limitation: `LANDLOCK_ACCESS_FS_IOCTL_DEV` is left out of `handledRights`, so ioctls on device nodes are not governed at all. The code states the reasoning (handling it without granting it on /dev would refuse the terminal ioctls every interactive program makes); §5's inventory does not mention it.

*Proof:* supervisor/profile.go:152-160 (handledRights = writeRights, with the IOCTL_DEV comment)


### `docs/integrating.md`

**docs/integrating.md:41 — `FALSE`**

> which is why every entry carries the tool, the version and the date it was checked against.

Three of the six entries carry no version at all: cursor is "verified against Cursor on 2026-08-24", vscode "verified against VS Code on 2026-08-24", junie "verified against JetBrains Junie on 2026-08-24". Only claude-code (v2.1.241), codex (0.149.1) and gemini (v0.56.0) name a version.

*Proof:* host/connect_clients.go:54, host/connect_clients.go:64, host/connect_clients.go:87

**docs/integrating.md:197 — `FALSE`**

> Doing this by hand is what `kelyfos connect <client>` will replace.

False for the limactl shape it is attached to, and stale in tense. `connect` exists today, but it refuses to run on macOS (host/platform_other.go:31), and even where it runs it writes `os.Executable()` plus `serve-mcp --policy <abs>` — never a `limactl shell kelyfos-dev --` wrapper. It cannot replace the hand-written macOS entry this paragraph is about.

*Proof:* host/connect.go:183-210 (serverCommand), host/connect_clients.go:102-127 (writer emits only command+args), host/platform_other.go:31-35

**docs/integrating.md:327 — `FALSE`**

> - **No inbound.** Nothing outside can open a connection to a guest. Port forwarding is planned and is not here.

Port forwarding shipped (E5-5, F-D7). `kelyfos run -p 8080:80` and `[[forward]]` in kelyfos.toml bind a host listener that carries connections into the guest over vsock; `--p-bind 0.0.0.0` exposes it to the LAN. Only the *packet* claim survives: nothing crosses the TAP, and the nftables ruleset is unchanged.

*Proof:* host/run.go:76 (`-p` flag), host/run.go:71 (`--p-bind`, default 127.0.0.1), host/forward.go:21-34, host/forward.go:96 (`cfg.Forwards`), host/run.go:264,676-679

**docs/integrating.md:62 — `STALE`**

> And the shim authenticates nobody, so its port is a local privilege surface the other three do not have.

Stale since the shim gained an optional bearer token. With KELYFOS_SHIM_TOKEN set, every route requires `Authorization: Bearer <token>`, compared with subtle.ConstantTimeCompare, and answers 401 without it. Unauthenticated is still the default, but "authenticates nobody" is now untrue — docs/e2b-shim.md:68 documents the token and this page was not updated with it.

*Proof:* shim/shim.go:140 (tokenEnv), shim/shim.go:162-176 (authenticated), shim/shim.go:153

**docs/integrating.md:511 — `STALE`**

> What it does not do is authenticate its caller.

Same drift as line 62: setting KELYFOS_SHIM_TOKEN makes the shim require a bearer token on every route. The advice that follows (bind to loopback, treat the port as equivalent to running kelyfos) is still right as the default, but the token is the answer for an embedder and this entry does not mention it exists.

*Proof:* shim/shim.go:140, shim/shim.go:162-176

**docs/integrating.md:526 — `STALE`**

> - [`cookbook.md`](cookbook.md) — fourteen recipes that run, including the Python client above

The cookbook has fifteen recipes, and CI enforces the count against the extracted set — its own opening line reads "Fifteen recipes". Recipe 9b (`connect-a-client`) is the one that was added.

*Proof:* tools/cookbook/main.go:161-176 (checkCount), tools/cookbook/main.go:75 (recipe marker), docs/cookbook.md has 15 `<!-- recipe: -->` markers

**docs/integrating.md:54 — `IMPRECISE`**

> All four go through the same wall. Each reads the project's `kelyfos.toml`, each is capped by its `[resources]`, and each writes a flight recorder

`kelyfos mcp` — the second of the four — never reads a policy file. It loads the state of an already-running sandbox, opens that session's recorder and copies bytes; the policy applied to it is whatever the door that booted the sandbox applied. True of the CLI, serve-mcp and the shim; not of the bridge.

*Proof:* host/mcp.go:54-74 (sandbox.Load + recorder.Open, no config.Load anywhere in the file)

**docs/integrating.md:82 — `IMPRECISE`**

> This boots a sandbox, exports `KELYFOS_SANDBOX` into `<command>`'s environment, runs the command **on the host**, then tears the sandbox down and exits with the command's own status.

Two cases override the command's status. If anything inside the guest was OOM-killed during the run, a command that exited 0 still makes kelyfos exit 137; if a time budget fired, the status becomes 124 whatever the command returned. §2 tells an orchestrator to branch on 124 and 137 without saying they can replace a successful command's own status.

*Proof:* host/run.go:806-828 (`if timedOut != "" { code = exitTimedOut }`, `if code == 0 && oomKills.Load() > 0 { code = exitOOMKilled }`)

**docs/integrating.md:216 — `IMPRECISE`**

> The bridge is a byte-level pass-through by design: it does not reframe, buffer by message, or parse.

It does parse, and it does buffer by message — on a copy. Each direction is fed through tee() into a line scanner whose output the observer json.Unmarshals to write flight-recorder events; that scanner has a 16 MiB frame ceiling (proto.MaxMCPLine), and a longer line ends the copy with bufio.ErrTooLong rather than reaching the guest. On close the bridge also *writes* JSON-RPC responses the guest never sent. The bytes that get through are unchanged, but the three things this sentence denies all happen.

*Proof:* host/mcp.go:66-74,84,93 (tee), host/mcpobserve.go:68-79 (scanner with proto.MaxMCPLine), host/mcpobserve.go:83-90 (Unmarshal), host/mcp.go:110,126-141 (answerOutstanding injects responses)

**docs/integrating.md:250 — `IMPRECISE`**

> Two rules the generator has to respect, because the parser refuses otherwise: an agent's `secrets` must each name a domain that is in *that agent's* `allow`, and `count` above 1 cannot be combined with a `workspace`.

There are at least five, three of which this page documents elsewhere or not at all: per-agent `idle_timeout` is refused (F-D20), `idle_timeout` in a spawn budget is refused, `max_runtime` in a spawn budget is refused as a second name for `lifetime`, two agents resolving to the same name are refused, and an edge endpoint matching no agent is refused. A generator built to the two rules named here still produces files the parser rejects.

*Proof:* host/teamplan.go:214-239 (secrets/allow, count+workspace), host/teamplan.go:245-251 (per-agent idle_timeout), host/teamplan.go:260-274 (spawn idle_timeout, spawn max_runtime), host/teamplan.go:82-84 (duplicate names), internal/team/topology.go:139-146 (glob matching no agent)

**docs/integrating.md:312 — `IMPRECISE`**

> `kelyfos log --verify` exits non-zero when the chain is broken. If you are storing these records as evidence, that exit status is the check to run.

The exit status catches an edited event and a deleted or reordered middle line, but a record truncated at the tail verifies clean and exits 0: Verify walks the links forward from line 1 and nothing records how many events there should have been. For evidence the check is the chain head the verdict prints, compared against a head recorded elsewhere — the exit status alone does not prove no trailing line was removed.

*Proof:* internal/recorder/recorder.go:398-443 (Verify returns nil at EOF), host/log.go:272-297 (`defer ... chain head %s`)

**docs/integrating.md:483 — `IMPRECISE`**

> An ask that goes unanswered is written when the host-side timeout fires, which is `timeout_ms` later, not when your client gave up.

"`timeout_ms` later" is only true inside the clamp: the broker waits waitFor(timeout_ms), which is one minute for any value <= 0 and at most 15 minutes however large the value. The `outcome: timeout` event is written when that clamped deadline fires.

*Proof:* internal/team/broker.go:127-136, internal/team/broker.go:289-293 (Ask writes OutcomeTimeout on the clamped timer)

**docs/integrating.md:15 — `MISSING`**

> `kelyfos connect <client>` writes the client's own configuration, in its own format and its own location, and `--check` then starts the server it named and completes a real MCP handshake

`connect` cannot run on macOS at all. runsHere() allows only doctor, verify, version and help on a non-Linux host; `kelyfos connect claude-code` prints "kelyfos connect needs Linux and /dev/kvm, and this is macOS" and exits 2. The whole section is Linux-only and the page never says so — which matters because the page's own macOS paragraph (line 182) is where a Mac reader is sent.

*Proof:* host/platform_other.go:31-35 (worksOnDarwin, connect absent), host/platform_other.go:37-49, host/main.go:57-60

**docs/integrating.md:351 — `MISSING`**

> The write-back is a **swap, not a merge**: the old directory is renamed away and the reconstructed one is renamed into place, so that a file the agent deleted is really gone.

Since the extraction rewrite the swap has two undocumented consequences an integrator will hit. If the host directory changed while the sandbox ran, Commit diverts: the reconstructed tree lands in `<dir>.kelyfos-out` and the workspace directory is left exactly as it was — so a script that assumes the directory was replaced reads pre-run state. And the directory that is renamed away is kept as `<dir>.kelyfos-previous` until the next successful run clears it, so every run leaves a sibling directory behind.

*Proof:* internal/sandbox/workspace.go:226-236 (fingerprint re-check → `.kelyfos-out`), internal/sandbox/workspace.go:244-266 (`old := w.HostDir + ".kelyfos-previous"`, kept deliberately)

**docs/integrating.md:499 — `MISSING`**

> The wait argument is `timeout_ms`, an integer of milliseconds, default 60000.

The host clamps it at both ends. waitFor() returns one minute for anything <= 0 and caps everything above MaxWait = 15 minutes, so an orchestrator that passes timeout_ms = 3600000 gets 15 minutes, not an hour. Neither bound is documented here.

*Proof:* internal/team/broker.go:107 (MaxWait = 15 * time.Minute), internal/team/broker.go:127-136 (waitFor), internal/team/broker.go:172


### `docs/mcp-surface.md`

**docs/mcp-surface.md:156 — `FALSE`**

> status is non-zero, and `structuredContent: {exit_code, stdout, stderr, signal}`

`sandbox_exec` returns `{exit_code, stdout, stderr}` — there is no `signal` key. The guest's own `exec` does carry `signal`; the host tool does not forward it, so a caller reading structuredContent alone cannot tell a killed command from one that exited.

*Proof:* host/servemcptools.go:525-527 vs supervisor/tools.go:204-209

**docs/mcp-surface.md:183 — `FALSE`**

> the cap is what refuses a large file rather than the transport (§4). Measured end to end at 512 KiB, 2 MiB, 4 MiB and 8 MiB; 9 MiB is refused by the guest, naming the limit in bytes.

An 8 MiB read cannot come back at all — the transport refuses it, not the cap. The E4-8 structuredContent rule made read_file put the whole file in BOTH the text block and structuredContent["content"], so the response frame is roughly twice the file. Measured: an 8 MiB (8,388,608-byte) plain-ASCII file marshals to a 16,777,376-byte frame against proto.MaxMCPLine = 16,777,216, and 8 MiB of typical newline-bearing text marshals to 17,196,790. proto.Writer.Write then returns ErrLineTooLong, mcpSession.serve returns on the send error and closes the connection, so the caller sees an unexplained EOF rather than a limit message. Only files up to roughly 8.0 MiB survive the round trip.

*Proof:* supervisor/tools.go:237-240 (content in text block and structuredContent), internal/proto/proto.go:62 (MaxMCPLine = 16<<20), internal/proto/proto.go:333-335 (ErrLineTooLong), supervisor/mcp.go:60-62 (send error closes the session), supervisor/tools.go:388-390 (readCapped allows exactly 8 MiB)

**docs/mcp-surface.md:420 — `FALSE`**

> It gets **exactly the environment every other command in the sandbox gets** — the same `PATH`, and the same egress proxy variables when the sandbox has egress. Not a second environment, and not the supervisor's own: one environment, decided in one place.

Not exactly: a plugin's environment is missing the trust-anchor variables every other command gets. defaultEnv is captured at exec time (cmd.Env = defaultEnv) and plugins are started before the sandbox reports ready, while installTrustAnchor — which appends SSL_CERT_FILE, CURL_CA_BUNDLE, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS and GIT_SSL_CAINFO to defaultEnv — runs only after the host sees the ready frame and calls InstallTrustAnchor over the control channel. A command run later through exec or the shell reads the grown defaultEnv and gets all five; a plugin never does. PATH and the four proxy variables are fine (applyEgressEnv runs before startPlugins).

*Proof:* supervisor/pluginhost.go:117 (cmd.Env = defaultEnv), supervisor/main.go:146-148 (startPlugins before ready), supervisor/trust.go:50-56 (variables appended by installTrustAnchor), supervisor/control.go:58 (installTrustAnchor reached only from the control channel), host/servemcptools.go:446-455 (host installs the anchor after WaitReady)

**docs/mcp-surface.md:452 — `FALSE`**

> [`networking.md`](networking.md) describes what that means in practice: the four proxy variables, `NO_PROXY`, and the trust anchor.

A plugin inherits the four proxy variables and NO_PROXY but not the trust anchor — its environment is fixed at exec, before the CA exists. In a project with `[secrets]`, where the proxy mints a CA and MITMs the secret-bound domains, a plugin written in Python (requests) or Node — both of which ignore the system store — fails certificate verification, while a curl/OpenSSL plugin still works because /etc/ssl/certs/ca-certificates.crt is appended on disk and read at connect time.

*Proof:* supervisor/trust.go:43-56, supervisor/pluginhost.go:112-117, host/servemcptools.go:398-402 (CA minted only when secrets exist)

**docs/mcp-surface.md:576 — `FALSE`**

> A flavor may also ship a server built into the image. Both routes launch identically — the manifest is what differs, and a built-in server appears in it the same way.

No such route exists. plugins.json is built only from the `[[plugin]]` entries in kelyfos.toml, and each entry must have a `path` host directory, which is copied onto the device and digested. Nothing reads an image flavor or image.json for servers, and the supervisor launches only what the manifest names. A server shipped inside an image has no way into the manifest.

*Proof:* host/plugins.go:20-46 (specs built from cfg.Plugins only), internal/config/plugin.go:84-86 (a plugin with no path is refused), internal/sandbox/plugins.go:90-120 (manifest written from those specs), supervisor/plugins.go:55-73 (guest reads the manifest, does not scan)

**docs/mcp-surface.md:4 — `STALE`**

> Written at E4-0 before any of it exists; E4-1 through E4-8 implement it. Where this document and the code disagree during the epic, the code is wrong.

E4 is finished — every tool in §2.2, the plugins drive, the plugin runtime and the audit lane exist — so "before any of it exists" and the during-the-epic rule no longer describe the situation. As written the header tells a reader to treat any drift found today as a code defect, which is the opposite of what most of the drifts above are.

*Proof:* host/servemcptools.go:27-167 (the whole tool surface), host/servemcpstate.go, host/servemcpteam.go, supervisor/pluginhost.go:89-106, host/servemcpaudit.go:160-191

**docs/mcp-surface.md:376 — `STALE`**

> line, keys sorted, with anything carrying content — `content`, `stdin` — replaced by its size:

The list is now three names: content, stdin and data. `data` was added so the outward summariser matches the guest-side one, which had always redacted the base64 payload of `upload` under that name — the code comment at host/servemcpaudit.go:36-40 records the fix and names this document as the thing that claimed the two were already the same shape. §3.5 (line 623) has the corrected list; §2.5 was not updated with it.

*Proof:* host/servemcpaudit.go:41 (contentKeys), supervisor/pluginhost.go:456 (the same list guest-side)

**docs/mcp-surface.md:650 — `STALE`**

> Sixteen leaves room for JSON escaping around eight and still bounds the buffer.

Sixteen no longer leaves room around eight. The arithmetic in this sentence assumes one copy of an 8 MiB file per frame; since the structuredContent rule of §2.2 the guest's read_file emits two copies, so a frame carrying an 8 MiB file starts at 16,777,376 bytes — above the 16,777,216 limit before any escaping. The code comment at internal/proto/proto.go:56-57 carries the same stale reasoning.

*Proof:* internal/proto/proto.go:47-62, supervisor/tools.go:235-240

**docs/mcp-surface.md:102 — `IMPRECISE`**

> | `image` | string | no | Image flavor. Defaults to the policy's, and must be one the policy permits. |

There is no set of permitted images: the code accepts exactly one value, the image the policy declares, and refuses every other with "image %q is not this project's image". When the file declares no image the accepted value is the built-in "base", so the refusal names a flavor the policy file does not mention. "Must be one the policy permits" reads as though a project could list several.

*Proof:* host/servemcptools.go:237 (default flavor "base"), host/servemcptools.go:257-264 (any image other than opts.Flavor is refused)

**docs/mcp-surface.md:155 — `IMPRECISE`**

> `exec` tool exactly — text output, then `[exit status N]`, `isError` when the

Not exactly. The host appends "[exit status N]" unconditionally; the guest appends it only when the status is non-zero, and renders "[no output, exit status 0]" for a silent success, which the host never emits. Together with the missing `signal` key, an agent that has used one does have something to learn about the other.

*Proof:* host/servemcptools.go:516-521 vs supervisor/tools.go:179-195

**docs/mcp-surface.md:326 — `IMPRECISE`**

> is a narrower set than it sounds: only a `params` object that will not parse, because then there is no call to answer.

The set is wider than "only". A frame that is not valid JSON at all comes back as a JSON-RPC parse error against a null id, and an unknown JSON-RPC *method* (as opposed to an unknown tool) comes back as a JSON-RPC method-not-found error. Both are requests that could not be attempted, and neither is an unparseable `params` object.

*Proof:* host/servemcp.go:356 (CodeParseError on an unreadable frame), host/servemcp.go:416 (CodeMethodNotFound for an unknown method), host/servemcp.go:407-409 (CodeInvalidParams, the case the document names)

**docs/mcp-surface.md:499 — `IMPRECISE`**

> A `[[plugin]]` whose name is already taken by another is refused when the file is read, naming both lines.

It is not refused when the file is read. CheckPlugins is deliberately not called by the parser — its own comment says so — and its single caller is packPlugins, so a duplicate name surfaces when a sandbox is being created and the plugins device is packed, not at load. Anything that only loads the policy (and never boots) accepts the duplicate silently. The message itself does name both lines.

*Proof:* internal/config/plugin.go:71-76 and 91-95, host/plugins.go:24 (the only caller)

**docs/mcp-surface.md:587 — `IMPRECISE`**

> | Time to answer `initialize` | **20 s**, and it is paid before the sandbox reports ready |

20 s is the budget for each of the two handshake calls, not for the handshake. handshake() calls initialize with pluginStartTimeout and then tools/list with pluginStartTimeout again, so a slow plugin can hold the boot for up to 40 s, and a plugin that answers initialize but never answers tools/list costs a second, undocumented 20 s before it is reported as "did not start".

*Proof:* supervisor/pluginhost.go:50 (pluginStartTimeout = 20s), supervisor/pluginhost.go:174-187 (both calls use it)

**docs/mcp-surface.md:152 — `MISSING`**

> | `timeout_ms` | integer | no | Kill it after this long. |

When `timeout_ms` is omitted, sandbox_exec applies a 60-second deadline of its own. The guest's `exec`, which this table says the tool mirrors, treats a missing timeout as no limit ("0 means no limit"). So an unbounded command run through serve-mcp is killed at 60 s and the same command run through `kelyfos mcp` is not — an undocumented divergence in the direction that loses work.

*Proof:* host/servemcptools.go:492-495 (timeout := 60 * time.Second), supervisor/tools.go:44 (guest schema: "0 means no limit")

**docs/mcp-surface.md:161 — `MISSING`**

> **`sandbox_write_file`** — `{sandbox, path, content}` → bytes written.

Since P6-24 a write is confined to the profile's writable trees and is refused before the size check if the path is outside them. writableFor allows only /work, /tmp, /run, /root, /dev/pts, /dev/shm and a short list of device nodes; a sandbox_write_file to, say, /etc/hosts or /srv/x comes back isError with "is outside the trees a sandbox may write". The document says nothing about this anywhere, and neither does the tool's own description at host/servemcptools.go:87-89. Reads are deliberately unrestricted, which is also unstated.

*Proof:* supervisor/writable.go:42-68, supervisor/profile.go:67 (writableEverywhere = /work, /tmp, /run, /root), supervisor/tools.go:398-407 (writableFor called before the size check), host/servemcpfiles.go:65-69 (sandbox_write_file forwards to the guest's write_file)


### `docs/media/demo.cast`

**docs/media/demo.cast:88 — `STALE`**

> supervisor 0.2.0-p2

The supervisor no longer reports that. It was a hand-maintained constant until P6-1 (commit 930ff74), which replaced it with a build-time stamp precisely because it was wrong: supervisor/main.go:29-32 records that the constant 'was a constant reading "0.2.0-p2" through v0.9 — so every boot printed, and every chain recorded, a version the guest had not been for seven releases.' A guest built from the current tree prints the KELYFOS_VERSION it was stamped with. The recording was made at P5-5, before that fix, so the GIF rendered from it — the first thing on README.md:11 — still shows the exact string P6-1 removed. Everything else in the cast checks out against current code: the kernel line matches the 6.12.105 pin, the allowlist refusal is verbatim internal/denial/denial.go:122-123, the ready-frame field order matches host/run.go:625-661, '26 syscalls refused' is what supervisor/profile_policy.go:21-53 resolves to on arm64 for the dev flavor, and the verify line matches host/log.go:292. Re-running `bash dev/demo-record.sh --record` is the fix.

*Proof:* supervisor/main.go:29-33 (Version now stamped at build time, was "0.2.0-p2"); Makefile:172-174 (-X main.Version=$(KELYFOS_VERSION)); host/run.go:628 prints ready.Supervisor


### `docs/networking.md`

**docs/networking.md:253 — `FALSE`**

> A `secret.scrubbed` event records that bytes were altered, once per credential per connection.

Once per credential per *response*, not per connection. The `seen` map that does the de-duplication lives on a `scrubber` that is built fresh by `scrubResponse` for every response, and `scrubResponse` is called inside the keep-alive loop of a terminated connection. A connection carrying five responses that each echo the same token produces five `secret.scrubbed` events, not one. (The code comment at scrub.go:108 makes the same claim and is wrong in the same way.)

*Proof:* internal/egress/scrub.go:178 (`newScrubber` with a new `seen: map[string]bool{}` per call, scrub.go:72) called from internal/egress/terminate.go:111, which is inside the `for {}` request loop opened at terminate.go:56

**docs/networking.md:296 — `STALE`**

> Running the whole VMM under the jailer, with the network set up before privileges are dropped, is P4-1.

The jailer landed (as P5-1) and is the default: `kelyfos run` jails unless `--no-jail` is passed, and the posture is recorded per session (`s.State.Jailed = !opts.NoJail`). The network is already set up before the VMM starts — the TAP and the nftables table are created by the CLI through `sudo -n`, then Firecracker is launched under `sudo -n jailer`. So §7's closing sentence still presents as future work something that shipped, and its opening sentence ("The CLI runs those two steps through `sudo -n`") is now two of three: `ip`, `nft` and `jailer` all go through passwordless sudo.

*Proof:* internal/sandbox/jail.go:18 ("Running Firecracker under its own jailer (P5-1, docs/hardening.md §2)"), internal/sandbox/jail.go:30 (jailer invoked via `sudo -n`), host/run.go:65 (`--no-jail` is the opt-out), internal/sandbox/sandbox.go:309

**docs/networking.md:9 — `IMPRECISE`**

> A sandbox with no `--allow` flag has **no network interface at all**.

The NIC is created whenever the resolved allowlist is non-empty, and `kelyfos.toml`'s `[egress] allow` key fills that list when the flag was not typed. So a sandbox started with no `--allow` flag at all, in a directory whose policy file has an `allow` list, does get a TAP, a proxy and a firewall. §3.1 is careful to say the opposite about `--p-bind` ("no key in `kelyfos.toml` does it"), which makes the omission here read as a deliberate contrast rather than a shorthand.

*Proof:* host/run.go:196-197 (`if len(cfg.Allow) > 0 && !typed["allow"] { *allow = strings.Join(cfg.Allow, ",") }`), consumed at host/run.go:335 (`if list := splitAllow(*allow); len(list) > 0`)

**docs/networking.md:187 — `IMPRECISE`**

> - `CONNECT host:port` and absolute-URI HTTP requests are accepted only when `host` matches the allowlist.

Origin-form requests are accepted as well, not only absolute-URI ones. `splitTarget` starts from `req.Host` and only prefers `req.URL.Host` when the URL carries one, and `forwardHTTP` fills in the missing scheme and host before forwarding — so a bare `GET /path HTTP/1.1` with `Host: github.com` sent straight at the proxy is allowlist-checked and forwarded to `github.com:80` like any other request. The security property the sentence is defending (the allowlist decides) does hold for that shape; the enumeration of accepted shapes does not.

*Proof:* internal/egress/proxy.go:344-353 (`target := req.Host` … `else if req.URL != nil && req.URL.Host != ""`), internal/egress/proxy.go:312-318 (scheme and host filled in when absent)

**docs/networking.md:194 — `IMPRECISE`**

> so the host prints the same refusal once, on its own stderr — `kelyfos run` and `team up` do; `serve-mcp` and the shim record it without printing, because there is no terminal of yours to print to.

There is a fifth door, and it prints too: `kelyfos snapshot restore` wires a `newBlockedOnce(os.Stderr)` exactly as `run` and `team up` do. The enumeration is complete on the silent side (serve-mcp passes nil, the shim's own wiring has no printer) but not on the printing side. The four-versus-five split is the subject of the comment directly above the function the document is describing.

*Proof:* host/snapshot.go:166 (`wireProxyAudit(proxy, rec, "", newBlockedOnce(os.Stderr))`); compare host/run.go:578-580, host/team.go:735, and host/servemcptools.go:604 (`nil`)

**docs/networking.md:189 — `MISSING`**

> A bare hostname matches itself and its subdomains, so `--allow github.com` also permits `api.github.com`.

A leading `*.` on an allowlist entry is accepted and silently stripped, so `--allow *.github.com` is not a wildcard that excludes the apex — it normalises to `github.com` and therefore also permits `github.com` itself. The same normalisation lower-cases the entry and trims trailing dots. The document explains why the suffix rule exists but never says what happens to the wildcard a reader is most likely to type instead, and the code path that strips it is shared with `--secret`, where a `*.` is a hard error when a path is present.

*Proof:* internal/egress/secret.go:212 (`strings.TrimPrefix(strings.TrimRight(strings.ToLower(s), "."), "*.")`), applied to allowlist entries at internal/egress/proxy.go:84-86


### `docs/protocol.md`

**docs/protocol.md:216 — `FALSE`**

> Errors use one shape everywhere:

Two channels carry an error as a bare string rather than the `{"kind":…,"message":…}` object. ForwardReply.Error is a `string` (`{"v":1,"ok":false,"error":"nothing answered on port 80…"}` — which §5.8 itself shows) and ShellExit.Error is a `string`. Neither carries a `kind`, so neither can be classified by the shared kinds this section defines.

*Proof:* internal/proto/forward.go:41-45 (`Error string`) and internal/proto/shell.go:60-65 (`Error string`)

**docs/protocol.md:319 — `FALSE`**

> | `shutdown` | — | Terminate children, flush, unmount, halt. The host still supervises the Firecracker process and force-kills after a grace period. |

Nothing is unmounted. halt() sets the stopping flag, calls syncWorkspace (which is a bare unix.Sync), sends SIGTERM to everything but PID 1, waits the grace period, SIGKILLs, syncs again and reboots into power-off. There is no umount2 call anywhere in the supervisor — the syscall name appears only in the seccomp deny lists.

*Proof:* supervisor/control.go:87-117 and supervisor/workspace.go:45-50; `grep -rn 'Unmount\|umount' supervisor/` hits only profile_policy.go:30 and the two profile_*.go syscall tables

**docs/protocol.md:421 — `FALSE`**

> returns the authoritative name alongside `peers` and alongside a `spawn` result, and **the guest MUST prefer it** over anything it read from `/proc/cmdline`

`agent` means two different things on the two responses. On `peers` it is the asker's authoritative name (broker.go:210, `Agent: agent`). On `spawn` it is the *newly created worker's* name (broker.go:240, `Agent: sreq.Name`), and the guest returns it to the caller as the worker's identity — a guest that followed this sentence literally would rename itself to the worker it just spawned.

*Proof:* internal/team/broker.go:202-210 vs :225-240; supervisor/team.go:152-170 (peers() adopts resp.Agent as its own name, spawn() returns it as the worker's)

**docs/protocol.md:480 — `FALSE`**

> **A closed connection with no exit frame is a supervisor that died**, which is a different thing from a shell that ended — the same distinction §5.2 draws for `exec`.

The host does not draw that distinction on the shell channel. When the connection ends without an exit control frame, pumpShell returns `proto.ShellExit{Code: 0}` and `kelyfos shell` prints "shell exited 0" and returns success — exactly the invented exit status §5.2 forbids on exec (where host/exec.go:119 returns "the supervisor closed the connection without an exit frame"). A supervisor that died mid-shell is reported to the user as a clean exit 0.

*Proof:* host/shell.go:173-174 (`if errors.Is(err, io.EOF) { return proto.ShellExit{Code: 0} }`), compared with host/exec.go:117-121

**docs/protocol.md:586 — `FALSE`**

> The `ready` frame carries `supervisor`; the host logs it with every session and refuses a `v` it does not implement.

The first half is true (host/run.go:628 prints it, internal/recorder/recorder.go:97 records it). The second half is not implemented anywhere: serveReady unmarshals the frame into a struct embedding proto.Ready and dispatches on `msg.Type == "ready"` alone, never on `msg.V`. No host path refuses any `v`.

*Proof:* internal/sandbox/sandbox.go:1424-1437

**docs/protocol.md:122 — `STALE`**

> the guest's listeners on `10001`/`10002`/`10003` survive — the supervisor MUST NOT tear them down and re-bind, and the host reconnects with a fresh `CONNECT` per §1.1.

The guest now binds five host-initiated ports, not three: 10004 (shell, E5-3) and 10005 (forward, E5-5) are bound alongside them and are covered by the same rule. The enumeration predates both channels.

*Proof:* supervisor/main.go:160-190, in particular :173 (PortShell) and :181 (PortForward)

**docs/protocol.md:173 — `STALE`**

> Every KelyfOS channel — and MCP itself, see §6 — uses the same framing:

Two of the eight channels do not. `shell` (10004) uses a binary frame — one kind byte, four big-endian length bytes, payload — and `forward` (10005) is completely unframed after its two handshake lines. §5.7 and §5.8 say so; §3's blanket statement was written before either channel existed and was never qualified.

*Proof:* internal/proto/shell.go:74-89 and internal/proto/forward.go:10-18

**docs/protocol.md:282 — `STALE`**

> The first thing the supervisor does once mounts are up.

The ready frame is deliberately the last thing announced, not the first. After the mounts the supervisor sets up the confinement profile, applies the egress environment, starts the reaper, builds the team client, starts the events pump and the kmsg watcher, starts every plugin and pays the MCP handshake with each one (explicitly so that ready means the tool surface is complete), brings up loopback, and binds all five listeners; only then does it call announceReady.

*Proof:* supervisor/main.go:93-192 — plugin startup at :146-148 ("A sandbox with plugins therefore takes longer to become ready"), announceReady at :192

**docs/protocol.md:407 — `STALE`**

> | `recv` | Take the next message for this agent, waiting up to `timeout_ms`. |

The broker no longer honours `timeout_ms` as written: it is clamped both ends by waitFor. A value of 0 or absent — or a negative one, which is what an overflowed millisecond count becomes — waits one minute, not zero; anything over MaxWait (15 minutes) waits 15 minutes. The same clamp applies to `ask`.

*Proof:* internal/team/broker.go:101-136 (MaxWait, waitFor) and :172 (`timeout := waitFor(req.TimeoutMS)`)

**docs/protocol.md:106 — `IMPRECISE`**

> `/dev/vsock` must exist in the guest; the supervisor uses it implicitly through `AF_VSOCK` sockets.

Nothing in the guest opens or requires /dev/vsock. The transport is socket(AF_VSOCK, SOCK_STREAM) plus bind/listen/connect; the device node is the misc device used for the local-CID ioctl, which no KelyfOS code calls, and the supervisor's mount setup never creates it.

*Proof:* internal/vsock/vsock.go:44-91 (the whole guest transport) and supervisor/mount.go:20-48 (no device node is created)

**docs/protocol.md:181 — `IMPRECISE`**

> - empty lines are ignored on read.

They are ignored up to a bound. After 1024 consecutive blank lines within a single Read, the reader gives up and returns ErrBlankFlood, which every caller treats as fatal for the connection. A peer that sends nothing but newlines is disconnected rather than ignored.

*Proof:* internal/proto/proto.go:67-70 (ErrBlankFlood), :368 (maxBlankLines = 1024) and :386-392

**docs/protocol.md:250 — `IMPRECISE`**

> element 0 is the executable, resolved against `PATH`

Resolved against the *supervisor's* PATH, not the request's. exec.Command runs LookPath at construction time using the supervisor's own environment; cmd.Env — the `env` object this same table says replaces the default set — is assigned afterwards and has no effect on the lookup. A request supplying env `{"PATH":"/opt/bin"}` still resolves a bare name against /usr/local/sbin:…:/bin.

*Proof:* supervisor/exec.go:107 (exec.Command) vs :112-118 (cmd.Env), with the supervisor's own PATH set at supervisor/mount.go:114-125

**docs/protocol.md:482 — `IMPRECISE`**

> When the *host* hangs up, the guest sends `SIGHUP` to the shell's session

The guest signals one process — the shell itself — with cmd.Process.Signal(SIGHUP). It does not signal the session or the process group (there is no kill(-pgid) on this path), so a child the shell left running on that terminal is not hung up with it.

*Proof:* supervisor/shell.go:128-137

**docs/protocol.md:287 — `MISSING`**

> {"v":1,"type":"ready","boot_id":"7f3a…","arch":"arm64","kernel":"6.12.105","supervisor":"0.1.0","monotonic_ns":41233000,"overlay":true}

The ready frame also carries `profile` and `profile_error` (P5-3), and they are not decoration: when `profile_error` is non-empty the host refuses the machine outright rather than treating it as ready. §5.3 documents `overlay` at length and does not mention either field.

*Proof:* internal/proto/proto.go:149-158 and supervisor/main.go:303-304 write them; internal/sandbox/sandbox.go:550-552 refuses the sandbox when ProfileError is set

**docs/protocol.md:313 — `MISSING`**

> {"v":1,"id":"c1","ok":true}

Every control response — not just the ones asked for it — also carries `profile` and `profile_error`. It is the only way the host learns the confinement of a restored machine, which sends no ready frame, and Resync reads them off the response to the resync RPC. §5.4 documents neither field.

*Proof:* supervisor/control.go:40-43 ("Every answer carries the confinement"), internal/proto/proto.go:288-295, internal/sandbox/sandbox.go:869-872

**docs/protocol.md:411 — `MISSING`**

> | `store_get`, `store_put` | The team store, E2-3. Both carry `key`; `store_put` also carries `body`. |

A `store_put` with an empty body is not a write of nothing — it deletes the key, and is recorded as a distinct `delete` event. The store also refuses a key over 1 KiB, a team with more than 10,000 keys, a value over 1 MiB and a store over 64 MiB, each with a `denied` error the agent sees. None of this is on the wire page.

*Proof:* internal/team/store.go:163-179 (delete-by-empty-value, KindDelete) and :57-73 (MaxKeyBytes, MaxStoreKeys, MaxValueBytes, MaxStoreBytes)

**docs/protocol.md:466 — `MISSING`**

> | host → guest | `{"op":"open","cwd":…,"cols":…,"rows":…}` | first frame, and the only one that starts anything |

The open frame also carries `cmd` and `args`, and the guest honours them: shellCommand runs `open.Cmd` with `open.Args` when `cmd` is non-empty, falling back to /bin/sh, /bin/ash, /bin/bash only when it is empty. So the host can name the binary that runs inside the machine — a wire capability with no documentation (and one supervisor/shell.go:29-30 asserts does not exist).

*Proof:* internal/proto/shell.go:36-46 (Cmd, Args) and supervisor/shell.go:172-184

**docs/protocol.md:468 — `MISSING`**

> | guest → host | `{"op":"exit","code":…,"signal":…}` | the shell ended |

The exit frame has a third field, `error`, sent with `code: 1` when the guest could not allocate a pty, could not open the slave, or could not start the shell — i.e. when the shell never ran at all. The host reads it and turns it into the command's error.

*Proof:* internal/proto/shell.go:60-65 (`Error string`), supervisor/shell.go:186-189 (sendShellError), host/shell.go:117-119


### `docs/qol.md`

**docs/qol.md:238 — `FALSE`**

> **Control** is a JSON frame, for the things that are not the stream: the opening request (which shell, what size, what environment) and window resizes.

The open frame carries no environment. ShellOpen is Cmd, Args, Cwd, Cols, Rows; the host fills only Cwd, Cols and Rows, and the guest's environment is the supervisor's own defaultEnv plus TERM=xterm-256color, which the host cannot influence at all. There is also a third control op the sentence does not list: ShellExit, the guest's "exit" frame carrying code, signal and error — it is what §3.3's "shell.end, with duration and exit status" is built from, and what ends the host's pump loop.

*Proof:* internal/proto/shell.go:36-46 and 57-65; host/shell.go:76-78; supervisor/shell.go:86-87

**docs/qol.md:60 — `IMPRECISE`**

> named.json what the *pause* was: the name, the sandbox and session ids, when it was paused, and which policy file was frozen

NamedMeta carries two more fields, and one of them is load-bearing rather than incidental: `kelyfos` (the version that wrote the file) and `workspace_host`, the host directory the workspace was packed from. workspace_host is the only record of which directory owes a write-back — resume skips the sync-back entirely when it is empty — so a list of named.json's contents that omits it describes the file as smaller than the pause's own contract. The section's "Corrected after the epic" note is specifically about what named.json holds, which makes the omission a live one.

*Proof:* host/sessions.go:41-55 (NamedMeta); host/sessions.go:454 (`snapMeta.HasWorkspace && meta.WorkspaceHost != ""` gates syncResumedWorkspace)

**docs/qol.md:122 — `IMPRECISE`**

> `sessions` shows the size so it is visible, and `sessions rm` says what it is about to discard.

`sessions rm` says what it discarded, after discarding it, and asks nothing. It reads the metadata and measures the directory, calls os.RemoveAll(dir), and only then prints "removed %q — %s, paused %s ago". The size is computed beforehand solely so it can be printed afterwards; there is no prompt and no line before the delete.

*Proof:* host/sessions.go:280-287

**docs/qol.md:181 — `IMPRECISE`**

> Mode changes are `M` with the modes named. A file whose contents are identical and whose mode changed is still a change, because it is one.

The comparison runs against the extracted tree, and extraction rewrites modes: safeMode strips world-write and then forces u+rw on every file and u+rwx on every directory. So the modes named are the host-sanitised ones rather than the guest's, and — the live defect — a file the sandbox never touched is reported as a mode change whenever its packed mode lacks those bits. A 0444 file comes back 0644 and is listed as ' M path mode 0444 → 0644'; a 0555 directory becomes 0755. The sync-back then renames that tree into place, so the permission on the user's own untouched file is changed. This is the same failure the safeMode comment records for group-write ("a boundary that rewrites the user's files to protect them from the user is not protecting anybody") — fixed for 0o020, still present for the u+rw / u+rwx floor.

*Proof:* internal/sandbox/extract.go:263-269 (safeMode) and 251-258 (the group-write precedent); internal/sandbox/diff.go:199-203 (mode-only change → 'M'); internal/sandbox/workspace.go:259 (the tree is renamed into place)

**docs/qol.md:46 — `MISSING`**

> A paused session is a snapshot with everything it needs to become the same machine again, under a name a person chose.

Not for a sandbox that had egress, and §1 never says so. resume refuses outright when the stored snapshot records a NIC — "session %q was paused from a sandbox with egress, and resuming one is the same problem restoring one is: the guest's address is inside its memory image and something else may hold it now (D22). bring it back with: kelyfos snapshot restore -name %s" — and HasNetwork is set for every machine that had a TAP, i.e. every run with an allowlist. pause does not check for this: it stores the session and prints "resume it with: kelyfos resume <name>", so the documented workflow dead-ends. §1.2's own example ("allow gained api.github.com") describes a policy difference that can only exist on a machine resume will not bring back.

*Proof:* host/sessions.go:436-442 (the refusal); internal/sandbox/sandbox.go:791-793 (HasNetwork set whenever st.TAP != ""); host/sessions.go:191 (pause's advice)


### `docs/resources.md`

**docs/resources.md:278 — `FALSE`**

> `SIGKILL`; the VM is shut down; the workspace is synced back; the session record is closed with `reason: "timeout"`.

The last two steps happen in the other order: the session record is closed *before* the workspace is written back. The three deferred stages are registered in the order workspace sync-back (run.go:403), session-end record (run.go:479), shutdown+receipt (run.go:537), and Go unwinds them last-registered-first — so teardown runs shutdown → `session.end` + `rec.Close()` → sync-back. That is also why a `--review` diversion has to reopen the closed chain and append after `session.end`.

*Proof:* host/run.go:403 (workspace defer), host/run.go:479-495 (session.end defer), host/run.go:537-559 (shutdown defer); host/review.go:129-139 (`recordReview` reopens the recorder)

**docs/resources.md:398 — `FALSE`**

> disk = "4G" # /work device size

`disk` is never the /work device size. The device is sized from the packed directory — `max(2 × directory size, 1 GiB)` — and `disk` is only a ceiling that sizing must come in under; exceeding it refuses the run before boot. The same page says so in bold at line 123 ("`disk` does not choose the device's size — it refuses one that is too big"), so the example's inline comment contradicts both the code and the prose above it.

*Proof:* internal/sandbox/workspace.go:55-65 (`size := used * 2` / `if size < workspaceMinSize` / `if maxSize > 0 && size > maxSize` → refusal), with `maxSize` supplied as the ceiling by host/run.go:397-398

**docs/resources.md:469 — `FALSE`**

> held — `/proc/<pid>/stat` and the sandbox's own `cpu.stat`, `/proc/<pid>/io`,

`dev/prove-caps.sh` never reads a cgroup `cpu.stat`. Its CPU measurement is utime+stime from `/proc/<pid>/stat` only, and the string `cpu.stat` does not appear anywhere in the script (the only mention of cgroups is the section heading at line 168). The sandbox's own `cpu.stat` is read by `dev/prove-team.sh`, which the page credits separately at line 489. The other three sources named — `/proc/<pid>/io`, the TAP counters, the flight recorder — are correct.

*Proof:* dev/prove-caps.sh:85-96 (`cpu_seconds()` reads /proc/<pid>/stat), dev/prove-caps.sh:155-159 (its only CPU sampling); contrast dev/prove-team.sh:96-98 (`usage_usec`/`throttled_usec` read `$1/cpu.stat`)

**docs/resources.md:133 — `IMPRECISE`**

> So a small repository gets a 1 GiB `/work` whatever `disk` says, and `ENOSPC` arrives at that 1 GiB rather than at the ceiling.

Only when `disk` is at least 1 GiB. The 1 GiB floor is itself checked against the ceiling, so `disk = "512M"` with a small repository refuses the run before boot and there is no `/work` device at all — the opposite of "gets a 1 GiB /work whatever `disk` says".

*Proof:* internal/sandbox/workspace.go:55-65 — the floor is applied first (`if size < workspaceMinSize { size = workspaceMinSize }`) and the refusal is checked after it

**docs/resources.md:243 — `IMPRECISE`**

> A `scratch` larger than `mem` is refused at boot rather than accepted:

Only two of the four entry points that apply `scratch` make that check: `kelyfos run` (run.go:277) and the E2B shim (shim.go:108). `kelyfos team up` hands `a.res.ScratchByte` straight into the machine with no comparison against that agent's `mem`, and `serve-mcp`'s sandbox_create does the same — so inside a team a `scratch` above `mem` is accepted, and the inert cap this section exists to prevent is exactly what you get.

*Proof:* host/run.go:277-282 and host/shim.go:108-112 (the refusal) vs. host/team.go:645 (`ScratchBytes: a.res.ScratchByte`, no check; also 811 and 887) and host/servemcptools.go:317

**docs/resources.md:289 — `IMPRECISE`**

> Inside a `[team]`, `max_runtime` works per agent and `idle_timeout` is **refused**

True of `[team.agent.resources]`, but not of every `[resources]` block inside a team: in a `[team.agent.spawn.resources]` budget `max_runtime` is *also* refused before boot, as "[team.agent.spawn] lifetime under another name (F-D33)", together with `idle_timeout`. A reader planning a spawn budget from this sentence writes a key that will not load a run.

*Proof:* host/teamplan.go:255-268 (`checkAgentPolicy` refuses both spawn-budget keys), internal/config/schema.go:236-247 (`RefusedLater` on both)

**docs/resources.md:315 — `IMPRECISE`**

> belongs to one device, and a sandbox with a workspace has two: the read-only root and `/work`. `disk_mbps = 10` therefore means ten megabytes a second on each, not five each.

A sandbox that also declares `[[plugin]]` entries has a third virtio-blk device — drive_id "plugins" — and it is given the same limiter object, so `disk_mbps = 10` is ten megabytes a second on each of up to three devices, not two. The count "two" was right before the plugins device landed (E4-6); the per-device reasoning still holds, the number does not.

*Proof:* internal/sandbox/config.go:203-209 (plugins Drive with `RateLimiter: driveLimit`), alongside 166-172 (rootfs) and 189-196 (workspace)

**docs/resources.md:15 — `MISSING`**

> | `[resources]` in `kelyfos.toml` | **hard ceilings.** The committed policy of the project. |

A `[resources]` ceiling is also the value applied when no flag asks for anything — `mem = "2G"` with no `--mem` boots a 2 GiB machine, not the 512 MiB default. The page never says this, and by contrasting `[resources]` with the v0.3 "defaults" behaviour (lines 31-37) and calling `[sandbox] vcpus`/`mem_mib` the keys that keep "the old defaults-only meaning", it invites the opposite conclusion. The schema table states the behaviour the page omits: "hard ceilings for a single run, and the value when no flag asks".

*Proof:* host/run.go:1050-1057 (`ceiling()`: `if !typed || *flagVal == 0 { *flagVal = limit; return nil }`), host/servemcptools.go:266-270 ("the ceiling is the [resources] value when there is one, and it is also the default"), internal/config/schema.go:115


### `docs/teams.md`

**docs/teams.md:59 — `FALSE`**

> Five VMs boot.

The example above it declares two `[[team.agent]]` blocks: `master` (no `count`, so 1) and `worker` with `count = 3`. `expandCount` turns that into master, worker-1, worker-2, worker-3 — four agents, four VMs. No fifth machine exists: a fork template is never booted in front of a team (cold-first, host/team.go:338-368) and is never in the roster. §6 line 468 (`cpu_quota = "200%" # two cores' worth, for all five agents together`) inherits the same miscount.

*Proof:* host/teamplan.go:353-361 with internal/config/team.go:147

**docs/teams.md:202 — `FALSE`**

> If the recipient's channel is gone, `team_send` fails with an explicit error — the message is not queued for a machine that may never come back

The broker queues into a 64-slot mailbox per agent (`const mailbox = 64`) and never checks whether the recipient's machine still exists. `deliver` fails only when that buffer is full, with reason `mailbox_full`. Nothing removes a *declared* agent's mailbox when its VM stops — only `Despawn` deletes a box, and it is called solely for spawned workers (internal/team/spawn.go:125, from host/team.go:330). So a `team_send` to an agent that was stopped by `max_runtime` (host/team.go:499-500 calls `crew.remove`, never `broker.Despawn`) or that crashed is accepted, returns success, and is recorded `outcome: delivered` — up to 64 times. §8.3 line 701 ("A message to a machine that has gone is an error to the sender") repeats the same untrue claim.

*Proof:* internal/team/broker.go:99 and internal/team/broker.go:376-389

**docs/teams.md:309 — `FALSE`**

> | `unreachable` | The recipient exists but its channel is gone. |

`unreachable` is returned for exactly one condition — a mailbox that is full or unread: `b.record(b.describe(from, to, body, kind, OutcomeUnreachable, "mailbox_full"))` then `&Error{Kind: "unreachable", Message: to + " is not reading its messages"}`. There is no channel-liveness check anywhere in the broker, so "its channel is gone" describes a condition the code never detects.

*Proof:* internal/team/broker.go:383-388

**docs/teams.md:666 — `FALSE`**

> them; commands, files, egress attempts, OOM kills and each member's usage receipt sit in that member's lane.

A *forked* member has no OOM record at all. `bootAgent` installs an `OnGuestEvent` handler that appends `resource.oom` (and plugin events) with the agent's name (host/team.go:657-674), but `forkAgent` builds its `sandbox.Options` without one (host/team.go:884-892), and the sandbox drops the frame when the handler is nil: `if s.opts.OnGuestEvent != nil { s.opts.OnGuestEvent(ev) }`. Since forking is reserved for no-egress workers (host/teamplan.go:292-294), the members that fork are precisely the replica workers a `count` group creates — their OOM kills and plugin calls reach no lane and no chain. Usage receipts and commands are unaffected (they go through `agentRig.stop` and `opts.Session`).

*Proof:* internal/sandbox/sandbox.go:443 and host/team.go:884-892

**docs/teams.md:658 — `STALE`**

> session 269043fa: chain intact, 44 events verified across 3 agents (master, worker-1, worker-2)

`verifySession` prints that line and then, unconditionally, a second line ` chain head <hex>` — the deferred print is set up before the team/single-sandbox verdict is chosen precisely so both shapes carry it. The transcript in the document shows the pre-P6 output, one line short.

*Proof:* host/log.go:281 with host/log.go:291-293

**docs/teams.md:635 — `IMPRECISE`**

> | `team.refused` | A message the edge list did not permit. Its own type, because it is the interesting one. |

`team.refused` covers three refusals, not one. `describe` promotes any refused message to that type, so a message to a name that is not in the team is recorded as `team.refused` with `reason: no_such_agent` (internal/team/broker.go:367-369), and `Reply` writes `team.refused` with `reason: missing_correlation` or `unknown_correlation` for a `team_reply` nobody was waiting for (internal/team/broker.go:312-322). A reader filtering the chain for `team.refused` to count edge violations will over-count.

*Proof:* internal/team/broker.go:401-403

**docs/teams.md:12 — `MISSING`**

> up` boots that graph.

Only one team may run on a host at a time, and the document never says so anywhere: `raiseTeam` stats `~/.cache/kelyfos/run/team.json` and refuses with "a team is already running; stop it with `kelyfos team down`" before it plans anything. The restriction is stated only in the serve-mcp tool description ("One team at a time.", host/servemcpteam.go:38).

*Proof:* host/team.go:181-183

**docs/teams.md:193 — `MISSING`**

> Every argument named `timeout_ms` is an **integer number of milliseconds** and defaults to **60000** when it is absent or not positive.

The default is right, but there is now a ceiling the section does not mention: `waitFor` clamps every `timeout_ms` to `MaxWait = 15 * time.Minute`, silently, rather than refusing it. The tool schemas the guest sees do say so ("Defaults to 60000, and the host holds a call open for at most 15 minutes", supervisor/teamtools.go:47 and :63), so the document is the only place that still promises an unbounded wait.

*Proof:* internal/team/broker.go:107 and internal/team/broker.go:127-136


### `docs/threat-model.md`

**docs/threat-model.md:76 — `FALSE`**

> **The binding is a suffix match**, so `--secret T@github.com` attaches the credential to `api.github.com` and `raw.githubusercontent.com` too, on any request the guest composes to any of them.

`raw.githubusercontent.com` is not covered by a binding to `github.com`. The suffix rule is `host == s.Domain || strings.HasSuffix(host, "."+s.Domain)`, and "raw.githubusercontent.com" does not end in ".github.com" (it ends in "usercontent.com"). The same is true of the allowlist rule in allowsHost, so `--allow github.com` does not reach it either. The example names a host the mechanism it is illustrating does not match — and it is the example a reader would use to decide how wide a binding is.

*Proof:* internal/egress/secret.go bindsHost (`return host == s.Domain || strings.HasSuffix(host, "."+s.Domain)`); internal/egress/proxy.go:83-90 allowsHost

**docs/threat-model.md:113 — `FALSE`**

> Guest-chosen **modes** do not survive either. The executable bit does, because an agent that built a binary needs it; group and world write, setuid, setgid and the sticky bit do not, and the workspace root keeps the mode the person's own directory had rather than the one the image's root carried.

Group-write survives. safeMode strips only the world-write bit — `p := m.Perm() &^ 0o002` — and the function's own comment says stripping group-write was tried and deliberately reverted: "Group-write is deliberately left alone, and the first version of this function did strip it. That was wrong in a way worth recording... The line is drawn where the danger is. World-write is reachable by any account on the host; group-write is ordinarily the user's own group." So an image entry the guest wrote mode 0664 or 0775 comes back to the host with group-write intact. (setuid/setgid/sticky and the root-mode claim are both correct: .Perm() masks 0o7000 away, and Commit chmods the tree to the replaced directory's mode.)

*Proof:* internal/sandbox/extract.go:263 (safeMode), and the comment at internal/sandbox/extract.go:243-262; workspace root mode at internal/sandbox/workspace.go Commit

**docs/threat-model.md:75 — `STALE`**

> **The binding is a suffix match**, so `--secret T@github.com` attaches the credential to `api.github.com` and `raw.githubusercontent.com` too, on any request the guest composes to any of them.

Three narrowings landed since this was written and none are in this section. (1) A spec carrying a path — the grammar is now `NAME@host[:scheme][/path]` — binds one host exactly, not by suffix: `if s.Scope.Path != "" { return host == s.Domain }`. (2) A scoped credential is withheld from any request whose path is outside the prefix or is not literal-and-normal (WithheldPath, WithheldNotPlain). (3) It is withheld from any request whose Host header names something other than the CONNECT target (WithheldHostMismatch), and from every plaintext HTTP request (WithheldUnencrypted). So "on any request the guest composes to any of them" is no longer the rule, and endpoint scoping — the thing that narrows the asset §2 calls the one the architecture is bent around — appears nowhere in the threat model.

*Proof:* internal/egress/secret.go bindsHost and ParseSecretSpec; internal/egress/scope.go:33-70 (Scope.covers, WithheldPath/WithheldNotPlain/WithheldUnencrypted/WithheldHostMismatch); internal/egress/terminate.go pick and sameHost; internal/egress/proxy.go forwardHTTP

**docs/threat-model.md:154 — `STALE`**

> Unwritten policy means shared state; the byte limits (1 MiB a value, 64 MiB a team) are footgun bounds, not security ones.

There are now four bounds, not two, and the two missing ones were added because the two named ones did not hold: MaxKeyBytes = 1 KiB and MaxStoreKeys = 10,000. The store's own comment records why (finding H-4): "MaxStoreBytes weighed len(value) and nothing else, so a key cost an agent nothing against the only budget there was. Ten thousand one-byte keys is ten kilobytes by that arithmetic and ten thousand map entries in fact." Keys are now weighed with values against MaxStoreBytes. The same paragraph's "Every access is recorded, permitted or not" is still accurate, but the store also gained delete-by-empty-value, recorded as a distinct `delete` kind.

*Proof:* internal/team/store.go:57-73 (MaxValueBytes, MaxStoreBytes, MaxKeyBytes, MaxStoreKeys and the H-4 comment); Put at :141-210 (key length check, MaxStoreKeys check, key weighed into `grown`, delete-by-empty-value)

**docs/threat-model.md:279 — `STALE`**

> `kelyfos shim` serves an E2B-compatible REST subset, by default on `127.0.0.1:3000`, and it checks nothing: there is no key, no account and no authorisation, because it has none to have.

There is a key. `KELYFOS_SHIM_TOKEN` gates every route on a bearer token when it is set, compared with subtle.ConstantTimeCompare; the handler is wrapped as `logging(authenticated(mux))`. Unauthenticated is still the default, but "there is no key... because it has none to have" is no longer true, and the same paragraph's closing claim that "`--addr` is the only thing between it and the network" (line 283) is stale for the same reason.

*Proof:* shim/shim.go:133-176 (tokenEnv, authenticated, Handler)

**docs/threat-model.md:282 — `STALE`**

> While it is running, **any process on that machine that can reach the port can boot microVMs, list them, kill them, and read and write arbitrary paths inside a running guest.**

Writes are no longer arbitrary. The shim's POST /files runs `sh -c 'mkdir -p ... && base64 -d > <path>'` through sandbox.Exec, and every process the guest supervisor starts is Landlock-confined to /work, /tmp, /run, /root, /dev/pts, /dev/shm and seven named device nodes — so a write anywhere else fails EACCES. Reads are genuinely arbitrary (readRights is granted beneath "/"), and boot/list/kill are unchanged. There is also now a ceiling of 16 sandboxes per shim (MaxSandboxes), which the paragraph's "What remains is the port itself, and it is the whole of the exposure" does not account for.

*Proof:* shim/shim.go:505-507 (write via exec); supervisor/reaper.go:75-83 (confine on every spawn); supervisor/profile.go:66-88 (writableEverywhere, writableDevices, writableDeviceTrees); shim/shim.go:130 (MaxSandboxes = 16)

**docs/threat-model.md:201 — `IMPRECISE`**

> 28 syscalls are refused with `EPERM`, among them `mount`, `reboot`, the clock-setting family, the keyring calls and module loading.

28 is the base flavor on x86_64 only. refusalPolicy names 28 syscalls, but Profile.Refused() drops ptrace when AllowPtrace is set, which profileFor does for flavor `dev` — 27 there — and drops any name this architecture lacks, which on arm64 is settimeofday: 27 for base, 26 for dev. The generated reference the same paragraph points at prints both numbers.

*Proof:* supervisor/profile_policy.go:22-52 (28 names); supervisor/profile.go:104-115 (AllowPtrace for "dev") and Refused() at :318; supervisor/profile_arm64.go (no settimeofday); docs/reference/profiles.md:37 and :49 ("Refused, 28 syscalls" / "Refused, 27 syscalls")

**docs/threat-model.md:211 — `IMPRECISE`**

> The syscall surface it leaves is everything the guest kernel offers root minus 28 names.

Same arithmetic as line 201: minus 27 names on the `dev` flavor, because that flavor keeps ptrace out of the refusal list — which is precisely the syscall a reader weighing this sentence would care about.

*Proof:* supervisor/profile.go:104-115 and Refused() at :318; supervisor/profile_policy.go:50-51

**docs/threat-model.md:229 — `IMPRECISE`**

> The sudoers grant it asks for is deliberately narrow — one line, the `jailer` binary and nothing else, so it is not a general `NOPASSWD` — but the process that invokes it is still ordinary code running as you.

That is the grant for the jailer alone. Egress needs more: the CLI shells out to `sudo -n ip ...`, `sudo -n nft -f -` and `sudo -n nft delete table ...`, and its preflight check is `sudo -n true` — i.e. it tests for, and `kelyfos doctor` tells the user to arrange, general passwordless sudo, not a second narrow line. Teardown also runs `sudo -n rm -rf <jail dir>`. jail.go's own comment states the shape ("KelyfOS invokes it through `sudo -n`, exactly as it already invokes `ip` and `nft` for egress"). §4's later "The host's own tooling" paragraph says sudo is required for the TAP and nftables, but this sentence's "one line... and nothing else, so it is not a general `NOPASSWD`" describes only the `--allow`-free case.

*Proof:* internal/sandbox/network.go:225-228 (sudo helper) and CheckPrivileges at :233-245 (`sudo("true")`); internal/sandbox/jail.go:97-110 (sudoersLine names only the jailer) and removeJail at :225-233; host/doctor.go:275-277 ("needs passwordless sudo")

**docs/threat-model.md:382 — `IMPRECISE`**

> What that covers, stated rather than summarised as "the parsers", because the useful question is which ones: the framing of every host/guest channel, and the decode of each message type the host reads from a guest; the policy parsers — `kelyfos.toml`, `--secret`, and the proxy's target parse that every allowlist decision keys on; the flight recorder; the argument summarisers on both sides of the M…

The enumeration is offered as the complete answer to "which ones" and misses two of the nineteen targets: FuzzScrubPreservesEverythingButTheSecret, which drives the response scrubber — the one component that rewrites bytes the agent is about to parse, and squarely inside the "anything the network returned" source the section declares — and FuzzDecodeBase64Lines, the shim's decoder for guest output handed back to an SDK client as file contents. The list names the shim's shell quoting but not its decoder.

*Proof:* internal/egress/fuzz_test.go:128 (FuzzScrubPreservesEverythingButTheSecret); shim/fuzz_test.go:89 (FuzzDecodeBase64Lines); `grep -rn "func Fuzz" --include="*.go" .` returns 19

**docs/threat-model.md:397 — `IMPRECISE`**

> What is **not** fuzzed, and why: the image manifest and the message types above the framing are `encoding/json` decoding into typed structs, so a harness there measures the standard library

This contradicts the covered list fifteen lines above it, which claims "the decode of each message type the host reads from a guest". The covered list is the accurate one: FuzzReaderRead drives the NDJSON framing and decodes the same input into Ready, GuestEvent, ExecResponse, TeamRequest, ControlResponse, Heartbeat and Error — its own comment says "decoding into the message types the HOST reads from a guest". Only the image manifest is genuinely unfuzzed.

*Proof:* internal/proto/fuzz_test.go:67-97 (FuzzReaderRead, seven message types); docs/threat-model.md:383-384 for the contradicting half

**docs/threat-model.md:405 — `IMPRECISE`**

> Seven defects came out of writing them, and they are the reason this section does not simply say the parsers are careful.

Seven is the count from when there were sixteen targets; the sentence now sits under "Nineteen Go fuzz targets" and does not account for what running them since has found. At least two further silent misbinds are recorded in the code as found by the scheduled run rather than by writing the harness: `--secret T@..` normalising to a domain no host can match (validDomain), and NormaliseDomain stripping one trailing dot where the host side strips all of them, so "0.." bound "0." and matched nothing. Both are the same failure mode the paragraph highlights — a credential that silently does not attach.

*Proof:* internal/egress/secret.go:169 ("Found by the scheduled fuzz run on its first outing") and :211 ("Found by the scheduled fuzz run"); PLAN.html:2556 ("Sixteen fuzz targets, and seven real defects out of writing them")

**docs/threat-model.md:125 — `MISSING`**

> Since v1.0 the exported report carries that record inside it, so the person you send it to re-runs the chain themselves — `kelyfos verify <report.html>`, offline, no key.

The section states what verification closes and what it does not (the rendering), but not the two limits the code itself names. A truncated chain verifies: Verify walks lines, checking seq == line number and prev-links, so dropping trailing events leaves a chain that is byte-for-byte what a shorter session would have written — host/verify.go's own comment says "A cut-short chain verifies", and the CLI prints an observation about a missing session.end rather than a verdict. And because there is no key in the default path, anyone who can write the file can rewrite it end to end and recompute every digest; Verify's doc comment says so and scopes the guarantee to the *selective* edit. Neither limit appears in a section whose stated job is honesty about where the protection stops, and §2 lists the audit record as "If it can be edited, it proves nothing."

*Proof:* internal/recorder/recorder.go Verify ("What the chain catches is the *selective* edit") and its seq/prev loop; host/verify.go endsCleanly and the comment above it ("A cut-short chain verifies: nothing after the cut exists to break")

**docs/threat-model.md:194 — `MISSING`**

> Every process the supervisor spawns — `exec`, a plugin, the interactive shell — is confined by Landlock and a seccomp refusal list, declared per flavor and generated into [`reference/profiles.md`](reference/profiles.md) from the code that enforces it.

True as written, and it leaves out the party that is not confined: the supervisor itself. applyLandlock and applySeccomp are reached only from the re-exec'd `--confine` helper, so PID 1 runs with the whole guest filesystem in front of it — and the MCP file tools (read_file, write_file, and their base64 counterparts) execute inside PID 1, not in a spawned child. write_file is limited by an application-level path check against the same three lists the profile is built from (writableFor); read_file is not limited at all. That is an agent-reachable carve-out from the row §5 states as "in-guest process → guest | Landlock + seccomp", it was a live defect (finding H-1: write_file passed the agent's path straight to os.WriteFile, reaching /dev/vda and /dev/vdb), and the threat model does not mention it.

*Proof:* supervisor/writable.go:9-40 (the whole header comment) and writableFor at :44; supervisor/tools.go:391 (os.ReadFile, no check) and :402-413 (writableFor then os.WriteFile); supervisor/confine.go:44-67 (profile applied only in runConfined)

**docs/threat-model.md:420 — `MISSING`**

> | a report → whoever received it | the record travels in the file; `kelyfos verify` | active since v1.0; covers the record, not the rendering |

The row and §3 both omit signing, which is the only thing on this boundary that says who produced the file. `kelyfos log --export ... --sign-key <ed25519 PKCS#8 PEM>` signs an export, and `kelyfos verify --key` checks the signature against a key the reader already holds — the CLI's own help draws the distinction the threat model would want: "A signed report says who exported it, and that is worth exactly what knowing the key is worth: --key checks the signature against one you already hold, rather than against the one the file supplied itself."

*Proof:* host/log.go:34 and :68 (--sign-key); host/verify.go:29 (--key), :43-46 (the help text) and reportSignature at :146; internal/report/sign.go:23



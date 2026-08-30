# Contributing to KelyfOS

Thanks for looking. KelyfOS is Apache-2.0 licensed (see [`LICENSE`](LICENSE)),
and every contribution needs a Developer Certificate of Origin sign-off.

## Before you write code

The [README](README.md) has the scope and the non-goals;
[`docs/roadmap.md`](docs/roadmap.md) has what was built and the task IDs the
source cites; [`docs/decisions.md`](docs/decisions.md) has why. Read the
non-goals first — they are boundaries, not preferences.

Two things it will save you from:

- **The non-goals in section 2 are hard boundaries.** No orchestrator, no control
  plane, no hosted service, no web dashboard, no new kernel, no VMM. Every one of
  those has a funded company doing it; the guest image is the empty niche. A pull
  request that crosses a non-goal will be declined however good the code is.
- **Deviations get recorded before they get written.** A change of approach,
  library or scope belongs in the decision log with its rationale, so the next
  reader learns why and not just what.

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by` line matching its author:

```
Signed-off-by: Jane Developer <jane@example.com>
```

`git commit -s` adds it for you. To fix the last commit: `git commit --amend -s`.
For a whole branch: `git rebase --signoff main`.

**This was required before it was enforced, and no commit before v1.0 carries
one.** That is stated here rather than quietly repaired, because the two honest
alternatives are worse: rewriting the history would invalidate every existing
clone and every commit hash the project's own records cite, and dropping the requirement
would abandon the mechanism that keeps provenance auditable without asking
anybody to sign a CLA (D5). So enforcement starts where it can be true — CI
checks the commits a push or a pull request *adds*, from v1.0 onward, and the
gap behind it is a fact about this project rather than a thing to discover
(D56). Merge commits are exempt: a merge carries no new work, and GitHub's own
merge commits cannot be signed by a contributor.

The sign-off is your statement that you have the right to submit the work under
the project's license. It is a lightweight alternative to a Contributor License
Agreement — no paperwork, no account to create — and it keeps the provenance of
every line auditable, so a future relicensing decision does not turn into
contributor archaeology (decision D5).

This is the DCO, version 1.1, verbatim from
<https://developercertificate.org/>:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same license (unless I am permitted to submit
    under a different license), as indicated in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## Working on the code

The Linux layer is required — Firecracker runs on Linux/KVM only:

```sh
limactl start --name kelyfos-dev dev/lima.yaml   # macOS; see dev/wsl2.md for WSL2
limactl shell kelyfos-dev -- bash dev/install-build-deps.sh
limactl shell kelyfos-dev -- bash dev/install-firecracker.sh
limactl shell kelyfos-dev -- make cli
limactl shell kelyfos-dev -- make image FLAVOR=dev
```

`limactl start` here rather than `kelyfos doctor --setup`, which is what the
README tells a *user*: you are building the binary that `doctor` lives in, so it
does not exist yet. The cost is that `kelyfos doctor` will later call this
instance unmanaged — it carries no marker saying which configuration it was made
from — which is correct and not a problem to fix. `kelyfos doctor --recreate`
brings it under management if you want that; it stops, deletes and re-provisions
the VM, so do it before you have anything in there worth keeping.

The CLI has a second target. Since P6-12 `make release-cli` also cross-builds
`kelyfos-darwin-{x86_64,aarch64}` — a smaller program in which `doctor` owns the
Lima layer, `verify` checks a report somebody sent you, and every command that
needs a guest refuses with the way in (`host/lima_darwin.go`,
`host/layer_darwin.go`, `host/platform_other.go`). **No per-commit check
compiles them**: `go vet ./...` and `go test ./...` build for the host, so a
change that breaks the macOS files passes every gate a pull request runs. The
only thing that compiles them is `make release-cli`, and CI reaches it at tag
time and on `repro-check`'s monthly run — both of which are after the commit
that broke it. Run it yourself before you push a change to the CLI.

Bare `make` prints the target list and builds nothing — the default goal is
`help`. The first `make image` on a machine also builds the cross toolchain,
which takes about thirty-five minutes; after that it is minutes.

`make test` runs `go vet ./...` and `go test ./...`. CI's `checks` job asks for
more, and `gofmt` is the first of them: a tree that is not gofmt-clean fails
before anything is vetted. After it come the unit tests, `make fuzz
FUZZTIME=10s`, the hostile-input corpus with `KELYFOS_HOSTILE=required`,
`make docs` compared against the
committed reference, and every cookbook recipe extracted and parsed.

To run that job itself rather than a description of it, `make ci-act` executes
`ci.yml`'s `checks` job in Docker with [act](https://github.com/nektos/act),
against a clean clone of `HEAD` (or `make ci-act REF=<commit>`), so an
uncommitted edit in your checkout cannot leak into the result. It needs Docker
and `act` (`brew install act`). Its summary is what a Progress Log row cites
when no hosted run exists for the commit. Two differences from the hosted
runner, stated so nobody rediscovers them: the container runs as root, and on
Apple silicon it is `linux/arm64`. The `build` and `boot` jobs need a machine
Docker on macOS is not; `limactl shell kelyfos-dev -- dev/ci-local.sh --boot`
in the Lima VM is their stand-in.

The guest toolchain — Buildroot, the kernel, Firecracker and Go — is pinned in
[`versions.mk`](versions.mk), and Go modules in `go.mod`. Bumping one means
changing the version and its checksum in the same commit, with the reason in the
progress log — except Firecracker, which is pinned by version alone because its
release tarballs ship their own `.sha256.txt` and `dev/install-firecracker.sh`
fetches and checks that at install time. What is *not* pinned: the host build
packages `apt` installs. Whether a build reproduces byte for byte is measured
rather than assumed — [`repro-check`](.github/workflows/repro-check.yml) builds
the same commit twice and diffs the result per artifact, monthly, and what the
project says about reproducibility is whatever that run last reported.

Keep commits small and reference the task ID they belong to:

```
P1-6: exec over vsock
```

**A user-visible change needs a `CHANGELOG.md` entry in the same commit.** That
file is the source the release notes are cut from rather than a mirror of them
(D50), and `tools/changelog.py --check` fails CI when a published tag has no
section. Put the entry under `## Unreleased`; the release workflow takes it from
there. A change that breaks something also needs a section in
[`docs/upgrading.md`](docs/upgrading.md) saying what to do about it — a break
recorded only in a changelog line is a break somebody discovers at the wrong
time.

## How a change is verified

These rules governed the project through its first eight phases. They are here
rather than in a planning document because they are what a reviewer applies, not
what a schedule says.

**A decision is recorded before it is implemented.** Any change of approach,
library or scope gets a row in [`docs/decisions.md`](docs/decisions.md) with the
reasoning, written before the code. The source cites these by number — a `D44`
in a comment is a row in that file — which is what makes a comment answerable
years later. Non-goals are hard boundaries: if a task seems to require crossing
one, propose a decision and stop.

**CI is the gate, and an absent run is a red one.** A clean tree is not a green
build. Session start-up establishes that a run exists for the current head of
`main` before reading what it said, and reads every workflow that gates `main`,
not only `ci.yml` — `security.yml` exists precisely to go red when nothing in
this repository has changed. Absence is the stronger signal, not the weaker one:
a red run says one job broke; no run says nothing was checked at all. A red
`main` is fixed before any new work starts — not noted, not carried, fixed.

**Documentation rides with the change that moved the surface.** Nothing is done
until `make docs` is clean; `llms.txt` and `llms-full.txt` are regenerated and
committed with it; and every new command, flag, `kelyfos.toml` key or MCP tool
has a cookbook recipe that CI executes.

**Verified by somebody who did not write it.** No change touching the flight
recorder, the egress proxy, the team broker or a renderer lands until someone
who did not write the diff has reviewed it *adversarially* — trying to make it
wrong rather than confirming it is right — and **against the source rather than
against the description**. The reviewer reports; the author fixes; the reviewer
does not push, because authorship and verification stop being separate the
moment the same hand does both. Findings are recorded including the ones
rejected and why: a review that records only what it changed is indistinguishable
from one that found nothing. `make test`, `make vuln` and every fuzz target the
change touched are part of the review, run by the reviewer rather than taken on
the author's word.

**The four checklists.** Which one applies depends on what the change touches.

- **RECORD** — a field appended and never inserted; every new field clippable,
  slices included; a `schema.go` row and a generated reference; the
  door-enumerating test; no secret value reachable by any path; and a real
  session's chain still verifying end to end.
- **PROXY** — no new plaintext path; the value never inside the guest; the CA
  never persisted; every decision recorded with its reason.
- **BROKER** — no path that reaches a peer without an edge; every refusal
  recorded; ACLs evaluated before the effect and not after it; caps enforced
  rather than reported.
- **RENDER** — contextual escaping on every value; `template.HTML` nowhere but
  the chain blob; every SVG attribute a number computed in Go;
  `proto.SafeText` on every terminal path; output bounded, and saying so when it
  truncates.

## Reporting a security issue

Do not open a public issue. KelyfOS is at v0.9, and it does make security
claims now: the VMM runs under the jailer with its own syscall filter read out
of `/proc` and refused if absent, and everything the guest's supervisor spawns
is confined by Landlock and a seccomp refusal list.
[`docs/threat-model.md`](docs/threat-model.md) states what is and is not
defended, and [`docs/hardening.md`](docs/hardening.md) §5 is the longer list of
what remains reachable.

[`SECURITY.md`](SECURITY.md) has the reporting channel, what to include, and —
the part worth reading first — which findings are in scope and which are
documented design decisions this project already publishes.

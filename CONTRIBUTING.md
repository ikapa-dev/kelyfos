# Contributing to KelyfOS

Thanks for looking. KelyfOS is Apache-2.0 licensed (see [`LICENSE`](LICENSE)),
and every contribution needs a Developer Certificate of Origin sign-off.

## Before you write code

[`PLAN.html`](PLAN.html) is the single source of truth: scope, non-goals,
architecture, the numbered task list, and the decision log. Read it first.

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
`tools/check-plan.py` over `PLAN.html`, `make docs` compared against the
committed reference, and every cookbook recipe extracted and parsed.

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

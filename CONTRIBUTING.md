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
limactl shell kelyfos-dev -- make
```

External component versions are pinned in [`versions.mk`](versions.mk). Nothing
floats. Bumping one means changing the version and its checksum in the same
commit, with the reason in the progress log.

Keep commits small and reference the task ID they belong to:

```
P1-6: exec over vsock
```

## Reporting a security issue

Do not open a public issue. KelyfOS is pre-v0.1 and makes no hardened-security
claims yet — host hardening (jailer) and guest hardening (seccomp/Landlock) are
phase 4 work, and `docs/threat-model.md` will state plainly what is and is not
defended. Until a security contact is published, raise concerns privately with
the maintainer.

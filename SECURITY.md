# Security policy

KelyfOS is a guest operating system for Firecracker microVMs: a sandbox an AI
agent reaches only through tools, with deny-all egress, credentials kept outside
the VM, and a host-written audit record. It is a **single-host developer tool**,
not a multi-tenant platform, and that distinction decides most of what follows.

Two documents matter more than this one for judging whether something is a
finding: [`docs/threat-model.md`](docs/threat-model.md) says what is defended
and what is not, and [`docs/hardening.md`](docs/hardening.md) §5 is the longer
list of what remains reachable after v0.9's hardening.

## Reporting

**Use GitHub's private vulnerability reporting** — the *Report a vulnerability*
button under this repository's **Security** tab, which opens a private advisory
only the maintainer can see:

<https://github.com/p4r4n0rm4l/KelyfOS/security/advisories/new>

> **If that button is not there, the channel has not been enabled yet.** It is a
> single repository setting and it is the maintainer's to turn on. Until it is,
> open a public issue containing **only** the sentence *"I have a security
> report and need a private channel"* — no details, no reproducer, no version.
> That is a coordination request, not a disclosure, and it is the least-bad
> option while there is no private door. Do not put the finding in a public
> issue.

There is no published email address, deliberately: an address in a public file
is a permanent spam target and this project would rather point at a channel
GitHub authenticates than at an inbox.

### What to include

- What you can do that you should not be able to do, stated as an outcome —
  "a process inside the guest read the bound token", not "Landlock is misconfigured".
- The version: `kelyfos version`, and the guest's, which the boot line prints as
  `supervisor <version>`.
- Whether the run was jailed. `kelyfos run --no-jail` disables the jailer by
  design and says so on every run, so a finding that depends on it is a
  different finding.
- A reproducer, ideally a `kelyfos.toml` and a command line.
- The flight recorder chain if you have one — `kelyfos log --export` produces a
  self-contained report.

### What happens next

I will acknowledge the report, tell you whether I think it is a vulnerability
and why, and — if it is — fix it and credit you in the release notes unless you
would rather I did not.

**No response time is promised here**, because this is a solo project and a
number nobody can keep is worse than no number. What is promised is that a
report will not be ignored, and that you will be told plainly if I disagree that
it is a finding.

## Supported versions

The most recent release is the supported one. There is no long-term-support line
and there are no backports: a fix ships in the next release. Nothing older than
the latest tag receives security fixes.

This is a `v0.x` project moving toward `v1.0`, and the support commitment above
is deliberately minimal until the compatibility promise exists to say more.

## What is a vulnerability here, and what is not

This project publishes what it does *not* defend, which makes the boundary
unusually crisp. Please check the list below before writing a report — not to
discourage one, but because the interesting findings are the ones that cross a
line this project claims to hold.

### In scope

- A path from inside a guest to the host that does **not** require a Firecracker
  or KVM zero-day — through the vsock channels, the supervisor's own protocol
  handling, the egress proxy, or the workspace machinery.
- Any way for code inside a guest to obtain a bound secret's **value**. The
  guarantee is that the value never enters the guest; the proxy attaches it on
  the way out.
- Any way for a guest to write, alter, delete or forge entries in the flight
  recorder, or to make a hash chain verify over a record that was tampered with.
  The record is written by the host precisely so the guest cannot flatter it.
- Egress reaching a destination the policy did not allow, or a credential being
  attached to a host it was not bound to.
- One agent in a team reaching another other than through the host broker, or a
  message crossing an edge the team's edge list does not declare.
- A resource cap that can be exceeded from inside the guest, where the docs say
  the host enforces it.
- A refusal that is reported as success, or a record that overstates the walls
  that were actually around a run — an unjailed run recorded as jailed, an
  unconfined guest recorded as confined.

### Not a vulnerability

These are documented design decisions. Reporting one is not a waste of anybody's
time, but it will be answered with a link rather than a fix.

- **An agent is root inside its own guest.** There is no user separation inside
  a KelyfOS sandbox and there never has been. `rm -rf /` inside a sandbox is a
  sandbox doing its job.
- **Escaping the chroot is not escaping the boundary.** The VM is the boundary;
  the jailer is depth behind it. Anyone who tells you a chroot is a security
  boundary is selling something.
- **The VMM runs as the invoking user**, not a dedicated account (decision D29),
  so a VMM escape reaches that user. This is priced and revisitable, and it is
  written down.
- **Anything the policy permits.** A sandbox allowed to reach `api.github.com`
  with a token bound to it can do whatever that token can do. The credential
  binding is a *suffix* match, so `--secret T@github.com` also covers
  `api.github.com` — bind narrowly.
- **`--no-jail` turns the jailer off.** It exists for machines that cannot grant
  the jailer passwordless sudo, it prints what is not enforced on every run, and
  it records `jailed: false` in the chain.
- **A guest image or snapshot made before v0.9 has no guest confinement.**
  Restoring a snapshot does not upgrade the guest inside it. The host warns
  about this every time rather than refusing, because the host walls are
  unchanged.
- **Side channels** — timing, cache, speculative execution — between guests or
  between a guest and its host. KelyfOS inherits Firecracker's position and adds
  nothing.
- **The supply chain, for now.** Release artifacts are checksummed but not yet
  signed or attested, and the build is not yet reproducible. Both are open work
  rather than an oversight, and both are tracked in
  [`PLAN.html`](PLAN.html). A report that the artifacts are unsigned tells us
  something we say ourselves, in four places.
- **Anything that requires already having code execution as the invoking user on
  the host.** At that point the sandbox is not the boundary that failed.

## Research is welcome

Poking at this is the point. If you are working in good faith against your own
machine and your own sandboxes, you are doing what the project wants — the
threat model exists so that claims can be *checked* rather than believed. Please
do not test against other people's hosts, and please do not publish a finding
before there has been a chance to fix it.

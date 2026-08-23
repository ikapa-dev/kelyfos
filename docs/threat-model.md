# KelyfOS threat model

**Status:** current as of v0.5. This document is a launch gate (P3-5) and is
meant to be read before anyone trusts KelyfOS with anything.

Its job is to be honest about the shape of the protection, including where it
stops. **KelyfOS is not hardened yet.** Host hardening (the Firecracker jailer)
is P4-1 and guest hardening (seccomp, Landlock) is P4-2, and neither is done.
Until they are, the accurate description is *isolation-first architecture*, not
*hardened*.

---

## 1. What KelyfOS is for

Running code you did not write and cannot fully predict — code an AI agent
generated, or a repository an agent was pointed at — with a boundary you can
reason about and a record you can check afterwards.

The design assumption is that **anything inside the guest may be hostile**.
Not "might have a bug": actively working against you, because a prompt-injected
agent is an attacker with your tools in its hands.

## 2. Assets, in the order they matter

1. **Credentials.** A token that reaches an agent is a token that can be
   exfiltrated. This is the asset the architecture is bent around.
2. **The host.** Your laptop or server, and everything else on it.
3. **Other sandboxes.** One compromised sandbox must not reach another.
4. **The audit record.** If it can be edited, it proves nothing.
5. **Your source code.** Whatever is in `--workspace`.

## 3. What KelyfOS defends against

### Agent-generated code doing damage
The guest is a Firecracker microVM: a separate kernel behind hardware
virtualisation, not a namespace. Escaping it means a hypervisor break, not a
container misconfiguration. The root filesystem is read-only with a tmpfs
overlay, so changes die with the sandbox unless they were made in `/work`.

### Exfiltration over the network
Egress is **off by default** — a sandbox with no `--allow` has no network
interface at all. Not a firewalled one: none. There is no rule that has to hold
for the guarantee to be true.

With `--allow`, the guest gets a point-to-point TAP whose nftables rules permit
exactly one destination: a proxy on the host. No NAT, no forwarding. The proxy
enforces a hostname allowlist and ports 80/443, and **the guest has no DNS at
all** (decision D16) — the proxy resolves. That last point closes DNS
tunnelling, which otherwise defeats any hostname allowlist completely, because
the data leaves inside query names to a resolver you explicitly permitted.

### Credential theft from the guest
With `--secret NAME@domain`, the value stays on the host. The proxy terminates
TLS for that domain only, attaches the credential, and forwards. `env` in the
guest shows nothing; there is no file to find. An agent that is fully
compromised can still *use* the credential against the domain it is bound to —
that is what binding it means — but it cannot read it, keep it, or send it
anywhere else.

### Tampering with the record
Every event is written by the **host**, never the guest, and each carries the
previous event's hash. A guest that could write its own audit trail could write
a flattering one, so it cannot write one at all. A small class of events
*transcribes* something the guest reported — the OOM killer running is the only
one today — and those are marked `"source": "guest"` in the schema so a reader
can weigh them differently. The host still writes them; it just did not witness
them.

### One agent reaching another, in a team
A team is several sandboxes on one host, and **no guest ever has a network path
to another guest**: there is no route, no shared bridge and no address to try.
Every message goes through a host broker that checks it against the edge list
you declared and records it either way, refusals included. Three things follow
that are worth saying out loud, because a team is a *deliberate* data path
between sandboxes and §2 otherwise reads as forbidding one.

- **The edge list is the boundary, not the network.** A team is usually a set
  of differently-privileged machines: one agent holds the credentials and the
  others do not. Those credentials are one edge away from every agent that
  cannot reach the network, so a mis-drawn edge is a credential mistake and not
  a routing one.
- **The team store defaults to shared.** A key that no `[[team.store.key]]` rule
  matches is readable and writable by the whole team. Unwritten policy means
  shared state; the byte limits (1 MiB a value, 64 MiB a team) are footgun
  bounds, not security ones. Every access is recorded, permitted or not.
- **A spawn budget is a standing authorisation.** An agent granted one can make
  new microVMs while the run lasts, bounded by the count, image whitelist and
  lifetime written down beforehand. No tool can grant or widen a budget, an
  empty image list permits nothing rather than everything, and a spawned worker
  gets no egress, no secrets and no workspace at all.

The broker itself is host-side code parsing frames from untrusted guests, so a
bug in it is a host-side bug any team member can reach. What limits that is that
the sender's identity is supplied by the host from the socket it accepted on and
never read from the guest's frame, mailboxes are small, and delivery is
at-most-once — so a chatty agent cannot make the host buffer without bound.

## 4. What KelyfOS does NOT defend against

This section matters more than the one above.

### Host-side attacks before the jailer (P4-1)
Firecracker currently runs as your user, unconfined. A Firecracker
vulnerability, or a bug in the KelyfOS CLI, gets the attacker your user account.
The jailer — chroot, cgroups, dropped privileges, seccomp on the VMM — is
Phase 4 and is not done. **This is the largest open gap.**

### A compromised guest is unconfined *inside* the guest
There is no seccomp or Landlock profile yet (P4-2). Code in the sandbox runs as
root in its own machine and can do anything a root user can do to that machine.
That is contained by the VM boundary, not by anything inside it.

### TLS termination is a real trade-off (decision D6)
For a domain with a secret bound to it, the proxy decrypts. Consequences you are
accepting:

- **the proxy sees that traffic in plaintext**, so a compromised host process
  sees it too;
- **certificate pinning breaks** for those domains — a client that pins will
  fail, correctly, because there genuinely is something in the middle;
- the ephemeral CA is trusted inside the guest, so anything that can act as that
  proxy address can impersonate the bound domain to the guest.

It is scoped as tightly as the feature allows: the CA is minted per run, lives
only in memory, is never written to disk, and only domains you deliberately
bound a credential to are terminated. Everything else is tunnelled untouched,
and `kelyfos log` records per connection how much the proxy could read, so you
can always prove it: `terminated` for a session it decrypted, `plain` for an
ordinary HTTP request it necessarily parsed, and `tunnelled` only for a
connection it relayed without opening.

### Side channels
No defence is claimed against Spectre-class attacks, cache timing, or any other
microarchitectural channel. Firecracker's own guidance on host configuration
(microcode, mitigations, SMT) applies and KelyfOS does not check it for you.

### Denial of service
A sandbox can spin the CPU, fill its own memory, and exhaust its own disk. v0.4
bounded all of that, and the bounds are real but soft in different ways, so it
is worth being precise about which is which.

`--cpus` and `--mem` are **absolute**: they are the machine's hardware and a
guest cannot allocate a core or a byte the VM was not built with. `disk` and
`scratch` surface as `ENOSPC` — an error the guest sees and may handle, not a
boundary. `cpu_quota`, the two network rates and the two disk rates are
**throttles**: they make an attacker slower and never stop one, because that is
what a rate limit is. `max_runtime` and `idle_timeout` end the run.

Three honest limits on all of it. Every cap is **off unless someone wrote it
down** — the defaults are 2 cores and 512 MiB and nothing else, so an
unconfigured sandbox has only the machine's own size protecting the host. None of them is a
confidentiality or integrity boundary; they bound consumption and nothing more.
And nothing protects against a guest wedging its own kernel, which remains its
own problem and not the host's.

### The shim is an unauthenticated local port
`kelyfos shim` serves an E2B-compatible REST subset, by default on
`127.0.0.1:3000`, and it checks nothing: there is no key, no account and no
authorisation, because it has none to have. While it is running, **any process
on that machine that can reach the port can boot microVMs, list them, kill them,
and read and write arbitrary paths inside a running guest.** That is a local
privilege surface the rest of the CLI does not have, and `--addr` is the only
thing between it and the network.

The sandboxes it creates are policed like any other: since F-D33 the shim reads
`kelyfos.toml`, the caps above apply to them, and each one writes its own flight
recorder. What remains is the port itself, and it is the whole of the exposure —
run it when you need it and stop it when you do not.

### The supply chain of what you run *inside*
`--allow github.com` means the agent can fetch and execute whatever is at
github.com. KelyfOS controls *where* it can reach, not *what comes back*. There
is no package pinning, no signature checking, no content inspection.

### The host's own tooling
Creating a TAP and loading nftables rules requires `sudo`. On a machine where
your user can escalate, so can anything running as your user.

### Snapshots and fork templates are guest memory on disk

A snapshot — and the fork-template cache a team fills (`docs/teams.md` §7) — is
a **memory image of a booted guest**, written under `~/.cache/kelyfos`. Anything
that was in that guest's RAM at the moment it was frozen is in that file.

KelyfOS keeps the directories `0700` and takes the group and world bits off the
image files themselves, so they are private to the user who made them. That is
the whole of the protection: they are not encrypted, and a backup tool or a
shared home directory will carry them wherever it carries anything else.

A fork template specifically is booted with no egress, no bound secrets and no
workspace, and nothing is run inside it before it is frozen — so what it holds
is a freshly booted machine and nothing that came from you. A snapshot *you*
take with `kelyfos snapshot save` is a different matter: whatever the agent had
in memory is in it.

### Data at rest
Snapshots and workspace images are ordinary files on the host with no
encryption. A snapshot contains the guest's entire memory — including anything
the agent was holding at the time.

### Multi-tenancy
KelyfOS is a single-host developer tool. It has no accounts, no authorisation
and no isolation between users of the same machine. Anyone who can run `kelyfos`
can read every session record and attach to every running sandbox.

## 5. Trust boundaries

| Boundary | Enforced by | Status |
| --- | --- | --- |
| guest → host | Firecracker + KVM | active; VMM unconfined until P4-1 |
| guest → network | no NIC, or TAP + nftables + proxy | active |
| guest → credentials | injection at the proxy | active |
| guest → audit record | host-side, hash-chained | active; absent under `kelyfos shim` |
| guest → guest (team) | host broker + declared edge list | active |
| guest → host CPU/RAM/IO | KVM config, cgroup v2, rate limiters | active, and only when configured |
| host process → host | the jailer | **not yet** (P4-1) |
| in-guest process → guest | seccomp / Landlock | **not yet** (P4-2) |

## 6. If you are evaluating KelyfOS

Reasonable today: running untrusted agent code on a machine where you accept
that a Firecracker escape reaches your user account; keeping credentials out of
agent reach; producing a checkable record of what an agent did.

Not reasonable today: multi-tenant hosting; anything where a VMM compromise is
unacceptable; regulated workloads needing encryption at rest; anything relying
on a hardened guest.

## 7. Reporting a vulnerability

Do not open a public issue. See [`CONTRIBUTING.md`](../CONTRIBUTING.md).

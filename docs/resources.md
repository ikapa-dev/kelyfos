# Resource limits

How much machine the agent gets, who decides it, and what actually enforces it.

Everything here is enforced **on the host**. The guest runs untrusted code, so a
limit the guest applies to itself is advisory at best (F-D2) — the same reasoning
that puts the egress proxy on the host rather than a firewall inside the VM.

## The precedence model

Two places set limits, and they do not mean the same thing:

| | role |
| --- | --- |
| `[resources]` in `kelyfos.toml` | **hard ceilings.** The committed policy of the project. |
| CLI flags | **requests within those ceilings.** |

A flag may ask for less than its ceiling. A flag asking for **more** does not
win and does not get silently clamped — the sandbox refuses to boot, naming
both the ceiling and the file and line it came from:

```
$ kelyfos run --cpus 8
kelyfos: --cpus 8 exceeds the ceiling cpus = 2 set at ./kelyfos.toml:6
    lower the flag, or raise the ceiling in the policy file
```

Refusing beats clamping because clamping is a silent lie: the agent would run
with limits nobody asked for and the command line would still read `--cpus 8`.

> **This is a change from v0.3**, where `kelyfos.toml` supplied defaults and any
> explicit flag overrode them. That was the right default-shaped behaviour for a
> policy file that declared *preferences*; it is the wrong behaviour for one that
> declares *limits*. A policy you can override from the command line is not a
> limit, it is a suggestion. `[sandbox] vcpus` / `mem_mib` keep the old
> defaults-only meaning for compatibility (F-D10) — use `[resources]` for
> anything you actually want enforced.

With no `[resources]` section there are no ceilings, and flags behave exactly as
they did in v0.3.

## Units

| key | type | examples |
| --- | --- | --- |
| `cpus` | integer — whole cores the guest sees | `1`, `4` |
| `mem`, `disk`, `scratch` | human size, or a bare byte count | `512M`, `2G`, `1073741824` |
| `cpu_quota` | percentage of **one core's worth** of CPU time | `"50%"`, `"150%"` |
| `net_mbps_rx`, `net_mbps_tx` | megabits per second | `10` |
| `disk_iops` | operations per second | `500` |
| `disk_mbps` | megabytes per second | `50` |
| `max_runtime`, `idle_timeout` | duration | `"60s"`, `"30m"`, `"2h"` |

Sizes accept `K`, `M`, `G`, `T` and are powers of two: `1G` is 1073741824 bytes.
A bare number is bytes. The same grammar parses `--disk 2G` and `disk = "2G"`,
from the same function, so the flag and the file can never drift apart.

**Sizes are binary, rates are decimal.** A `1G` disk is 2³⁰ bytes, because that
is what a size means; a `net_mbps_rx` of 10 is 10 000 000 bits per second and a
`disk_mbps` of 50 is 50 000 000 bytes per second, because that is how a rate is
quoted. The two conventions disagree by 7% and both are correct in their own
context, so the rule is written down rather than left to be inferred.

The four I/O rates have **no CLI flags** — they are `kelyfos.toml` keys only.
Nothing about them is a per-run choice the way `--cpus` is, and a limit with no
flag has no request to check against a ceiling: the declared value is the value.

`cpu_quota` is **absolute, not relative to `cpus`**. `100%` is one core's worth
of CPU time per wall-clock second; `150%` is one and a half. It is not a
percentage of the cores the guest can see, and a quota above `cpus × 100%` is
simply unreachable.

## `cpus` and `cpu_quota` are different questions

This is the distinction most worth understanding, because the two look
interchangeable and are not:

- **`cpus` caps parallelism** — how many cores exist inside the VM. Four cores
  let four threads run at once. It says nothing about how much CPU time they get.
- **`cpu_quota` caps consumption** — how much host CPU time the VM may actually
  burn, whatever it does with its cores.

`cpus = 4` with `cpu_quota = "100%"` gives the guest four cores that together
never exceed one core's worth of work: parallel, but not fast. That combination
is usually what you want for an agent — build systems and test runners assume
several cores and behave badly with one, but you still do not want a runaway
loop eating your laptop.

## What enforces what

Every cap and the mechanism behind it. The mechanism matters: it tells you what
happens at the limit and how hard the limit is.

| cap | enforced by | at the limit |
| --- | --- | --- |
| `cpus` | KVM machine config (`vcpu_count`) | absolute — the cores do not exist |
| `mem` | KVM machine config (`mem_size_mib`) | absolute — the RAM does not exist; the guest OOM-kills, and says so |
| `cpu_quota` | cgroup v2 `cpu.max` on the Firecracker process's own slice — inside the team's, when it is in one | throttled — work slows, nothing fails |
| `disk` | size of the packed workspace block device | `ENOSPC` on writes to `/work` |
| `scratch` | `size=` on the tmpfs backing the overlay upper layer, applied by the guest kernel inside the `mem` cap | `ENOSPC` on writes outside `/work` |
| `net_mbps_rx` / `net_mbps_tx` | Firecracker token-bucket rate limiter on the network device | throttled |
| `disk_iops` / `disk_mbps` | Firecracker token-bucket rate limiter on the block devices | throttled |
| `max_runtime` / `idle_timeout` | host timer in `kelyfos run` | SIGTERM, grace, sync-back, teardown |

Two of these are absolute because they are hardware: a guest cannot allocate a
core or a byte of RAM that the VM was not built with. The throttles are soft by
nature — they make work slower, not impossible — and the two `ENOSPC` caps are
device sizes, which is why a full scratch is an error the guest sees rather than
a limit the host has to police.

`scratch` and `disk` are separate devices and separate budgets. `/work` is the
workspace block device sized by `disk`; everything else the guest writes lands on
the tmpfs overlay sized by `scratch`. Filling one does not affect the other.

`scratch` defaults to 50% of the **guest's** RAM — the Linux tmpfs default,
relative to `mem`, not to host memory. Stated here because it was previously
implied by inheriting the kernel default.

## What is live today

This document is the specification for the whole of resource governance, and
parts of it are still being built. The parser refuses a key it cannot yet
enforce rather than accepting it and doing nothing — a policy file whose limits
are silently inert is the worst possible outcome for a file whose entire job is
limits.

| key | status |
| --- | --- |
| `cpus`, `mem`, `disk`, `cpu_quota` | **enforced**, including the ceiling behaviour above |
| `net_mbps_rx`, `net_mbps_tx`, `disk_iops`, `disk_mbps` | **enforced** (E1-3) |
| `scratch` | **enforced** (E1-5) |
| `max_runtime`, `idle_timeout` | **enforced** (E1-6) |

Every key this document specifies is now enforced, so the machinery that refused
an unenforced key — and named the task it was waiting on — has been retired. A
key this file does not list is still an error, as it always was.

### How the quota is applied

`cpu_quota` needs the Firecracker process to live in a cgroup with `cpu.max`
set, and how KelyfOS gets one depends on the machine:

- **Under a systemd user session** — the usual case on a developer's box — the
  cgroup is requested through `systemd-run --user --scope`. This is not a
  convenience: a login session's own cgroup is root-owned, and moving a process
  into the subtree systemd delegates to you requires write access to the
  *common ancestor* of both, which is also root's. The user manager is the one
  component that legitimately holds that privilege.
- **As root, or where the cgroup is genuinely delegated** (containers, CI),
  KelyfOS creates the cgroup itself and places the process in it at clone time,
  so there is no window in which the process runs uncapped.

Either way the percentage is translated in the CLI, and the resulting `cpu.max`
is **read back and checked** after launch. If the quota did not land, the
sandbox refuses to start rather than running unlimited while claiming a cap.
If neither path is available, `--cpu-quota` fails with the reason.

### When the RAM cap is reached

The `mem` cap is the VM's hardware: the guest cannot allocate a byte the machine
was not built with, and nothing on the host has to police it. What E1-4 adds is
that reaching it is *legible*. The supervisor watches `/dev/kmsg` for the
kernel's OOM-killer line and reports it; the host records a `resource.oom` event
naming the process, its pid and its resident size, and prints:

```
kelyfos: the guest ran out of memory and killed python3 (pid 57, 224 MiB resident
         of a 256 MiB machine)
         raise --mem, or lower what the agent is asked to hold
```

`kelyfos run` then exits **137** — the shell's convention for death by SIGKILL,
which is literally what the OOM killer sent — where it would otherwise have
exited 0. That is the difference between "the agent was killed for using too
much memory" and "the agent crashed", and it is the difference a CI log needs to
show.

PID 1 exempts itself from the OOM killer (`oom_score_adj = -1000`). That limits
nothing; it means the machine survives its own memory exhaustion long enough to
report it. Killing PID 1 is a kernel panic, and a sandbox that vanishes at
exactly the moment it ran out of memory is the least diagnosable outcome
available.

### How the scratch cap is applied

`scratch` sizes exactly one thing: the tmpfs that backs the overlay's upper and
work directories. That is where every write outside `/work` lands, because the
root filesystem itself is read-only. The size travels to the guest on the kernel
command line as `kelyfos.scratch=<bytes>` — the overlay is mounted before any
vsock channel exists to ask over, and the command line is the one thing inside
the guest that the guest did not write.

With no `scratch` key the mount gets no `size=` at all and the guest kernel
applies its own default of half the machine's RAM. That default is deliberately
left to the kernel rather than restated by KelyfOS: a number copied into two
places is a number that will eventually disagree with itself.

At the cap, writes fail with `ENOSPC`, which is an error the program doing the
writing can see and handle. `/work` is a separate block device sized by `disk`
and is completely unaffected; so is `/dev/shm`, which is its own tmpfs with its
own kernel default of half the RAM.

A `scratch` larger than `mem` is refused at boot rather than accepted:

```
kelyfos: scratch = 2147483648 bytes at ./kelyfos.toml:2 is larger than the
         512 MiB the machine has
    the scratch tmpfs lives in that memory, so a cap above it can never be reached
```

**This is the one cap the guest kernel applies rather than the host**, and it is
worth being exact about what that does and does not mean (F-D13). A tmpfs's size
is by construction a property of the kernel that mounts it, and that kernel is
the guest's. A guest determined to defeat the cap can remount with a larger size
— and gains nothing by it, because the tmpfs lives in guest RAM and `mem` is the
VM's hardware. `scratch` is a partition of a budget the host has already fixed,
not a new boundary: it stops an agent filling its own memory with build output by
accident, and it is not a defence against an agent trying to.

### How the time budgets are applied

`max_runtime` is wall-clock from the moment the sandbox starts. `idle_timeout`
is wall-clock since the last thing the sandbox did, which is measured from two
host-side facts and no guest-side ones:

- **the flight recorder grew** — every `exec` and every MCP tool call is
  recorded, whichever process issued it, so the file growing is exactly "a vsock
  RPC happened";
- **a byte crossed the egress proxy** — tracked as bytes move rather than when a
  connection finishes, because a sandbox halfway through a large download is not
  idle and would otherwise look it for as long as the transfer lasted.

A sandbox doing neither is doing nothing the host can see, and the host is the
only side entitled to an opinion about it (F-D2).

When a budget expires the run ends the way a careful `Ctrl-C` would, in this
order: the trailing command gets `SIGTERM` and five seconds to stop itself, then
`SIGKILL`; the VM is shut down; the workspace is synced back; the session record
is closed with `reason: "timeout"`. The audit log gets a `resource.timeout`
event naming which budget fired, its size and how long the run actually lasted.

`kelyfos run` exits **124** — `timeout(1)`'s status, for the same meaning, so a
CI job that already treats 124 as "this took too long" needs no teaching.

The grace period is not politeness. An agent killed outright leaves the
workspace mid-edit, and the sync-back that follows would carry that state to the
host as if it were a result.

Inside a `[team]`, `max_runtime` works per agent and `idle_timeout` is
**refused** — by name and line, at the file, rather than accepted and ignored
(F-D20). A team is deliberately one session with one flight recorder, so "the
recorder grew" is a fact about the whole team: a busy master would keep an idle
worker's clock alive forever and the key would be inert in exactly the case it
was written for. `max_runtime` needs none of that — an agent's wall clock starts
when the host boots it, and the host is holding the clock. The refusal lifts
when the team transcript carries a per-agent activity signal (E2-7).

### How the I/O throttles are applied

`net_mbps_rx` / `net_mbps_tx` become `rx_rate_limiter` / `tx_rate_limiter` on
the guest's network interface; `disk_iops` and `disk_mbps` become a
`rate_limiter` on each block device. These are Firecracker's own token buckets,
applied in the VMM's I/O thread at the point where guest traffic is copied to
the host device — KelyfOS configures them and builds nothing.

Three consequences worth knowing before you tune them.

**The disk limits are per device, not a shared budget.** A Firecracker limiter
belongs to one device, and a sandbox with a workspace has two: the read-only
root and `/work`. `disk_mbps = 10` therefore means ten megabytes a second on
each, not five each. The alternative — one budget split between them — is what
people assume, so it is worth saying that it is not what happens.

**A limit is a rate plus an opening burst, and the burst is about two seconds'
worth.** A token bucket is a size and a refill time, and the rate it enforces is
the ratio; KelyfOS always sizes the bucket at a whole number of seconds' worth
of tokens. The bucket starts full, and Firecracker hands out roughly a second
bucket before the limit begins to bite, so a transfer short enough to fit inside
that burst runs at full speed. Over anything longer the observed rate converges
on the configured one. Measured against a 50 MB download on the dev machine: a
10 Mbps cap took 38.2 s where an uncapped one took 0.13 s, and the steady-state
rate worked out at 9.95 Mbps.

Whole seconds are not an arbitrary choice. A smaller bucket sounds like a
tighter limit and is not: when the bucket empties, Firecracker waits a fixed
100 ms before retrying, so a bucket only a little larger than one request leaves
most of each window unspent. The same 10 Mbps cap with a 125 kB bucket delivered
6.8 Mbps — 32% *under* what was asked for. And a bucket *smaller* than one
request is worse in the other direction: Firecracker charges only the deficit
and forgives the rest, which measured 23% over. One second's worth is the size
that is exactly right, and the window widens past a second only when a second's
worth would be smaller than a single 4 MiB block request — at `disk_mbps = 1`,
for instance, the bucket is 5 MB refilling over 5 s.

**Setting a network rate on a sandbox with no `--allow` does nothing, and says
so.** No network interface is a stricter limit than a throttled one, so this is
not an error; `kelyfos run` prints `net limit not applied — this sandbox has no
network interface` rather than leaving you to infer it from silence.

## A team's collective cap

A `[team]` gets one more level. `[team.resources] cpu_quota` is a cap on the
whole team, applied as a parent cgroup v2 slice with each agent's own slice as
a child of it, so the kernel composes the two ceilings and the host does no
arithmetic (E2-6, F-D21):

```toml
[team]
name = "reviewers"

  [team.resources]
  cpu_quota = "200%"      # two cores' worth for all the agents together

[[team.agent]]
name = "master"
  [team.agent.resources]
  cpu_quota = "150%"      # and no more than 1.5 on its own
```

`cpu_quota` is the only key `[team.resources]` takes, because it is the only cap
the kernel will divide: cores, RAM and disk are handed to each agent at boot as
that machine's hardware, and no parent can pool them afterwards. A per-agent key
written at team level is refused with a message saying where it belongs.

Every agent's slice also carries `cpu.weight = 100` — an equal share of whatever
the parent's ceiling leaves. The ceiling/share distinction is the same one this
document draws between `cpus` and `cpu_quota`, one level up: `cpu.max` binds on
an idle machine, `cpu.weight` only decides anything when siblings contend.

The **sum of the agents' quotas may exceed the team's**, deliberately: each may
burst to its own ceiling while the others idle, and the parent holds the total.
That is the mirror of the disk limits being per device rather than a shared
budget — stated because a reader will otherwise assume the arithmetic is
checked. A *single* agent asking for more than the whole team is refused, since
a ceiling written above another ceiling and then ignored is a number that would
later be trusted.

`docs/teams.md` §6 has the full account, including how the cap is applied under
a systemd user session.

## Example

```toml
[sandbox]
image = "dev"
allow = ["github.com"]

[resources]
cpus        = 4          # four cores exist inside the VM
cpu_quota   = "150%"     # ...but together they burn at most 1.5 cores' worth
mem         = "2G"
disk        = "4G"       # /work device size
scratch     = "512M"     # everything written outside /work
net_mbps_rx = 50
max_runtime = "30m"
```

An agent given this can compile in parallel, cannot pin the machine, cannot fill
the disk, and cannot run past half an hour.

## Seeing the limits hold

`kelyfos watch` carries a resources lane showing live consumption against each
cap:

```
cpu  50.0% of 60% quota · mem 122 MiB of 512 MiB · net 3.0 MiB in / 1 KiB out
(cap 10/0 Mbps) · disk 40.0 MiB written
```

CPU is a rate, so it needs two readings; the first tick shows the machine's
shape and no percentage rather than a number it has not measured yet. Once the
sandbox stops there is nothing left to sample and the lane shows the recorded
receipt instead.

Every session ends with a `resource.summary` event in the flight recorder — CPU
seconds, peak RSS, bytes in and out, disk bytes written, each alongside the cap
it was consumed under — which `kelyfos log --export` renders as a receipt. Both
the lane and the receipt read the same host-side counters: cgroup `cpu.stat` and
`memory.current` when the sandbox has a cgroup, `/proc/<pid>` when it does not,
the TAP's own byte counters, and `/proc/<pid>/io` for storage. The guest is never
asked.

Limits that fire leave their own audit events: `resource.oom` when the guest
OOM-killer runs, `resource.timeout` naming which budget expired.

That is the point of enforcing host-side: the record of what the sandbox
consumed is written by the same side that imposed the limits, so it is worth
something.

## Proving it

```
bash dev/prove-caps.sh
```

Drives CPU, memory, disk, network, scratch and time past their limits with
`stress-ng` and `dd` inside the guest, and checks from the host that each one
held — `/proc/<pid>/stat` and the sandbox's own `cpu.stat`, `/proc/<pid>/io`,
the TAP's byte counters, the flight recorder. It prints what it measured, not
just whether it liked it.

Two things it does deliberately. Bandwidth is reported **gross and steady**, and
asserted on steady: a bucket starts full and a short transfer measures the
opening burst rather than the cap. And a cap that was never approached is
reported as a skip rather than a pass — on a nested host the uncapped run
reaches about one core's worth against four stressors on four vCPUs, so there is
nothing there to cap, and saying so is the only honest result available. The
`caps` workflow runs the same script on a bare-KVM runner, which is the
environment D15 makes binding.

```
bash dev/prove-team.sh
```

The same idea one level up: five agents under a `[team.resources] cpu_quota` of
`200%`, all running `stress-ng` at once, measured from the parent slice's own
`cpu.stat`. It asserts four things rather than one — that the cap held, that the
kernel actually had to throttle somebody (a cap never approached reads exactly
like a cap that held), that the children's CPU time adds up to the parent's
(five unrelated cgroups would not), and that every child's `cpu.weight` is 100.
Then it takes the team down and checks the slice went with it.

`bash dev/accept-e1.sh` runs Epic E1's acceptance list the same way.

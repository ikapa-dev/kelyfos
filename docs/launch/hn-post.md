# Launch post — draft (not posted)

Submission is the maintainer's action, not the build's. This file is the text,
ready to paste. It tracks the repo: the numbers below are the ones the CI
benchmark last published, and they get re-checked before the post goes out. The
run ids are recorded beside each figure below and in PLAN.html's progress log,
which is where to look if a number is challenged.

Current as of **v0.9** (hardening: the jailer, the VMM's own syscall filter
proved in force, and per-flavor guest confinement). The numbers below come from
the CI runs named beside them and were re-measured for this release, because the
jailer and both filters sit on the boot path and a bar is never assumed across a
change of security posture.

---

## Hacker News

**Title** (80 char limit — this is 74):

    Show HN: KelyfOS – a Firecracker guest OS that only speaks MCP to the agent

**URL:** https://github.com/p4r4n0rm4l/KelyfOS

**First comment** (post immediately after submitting):

> Every agent-sandbox product I looked at builds an excellent control plane and
> then boots a generic Ubuntu inside it. The guest is an afterthought. I wanted
> to see what happens if you treat the guest as the product instead.
>
> KelyfOS is a Buildroot image whose PID 1 is an MCP server. There is no shell
> login, no SSH, no getty. An agent attaches over vsock and sees six tools —
> exec, read_file, write_file, list_dir, upload, download. That is the entire
> surface.
>
> Four things fall out of that which I think are more than repackaging:
>
> **Egress is off, not filtered.** A sandbox with no `--allow` has no network
> interface at all — no TAP device is created. The guarantee doesn't depend on
> a rule being correct, because there is nothing to write a rule about. Adding
> `--allow github.com` creates the interface and an nftables table scoped to
> that VM. There is deliberately no DNS in the guest: name resolution happens
> on the host, inside the proxy, so the allowlist is enforced on the name the
> agent actually asked for rather than on an IP it could have obtained anywhere.
>
> **Secrets never enter the VM.** `--secret GITHUB_TOKEN@api.github.com` keeps
> the value on the host. The proxy terminates TLS for exactly the domains a
> secret is bound to, attaches the header, and tunnels everything else opaquely.
> `env` inside the sandbox shows nothing. A prompt injection that talks the
> agent into exfiltrating its credentials finds none to exfiltrate — though it
> can still *use* them against the bound domain, which is the honest limit of
> the design.
>
> **The audit record is written by the host.** A guest that could write its own
> log could write a flattering one, so it cannot write one at all. Every event
> is hash-chained JSONL, and `kelyfos log --verify` checks the chain. Every way
> in writes it — the CLI, the MCP bridge, and the E2B-compatible shim — because
> an entry path that skips the record is a hole rather than a shortcut. It is
> tamper-evident, not tamper-proof, and the docs say so.
>
> **A team is an edge list, not a network.** v0.5 added a `[team]` section to
> the project's toml: you declare the agents and the edges between them, and
> `kelyfos team up` boots the graph — docker-compose for agent teams. The part
> that needed a guest OS to do properly is that *no guest ever has a network
> path to another guest*. Every inter-agent message transits a host broker over
> the existing vsock channels, is checked against the edge list, and lands in
> the same hash-chained record — including the refusals. The agents see seven
> more tools (`team_send`, `team_recv`, `team_ask`, `team_reply`, `team_peers`,
> `team_store_get`, `team_store_put`), plus a `team_spawn` that is only shown to
> an agent you actually granted a spawn budget. The reasoning about who
> delegates what stays in your agent framework; this is only the substrate.
>
> Boot-to-ready is 135 ms median (p95 149 ms) and snapshot restore 49 ms (p95 51),
> both x86_64 on a bare-KVM CI runner, 10 runs each — the benchmark is a
> workflow in the repo, not a number I typed (bench run 32715343990). A
> five-agent team comes up in 412 ms with all five cold and 286 ms once a fork
> template is cached (caps run 32715397107, one run of the five-agent graph in
> the repo rather than ten). `kelyfos fork -n 4` gives you
> four divergent copies of one prepared machine; each gets fresh entropy and a
> corrected clock on resume, because four VMs restored from one memory image
> otherwise share a random pool, which is a genuinely bad way to generate a key.
>
> That team number has a story I'd rather tell than hide, because it is the
> thing I actually learned. The first design forked the workers from a snapshot,
> which is much faster than booting them on my laptop. On the reference runner
> it measured 1098 ms against a 1 s bar — missed — and when I broke the number
> down, 927 ms of it was writing the template's memory image once, while a cold
> boot on that machine costs 109–134 ms. So the fast path was the reason the bar
> was missed, and five plain concurrent boots would have sailed under it. The two
> costs scale in opposite directions: my dev box is slow to boot and fast to
> write, the CI runner is the reverse. The fix was to boot cold by default, cache
> the template in the background, and fork only when the cache is warm — 366 ms
> and 215 ms were the two paths after that change. Both runs are in the repo with
> their CI ids (32630824099 for the miss, 32632420532 for the re-measure) and the
> 1098 ms is still in the log where it was written. A benchmark you only publish
> when it flatters you is marketing.
>
> Two of those numbers have moved since, both for reasons worth stating. The
> build system went to Buildroot's supported LTS line, which only carries kernel
> headers to 6.12, so the guest kernel went back from 6.18 — costing about a
> third of the boot time and buying a build system whose maintainers support it
> until 2028. And the hardening below sits on the boot path: the jailer and
> probing the guest's profile cost about 12 ms each way. Reading the VMM's filter
> out of /proc happens after boot-to-ready has been taken, so it is deliberately
> not in that number. Both targets — 300 ms cold, 100 ms restore — still hold with room,
> and the numbers above are the ones measured after those changes rather than the
> ones from before them.
>
> Every release before this one said "not hardened yet", and it was true: the VM
> boundary was the whole of it. v0.9 adds the two layers that sentence was
> waiting on. Firecracker runs under the jailer — a chroot holding only that
> sandbox's files, a dropped uid, its own cgroup — on every entry point or none.
> Its own seccomp filter is read out of /proc on every one of its threads at
> boot, and a VMM without one is refused rather than run; I pulled the installed
> BPF program back out of the kernel with ptrace and decoded it, and what it
> permits agrees syscall for syscall with the JSON Firecracker publishes, on both
> architectures. Inside the guest, every process the supervisor spawns is
> confined by Landlock and a 28-syscall refusal list, declared per flavor.
>
> What that is not: an agent is still root inside its own guest, and the profile
> narrows what root can ask the kernel for without making the kernel smaller. The
> chroot is not the boundary — the VM is — and the VMM drops to your uid rather
> than to a dedicated account, so it could still signal your other processes.
> Side channels and the supply chain are untouched. A snapshot or a cached fork
> template is still a guest's RAM sitting in a file under your home directory
> with nothing but file permissions on it, and a snapshot taken before v0.9
> restores into the guest it captured — which has none of the above, and says so
> on the terminal. The README carries that list beside the enforced one, and
> docs/threat-model.md is the long version.
>
> The whole thing was built in the open against a plan file that doubles as the
> status tracker; PLAN.html in the repo has every decision and a progress log
> with the actual command output behind each claim, including the mistakes.
> Happy to go into any of it.

---

## Notes for the poster

- Best window is a weekday morning US Eastern. Do not post and walk away —
  the first hour of replies decides the thread.
- Re-run `make bench` (or check the newest `bench.yml` run) before posting and
  fix the four numbers in the comment if they moved: cold boot, restore, and the
  cold/warm team-up pair, and update the run ids beside them.
- Expect these four questions; the answers are all in the repo:
  1. *"Why not just gVisor / a container?"* → the guarantees here are about
     what the guest **can express**, not just what the kernel blocks. A
     container can't have "no network interface exists" as a default and still
     be one command from having one.
  2. *"TLS termination means you MITM my traffic."* → only for domains a secret
     is explicitly bound to, the CA is generated per-run and never persisted,
     nothing but the trust anchor enters the guest, and every egress event
     records how much the proxy could read — `terminated` for a session it
     decrypted, `plain` for an ordinary HTTP request it necessarily parsed,
     `tunnelled` only for one it relayed unopened — so you can prove which was
     which. docs/networking.md documents the cert-pinning limitation.
  3. *"135 ms is just Firecracker's number."* → Firecracker's own claim is about
     the VMM; this is measured to guest-ready over vsock, which includes init,
     mounts, the overlay and the MCP listener binding. The harness is in the repo.
  4. *"Isn't multi-agent just orchestration you said you wouldn't build?"* →
     the non-goal was renegotiated in writing before any code (PLAN-FEATURES.html
     F-D3) and narrowed rather than dropped: single-host, user-declared
     topologies with host-enforced edges are in; multi-host scheduling, hosted
     control planes and autoscaling stay permanently out. KelyfOS enforces a
     topology you wrote down. It does not decide anything about your agents.
- Do not editorialise the security posture upward in replies. The threat model
  is the answer, and it is deliberately unflattering.
- Independent validation, fair to cite if the premise itself is challenged
  ("why put the policy in the OS?"): Microsoft's Azure SRE Agent architecture
  post, "Stop restricting the agent. Start restricting its environment"
  (commandline.microsoft.com, 2026-08-21). It reaches the same conclusion from
  production — agent code in isolated microVMs, the policy machinery outside the
  agent's reach, credentials that never enter the sandbox — which is the exact
  shape of this project, arrived at independently and at a scale this one will
  never see. Cite it as convergent evidence that the environment is the right
  place to put the policy, not as an endorsement of KelyfOS; they have never
  heard of it. Two things they do that KelyfOS does not are parked in
  PLAN-FEATURES.html §4 (per-call credential handles, output-side secret
  scrubbing) — mention them as known gaps if someone asks, rather than being
  caught not knowing.

# Launch post — draft (not posted)

Submission is the maintainer's action, not the build's. This file is the text,
ready to paste. Update the boot number if the benchmark moves before launch.

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
> Three things fall out of that which I think are more than repackaging:
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
> is hash-chained JSONL, and `kelyfos log --verify` checks the chain. It is
> tamper-evident, not tamper-proof, and the docs say so.
>
> Boot-to-ready is 90 ms median (p95 95 ms) and snapshot restore 29 ms (p95 35),
> both x86_64 on a bare-KVM CI runner, 10 runs each — the benchmark is a
> workflow in the repo, not a number I typed. `kelyfos fork -n 4` gives you four
> divergent copies of one prepared machine; each gets fresh entropy and a
> corrected clock on resume, because four VMs restored from one memory image
> otherwise share a random pool, which is a genuinely bad way to generate a key.
>
> What it is not, yet: the Firecracker jailer and guest seccomp/Landlock
> profiles are not done. Calling it "hardened" today would be a lie, so the
> README calls it isolation-first and docs/threat-model.md is explicit about
> the gaps — including that the host-side supervisor is currently the largest
> one.
>
> The whole thing was built in the open against a plan file that doubles as the
> status tracker; PLAN.html in the repo has every decision and a progress log
> with the actual command output behind each claim, including the mistakes.
> Happy to go into any of it.

---

## Notes for the poster

- Best window is a weekday morning US Eastern. Do not post and walk away —
  the first hour of replies decides the thread.
- Expect these three questions; the answers are all in the repo:
  1. *"Why not just gVisor / a container?"* → the guarantees here are about
     what the guest **can express**, not just what the kernel blocks. A
     container can't have "no network interface exists" as a default and still
     be one command from having one.
  2. *"TLS termination means you MITM my traffic."* → only for domains a secret
     is explicitly bound to, the CA is generated per-run and never persisted,
     nothing but the trust anchor enters the guest, and every egress event is
     recorded as terminated or tunnelled so you can prove which was which.
     docs/networking.md documents the cert-pinning limitation.
  3. *"90 ms is just Firecracker's number."* → Firecracker's own claim is about
     the VMM; this is measured to guest-ready over vsock, which includes init,
     mounts, the overlay and the MCP listener binding. The harness is in the repo.
- Do not editorialise the security posture upward in replies. The threat model
  is the answer, and it is deliberately unflattering.
- Independent validation worth citing if the premise is challenged: Microsoft's
  Azure SRE Agent architecture post, "Stop restricting the agent. Start
  restricting its environment" (commandline.microsoft.com, 2026-08-21). It
  reaches the same conclusion from production — agent code in isolated
  microVMs with the policy machinery outside the agent's reach, and credentials
  that never enter the sandbox — which is the exact shape of this project.
  Cite it as convergent evidence that the environment is the right place to put
  the policy, not as an endorsement of KelyfOS; they have never heard of it.
  Two things they do that KelyfOS does not are parked in PLAN-FEATURES.html §4
  (per-call credential handles, output-side secret scrubbing) — mention them as
  known gaps if someone asks, rather than being caught not knowing.

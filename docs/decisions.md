# Decision log — the build plan

Every irreversible or contested choice made while building KelyfOS, with the
reasoning that produced it. The source comments cite these by number: a `D44` in
a comment means the row below, and 115 of this repository's Go files carry at
least one such citation.

These were kept in `PLAN.html`, the working status tracker, which is not part of
this repository — it is a process document, not a product one. The decisions
are, because the code points at them.

Numbering is historical and has one gap: **D48 was never issued.** A `D48` you
find in a comment is `F-D48`, in [the feature decisions](decisions-features.md).


## Index

- [D1](#d1) — Build the guest image + single-host CLI; explicitly not a kernel, VMM, control plane, or hos…
- [D2](#d2) — Buildroot for v0.x; revisit a Nix flake in phase 4
- [D3](#d3) — Go for supervisor and CLI
- [D4](#d4) — "agos" is a working title
- [D5](#d5) — License: Apache-2.0, with DCO sign-off required on all contributions from day one
- [D6](#d6) — TLS strategy: option (a), a TLS-terminating proxy with a per-install KelyfOS CA in the guest…
- [D7](#d7) — Monitoring = readers of the flight-recorder JSONL only: HTML session export (P3-8) and termi…
- [D8](#d8) — Daily-driver and trust features adopted: workspace block-device sync (P3-10), kelyfos doctor…
- [D9](#d9) — Dev machine = MacBook Pro M5 Max / 64 GB: macOS 15+ → Lima (vz, nested virtualization) → Lin…
- [D10](#d10) — Project named KelyfOS — κέλυφος (kélyfos), "shell"
- [D11](#d11) — Version policy fixed at P0-6: Buildroot 2026.02.3 (the yearly .02 long-term-supported line,…
- [D12](#d12) — Guest kernel configuration strategy for P1-2: the base is Firecracker's own reference guest…
- [D13](#d13) — AF_VSOCK in Go is wrapped by hand in internal/vsock — a small net.Conn and net.Listener over…
- [D14](#d14) — The guest kernel is trimmed well past Firecracker's reference config, and the cuts are a sec…
- [D15](#d15) — Boot-time numbers measured under nested virtualisation are informational only
- [D16](#d16) — The guest gets no DNS at all
- [D17](#d17) — P3-3 (the dev flavor) is pulled forward to run before P2-6's verification and P2-7
- [D18](#d18) — P2-7 is completed in two stages, both required: (1) protocol interop — the official MCP Pyth…
- [D19](#d19) — The P3-1 resync design is endorsed as written and must not be simplified later: mix host-sup…
- [D20](#d20) — The README quickstart installs a prebuilt image from the GitHub release; building from sourc…
- [D21](#d21) — Every built or fetched image carries an image.json manifest, and the sandbox refuses to boot…
- [D22](#d22) — kelyfos snapshot restore re-creates the egress path and re-pairs the guest's NIC to a fresh…
- [D23](#d23) — kelyfos run [flags] -- <command> runs that command on the host for the lifetime of the sandb…
- [D24](#d24) — CI build economics, settled as one change: a documentation-only change skips the build and b…
- [D25](#d25) — Parked, not taken: the move to Bubble Tea v2 and Lip Gloss v2
- [D26](#d26) — D25 is discharged: the Bubble Tea v2 / Lip Gloss v2 move is declined, not deferred again
- [D27](#d27) — P4-1 and P4-2 are promoted into a new Phase 5, hardening, exiting at v0.9 — and nothing else is
- [D28](#d28) — Buildroot moves to the LTS line and the guest kernel moves back to 6.12, because the LTS lin…
- [D29](#d29) — The jailed VMM drops to the invoking user, not to a dedicated account — and the acceptance i…
- [D30](#d30) — A regression found by one task becomes a task of its own, not a line in somebody else’s comm…
- [D31](#d31) — The guest profile is a refusal list applied by a re-exec, and the supervisor is not inside it
- [D32](#d32) — A snapshot is a time capsule of the authority it was taken with, and the record has to say s…
- [D33](#d33) — dev does not relax the sibling-ptrace refusal, and the reason is that relaxing it is not a p…
- [D34](#d34) — Phase 6 is opened as “v1.0, the promise”, on the product owner’s instruction, with five pill…
- [D35](#d35) — The Phase 4 disposition: every item gets a verdict, and the two that stay blocked get a revi…
- [D36](#d36) — The per-call credential handle is scoped to the three quarters of it the architecture can ca…
- [D37](#d37) — Output-side secret scrubbing ships as echo suppression, and the general credential recognise…
- [D38](#d38) — Reproducibility is configured and then measured; the word does not enter the documentation a…
- [D39](#d39) — Release artifacts are attested by the platform that builds them, which means the build moves…
- [D40](#d40) — §8 gains rule 9: documentation rides with the task that changed the surface
- [D41](#d41) — The clients kelyfos connect supports: six, chosen from a live survey on 2026-08-24, with the…
- [D42](#d42) — The disclosure channel is GitHub’s private vulnerability reporting rather than a published a…
- [D43](#d43) — The trust boundary for fuzzing is declared as three sources, the runner discovers its target…
- [D44](#d44) — D36 is amended: the credential grammar carries an endpoint and not a method set, the guest’s…
- [D45](#d45) — An independent external security audit is received, and v1.0 does not tag until its trust-bo…
- [D46](#d46) — Seven findings triaged against HEAD, and two of them do not say what the audit said they say
- [D47](#d47) — M-2 and M-5 confirmed, the triage closed at eleven of twenty-three, and the rest blocked on…
- [D49](#d49) — The documentation audit found eighteen defects in the code, and they are routed rather than…
- [D50](#d50) — CHANGELOG.md is the source the release notes are cut from, not a mirror of them
- [D51](#d51) — §1 criterion 5 is re-worded, and backed by a fourteenth acceptance suite that drives HTTP ra…
- [D52](#d52) — A stopped agent keeps its mailbox, and that is left alone rather than repaired
- [D53](#d53) — Immutable releases: ON, and it still never shares a sentence with provenance
- [D54](#d54) — Dependabot security updates: ON, as its own consent
- [D55](#d55) — macOS ships raw and unsigned for v1.0, and says so where somebody will hit it
- [D56](#d56) — The DCO is gated on new commits, and the gap in the history is stated rather than papered over
- [D57](#d57) — The remaining thirteen findings triaged against HEAD: twelve confirmed, one already fixed, a…
- [D58](#d58) — The three Dependabot pull requests are held until v1.0 ships, and the reason is what the rel…
- [D59](#d59) — The declared policy of a run enters the flight recorder, and the views read it
- [D60](#d60) — The “no web dashboard” non-goal is renegotiated, by name, and narrowly
- [D61](#d61) — Retention, pruning and tombstones are adopted as P7-5 rather than left as a papercut
- [D62](#d62) — Phase 7 is worked by several agents in four lanes, which is a deliberate deviation from §8 r…
- [D63](#d63) — §8 gains rule 10: verified by somebody who did not write it
- [D64](#d64) — §8 rule 8 is satisfied by local verification, not GitHub’s CI, while Actions stays disabled…
- [D65](#d65) — P7-4’s second silence — every sandbox reaching ports 80 and 443 only, with egress.Policy.Por…
- [D66](#d66) — P7-4’s first silence, when refused rather than wired in, narrows a §2-stabilised surface (th…
- [D67](#d67) — P7-14 added mid-phase: a real, narrow defect in path-scoped credential matching, found as a…
- [D68](#d68) — The door-enumerating test for session.policy runs two mechanisms, not the one docs/policy-re…
- [D69](#d69) — P7-15 added mid-phase: FuzzAppendFieldValues reproducibly OOM-kills its own worker once its…
- [D70](#d70) — P7-16 added mid-phase: two independent adversarial reviews, in separate worktrees on the sam…
- [D71](#d71) — The twenty-one findings of the independent security review of 2026-08-28 (SECURITY-REVIEW-20…
- [D72](#d72) — P7-17/F19 moves sandbox.json and the paused marker out of the jailer’s chroot, from <base>/f…
- [D73](#d73) — GitHub Actions is disabled at the account level, so P7-17 proceeds on local evidence, bounded
- [D74](#d74) — The 30-second ResponseHeaderTimeout F15 added to both egress transports is raised to ten min…
- [D75](#d75) — kelyfos connect follows a leaf symlink again (P7-17/B1) — and a project-local configuration…
- [D76](#d76) — A serve-mcp whose own audit chain has failed refuses every tool call except the three that o…
- [D77](#d77) — The committed ci.yml now runs here, in a container, and it is the local evidence of record f…
- [D78](#d78) — P7-14 is fixed by refusing a scope path that is not in normal form, not by normalising one —…
- [D79](#d79) — P7-16: a team's host-level state is scoped to the team's own session id, and two teams on…
- [D80](#d80) — P7-15 is a recording-integrity defect and not a fuzz-harness one: the clip loop is made…
- [D81](#d81) — The release SBOM is a document about KelyfOS, and everything in it that KelyfOS did not…
- [D82](#d82) — FuzzAppendFieldValues' seeds stay as they are, because the thing they were going to be…
- [D83](#d83) — D79's deferred class is closed: all fifteen dev/ suites now run against a private…


## D1

*2026-08-21*

Build the guest image + single-host CLI; explicitly not a kernel, VMM, control plane, or hosted service.

**Why:** The only under-served niche in a crowded market; solo-sized; portable across runtimes.

## D2

*2026-08-21*

Buildroot for v0.x; revisit a Nix flake in phase 4.

**Why:** Fastest path to first boot; reproducible-build story can come later with signing/SBOM.

## D3

*2026-08-21*

Go for supervisor and CLI.

**Why:** Single static binaries, trivial cross-compilation, fast iteration. Revisit Rust only if binary size or startup cost becomes a measured problem.

## D4

*2026-08-21*

"agos" is a working title.

**Why:** Collision check is a launch-gate task (P3-7), not a today problem.

## D5

*2026-08-22*

License: **Apache-2.0**, with DCO sign-off required on all contributions from day one.

**Why:** Decided by John, 2026-08-22. KelyfOS is positioned as the portable guest image other runtimes adopt — AGPL would block commercial runtimes from embedding it and fight the distribution strategy. The EU-compliance thread sells services and signed artifacts, not code exclusivity, so it survives under Apache (the Talos / Red Hat model). Matches the ecosystem: Firecracker itself is Apache-2.0. DCO keeps a future relicensing move possible. Executed in P0-7.

## D6

*2026-08-22*

TLS strategy: **option (a), a TLS-terminating proxy with a per-install KelyfOS CA in the guest trust store — applied selectively.** A domain is terminated *only* when a secret is bound to it with `--secret NAME@domain`; every other allowlisted domain gets a plain `CONNECT` tunnel with no MITM. Default posture is therefore "tunnel and log", and termination is opt-in per domain, chosen by the person who binds the credential. Decided by Claude Code at the P2-0 gate after prototyping; implemented in P2-5/P2-6 and documented as a trade-off in P3-5.

**Why:** **Option (b) cannot deliver the product's headline guarantee.** Section 1 and P2-6 both promise that the secret value never exists inside the guest. For the guest to authenticate over a TLS session it terminates itself, it must hold a bearer credential — and a short-lived token is still a secret inside the guest for its whole validity window, reachable by exactly the prompt-injected code the threat model exists to contain. Option (b) also needs tool cooperation (a git credential helper and friends), which is no help at all against arbitrary agent-written code, and arbitrary agent code is the entire point. Option (a) works here for a reason that would not hold on a general-purpose machine: **KelyfOS owns the whole guest** — the image, the trust store, and the default environment, which `docs/protocol.md` §5.2 already defines as replacing rather than merging. That makes `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` and `GIT_SSL_CAINFO` settable authoritatively, so the usual defeater — Python's certifi and Node's bundled roots ignoring the system store — is solvable rather than fatal. Terminating *selectively* keeps the blast radius honest: the proxy only ever sees plaintext for domains the user deliberately handed a credential to, and connection-level logging of everything else is exactly what P2-4 and P3-8 ask for (egress attempts, not HTTP transcripts). Accepted costs, to be stated plainly in `docs/threat-model.md`: certificate pinning breaks for terminated domains, and the proxy becomes a trust boundary holding plaintext for them. **Binding implementation requirements, added by John on 2026-08-22 when endorsing this decision:** (1) the KelyfOS CA is **generated fresh per run**, lives only in host memory or tmpfs, is **never persisted**, and nothing but the trust anchor ever crosses into the guest — a restart means a new CA, so a leaked anchor is worthless past the session that made it; (2) the flight recorder must record **terminated vs tunnelled per egress event**, so a user can always prove exactly which traffic the proxy was able to read, and the certificate-pinning limitation for secret-bound domains is documented in `docs/networking.md`. Both are conditions on P2-5/P2-6, not separate decisions.

## D7

*2026-08-21*

Monitoring = readers of the flight-recorder JSONL only: HTML session export (P3-8) and terminal TUI (P3-9, P4-6). No web dashboard — no server with auth, persistence, or a fleet view. A localhost read-only viewer is the absolute ceiling, and only on demonstrated community demand.

**Why:** A dashboard is a control plane — non-goal territory where funded competitors live. Litmus test for any monitoring feature: does it read the JSONL, or does it manage sandboxes? Readers are fine; managers are scope creep.

## D8

*2026-08-21*

Daily-driver and trust features adopted: workspace block-device sync (P3-10), `kelyfos doctor` (P3-11), `kelyfos.toml` policy-as-code (P3-12), hash-chained audit (P2-4) with signed exports (P4-3), CI benchmark (P3-6). Phase 3 re-estimated to 5–7 weekends.

**Why:** Approved by John, 2026-08-21. Differentiators no competitor ships as a set; all stay inside the non-goals (single-host, readers not managers, policy in files not servers).

## D9

*2026-08-22*

Dev machine = MacBook Pro M5 Max / 64 GB: macOS 15+ → Lima (`vz`, nested virtualization) → Linux → Firecracker. aarch64 is the primary architecture; x86_64 is cross-built and gated from Phase 1 (P1-8) and is the CI reference. Host support model = the Docker Desktop pattern (P4-7): one CLI everywhere, transparently managed Linux layer on macOS/Windows; Firecracker itself always runs on Linux/KVM.

**Why:** Approved by John, 2026-08-22. Fastest compile loop for the Buildroot/kernel-heavy phases; 64 GB enables the many-fork demo; aarch64-first covers Graviton and cheap EU ARM hosting; the early x86 gate prevents drift. Native macOS backend (libkrun) stays a backlog experiment, not v0.x scope.

## D10

*2026-08-22*

Project named **KelyfOS** — κέλυφος (kélyfos), "shell". CLI binary `kelyfos`, config `kelyfos.toml`, TAP prefix `kelyfos<id>`. Supersedes the "agos" working title (D4).

**Why:** Chosen over KratOS: "kratos" is heavily occupied in adjacent open source (a major Go microservices framework whose CLI binary is literally `kratos`, the Ory Kratos identity server) plus a listed defense contractor — bad findability and a PATH collision for a Go CLI. KelyfOS has clean airspace and the metaphor is literal: a shell wrapped around the agent. Final availability sweep stays gated at launch (P3-7).

## D11

*2026-08-22*

Version policy fixed at P0-6: Buildroot **2026.02.3** (the yearly .02 long-term-supported line, not the newer 2026.05.x), guest kernel **6.18.45** (newest longterm line on kernel.org, pinned to an exact patch), Firecracker **v1.16.1**, Go **1.27.0**. Every pin carries its sha256 in `versions.mk`. Go is installed from the official tarball by `dev/install-go.sh` instead of the `golang` apt package, and the quickstart in section 7 is updated to match.

**Why:** Buildroot's LTS line is the right default for a project whose selling point is reproducible images: a year of fixes without feature churn. The kernel is pinned to a patch release because "latest 6.18" is a floating version by another name, which is exactly what this task exists to prevent; buildroot.org ships only a PGP-signed manifest, so the digest is transcribed into `versions.mk` where the build can check it. Go from apt is 1.22 on Ubuntu 24.04 — old enough that a `go.mod` toolchain directive fails outright, so the distribution package cannot be the pin. Overrides stay possible for bisecting upstream regressions: every value uses `?=`.

## D12

*2026-08-22*

Guest kernel configuration strategy for P1-2: the **base** is Firecracker's own reference guest config (`resources/guest_configs/microvm-kernel-ci-<arch>-6.1.config` @ v1.16.1), vendored into `image/buildroot/kernel/` with attribution, and the KelyfOS delta rides on top as Buildroot kernel config fragments. Two supporting decisions: (1) the kernel tarball is **checksum-verified by KelyfOS itself** before Buildroot ever sees it, because Buildroot documents that it "checks hashes of all packages downloaded, *except those for which a custom version is used*" — and 6.18.45 is a custom version to Buildroot 2026.02.3, whose hash file lists only 6.19.14 and 6.18.33; (2) kernel headers are pinned to the kernel version (`BR2_KERNEL_HEADERS_AS_KERNEL`) instead of Buildroot's default 6.19.14.

**Why:** Starting from an arch `defconfig` would mean switching off two thousand drivers and a module system by hand and hoping none crept back; starting from Firecracker's config means starting where the VMM's own CI already proved a virtio-only, module-free kernel boots. It already carries `ext4`, `tmpfs`, `overlayfs`, `devtmpfs` + auto-mount, virtio blk/net/mmio, vsock, and `# CONFIG_MODULES is not set`. The 6.1 → 6.18 gap is absorbed by `olddefconfig` and every guarantee we care about is then re-asserted by our own fragment and verified in the resulting `.config`, so nothing rests on trust. Un-verified downloads would have made the `versions.mk` kernel pin decorative — a checksum that nothing checks. Pinning headers to the kernel keeps userland from being compiled against a kernel interface newer than the one it will run on.

## D13

*2026-08-22*

AF_VSOCK in Go is wrapped by hand in `internal/vsock` — a small `net.Conn` and `net.Listener` over `golang.org/x/sys/unix` and `os.File` — rather than taking a vsock library such as `mdlayher/vsock`. The Go module is single and repo-wide, with the wire format in `internal/proto` shared by guest and host.

**Why:** Discovered by failing: `net.FileListener` and `net.FileConn` reject an AF_VSOCK descriptor outright ("address family not supported by protocol") because Go's net package only parses AF_INET, AF_INET6 and AF_UNIX addresses. Something has to bridge the gap. The whole bridge is about eighty lines, because `os.NewFile` on a non-blocking descriptor registers it with the runtime poller — so real deadlines and goroutine-friendly blocking come for free and only the two address methods and a poller-aware `Accept` are left to write. Vsock is the single interface this entire product is built on and it lands in PID 1 at P2-1; owning it outright is worth more than the eighty lines saved, and it keeps the guest's init free of third-party runtime code. One module for both sides means the host and guest cannot disagree about the wire format, because there is only one copy of it.

## D14

*2026-08-22*

The guest kernel is trimmed well past Firecracker's reference config, and the cuts are a security posture as much as a boot-time one. Removed: all SCSI/iSCSI, XFS, HID and the entire input stack (with `CONFIG_VT`, since the console is a serial port), the extra I/O schedulers, the virtio devices KelyfOS never attaches (PCI transport, balloon, mem, pmem, console), loop devices, filesystem encryption, module-signature machinery, kernel audit, **all network filesystems (NFS/SUNRPC/FUSE)**, **all of netfilter**, **eBPF**, magic-sysrq and profiling. `CONFIG_EXPERT=y` is enabled because several of these have no Kconfig prompt without it. Kept deliberately: IPv6, cgroups, namespaces, virtio-rng, the PL031 RTC, and `DEBUG_KERNEL`/`SLUB_DEBUG`.

**Why:** Every line removes code that this machine cannot reach: there is one virtio-blk disk, one virtio-net NIC, one vsock device and one 16550A UART, and a kernel that cannot load modules will never grow another. Netfilter is the pointed one — KelyfOS enforces egress policy on the *host* TAP (P2-5) precisely so the guest cannot participate in its own containment, and shipping the guest a firewall it might reconfigure would be arguing with the design. eBPF goes for the same reason a sandbox does not ship a debugger: it is large, privileged and historically exploitable, and seccomp filters (P4-2) are classic BPF and do not need it. `DEBUG_KERNEL` and `SLUB_DEBUG` stay because they are menu gates, and turning them off would take `CONFIG_DEBUG_LIST` — list-corruption detection, a hardening feature — with them. IPv6 stays until P2-5 can actually test egress with it gone; removing it on a guess would be the kind of change that fails three phases later.

## D15

*2026-08-22*

**Boot-time numbers measured under nested virtualisation are informational only.** The Lima / `vz` dev machine does not define pass or fail for any timing claim. The binding measurements — the **≤ 500 ms** Phase 1 target and the **≤ 300 ms** cold-boot claim in the definition of done — are defined on the **P3-6 reference environment: a bare-KVM x86_64 CI runner**, measured by `make bench` the same way P1-7 measures locally (host timestamp to the first frame on the guest-initiated ready channel). P1-7's local median of 899 ms therefore records the dev-machine baseline and does not put the phase target in question. Further local boot optimisation stops here: **IPv6 removal and init-path trimming are deferred** and will be revisited only if the bare-KVM number demands it. **Extended by John on 2026-08-22 to Phase 3's ≤ 100 ms restore target**, which binds on the same bare-KVM reference environment and is measured the same way: `make bench` with n ≥ 10, median and p95 published in the CI job summary alongside cold boot. Local restore numbers are informational for the same reason local boot numbers are.

**Why:** Approved by John, 2026-08-22, on the P1-7 evidence: guest user-mode CPU is at parity with its host and syscalls are free, but virtio block I/O runs at ~77 MB/s and the kernel's 465 ms to userspace is spread across ~100 initcalls with no hotspot — the cost is in the virtualised device and MMIO path, where every L2 exit is serviced by Lima's hypervisor. Optimising against that number would be tuning for an artefact of the development environment, and risks trading real guest capability (IPv6, a readable init path) for milliseconds that do not exist on the hardware the claim is actually about. This is the risk table's own position — "Mac-local timings are informational; Linux CI publishes the reference numbers" — promoted from a note to a rule.

## D16

*2026-08-22*

**The guest gets no DNS at all.** P2-5 as written says the nftables chain permits "only the host-side proxy port and DNS"; KelyfOS permits *only the proxy port*. There is no DNS responder on the TAP address, no `nameserver` in the guest's `/etc/resolv.conf`, and UDP/53 is dropped like everything else. Name resolution happens in the egress proxy, on the host, as part of deciding whether a connection is allowed.

**Why:** It falls out of the proxy design rather than being an extra restriction: a guest configured with `HTTPS_PROXY` does not resolve anything itself — it sends `CONNECT github.com:443` to the proxy and the proxy resolves. So DNS in the guest is not load-bearing for any traffic KelyfOS intends to allow, and every rule that exists but is never needed is surface without benefit. Removing it also closes the oldest exfiltration channel there is: DNS tunnelling defeats a domain allowlist completely, because the data leaves inside the query names to a resolver that was explicitly permitted, and an allowlist checking *hostnames* cannot see it. A prompt-injected agent with UDP/53 to anywhere has a working covert channel no matter how careful the HTTP policy is. The cost is honest and worth stating in the threat model: anything that resolves before connecting — `ping`, raw sockets, a library that ignores proxy environment variables — fails rather than being silently allowed, which is the correct failure for a deny-all sandbox.

## D17

*2026-08-22*

**P3-3 (the `dev` flavor) is pulled forward to run before P2-6's verification and P2-7.** It is a prerequisite for finishing Phase 2 as written, not a phase-3 convenience. The `base` flavor stays exactly as minimal as it is; nothing is added to it. Phase 2's acceptance test will be run against `--image dev`, and the plan's step 1 wording (`--image base`) is read as "a sandbox" rather than as a requirement that base carry tools it deliberately does not have. P3-3 stays in the Phase 3 list and will be ticked there; only its execution moves.

**Why:** Discovered by trying to run the acceptance test. `base` is BusyBox with `CONFIG_TLS`, `CONFIG_SSL_CLIENT` and `CONFIG_FEATURE_WGET_HTTPS` all unset — it has *no HTTPS client of any kind*. But Phase 2's acceptance test requires `git clone https://github.com/…` and an authenticated API call, and P2-7 requires cloning a repository, editing it and running its tests. Those are git, curl and python3, which the plan itself assigns to the `dev` flavor at P3-3. So the phase cannot be closed honestly without it: the alternative is either adding language runtimes to the flavor whose entire purpose is minimalism, or declaring an acceptance test passed on evidence that does not exist. Pulling one task forward is the smaller change, and the dependency is real rather than a matter of taste — an agent sandbox with egress and no TLS client cannot use the egress.

## D18

*2026-08-22*

P2-7 is completed in **two stages, both required**: (1) **protocol interop** — the official MCP Python SDK 2.0.0 drives a full clone → edit → test workflow; (2) **product dogfood** — real Claude Code, attached through the `.mcp.json` in the README, does the same. Stage 1 is recorded; stage 2 is appended to the progress log as supplementary evidence. The checkbox stays ticked throughout — this is completing the proof, not reopening the task.

**Why:** Ruled by John, 2026-08-22. The SDK was the right instinct and is stronger interop evidence than validating my own client against my own server would have been — but the two prove different things. A strict SDK tolerates what a real agent product might fumble, and a real product exercises paths a conformance-minded SDK never touches: how it lists and describes tools to a model, how it handles a tool that returns `isError`, what it does with `structuredContent`, whether it copes with a server that appears only when a sandbox happens to be running. The plan named Claude Code deliberately, and "an MCP client worked" is not the same claim as "the product this exists to serve worked".

## D19

*2026-08-22*

The P3-1 resync design is **endorsed as written and must not be simplified later**: mix host-supplied entropy into `/dev/urandom` first, attempt `RNDADDENTROPY` credit second and ignore its failure, set the wall clock with `clock_settime(CLOCK_REALTIME)`. Restore is measured *through* the resync round trip rather than stopping at `resume()`.

**Why:** Endorsed by John, 2026-08-22. The ordering is load-bearing rather than stylistic. The plain write is what makes N forks of one snapshot *diverge*: without it every fork resumes with an identical random pool and generates the same session ids, nonces and temporary filenames — a correctness failure that looks like nothing until two forks collide. The `RNDADDENTROPY` credit is second and optional because it solves a different problem — a restored guest can otherwise block in `getrandom(2)` waiting for the kernel's entropy estimate to recover, which is how a 100 ms restore becomes a two-second one — and the guaranteed part must not depend on the optional part. Measuring through resync matters for the same reason: stopping at `resume()` reported **3 ms** locally where the honest number, with the guest proven to be answering, is **130 ms**. The flattering number was available and is not the one that gets published.

## D20

*2026-08-22*

The README quickstart installs a prebuilt image from the GitHub release; building from source is the documented alternative, not the default path.

**Why:** The Phase 3 acceptance test requires a person following only the README to reach a working `kelyfos exec` in ≤ 5 minutes. The from-source path cannot satisfy that under any optimisation: `make image` compiles a cross toolchain, a kernel and a userland, and takes ~35 minutes on CI hardware. Either the criterion is dropped or the image ships prebuilt, and dropping it would mean the first thing a visitor does with KelyfOS is wait half an hour, which is the opposite of the product's whole claim. So the v0.3 release publishes `vmlinux`/`Image` + `rootfs.ext4` per arch with a `SHA256SUMS` file, and `make fetch-image` (script `dev/fetch-image.sh`) downloads and verifies them into `$(IMAGE_DIR)`. Artifacts ship gzipped: 141 MB of kernel + rootfs becomes 32 MB, which is most of the quickstart's wall clock. gzip rather than zstd (which would reach 21 MB) because `gunzip` is on every machine already and the quickstart must not require installing a decompressor. The sums cover the compressed files — that is what gets downloaded — and decompression happens only after they verify, into a temp dir, so a bad download cannot damage an image already in the cache. This is a distribution change, not an architecture change: the artifacts are byte-identical to what `make image` produces, the build path stays first-class and is what CI exercises on every commit, and the checksums are published so the download is verifiable. It also does not cross a non-goal — the artifacts are static files on a GitHub release, not a hosted service or a registry KelyfOS operates. Signed images and reproducible builds are P4-3; until then the checksum is integrity, not provenance, and `dev/fetch-image.sh` says so.

## D21

*2026-08-22*

Every built or fetched image carries an `image.json` manifest, and the sandbox refuses to boot when the requested flavor does not match it.

**Why:** Found while preparing the v0.3 release: `ImageDir()` resolves to `out/<arch>` with no flavor component, so `--image` was a label that selected nothing. Build `base`, run `--image dev`, and the sandbox boots `base` while the flight recorder writes `image: dev` into `session.start`. That is not a cosmetic bug: the entire value proposition of the recorder is that it is the one account of the session the guest cannot influence, and here the *host* was writing a field it had never checked. An audit record that is confidently wrong is worse than one that is absent. Rejected the alternative of making the path flavor-scoped (`out/<arch>/<flavor>/`): it is the tidier model, but it invalidates every existing cache and snapshot `workspace_path`, and it still would not stop a hand-placed rootfs from being mislabelled. The manifest fixes the actual defect — the host asserting an unverified fact — and it earns its keep twice more: it is the provenance record the release artifacts needed anyway (arch, flavor, kernel and rootfs digests, pinned Buildroot/Linux versions, build date), and it lets `fetch-image` tell you what you just downloaded. `make image` and `dev/fetch-image.sh` both write it; a missing manifest is a hard error naming the fix rather than a silent fallback, because a silent fallback is how the original bug survived this long.

## D22

*2026-08-22*

`kelyfos snapshot restore` re-creates the egress path and re-pairs the guest's NIC to a fresh TAP via Firecracker's `network_overrides`. Forks stay vsock-only exactly as P3-2 specifies.

**Why:** The Phase 3 acceptance test surfaced this: step 1 prepares a sandbox by cloning a repo *inside* it, which requires a NIC, and step 2 restores that snapshot. Restore had only ever been exercised on vsock-only machines, so it failed — and failed badly. With the parent still running, Firecracker reported `Resource busy` on the original TAP; with the parent gone, `Operation not permitted`, because the TAP no longer existed and nothing re-created it. Either way the user had already paid for a 512 MB snapshot that could never be loaded, and the error they saw was a raw Firecracker fault string about ifreq structures. P3-2 deliberately scopes *forks* to vsock-only, and that stands: N forks would need N distinct guest network identities, and the guest's address and default route are baked into the memory image, so genuinely separating them needs a network namespace per fork — which is P4-1 jailer territory. But P3-1 never scoped restore that way, and restore is the tractable case precisely because there is only one machine: it can re-use the original addressing. The mechanism was already available and simply unused — Firecracker's `PUT /snapshot/load` takes `network_overrides` (host device re-pairing per interface) alongside the `vsock_override` KelyfOS already passes. Restore now builds the egress path in the same order `run` does (TAP, proxy, firewall, then the machine), loads with the override, and re-installs the trust anchor over the control channel — necessary because D6 mints a fresh CA per run, so a restored guest is otherwise carrying an anchor for a CA that no longer exists. `fork` now refuses a networked snapshot with a message that says so, instead of emitting the same Firecracker fault four times.

## D23

*2026-08-22*

`kelyfos run [flags] -- <command>` runs that command on the host for the lifetime of the sandbox, exports `KELYFOS_SANDBOX` to it, and exits with its status.

**Why:** Section 1's definition of done names this exact invocation — `kelyfos run --image dev --workspace . --allow github.com --secret GITHUB_TOKEN@github.com -- <agent cmd>` — and it did not exist: `run` took no positional arguments at all, so the only way to use a sandbox was `run &` followed by `exec`. Found while checking §1 line by line rather than assuming it was covered, since the PLAN-FEATURES activation gate depends on §1 being met. The bullet also settles what the command *is*: it says the agent “operates only through MCP tools on your project files”. An agent running inside the guest would not use MCP tools, it would just use the filesystem. So the trailing command runs on the **host**, reaching the sandbox over the MCP bridge — which is also the shape that makes the secret guarantee meaningful, since the value stays on the host side of the proxy and never enters the guest either way. `sandbox.Load` now falls back to `$KELYFOS_SANDBOX` when no `--sandbox` is given, so the child's `kelyfos mcp` and `kelyfos exec` attach to the right machine even when other sandboxes are running — previously an empty id meant “the only running one” and simply failed when there were several. Teardown, workspace sync-back and the flight recorder's `session.end` all run on the child's exit, so the sandbox's lifetime is exactly the command's.

## D24

*2026-08-23*

CI build economics, settled as one change: a **documentation-only** change skips the `build` and `boot` jobs; Buildroot gains a **compiler cache** (`BR2_CCACHE`) persisted between runs and keyed on `versions.mk`, next to the download and per-arch tree caches that were already there; and a **weekly scheduled run restores no cache at all**.

**Why:** A from-source Buildroot run is tens of minutes per architecture, and this project’s own protocol asks for a commit per completed task — most of which touch nothing but `PLAN.html`, `PLAN-FEATURES.html` and `STATUS.md`. Paying an hour of runners to rebuild a kernel because a progress row was appended is waste, and slow feedback is the mechanism by which people stop reading CI. Three specifics worth recording because the obvious alternative is wrong in each case. **The filter is a job-level `if`, not `paths-ignore`:** a workflow skipped by `paths-ignore` never reports a status at all, which leaves a required check pending forever, whereas a job skipped by a conditional reports as skipped and satisfies it. `checks` stays unconditional regardless, so a documentation-only commit is still audited by `tools/check-plan.py` — the plan files are exactly the documentation most able to break. And the filter is four lines of `git diff` rather than a marketplace action: a third-party action in the path of every build is a supply-chain dependency bought for nothing. **The ccache key has no `restore-keys`:** Buildroot’s own help text makes purging the cache the user’s responsibility when the compiler changes, and `versions.mk` is what changes it, so a bump starts a clean cache instead of inheriting objects built by a toolchain that no longer exists. The download cache keeps its loose restore key, because those tarballs are checksum-verified on every use and a stale one is inert. **The weekly run exists to make the caches falsifiable:** a build that only succeeds because of what a cache is holding — a vanished upstream tarball, a package that no longer configures from scratch — is a build that works until the first person clones the repository. Seven days is the longest that can now stay hidden. `cmake` joins `dev/install-build-deps.sh` for ccache’s sake alone: without a host cmake ≥ 3.18 Buildroot quietly builds its own, spending ten minutes to save a few.

## D25

*2026-08-23*

**Parked, not taken: the move to Bubble Tea v2 and Lip Gloss v2.** KelyfOS stays on `bubbletea v1.3.10` and `lipgloss v1.1.0` — the newest releases of the v1 lines — while `bubbletea/v2 v2.0.9` and `lipgloss/v2 v2.0.6` exist and are current. Revisit at E1-7, which is the next task to open `host/watch.go`.

**Why:** Recorded because a version that exists and is not taken should be a decision rather than an oversight. The two libraries are used by exactly one file, `host/watch.go`, and a major version is an API rewrite: taking it means rewriting the TUI, and rewriting the TUI on a dependency refresh — a change whose entire purpose is to be uneventful — mixes a mechanical upgrade with a real one. The v1 lines are not abandoned; both are the current release of their line and neither carries an advisory. E1-7 adds a resources lane to `kelyfos watch` and E2-8 rebuilds it as a multi-lane team view, so the file is going to be rewritten on purpose soon enough; that is when the v2 API should be adopted, if it is adopted at all, and the work will be paid for once instead of twice.

## D26

*2026-08-23*

**D25 is discharged: the Bubble Tea v2 / Lip Gloss v2 move is declined, not deferred again.** KelyfOS stays on `bubbletea v1.3.10` and `lipgloss v1.1.0`. The full reasoning is **F-D23** in PLAN-FEATURES.html; this row exists so a reader of *this* file does not find D25’s condition still open and pointing at a task that has already happened. Two corrections of fact to D25 while it is being answered. The v1 pins are the newest release of their line (`go list -m -u all` offers no update for either), and `govulncheck ./...` is clean. And the v2 modules are **not** at the path D25 gives them: their `go.mod` files say `charm.land/bubbletea/v2` and `charm.land/lipgloss/v2`, not `github.com/charmbracelet/…/v2`.

**Why:** D25 named its own revisit point — “E1-7… and E2-8 rebuilds it as a multi-lane team view; that is when the v2 API should be adopted, *if it is adopted at all*.” E1-7 passed without the question being asked, and E2-8 has now rebuilt the file. Leaving it open a third time would turn a decision into a habit, and log rows are immutable, so the only way to discharge a stale condition is to append the answer. The answer is that E2-8 needed nothing v2 has: the multi-lane view is fixed-width columns, a bounded ticker and a status line, and the one library call that carries weight — measuring a styled string in terminal columns — exists in both. Adopting a major version whose only argument is that it exists would be paying an API rewrite for nothing, in the middle of the task with the most reason to be about something else. That is D25’s own argument, applied to the moment D25 pointed at. The module-path correction matters more than it looks: taking v2 would mean depending on a vanity domain this project has never resolved, which is a supply-chain fact neither D25 nor F-D23 could weigh because both had it wrong. F-D23’s condition for revisiting stands and is better than a date: a v2 API this project actually needs, an advisory on a v1 pin, or the v1 line ceasing to receive releases.

## D27

*2026-08-23*

**P4-1 and P4-2 are promoted into a new Phase 5, hardening, exiting at v0.9 — and nothing else is.** [PLAN-FEATURES.html](PLAN-FEATURES.html) is complete and closed as of v0.8; this document governs from here. *Where the work goes.* PLAN-FEATURES §2 says a promoted P4 item becomes an epic *there*. That rule assumed that plan was the active one. It is not: with v0.8 tagged its five epics are done and its masthead says COMPLETE, and adding an epic to a closed record would make the word mean nothing. The hardening items were always this document’s own backlog, so they are promoted here, under this document’s rules, with the redirect recorded there as F-D56 and here as this row rather than left as a rule one file quietly stopped following. *What “done” means, ruled by the product owner.* Three things beyond the tasks themselves: the README’s “not hardened yet” sentence replaced by a true sentence stating what IS now enforced and what remains out of scope, with `docs/threat-model.md` updated to match; the boot and restore bars re-earned on the bare-KVM reference, because the jailer and a seccomp filter sit on the boot path and a bar is never assumed across a security-posture change; and the full acceptance suites re-run green. *What is not promoted.* P4-3, P4-6 and P4-7 stay in the backlog. P4-4 and P4-5 stay `[BLOCKED]` on the conditions they were blocked on — no user has asked for a browser flavor, and there is still no evidence to decide the compliance-pack question with. A hardening phase that quietly absorbed the rest of the backlog would be a hardening phase in name. *And one task alongside it*, P5-5: the launch assets — a terminal recording at the top of the README, a first-time-visitor pass over its opening screen, and the HN post refreshed to v0.8/v0.9 reality. Committed, posted nowhere. John submits things.

**Why:** The product owner’s ruling of 2026-08-23, given while Epic E5’s exit was in flight and explicitly not touching it. *Revisit when* v0.9 is tagged: what is left in P4 is then either promoted with the same explicitness or written off.

## D28

*2026-08-24*

**Buildroot moves to the LTS line and the guest kernel moves back to 6.12, because the LTS line cannot express 6.18 — and both are longterm to the same date.** *The trigger.* F-D40 ruled the hop to Buildroot 2025.02.x and F-D50 queued it behind an origin outage, to execute at the first task boundary after the origin answered. It answered on 2026-08-24 and this is that boundary. *The facts, read rather than assumed.* buildroot.org’s download page lists exactly three releases: candidate 2026.08-rc1, stable 2026.05.1 (EOL September 2026), and **long-term support 2025.02.17, EOL March 2028**. The 2026.02.x line this project built on is on neither list. The tarball’s digest comes from its PGP-signed message, signed by the same key that signed the 2026.02.3 release already trusted here, and that message’s digest for 2026.02.3 matches the value this file pinned before the change — which is how the transcription method was checked against a known-good value rather than asserted. *The blocker F-D40 anticipated, and it is structural rather than a build failure.* Buildroot 2025.02.x offers kernel header series up to **6.12**. KelyfOS built 6.18.46, and the config fragment templates the series from the pin precisely so that a kernel the Buildroot does not list fails loudly — which it did, on the first attempt, exactly as its comment said it would. *Alternatives.* Stay frozen on 2026.02.3, which F-D40 pre-authorised: that keeps 6.18 and leaves the build on a line the project itself does not list as supported, which is the condition F-D35 objected to and which only worsens. Or pin the header series to 6.12 while building 6.18: a supported arrangement in general — headers older than the running kernel is normal — but it makes the fragment tell Buildroot something other than the truth about the kernel, and deliberately weakens the check that just did its job. *Chosen: 2025.02.17 with Linux 6.12.105.* The deciding fact is kernel.org’s own table: **6.12 and 6.18 are both longterm with a projected EOL of December 2028**. The move costs six release cycles of kernel and buys a build system on the line its maintainers support until March 2028, with toolchain, headers and kernel all agreeing and the loud-failure property intact. Paying maintenance risk to keep a kernel whose support window ends on the same date would be paying for nothing. This supersedes F-D52’s reasoning, which was right that 6.18 is the newest longterm line and wrong to treat newest as the requirement. *Evidence.* Full aarch64 rebuild from a fresh tree: every requested kernel symbol present, kernel 13 058 560 bytes, rootfs under budget, supervisor is PID 1, and the guest reports 6.12.105. Then accept-denials 12/12, accept-shell 13/13, accept-runs 18/18, accept-notify 22/22, accept-forward 19/19, accept-e5 33/33, and all fourteen cookbook recipes. x86_64 and the boot smoke test are CI’s; the boot and restore bars are re-measured on the bare-KVM reference (D15) because a version change on the boot path is exactly where a bar is never assumed. *One operational note worth keeping:* the first attempt died with `No space left on device` after two Buildroot trees and three build directories filled the dev VM. Stale per-arch build trees are disposable and were disposed of; nothing was lost, but a build that fails for disk rather than for code costs an hour of reading the wrong logs.

**Why:** F-D40 (PLAN-FEATURES, closed), F-D50 for the queue and the retry rule, F-D52 for the kernel reasoning this supersedes. *Revisit when* the Buildroot LTS line gains a header series at or above the kernel line KelyfOS wants, or when 2026.02.x appears on buildroot.org as supported.

## D29

*2026-08-24*

**The jailed VMM drops to the invoking user, not to a dedicated account — and the acceptance is amended to say so rather than quietly passing.** *What the acceptance said.* P5’s recreate-and-verify list, written at P5-0 before the jailer had been run, asked that the Firecracker process be “not running as the invoking user”. Two things were established afterwards by running it: the jailer requires root, so KelyfOS invokes it through `sudo -n` (the product owner’s ruling of 2026-08-24), and `--uid` is therefore what decides who the VMM ends up as. *Alternatives.* A dedicated system account — strictly stronger, because a VMM escape could then not signal or `ptrace` the invoking user’s other processes, which sharing a uid permits even across a mount namespace. It costs “create a user” in the quickstart, on top of the sudoers line the owner has already ruled into it, and it costs a chown of every image and workspace file into that account. Or leave `--uid` at root, which is not a drop at all and would make the jail a regression: without it, `sudo jailer` leaves the VMM running as root, which is worse than the unjailed status quo. *Chosen: the invoking user.* It is a real drop relative to the only alternative on the sudo path, and the chroot — verified from the host’s own `mountinfo` — already takes the host filesystem away entirely, which is the reach that mattered most. The residual is named in `docs/hardening.md` §5 rather than left for a reader to discover: same-uid signal and `ptrace` reach to the user’s other processes is *not* closed by this phase. *And the second half of the amendment is a correction of method.* The item named `/proc/<pid>/root`, which reports the path as the process sees it: `/` for a chrooted process and `/` for an unjailed one, the same answer for opposite facts. The acceptance now reads `mountinfo`, which names the chroot from the host’s side. Writing an acceptance before the mechanism exists is right; keeping one that cannot distinguish what it claims to is not. *Revisit when* somebody runs KelyfOS as a service account, where a dedicated uid costs nothing because the account already exists.

**Why:** P5-0’s acceptance list, amended in place with this row cited beside it. `dev/accept-jail.sh` is the check as it now stands: 14 of 14.

## D30

*2026-08-24*

**A regression found by one task becomes a task of its own, not a line in somebody else’s commit message.** *What was found.* P5-2 read the VMM’s `/proc` to prove its syscall filter, and while it was in there it established that `kelyfos run --cpu-quota` is refused on every jailed run on a host whose cgroup path resolves to the systemd user manager — which is the dev machine [section 7](#quickstart) tells a new user to build. The mechanism is not in doubt: the jailed branch of `Sandbox.Start` replaces the command line with the jailer’s and so never calls `WrapArgv`, which is the only thing that creates a systemd scope; `--parent-cgroup` is added only when the slice is in direct mode; so on a systemd-mode machine nothing places the VMM in a slice at all, and `Confirm` reads `/proc` and refuses a quota that was never applied. The same command works with `--no-jail`, which is the pre-P5-1 behaviour, and fails identically under `sudo`, which rules out privilege. *Alternatives.* Fold the fix into P5-2 — the temptation was real, because it is two files from code that task already touches. Rejected: it is a design question about how the jailer’s cgroup handling composes with the two modes E1 chose between, not a line, and a commit that has to explain two unrelated mechanisms is a commit nobody can review. Or leave it as a note for P5-4 to trip over. Also rejected, and more firmly: P5-4 is where the bars are re-measured and the README’s sentence is replaced, and arriving there with a shipped feature broken either delays the phase exit or tempts somebody into a sentence that steps around it. A hardening phase that quietly broke a v0.4 feature and did not say so would be exactly the kind of thing this document exists to prevent. *Chosen: a new task, P5-6, in list position immediately after P5-2 and before P5-3.* Section 6’s own rule — execution order is list position, task IDs are stable labels and may be non-sequential after amendments — is what makes a P5-6 sitting third both legal and readable: the number says when it was written, the position says when it runs. It carries its own check into `dev/accept-jail.sh`, which is also the half of this phase’s second acceptance item that P5-1 left unobserved, so one task closes both. *Revisit when* P5-6 lands: if the fix turns out to be the one-line move of `WrapArgv` that it looks like from here, this row should say so plainly rather than let a careful decision stand as retrospective justification for a small change.

**Why:** Found by P5-2, 2026-08-24. Evidence in the progress row of the same date. The task text is P5-6; this phase’s acceptance item 2 is what makes it a phase-exit blocker rather than a backlog item.

## D31

*2026-08-24*

**The guest profile is a refusal list applied by a re-exec, and the supervisor is not inside it.** *Three forks, decided together because each answer constrains the next.* *Allowlist or refusal list.* An allowlist is the stronger shape and it is what Firecracker uses for its own VMM — but Firecracker knows every syscall its own code makes. A KelyfOS guest runs `python3`, `node`, `git` and whatever an agent installs, and an allowlist for that is a research project whose first miss is a crash in somebody’s build. P5-2 refused to hand-write an allowlist for somebody else’s binary and called it “a way to produce a crash that looks like a security feature”; the same sentence applies here with more force. **Chosen:** a refusal list of twenty-eight names, every one of them something no compiler, package manager or test runner calls, refused with `EPERM` rather than a kill so the program reports the error its libc documents. *Where the restrictions are applied.* Both mechanisms restrict the calling thread and are inherited across fork and exec, and Go has no safe hook between the two — after `fork` only async-signal-safe work is legal. The alternatives were to restrict a locked OS thread inside the supervisor and spawn from it, which leaves a permanently crippled thread in PID 1 and makes the Go runtime’s own syscalls a hazard, or to wait for Go 1.28, whose `SysProcAttr` gains `UseLandlock`/`NoNewPrivs` (golang/go#68595, merged for that release) and still has nothing for seccomp. **Chosen:** a re-exec of the supervisor that restricts itself and then `execve`s the target. It costs one exec per spawned process, off the boot path, and it is the shape Go 1.28 will let us delete rather than rewrite. *Whether the supervisor is confined too.* It cannot be: it calls `reboot` to power the machine off, which is on the refusal list, and it writes `/proc/sys` during setup. Confining PID 1 would mean a profile with holes in it shaped exactly like the supervisor, which is a profile that protects nothing. **Chosen:** the profile is for what the supervisor spawns, which is what `docs/hardening.md` §4 says and what the phase promised. *And one thing §4.3 asked for that a PID 1 cannot do.* It says the supervisor “refuses to start” when the kernel cannot apply the profile. PID 1 exiting is a kernel panic, which turns a diagnosable condition into an unreadable one. So the refusal is split: the supervisor probes Landlock at boot and reports the failure in its ready frame, the host refuses the machine with `[profile.not_enforced]` and tears it down, and the confining step refuses every spawn anyway if one somehow got that far. From the outside that is a machine that would not start; from the inside it is a machine that can say why.

**Why:** P5-3, 2026-08-24. Evidence in the progress row of the same date and in `dev/accept-profile.sh`. *Revisit when* the project moves to Go 1.28: the re-exec for Landlock becomes three struct fields, and the question is then whether seccomp alone still justifies it.

## D32

*2026-08-24*

**A snapshot is a time capsule of the authority it was taken with, and the record has to say so — but it is not refused.** (The product owner’s ruling of 2026-08-24.) *The finding.* P5-3 confines every process the supervisor spawns. A snapshot taken before v0.9 restores into the guest it captured, and that guest’s supervisor has no profile: restoring it does not upgrade it. P5-3 logged this as a release note. The ruling is that a release note is not sufficient. *Why not.* This is F-D39’s class — a snapshot carrying authority the current policy would not grant — meeting P5-1’s principle that the record must never overstate the wall that was around a run. `jailed: true/false` exists so a transcript cannot make an unjailed run look jailed; a restored session that says nothing about guest confinement is the same failure with a different field missing. *What is required, and what is not.* Required: `session.start` carries the guest-confinement posture on the restore path, and restoring a pre-confinement snapshot warns in the terminal with an actionable fix. **Refusal is explicitly not required**, and that is the interesting half of the ruling: the host-side walls — the jailer, the VMM’s own filter, the egress policy, the cgroup — are unchanged by the age of the snapshot, and guest confinement is depth behind a boundary that still holds. Refusing would make old snapshots unusable to buy nothing the boundary does not already give. *Consequence for the phase.* P5-7, before P5-4, because P5-4 writes the sentence that has to be true and `docs/threat-model.md` has to say this in exactly these terms.

[ENDORSED 2026-08-24 — the product owner, on P5-7’s deviation.] This row asked for the posture on `session.start`; P5-7 put it on `session.ready` instead and that choice supersedes this one, for the reason P5-7 gave: `session.start` is per-command, so a five-agent `team up` is one chain with five machines in it and no place to put five postures, while `session.ready` fires once per machine on all eight paths. That the same change closed P5-1’s `jailed` gap for teams confirms the original placement carried the same one-command assumption rather than a considered one. **And the taxonomy that came with it is adopted as doctrine**, beyond this pair of fields and beyond this phase: *a fact knowable before the machine boots — a choice — may ride the event that opens the chain; a fact that had to be observed rides `session.ready`, because that is the first event that could carry it truthfully.* Any record field added later is placed by that rule, and `docs/events.md` states it as a rule rather than as a note about two fields.

**Why:** The product owner’s ruling of 2026-08-24, on the release-note item P5-3 raised. F-D39 for the class; P5-1 and D29 for the record principle. *Revisit when* a snapshot format change makes it cheap to record the guest’s posture inside the snapshot itself, which would let a restore know before it boots rather than after.

## D33

*2026-08-24*

**`dev` does not relax the sibling-ptrace refusal, and the reason is that relaxing it is not a profile change at all.** *The question, put by the product owner and left to this seat to decide on cost.* P5-3’s profiles leave `ptrace` out of `dev`’s seccomp refusal list on purpose. Landlock then refuses it anyway between siblings, so attaching a debugger to a process already running in the guest fails on both flavors. *What relaxing it would cost, which is the whole answer.* There is no per-flavor knob for this. A Landlock domain is created by the thread that restricts itself, so two children that each restrict themselves are siblings whatever rules they used, and the hook compares hierarchy rather than content. The only arrangement in which two spawned processes share a domain is one where their common ancestor entered it — that is, where the supervisor confines itself and every child inherits. D31 ruled that out already and the reasons have not moved: PID 1 calls `reboot` to power the machine off, which is on the refusal list, and a profile with holes shaped exactly like the supervisor protects nothing. So the choice is not “relax ptrace for dev” but “confine PID 1 to make debuggers attach”, days before a release, to buy an operation an agent sandbox rarely wants. *Chosen: keep it.* `dev`’s seccomp entry is not wasted — it is exactly what makes `gdb ./prog` work there and fail on `base`, because a child inherits its parent’s domain and a launched target is not a sibling. What is lost is attach-to-running, and it is lost identically on both flavors. *One deviation from the ruling, stated rather than quietly taken.* The ruling asks for an E5-4 catalog entry. The catalog cannot hold this one: `tools/gendocs` fails the build for an entry nothing raises, and there is no site to raise it from — the refusal is the guest kernel’s answer to a syscall KelyfOS never sees, not a decision KelyfOS makes and reports. Putting it in the catalog anyway would mean a documented refusal with no code behind it, which is the exact condition F-D4 built that check to prevent. So it goes where `docs/denials.md` already keeps this class — its section on what is deliberately not in the catalog and why — plus the generated profiles page, with both halves proved in `dev/accept-profile.sh` rather than asserted. If the owner wants it in the catalog regardless, that is one line to overrule and the raise site is the open question.

[ENDORSED 2026-08-24 — the product owner; the overrule is declined.] A catalog entry with no raise site is precisely the forged promise F-D4’s drift gate exists to prevent, and weakening that gate to satisfy the letter of a ruling would cost more than the entry is worth. The ruling’s intent — that somebody who hits the wall learns what still works and why — is met by the “what is not in the catalog” section and the generated profiles page, with both halves proved rather than asserted. **If a verified guest-side refusal mechanism ever exists, that is where this belongs; one is not to be built for this.**

**Why:** P5-8. The owner’s ruling of 2026-08-24 left this call here and asked for it either way. D31 for why the supervisor is outside its own profile. *Revisit when* Go 1.28’s `SysProcAttr.UseLandlock` lands and the ruleset is built once in the parent — the domain shape does not change, so this answer should survive it, and if it does not, this row is wrong and should be replaced rather than reinterpreted.

## D34

*2026-08-24*

**Phase 6 is opened as “v1.0, the promise”, on the product owner’s instruction, with five pillars fixed by him and the sizing done here — and three of the five are scoped down, each with its own row rather than by a quiet omission.** *Why the sizing had to be done first.* P6-0 read the pillars against the code instead of against the backlog’s wording, in eleven parallel audits plus two adversarial critics. The verdict was blunt and is recorded because acting on it is the decision: **as briefed this is three to four phases wearing one phase’s name, and at least two pillars would produce a claim the project cannot honestly make.** The response is not to decline the pillars — they are the owner’s and every one of them is in — but to write each task at the size of the honest version of it, and to say in the task text what the honest version does not include. *What was scoped, and where.* Per-call credential handles → D36. Output-side secret scrubbing → D37. Reproducible builds → D38. P4-7’s macOS half → D35. Everything else is promoted whole. *What the audit found that no pillar had asked about, and which is now P6-1.* The repository asserts in three places that the published artifacts are byte-identical to what `make image` produces; the shipped v0.9 kernels name two different build hosts, one of them the developer’s laptop. `llms.txt` still ships “not hardened yet” — a *generated* string, so the drift gate has been keeping a retracted claim consistently wrong since P5-4 retired it everywhere a human looks. The generated CLI reference silently drops one-letter boolean flags, so `kelyfos log -f` is undocumented and the gate structurally cannot notice, because the generator and the file agree and both are wrong. `docs/protocol.md` §7 claims a host-side check that no code performs. A phase called “the promise” that built anything on top of those would be building on sand, so the sweep is task one and every later task inherits a repository that tells the truth. *The arithmetic, decided up front rather than discovered at the exit.* Phase 4 can never read 7/7: two rows are the history of work done in Phase 5, two more are the history of work now done here, one is closed with its residual parked, and two are blocked on conditions this project cannot manufacture. The dashboard keeps counting all seven and Phase 4 is marked `PARKED` rather than quietly excluded, because a denominator adjusted to flatter the numerator is the same defect as a ticked box with unmet conditions. **v1.0 does not mean 100%, and the masthead says so in words.**

**Why:** The product owner’s instruction of 2026-08-24. P5-0 for the spec-first pattern; D27 for the promotion machinery. *Revisit when* a pillar’s scoped-down version is delivered and the parked remainder has a user asking for it — each of D36, D37 and D38 names its own condition.

## D35

*2026-08-24*

**The Phase 4 disposition: every item gets a verdict, and the two that stay blocked get a revisit condition instead of a permanent silence.** *P4-3 — PROMOTED whole* into P6-6 through P6-11. It is the pillar the README already owes a stranger in four separate places. *P4-7 — PROMOTED, scoped by the owner’s own ruling*, into P6-12. The ruling is that `kelyfos doctor` provisions, starts and stops the Lima layer and the user never runs `limactl`; that is deliverable and the audit sized it at five to seven tasks, of which the compile-level port to darwin is **seven lines** behind two build-tag file pairs. What is *not* deliverable is P4-7’s own next sentence, “same commands, same `kelyfos.toml`, same images everywhere”: that needs every command proxied across `limactl shell`, and the audit measured that an interrupt does not cross it — which would leave a Firecracker microVM running and silently discard the workspace the deferred teardown was syncing back. That is data loss, not polish. So the sentence is retired in the v1.0 copy and the compatibility document says plainly that macOS means “KelyfOS manages the Linux layer”, not “KelyfOS runs on macOS”. **Windows and WSL2 are explicitly post-1.0**, by name, in that same document. **Steering needed: no** — the owner’s ruling already scoped this to the half that is real; it is the plan’s older wording that needed correcting, not the ruling. *P4-6 — CLOSED, half delivered and the residual parked.* E2-8 delivered the lane rendering — fixed-width columns, per-lane live usage against caps, the message ticker, the collective budget, the narrow-terminal fallback — and `watch`’s own header comment says it supersedes P4-6 for the team case. The residual is precise and is *not* what the first audit claimed: lane *selection*. `watch` reads one session chain and creates a lane per `agent` field, so `kelyfos fork -n 4` — the headline in P4-6’s own text — shows one of the four. **A correction to that audit, made here because it would otherwise have decided this:** one reader argued the residual is forbidden by D7’s “no fleet view”. It is not. D7 names P4-6 by id in the *sanctioned* half of the same sentence and attaches the prohibition to a *server* with auth and persistence; a terminal reader of JSONL is the category D7 permits. So this is parked on cost and value, not on principle: a fork fleet is vsock-only with no broker and no parent cgroup, so three of the four lane regions would render empty, and `team up` is now how this product runs several agents side by side. The cheapest path to P4-6’s literal demo is recorded so it need not be rediscovered — give forks a shared session and agent names, about fifteen lines in `fork.go`, and the delivered lane view works unchanged. *Revisit when* somebody asks for lanes over sandboxes that were not forked from one command. *P4-4 and P4-5 — still [BLOCKED], on their own written conditions, verified rather than assumed:* the repository went public on 2026-08-22 and has zero stars, zero forks, zero issues and discussions disabled, so “if users ask for it” and “decide with evidence” are both unmeetable today. **But the block is now dated rather than eternal**, because this phase’s own exit performs the act most likely to change those facts: the launch. So both carry an explicit revisit condition — thirty days after the v1.0 launch, on whatever evidence the launch produced — in the shape D27 used for Phase 4. Restated in the 1.0 documents as demand-gated future work rather than as absence.

**Why:** The product owner’s instruction of 2026-08-24; D27 for the promotion machinery and for the “promoted with the same explicitness or written off” condition it set for v0.9, which this row discharges; D7 for the monitoring ceiling and what it does and does not forbid; F-D26 on the cost of letting a decision decay into a habit.

## D36

*2026-08-24*

**The per-call credential handle is scoped to the three quarters of it the architecture can carry, and the word “handle” is not used for the part that is really scoped injection.** *What was asked.* Evolve secret injection toward a credential that is call-bound, destination-locked, scope-limited and single-use — a smaller window on the existing guarantee rather than a new one. *What the code allows, measured.* Injection is a single line inside a keep-alive loop, and the proxy can only inject on a connection it terminates — which it does precisely when a secret is bound, so “can inject” and “has a credential” are today the same condition. Destination-locking and scope-limiting are therefore free: the parsed request is already in hand at the injection point, and adding a method and path matcher plus recording them is mechanical. Call-binding is not free. There is no call boundary the proxy can observe: the guest’s own MCP exec tool passes a constant identifier, the exec request id crosses the wire and is never put in the child’s environment, and on the flagship path the proxy lives in `kelyfos run` while the tool-call boundary lives in `kelyfos mcp` — two processes sharing only a locked file. In `serve-mcp` and the shim, one process holds both, and there call-binding and single-use redemption are real. *Chosen.* Ship destination-locking, scope-limiting and the receipt everywhere; ship call-binding and single-use where one process holds both ends; park the guest-presented handle. **And say why it is parked in the terms that matter**: the current design’s strongest property is that there is *nothing in the guest to steal*. A handle the guest holds is a bearer token in an untrusted environment, readable by every process the agent spawns — it changes the guarantee’s shape from “nothing exists” to “something short-lived exists”, and that trade must be argued, not assumed, before it is made. **One more honest limit**, which the docs must carry: even a full handle only narrows the window for domains the proxy already terminates — that is, domains that already have a credential bound. It is not a general egress improvement, and a prompt-injected agent that controls the tool call holds that call’s authority legitimately, so the window shrinks from a session to a request rather than closing. *The two questions the parking lot posed stay posed* and are the promotion condition: who mints and redeems when the proxy is the only party that ever sees plaintext, and what “a call” means when the caller is `exec` running arbitrary agent-written code rather than a tool with a schema.

**Why:** P6-4. [PLAN-FEATURES.html §4](PLAN-FEATURES.html#parking)’s parked entry and its Azure SRE Agent source; D6 for why the value stays on the host; F-D33 for the standard this project holds itself to when describing what the proxy can and cannot see. *Revisit when* either blocking question has an answer, or when a guest→host request channel exists for a non-team sandbox for some other reason.

## D37

*2026-08-24*

**Output-side secret scrubbing ships as echo suppression, and the general credential recogniser is declined rather than deferred.** *The distinction, because the feature’s name hides it.* Exact matching on the bound secret values catches a credential being *echoed* — an API reflecting the header, an error quoting the token, a redirect carrying basic credentials. It has zero false positives and the material is already in the same package and already in memory. It does **not** catch the parking lot’s own motivating case, a response that mints a *new* credential, because a new token is equal to no bound string. *Why the thing that would catch it is declined.* A general credential-pattern recogniser is a false-positive machine operating on a byte stream the agent will parse. A wrong match inside a tarball, a binary, or a JSON document produces a failure with no cause anybody can find, and it is undiagnosable from inside the guest — the blast radius of a false positive is strictly worse than that of a missed scrub. That is a worse trade than the one it is meant to improve. *What ships, with its limits stated first rather than last.* Length-preserving replacement, so a keep-alive connection cannot desync on a content length that no longer matches; the terminated and plain-HTTP paths only, because the tunnelled majority is ciphertext the proxy cannot read and never will be; the compressed-body case handled or declared, since the terminated path deliberately disables compression to keep bodies untouched and a guest that asks for gzip gets a body the matcher sees as noise; and a record field saying the proxy *altered* bytes, because a chain that reports only how much the proxy could read understates a proxy that writes. And it is named for what it is in every document that mentions it, so nobody reads it as a guarantee that a credential can never reach the agent. *One thing it does not touch, stated because the obvious reading is wrong.* On the `kelyfos run -- <agent>` form the agent is a host child process inheriting the environment, so a bound credential is in it verbatim. §1’s wording — the value never exists *inside the guest* — is still exactly true; any prose that drops the word “guest” would not be.

**Why:** P6-5. [PLAN-FEATURES.html §4](PLAN-FEATURES.html#parking)’s parked entry, which poses the recogniser question and leaves it open; F-D33 for the standard of describing what the proxy can read. *Revisit when* a recogniser exists that can be wrong safely — one whose failure mode is a refusal a person can see rather than a silent corruption they cannot.

## D38

*2026-08-24*

**Reproducibility is configured and then *measured*; the word does not enter the documentation ahead of the measurement.** *What is already true, measured rather than hoped.* The Go CLI is bit-reproducible today: a cold-cache rebuild from a different source path produced an identical digest. The image layer is not, and the reasons are four knobs — `BR2_REPRODUCIBLE` is absent, `SOURCE_DATE_EPOCH` is read by one script and set by nothing, the compression wrapper keeps a filename and a timestamp, and every filesystem gets a random UUID and hash seed and a wall-clock creation time. Setting an epoch, a fixed UUID and a fixed hash seed produced a byte-identical filesystem in the audit’s own experiment. *What is unknown and expensive.* Whether a full Buildroot tree — a cross toolchain, a kernel, musl, BusyBox, git, Python, OpenSSL, curl — rebuilds byte-identically has never been measured here. Upstream calls the feature experimental and requires an identical build path, while this project’s build directory is under `$HOME` and therefore differs between CI and the dev machine; and the compiler cache has been mixing cached and fresh objects in every build this project has ever done, so an experiment that does not control for it measures the cache. One round is tens of minutes per architecture and the honest experiment is a matrix. *Chosen.* Ship the deterministic configuration, then a `repro-check` workflow that rebuilds and diffs, and **let its result be the claim** — per artifact, pass or fail, with the run named. “The CLI reproduces; the rootfs does not yet, and here is the run that shows it” is a statement this project is entitled to make and a reader can act on. “Reproducible builds” is not, until something has run twice. This is the same rule P5 item 8 was created to enforce, applied before the mistake rather than after it.

**Why:** P6-9, with P6-1 withdrawing the three byte-identity claims first. P5’s acceptance item 8 for the principle; D20 for the checksum-not-provenance posture the artifacts have carried since v0.3. *Revisit when* the repro-check has run its matrix — the answer it returns is what the documentation then says, whatever it is.

## D39

*2026-08-24*

**Release artifacts are attested by the platform that builds them, which means the build moves into CI first; session exports are signed with a key the *user* holds, or not at all.** *Chosen for artifacts, from live research on 2026-08-24.* A tag-triggered workflow builds both architectures, then `actions/attest` at **v4.2.2** (2026-08-04, pinned by commit `1e69f48acb82d1966a394da916b4c1698aa569d6`) takes the `SHA256SUMS` file KelyfOS already emits, in the format it already emits it, through its `subject-checksums` input — one attestation covering every asset, no reformatting — and a second call with `sbom-path` attests the SBOM. Permissions are exactly `id-token: write`, `contents: read`, `attestations: write`. That is **SLSA v1.0 Build Level 2**, and it verifies offline: `gh attestation trusted-root` once, then `gh attestation verify --bundle
--custom-trusted-root`. *Rejected, with reasons.* `actions/attest-build-provenance` and `actions/attest-sbom` are now thin wrappers over `actions/attest` and their own release notes say new implementations should not use them. Cosign keyless would need an installer, a pin no earlier than **v3.1.3** (which exists because v3.1.2 and earlier had a verification bypass), and buys nothing the native path does not already give a GitHub-hosted build. The SLSA reference generator and its verifier are eighteen and fourteen months stale against a native path that is current. *Named separately and never conflated.* GitHub’s **immutable releases** produce a GitHub-signed attestation over a release’s assets however the release was cut — but its predicate carries repository, tag and package identity and **no builder identity at all**, and `gh release verify` has no offline mode. It asserts that GitHub received these bytes under this tag; it says nothing about where they came from. It is worth enabling, it is an owner action because it locks published assets and protects tags, and describing it with the same word as build provenance would be precisely the overclaim P5’s eighth item withdrew. *Chosen for session exports.* The chain already gives keyless offline *integrity*. A signature adds *who*, and the only shape that adds a “who” a reader can anchor is a key the user supplies: `--sign-key`, ed25519 from the standard library, zero new dependencies against a forty-line `go.sum`. A per-run ephemeral key is rejected — it proves one process produced both halves, which the chain already proves, and it would be the first badge in this repository that invites a reader to stop asking. Sigstore is rejected for exports: a hosted service in the verify path contradicts both the non-goals and the report’s own “one file, no scripts, no external requests” premise, and keyless signing needs an interactive identity flow on a CLI that runs headless on servers. **The developer holds no key and needs none**, which is the property that makes this shape work at all.

**Why:** P6-8, P6-10, P6-11 for artifacts; P6-6 and P6-7 for exports. Live research of 2026-08-24 against the actions, cosign, SLSA and Buildroot sources, with versions and dates recorded in the P6-0 progress row. *Revisit when* a reusable workflow is worth the isolation it buys (Build Level 3), or when `gh` gains offline verification for release attestations, which would make the immutable-release path independently useful.

## D40

*2026-08-24*

**§8 gains rule 9: documentation rides with the task that changed the surface.** F-D9 said this and enforced it through five epics, and F-D9 lives in [PLAN-FEATURES.html](PLAN-FEATURES.html), which is closed. **This document’s protocol never had the rule**, and the consequence is visible: Phase 5 shipped v0.9 with no token re-measurement and no docs-only exam, not because anyone decided to skip them but because nothing here required them. A rule that governed the project through its most productive stretch should not have evaporated when the file it lived in closed, so it is restated in the governing document, in the same shape rule 8 was added: as a rule, with the failure that produced it named.

**Why:** P6-0. F-D9 in PLAN-FEATURES.html §2; F-D4 for the generated-reference gate that makes half of it automatic; rule 8 for the precedent of promoting a lesson into the protocol rather than into a memory.

## D41

*2026-08-24*

**The clients `kelyfos connect` supports: six, chosen from a live survey on 2026-08-24, with the burden of proof on inclusion.** Every supported client costs a writer, an idempotent update, a `--remove`, a byte-level assertion, a recipe, and a “verified against <tool> <version> on <date>” line somebody re-verifies forever. Two independent surveys of the landscape were reconciled by a third pass that re-fetched every disputed claim. **Supported, in order of how much they earn the slot:** **(1) Claude Code** v2.1.241 — `.mcp.json` at the project root written directly, and `~/.claude.json` never hand-edited but written through `claude mcp add-json`, because that file holds the live sign-in session and a corrupt parse triggers a recovery flow. **(2) OpenAI Codex CLI** 0.149.1 — `[mcp_servers.<name>]` in `config.toml`, snake_case and not `mcpServers`; a direct merge-write is the *primary* path rather than a fallback, because `codex mcp add` physically cannot target project scope — verified in the shipped source at the release tag, not inferred from documentation. It is also the only one of the six publishing a JSON schema, so its output is validated before it is written. **(3) Cursor** — `.cursor/mcp.json`, a file dedicated to MCP, so a rewrite cannot clobber unrelated settings. **(4) VS Code** — `.vscode/mcp.json`, whose top-level key is `servers` and not `mcpServers`, which is the most common integration mistake and which this repository already gets right in recipe 9. **(5) Gemini CLI** v0.56.0. **(6) JetBrains Junie** — the cheapest writer on the list and the only one reaching the JetBrains population. **The engineering consequence, which is the survey’s real finding:** one template with a swapped key is *impossible*, because the working-directory and variable-expansion matrix is asymmetric across all six. Claude Code has **no `cwd` field at all** — zero occurrences in its whole MCP page — and offers only a variable set in the *server’s* environment, which independently vindicates F-D44: under Claude Code there is genuinely no way to pin a server’s working directory from configuration, so `--policy` is not a nicety. Cursor has no `cwd` either and pins with its own workspace variable; Codex, VS Code and Gemini have `cwd` but document expansion differently or not at all; Junie has neither. **Half of them would silently attach the wrong policy under a shared snippet** — which is F-D44’s failure, once per client. **Generic-only, and why the cheap-looking ones are not free:** opencode has the highest star count found anywhere and its configuration is the user’s whole-product file in a commented dialect, so an idempotent rewrite needs a comment-preserving editor; Zed the same, plus an open bug that makes project-scoped servers silently do nothing in multi-root workspaces — and a one-command flow that silently does nothing is worse than a printed snippet; Cline’s only documented path is user-scoped and the extension path embeds the host editor’s name, so deriving it is guessing; Continue is the cleanest write target found anywhere and its format has churned three times; Goose is mid-move, with its documentation renamed and open issues about whether its config file becomes a directory; Crush stores configuration as executable shell, which cannot be idempotently rewritten at all. Qwen Code is the Gemini schema with one path constant changed and is the first promotion if a seventh slot opens — held back only because its release endpoint returns a tooling tag rather than a version, so no “verified against” line can be written. **Rejected outright**, on evidence rather than taste: Roo Code and Void are archived read-only; Windsurf is retired as a brand and its MCP page now says so of itself, so it is struck from the generic text too; Aider has 48k stars and no MCP implementation at all, which is the clearest illustration in the whole survey that stars are not a liveness signal. **Three rules that follow and are binding on the implementation.** Never emit Gemini’s `trust` flag — it bypasses every tool-call confirmation, which for a server whose tools boot microVMs is exactly backwards, and it is precisely the field a later “make setup smoother” change would reach for. Read the *installed* binary’s version rather than assuming the latest, because package managers lag npm by as much as ten minor versions. And `connect` must print the per-client follow-up, because at least three of the six hold a newly written server behind a trust or approval gate — a command that writes a file and says “done” would be lying on half the list. **And the maintenance clause the compatibility document has to carry:** there is no universal standard coming. The proposal for one was opened in February, drew no maintainer response, and was never accepted. Per-client writers are permanent infrastructure, not a bridge — so client formats are *external* surfaces, re-verified on their own cadence, explicitly outside the drift gate and outside the semver promise. Two of the six cannot anchor a version string at all and must be stamped with a date and the documentation URL as fetched.

**Why:** P6-13, and a required clause in P6-14. The product owner’s addition of 2026-08-24. F-D44 for why the policy path is explicit; F-D48 for why the surface is `serve-mcp`. Sources, versions and fetch dates are recorded per client in the P6-13 working notes. *Revisit when* any supported client’s format moves — the highest-probability move on the list is Gemini CLI’s, whose successor already uses a different file in a different place, with no deprecation announced and no end-of-life date.

## D42

*2026-08-24*

**The disclosure channel is GitHub’s private vulnerability reporting rather than a published address, and the scanner runs on a schedule because the failure it guards against needs nobody to do anything.** *The channel.* Three documents told a reporter to contact the maintainer privately and none said how. The fix is not an email address: an address in a public file is a permanent spam target, GitHub’s channel authenticates the reporter and needs no inbox published — and, decisively, publishing the maintainer’s personal address is his call and not this seat’s. [BLOCKED — needs John: enable private vulnerability reporting on the repository (Settings → Security, or `PUT /repos/ikapa-dev/kelyfos/private-vulnerability-reporting`). It reads `{"enabled":false}` today. It is one toggle, it is reversible, and unlike immutable releases it locks nothing and commits to nothing.] *So `SECURITY.md` is written to be true either way*, which is the part worth copying: it names the button and its URL, and then says plainly that if the button is not there the channel is not enabled yet — and what to do instead, which is a public issue containing *only* a request for a private channel and no details at all. A document that would be wrong on the day it lands is the failure P6-1 spent a commit undoing. *What the document is actually for.* The reporting instructions are the short half. The long half is **what is and is not a vulnerability here**, and this project can write that with unusual precision because it already publishes what it does not defend: an agent being root in its own guest, the chroot not being the boundary, the VMM sharing the invoking user’s uid (D29), anything the policy permits, `--no-jail`, a pre-v0.9 snapshot restoring unconfined, side channels, and — stated rather than hidden — the unsigned artifacts, which this repository says about itself in four places. Against that, the in-scope list is sharp: a guest→host path that is not a VMM zero-day, any way to read a bound secret’s value from inside a guest, any way to write or forge the record, egress leaving the allowlist, a team edge unenforced, and *a record that overstates the walls that were around a run*. *No response time is promised*, deliberately. This is a solo project and a number nobody can keep is worse than no number; what is promised is a plain answer, including a plain disagreement. *The scanner.* `govulncheck`, pinned at **v1.7.0** — and the pin is read from the module proxy, not from GitHub releases, which stop at v1.1.4 in January 2025: the familiar page would have pinned a scanner nineteen months stale and called it current. It runs through `make vuln` so a developer and CI run the same scanner at the same version rather than two invocations that drift, and it lives in its own workflow on its own day, because ci.yml’s Monday cron means “the build does not secretly depend on a cache” and cookbook.yml’s Tuesday means “the recipes still run”, and a third meaning in either would muddy both. *Two choices inside that, made rather than defaulted.* It does **not** run on every push: a scan of an unchanged dependency set against an unchanged database repeats the last answer, and a network call to `vuln.go.dev` on the hot path of every commit buys nothing — so it runs on the schedule, on a change to `go.mod`/`go.sum`, and on demand. And a finding **fails the run** rather than opening an issue: everything in this product is fail-closed, an issue-opening step needs write permissions and is a moving part that can break quietly, and a red run on a repository whose main is otherwise green is the loudest signal available for free. *The consequence, stated because it is real.* Under §8 rule 8 a red run is a blocker fixed before any new task — so an advisory against a transitive dependency will stop feature work. That is the correct answer for a project that ships a security boundary, and it is better said now than discovered on a Wednesday. Rule 8 is amended to say so in as many words. *Noted, not done:* Dependabot security updates are also disabled on the repository. That is a second owner toggle and a different kind of thing — it opens pull requests rather than reporting — so it is recorded for John rather than folded in here.

**Why:** P6-2. The `govulncheck` discipline this promotes has its own evidence trail: PLAN.html records it catching GO-2026-5024 in `x/sys/windows`, and ten or more clean runs at gates across both plan documents. D29 and the threat model for the scope section. *Revisit when* the compatibility promise (P6-14) exists and can say more than “the latest release is the supported one”, and when there is more than one maintainer to promise a response time on behalf of.

## D43

*2026-08-24*

**The trust boundary for fuzzing is declared as three sources, the runner discovers its targets instead of listing them, and the coverage claim names what it covers.** *Why a declaration was needed at all.* The instruction said “every untrusted-input parser”, which has no completion criterion: on one reading it is four functions and on another it is every `json.Unmarshal` in the tree. So the boundary is written down first and the target list follows from it. **Hostile:** anything a guest wrote (a guest runs whatever the agent decided to run); anything the network returned (an allowlisted domain is not a trusted one); anything arriving with a cloned repository or a download (`kelyfos.toml` is *meant* to be committed and cloned, which makes a policy file a stranger’s file). **Not hostile:** state KelyfOS wrote to its own cache for its own use — a corrupt sandbox state file is a bug worth fixing and is not an adversary, and calling it one would make the word mean nothing. *Two of the four targets the instruction named do not exist as described*, which P6-0 had already found: `internal/vsock` parses no bytes, and the MCP stdio protocol is `internal/proto` plus `encoding/json`. Retargeted rather than faked. *Discovery instead of an inventory.* `go test -fuzz` takes one target in one package per invocation, so something must enumerate them — and a list in a workflow file is a list that goes stale silently, which is why a guard test was the obvious answer. The better answer is to remove the list: `go test -list` reports fuzz targets, so `dev/fuzz.sh` asks the toolchain what exists. **Drift becomes impossible rather than detectable**, and the only failure left — discovering nothing and exiting cleanly, which looks exactly like success — is checked explicitly. *The claim is scoped, deliberately.* Sixteen targets is not “every parser”, and `docs/threat-model.md` now says which parsers rather than asserting totality, and names what is left out with the reason: the message types above the framing and the image manifest are the standard library decoding into typed structs, the exported report is `html/template`, and the MCP observer’s pairing is state rather than parsing. A list that reads as a boundary is worth more than one that reads as everything somebody got to — and this phase spent its first commit deleting claims of the second kind. *Where the harness could assert a property, it does.* Crash-freedom is the weakest thing a fuzzer can check. `Verify` and `Read` must agree about a chain; a credential must match the domain it was just bound to; an argument carrying content must never appear in the record verbatim; a shell-quoted string must survive a shell unchanged, checked against a reference unquoter rather than by spawning one. Four of the seven defects found came from those assertions and would not have come from waiting for a panic.

**Why:** P6-3. The four-target brief in this document’s Phase 6 text, corrected here rather than implemented as written. F-D4 for the drift-gate pattern the discovery replaces; F-D16 for why the policy parser stays hand-rolled, which the `parse` extraction leaves untouched. *Revisit when* a parser is added on the hostile side that is not stdlib-shaped — the runner will pick up its target automatically, but the boundary paragraph is prose and only a person can extend it.

## D44

*2026-08-24*

**D36 is amended: the credential grammar carries an endpoint and not a method set, the guest’s request path is never recorded in any form, and call-binding leaves P6-4.** Written before the code, on an adversarial review of the design commissioned because P6-14 freezes this grammar — three independent critiques and a judge, every fatal finding re-verified here against the repository before it was accepted. *Cut: `+METHODS` in the spec string.* Three independent reasons, any one sufficient. The policy file **cannot carry it**: `internal/config/config.go` splits an array’s inner text on the comma *before* parsing quoted strings, so `secrets = ["T@h/p+GET,POST"]` fails to load and there is no escape — and widening that parser is what F-D16 argued against. `+` is a legal and ordinary path character, so an anchored suffix rule silently misreads `/search/A+B` as a method. And a method set is a second dimension on a surface about to be frozen. Scope-limiting by method is not abandoned; it needs a structured home (`[[secret]]`) rather than a corner of a string, and that is post-1.0 work with somewhere to live. *Cut: call-binding and single-use redemption.* D36 committed to them on the two paths where one process holds both the tool-call boundary and the proxy, and this amends that rather than quietly dropping it. They have no home in the string grammar, they are the part of the parked idea whose two blocking questions are still unanswered, and P6-4 is already carrying two security fixes it did not set out to make. The window they would close — a credential spendable between tool calls — stays open and stays named in `docs/networking.md`. *Cut, and this one removes a capability rather than deferring it: **the guest’s request path is never recorded***, in any field, in any form — not truncated, not hashed, not scrubbed. `docs/events.md` already promises exactly that of a credential’s *value*, and a path *is* the credential on more APIs than is comfortable: `api.telegram.org/bot<TOKEN>/…`, a Slack webhook, a Discord webhook. The record is append-only, outlives the sandbox and is meant to be forwardable. A withheld event says which secret, which domain and why not, and that is enough to diagnose without writing somebody’s token into a file they will send to someone else. *Chosen: a new event type rather than new event fields, and the reason is measured.* A chain written by a binary whose `Event` struct has one more field makes an *older* binary report `event N has been modified` — the hash preimage is the marshalled struct, and a verifier drops the key it does not know before re-serialising. That is tamper-detection firing on a legitimate record, which is the loudest false alarm this product can produce. **So `docs/events.md` §3’s “adding a field is not breaking” is false**, and the fix — hashing a canonical form rather than the struct — is added to P6-6 and must land before v1.0 freezes anything. *The grammar that survives:* `NAME@host[:scheme][/path]`, split on the first `/` *before* any sigil is looked for, so nothing in a path can be mistaken for anything else; the scheme parsed exactly as today so `:BEARER` keeps working and `:8080` stays a loud error; the host normalised and the path never touched, because hosts are case-insensitive and paths are not.

**Why:** P6-4, amending D36. The adversarial review of 2026-08-24 and this seat’s own verification of each finding — the toml comma, the second spec parser in `host/teamplan.go`, the record promise, and the cross-version hash break, each reproduced before being accepted. *Revisit when* `[[secret]]` exists: methods and call-binding both belong in it, and neither needs the string grammar to change.

## D45

*2026-08-24*

**An independent external security audit is received, and v1.0 does not tag until its trust-boundary group is closed and proven.** 23 findings against `babec8f` — 1 critical, 6 high, 9 medium, 7 low — from a static-analysis pass outside this project. The product owner’s ruling of 2026-08-24, recorded here with its plan rather than acted on quietly, because a phase whose thesis is “no claim this project has not earned” cannot absorb an audit informally. *What it found, and why it lands hard.* C-1 is a guest-authored ext4 dirent turning `debugfs rdump` into an arbitrary host file write as the invoking user; it has been reproduced independently, outside the product. H-1 is `write_file`/`read_file` validating no path and handing back `/dev/vda` and `/dev/vdb` — the block devices the Landlock profile withholds — because PID 1 is not confined by it. H-2 is guest-authored file modes surviving the write-back onto the host. The three are one defect: **the workspace block device is a guest→host surface and §5’s trust-boundary table does not list it**. The table listing `guest → host` as “Firecracker + KVM” is true of the VM and silent about the disk the VM writes and the host then reads, which is the surface an agent actually has. *The gate.* No v1.0 tag until C-1, H-1 and H-2 are closed and proven, fixed in the report’s two-layer shape: **validate and refuse rather than sanitise** on any name carrying `/`, `\0`, `.` or `..`, **and** extract beneath a pinned root with `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` semantics — two layers because a boundary held by one check is a boundary one mistake from gone. The workspace device joins the table. The boot and restore bars are re-earned if the extraction path moved the timing. *The order, and why fixtures come before fixes.* P6-21 takes M-3 first: six lines, and live data loss in the *default* `--review` flow. P6-22 builds `testdata/hostile/` and its CI job **before** any boundary fix, seeded with the nine KVM-free fixtures the report enumerates, each a failing test before it is a fixed one. That is the finding under the findings: this project has nineteen fuzz targets and, until P6-6 put one on a file a stranger sends, every single one fed a parser a *host-authored* string. None was a guest→host path, and the guest is the untrusted party. A hostile corpus is what stops the list regrowing. *The triage rule.* P6-23 gives every finding one of four verdicts — `CONFIRMED-against-current-code`, `ALREADY-FIXED-since-babec8f`, `STALE`, `WONTFIX` with its reason — re-checked against **HEAD and not against `babec8f`**, since the tree has moved and H-6 is already partly fixed. **Nothing is fixed that was not first reproduced or read as present in current source.** An audit is evidence, not an instruction set, and fixing a finding one cannot find is how a codebase acquires changes nobody can explain. *The blocking set beyond the boundary group* is the exhaustion clamps a hostile agent can reach: H-3 (an unbounded `timeout_ms`), H-4 (a store that accounts no keys and cannot delete one), H-5 (a record writing a body where a digest would do, and describing before it checks), H-6 (a missing ceiling and bearer token, partly moved since the audit read it) and M-9 (no total-output ceiling). Each is small; each is a host-side denial of service driven from the untrusted side. **Not blocking**, and ahead of the trivia because both are claims the code does not keep: M-2, where `fork` applies no CPU quota and bypasses a documented hard ceiling, and M-5, where an agent name reaches the kernel command line. The rest — M-1, M-4, M-6, M-7, M-8, every `L-*` and D-1 — is batched into P6-27 or parked with a reason. *Documentation last, deliberately.* Every overstatement the report lists is corrected in P6-1’s spirit, **as each underlying fix lands and not before it**, the README’s “Both layers exist now” included — untrue of the host-side workspace path until C-1 is closed. A document that claims a fix which is not in yet is the exact defect P6-1 spent a commit removing, and doing it in the wrong order here would re-introduce it while nominally fixing security.

**Why:** The product owner’s ruling of 2026-08-24, on an external audit of `babec8f`. Tasks P6-21 through P6-27, inserted before P6-7 because list position is work order. C-1 reproduced independently outside the product; H-1, H-3, H-4 and M-5 confirmed against current source by the owner; H-6 partly fixed since `babec8f`. *Revisit when* the boundary group is proven: the gate lifts on evidence, not on the tasks being ticked.

## D46

*2026-08-25*

**Seven findings triaged against HEAD, and two of them do not say what the audit said they say.** The first instalment of P6-23, recorded now because two of its verdicts change what the blocking set contains and a fixture written to a wrong sentence asserts a wrong thing. Each was read in current source and reproduced by driving the real code in-process; none was accepted on the report’s wording. *CONFIRMED-against-current-code.* **H-1** — `write_file` and `read_file` pass the agent’s path to the operating system with nothing between: `grep` for `filepath.Clean`, `IsAbs` or `IsLocal` across `supervisor/` returns nothing, and PID 1 is unconfined because `applyLandlock` is reached only from the re-exec’d `--confine` helper. **H-3** — unclamped at three independent hops; `broker.go` has a floor and no ceiling, and **nothing in the tree calls `Broker.Serve` at all**. **H-4** — a store key is validated nowhere on the path from the guest, there is no accounting and no `Delete`. **H-5** — `describe` captures the body on the *refused* path, beside the digest that would have done. *And two corrections, which are the reason this entry exists rather than waiting for the rest.* **H-6 is not partly fixed.** The instruction carried that it was; the tree says otherwise. `git diff babec8f..HEAD -- shim/` is five lines, all of them `OnScrubbed` audit wiring, and `host/shim.go` and `docs/e2b-shim.md` are byte-identical to the audit’s base commit. Both halves — no ceiling on concurrent sandboxes, no bearer token — are present, measured. **M-9 as worded is already fixed**, by `ac8968f` in P6-3, after the audit read `babec8f`: there *is* a total-output ceiling. But the rest of that finding’s own sentence is live and worse than the half that was fixed — the ceiling counts **bytes**, so a guest sending frames that carry none, and never sending `StreamExit`, makes `sandbox.Exec` never return. The `timeout` argument is not a host-side deadline; it is a number mailed to the untrusted party. Four hangs reproduced in-process. *What changes.* M-9 stays in the blocking set under its true description — a host call that never returns, driven from the guest — and not under “no total-output ceiling”, which would have been a fixture for a defect that no longer exists. H-6 stays in the blocking set whole rather than half. Neither would have been visible to a triage that read the report instead of the code, which is what the “against HEAD, not against `babec8f`” rule is for.

**Why:** P6-23, first instalment; the remaining sixteen follow. Every verdict here was reproduced by driving the real code in-process, KVM-free, and the reproductions are what P6-22’s fixtures are built from. *Revisit when* the rest are triaged: two corrections in seven is a rate worth remembering when reading the other sixteen.

## D47

*2026-08-25*

**M-2 and M-5 confirmed, the triage closed at eleven of twenty-three, and the rest blocked on text this seat does not have.** *M-2 — CONFIRMED.* `host/fork.go:91` builds `sandbox.Options{Arch, Flavor, Quiet}` and nothing else; `NewCPUSlice` appears in `run.go` and twice in `team.go` and **nowhere in `fork.go`**. A forked machine gets no CPU quota at all. The ceiling is documented as hard, and a ceiling that is not applied is worse than one never claimed: the claim is what a reader plans around. *M-5 — CONFIRMED, and it reaches further than the report says.* `bootArgs` writes `"kelyfos.agent="+agent` with no validation, and `NewTopology` checks only for an empty name and a duplicate one — no character is refused anywhere on the path. Measured: an agent named `worker init=/bin/sh` produces a command line carrying **two** `init=` parameters, and one named `w<tab>kelyfos.spawn=1` grants itself a spawn budget the host never gave it. The comment three lines above that `append` says the kernel command line is “the one thing inside the guest that the guest did not write”, which stays true and is beside the point: what writes it is a name from `kelyfos.toml`, and a team file travels — from a template, a repository, a colleague. **The spawn-budget injection is the half the report does not mention**, and it is a privilege escalation inside the team model rather than a curiosity about kernel arguments. *The state of the triage.* Eleven findings now have a verdict: C-1 and H-2 reproduced at P6-22, H-1, H-3, H-4, H-5, H-6 and M-9 at D46, M-3 fixed at P6-21, and M-2 and M-5 here. **Twelve do not, because their text was never provided** — M-1, M-4, M-6, M-7, M-8 and every `L-*` are known to this seat only as identifiers, along with D-1. They cannot be triaged and they will not be guessed at: “do not fix a finding you cannot first reproduce or read as present in current source” is the rule this instalment is written under, and inventing a plausible defect to match an identifier is the worst available way to break it. P6-23 carries the blocker with the exact ask. *What this does not change.* The v1.0 gate is the boundary group, and every finding in it has a verdict and a fixture. The blocking set beyond it — H-3, H-4, H-5, H-6, M-9 — is triaged whole. Nothing waiting on text is in either.

**Why:** P6-23, second instalment. M-2 read in current source; M-5 measured by driving `bootArgs` in-process — `init= count: 2`. **Needs John:** the audit’s text for M-1, M-4, M-6, M-7, M-8, L-1 through L-7 and D-1. *Revisit when* it arrives: three of the eleven triaged so far did not say what they were reported to say, so the remaining twelve are worth reading rather than assuming.

## D49

*2026-08-25*

**The documentation audit found eighteen defects in the code, and they are routed rather than folded in.** Reading a sentence against the code that implements it answers two questions, not one: whether the sentence is true, and whether the code is. E3-0 turned up four of the second kind; this run turned up eighteen, and three of them are this task’s own business rather than a routed finding. *Fixed here.* Two stale `reason` lists in `internal/recorder/schema.go` — the `team.store` list was missing `key_too_long` and `too_many_keys`, and `session.start`’s said “restore and fork” when the shim, a `serve-mcp` server and a team all write it. Those drive the **generated** reference, and P6-15’s own rule is that a finding against a generated page is a finding against its generator. And the release workflow’s `rm -f dist/kelyfos-linux-*`, which left both matrix jobs uploading the same two macOS filenames into a merge that had to pick one; the shipped bytes were right only because the publish job rebuilt them afterwards. *Routed to P6-28.* The other fifteen are code changes with their own blast radius, and folding them into a documentation commit would make the diff unreviewable and the record dishonest about what was changed and why. The sharpest is `host/shell.go`: a supervisor that dies mid-session is reported as `shell exited 0`, which is a success a script will believe — and `docs/protocol.md` §5.7 and `proto.ShellExit`’s own doc comment both already say otherwise, so this is the code disagreeing with two of its own specifications rather than an undocumented gap. *The ruling that produced them.* The audit was told to read documents against **code** and never against other documents. Every one of these eighteen is a thing the other version of this audit — the tidy one, where the documents agree with each other — would have reported as fine.

**Why:** P6-15. The eighteen are in `dev/docs-audit-2026-08-25.md`, each with the file and line that proves it. *Revisit when* P6-28 runs: the shell exit-code one is a correctness bug in a shipped command and should be first.

## D50

*2026-08-25*

**`CHANGELOG.md` is the source the release notes are cut from, not a mirror of them.** P6-16 had to settle this once, and the alternative loses on this project’s own terms: a changelog that mirrors release bodies written in a web form is a second copy of the truth that nothing keeps honest, which is the exact failure the generated reference exists to prevent. The release notes for v0.3 through v0.9 live today *only* as GitHub release bodies — outside the tree, outside the drift gate, and three of them carry commitments this project treats as binding. *What makes it a source rather than an intention.* The release workflow no longer writes its own notes. It runs `tools/changelog.py <tag>`, which cuts the section matching that tag out of `CHANGELOG.md`, and **exits non-zero when there is no section** — so a tag with no notes fails the release rather than publishing an empty one. The provenance boilerplate is appended underneath rather than replacing it. `tools/changelog.py --check` runs in CI on every commit and fails when a published tag has no section, which moves the cost from publish time to push time. *The heading matches the tag on a word boundary*, so `v0.1` does not match `v0.10` the day that exists, and `## Unreleased — v1.0` is publishable the moment it is tagged without being renamed first. *What this does not do.* It does not backfill the eight existing GitHub release bodies to match the file — they are what was published and rewriting them would be editing the past. The changelog records the same releases in this project’s own words, and from v1.0 the two are the same text because one produced the other.

**Why:** P6-16. `tools/changelog.py --check` covers all 10 published tags; a tag with no section prints the fix and exits 1, proved against `v9.9`.

## D51

*2026-08-25*

**§1 criterion 5 is re-worded, and backed by a fourteenth acceptance suite that drives HTTP rather than an SDK.** P6-18 required this to be decided rather than to pass unexamined, and both options the task offered were checked against the world before choosing. *Why not a pinned SDK suite.* The E2B Python SDK went 2.41.0 → 2.45.1 between 19 and 21 August 2026 — five releases in three days. Pinned, such a suite proves compatibility with a version superseded within the week and then quietly stops meaning anything; unpinned, it hands a third party the ability to turn this project’s `main` red on their release schedule. `docs/compatibility.md` §3 already places the shim outside the promise for that reason, and a suite that contradicted it would be the project arguing with itself. *Why not simply re-word and cite what exists.* What existed was one hand-run in August against an SDK that has since moved, which is not evidence about the SDK anybody would install today. Re-wording alone would have swapped an unmet criterion for an unfalsifiable one. *So: both halves, honestly split.* `dev/accept-shim.sh` tests the half this project owns and can keep true — `/health`, `POST`/`GET /sandboxes`, `DELETE /sandboxes/{id}`, `GET`/`POST /files` including a 4 KiB binary round trip, the 501 that names what to use instead, and the flight recorder each shim sandbox gets — over a real socket, against real microVMs, with no SDK installed. **23 checks, all passing.** It runs in `caps`, on the bare-KVM reference. The criterion now says what that proves. *And it corrected a document on the way.* `docs/e2b-shim.md` told a reader to export `E2B_SANDBOX_URL`, which the current SDK’s connection config does not read. It reads `E2B_API_URL` first, falls back to `E2B_DOMAIN` — a *domain*, from which it composes `https://api.{domain}`, so it is not a substitute for a URL pointing at plain HTTP on loopback — and `E2B_DEBUG`, which defaults to `http://localhost:3000` and happens to be this shim’s own default address. Verified against the SDK’s source rather than its reference page, which omits `E2B_API_URL` entirely.

**Why:** P6-18. `bash dev/accept-shim.sh` — 23 passed, 0 failed, against real microVMs. *Revisit when* the SDK’s configuration moves again: the paragraph in `docs/e2b-shim.md` is what goes stale, and the suite is what does not.

## D52

*2026-08-25*

**A stopped agent keeps its mailbox, and that is left alone rather than repaired.** Fourteen of D49’s fifteen defects are fixed. This one is confirmed and deliberately not, because every available fix is a decision about what a team *is* rather than a repair to code that misbehaves. *What happens now.* Nothing removes a **declared** agent’s mailbox when its VM stops: `max_runtime` calls `crew.remove` and `rig.stop` and no broker call at all, and `Despawn`’s spawner lookup only ever resolves for a worker that was *spawned*. `broker.deliver` consults the topology and the 64-slot channel and nothing else, so `team_send` to a stopped member is recorded `delivered` until the slots fill. *Why not simply despawn it.* A declared agent is in the `[team]` graph; a spawned worker is not. Removing a declared agent’s mailbox on stop makes the topology mean something different from what the policy file says, and it would make a `team_send` to an agent that is merely *restarting* fail where it currently queues. The other direction — refusing the send — needs a liveness notion the broker does not have and cannot get without asking the host about every recipient on every message. *What is done instead.* The behaviour is written down where a reader meets it: `docs/teams.md` §3.1 says a message to a stopped agent is recorded `delivered` until the sixty-four slots are full, that a dead agent’s mailbox is never drained, and that an agent needing a message to arrive should ask for an answer rather than assume. A documented bound beats an undocumented one, and this is a v1.x decision rather than a v1.0 defect.

**Why:** P6-28. Confirmed at HEAD: `host/team.go`’s `max_runtime` path, `internal/team/spawn.go`’s `Despawn`, `broker.deliver`. *Revisit when* a team gains any notion of a member being down — the fix costs nothing once that exists, and cannot be made honestly before it.

## D53

*2026-08-25*

**Immutable releases: ON, and it still never shares a sentence with provenance.** The owner enabled it. It locks published assets and protects tags, which is a commitment rather than a toggle, and that is the point: a stranger who downloads a v1.0 artifact can know GitHub received those bytes under that tag and nobody has replaced them since. **What it does not say, and what D39 forbids implying.** Immutability carries *no builder identity at all*. It does not say which workflow built the bytes, or from which commit, or that anything built them rather than a laptop. Build provenance is the separate statement `actions/attest` makes, and the two must never appear in one sentence — a reader who merges them concludes that “immutable” means “traceable to source”, which is exactly false. Every document that mentions either keeps them in separate paragraphs with their own verbs.

**Why:** Owner action, 2026-08-25. The wording rule is D39’s and is unchanged; this decision records that the setting is now on so the documents may stop saying “not enabled”.

## D54

*2026-08-25*

**Dependabot security updates: ON, as its own consent.** Deliberately not folded into P6-2 when the rest of the supply-chain work was done. The distinction is that Dependabot does not *report* a vulnerability — it **opens a pull request**, authored by a bot, against a repository whose workflows boot microVMs. Agreeing to be told about a vulnerable dependency and agreeing to receive machine-authored branches are different agreements, and this project takes the second one explicitly. *What follows from it* is P6-30: a bot branch must not reach the KVM workflows. Those are `workflow_dispatch` and `schedule` only, which is what keeps untrusted branches off a runner that boots VMs, and a Dependabot PR is not a reason to widen that.

**Why:** Owner action, 2026-08-25. P6-30 carries the work.

## D55

*2026-08-25*

**macOS ships raw and unsigned for v1.0, and says so where somebody will hit it.** There is no Apple Developer identity for this project today, so the darwin binaries in a release are unsigned and unnotarized. Gatekeeper quarantines a binary downloaded from a browser and refuses to run it, with a message — *“cannot be opened because the developer cannot be verified”* — that reads like a broken download rather than a missing signature. *The ruling is to ship it anyway and document it plainly*, because the alternatives are worse: not shipping a macOS binary makes `kelyfos verify` unreachable on the machine reports are most often sent to, and shipping it silently spends a first-time user’s goodwill on a dialog nobody warned them about. The documentation states the quarantine, gives the clearing step, and says the cause is an absent signing identity rather than a damaged file. *Post-1.0, with the condition named:* signing and notarization become a task the moment an Apple identity exists. That is the blocker, and it is an account and a fee rather than engineering.

**Why:** Owner ruling, 2026-08-25. P6-31 carries the documentation. *Revisit when* an Apple Developer identity exists.

## D56

*2026-08-25*

**The DCO is gated on new commits, and the gap in the history is stated rather than papered over.** `CONTRIBUTING.md` has required a `Signed-off-by` line since v0.1, and **zero of this repository’s commits carry one**. Three options existed: sign from here on and say nothing, rewrite history, or amend the document to drop the requirement. *The ruling takes the first and refuses the silence.* A CI check requires the trailer on new commits, and `CONTRIBUTING.md` gains one line saying pre-v1.0 history predates enforcement. Rewriting history was refused because it invalidates every existing clone and every commit hash this plan cites; dropping the requirement was refused because the DCO is the mechanism that keeps provenance auditable without a CLA (D5), and a project that abandons it the first time it is inconvenient has chosen the wrong one. *The convention is the one this project already uses*: a claim it intends to earn is written down as false until it is true, rather than removed until it is convenient.

**Why:** Owner ruling, 2026-08-25. P6-29 carries the work.

## D57

*2026-08-25*

**The remaining thirteen findings triaged against HEAD: twelve confirmed, one already fixed, and the audit inaccurate about something in *all thirteen*.** The owner supplied the text on 2026-08-25 and the triage was run the way D46 and D47 were: read the named line in current source, confirm the mechanism rather than the neighbourhood, then have somebody else re-read the verdict. No verdict was disputed. **The pattern is the one that made reading them worth insisting on.** Every defect but one is real, and every report is wrong about some part of it — usually the part a fix would be built on. *M-1* says `host/team.go` is “the one site that does it right”; there are five sites and three are correct, and the right oracle is `servemcpstate`’s `b.close()` rather than team’s inline call — both leaking sites already own a correct `close()` and hand-roll a subset of it instead. *M-4*’s race is real but far narrower than stated, because both timers call `crew.remove` *before* `rig.stop` — and the consequence it omits is worse than the one it names: the collision can delete the person’s actual project directory rather than a staging tree. *M-6* joins two independent defects as cause and effect; the mailbox wipe it leads with is not reachable at HEAD, while the collision it undersells hands a spawned worker the declared agent’s **entire edge set**, contradicting the one-edge guarantee in `docs/teams.md` §5. *L-3* names the wrong casualty: on stock cloud images a /32 host route wins on longest prefix, so the host’s metadata keeps working and the **sandbox** is what breaks. *L-6* is off by one against HEAD, because P6-21’s “keep `.kelyfos-previous`” changed the arithmetic without closing the hole — the *third* diverted run destroys the first’s output, not the second. *L-4*’s proposed fix would leave a second instance of the same bug untouched, because the path is adopted *before* it is verified. *D-1* is accurate in every claim and wrong about scope: a worse, filesystem-independent variant is live, because a jailed restore points the workspace into the run directory. **L-2 is already fixed**, by C-1’s rewrite in P6-24 — and its proposed fix would not have worked, since one request per line was already the shape and `debugfs`’s parser splits on whitespace regardless. It was a v1.0 blocker and it closed as a side effect of the boundary work. **What this settles about the audit as a whole.** Across all twenty-four findings now read, the score is the same: the defects are worth having and the descriptions are not load-bearing. Reading each one against current source before touching anything was the right rule, and it is the reason nothing was fixed here from a description alone.

**Why:** P6-23, third and final instalment. 12 CONFIRMED, 1 ALREADY-FIXED, 0 disputed by the second reader. Severity for v1.0: 10 should-fix, 2 latent-edge (L-4, D-1), and L-2 which blocked and no longer exists. The fixes are P6-27, which is where the corrections that reach documents ride the same commits.

## D58

*2026-08-25*

**The three Dependabot pull requests are held until v1.0 ships, and the reason is what the release candidate is for.** They arrived within minutes of D54’s toggle: `upload-artifact` 4→7, `download-artifact` 4→8, `setup-go` 5→7. All three are green on every check this repository runs. *Green is not the same as safe here.* CI does not run `release.yml`, and `release.yml` is the only workflow that uses `merge-multiple` — the step that merges two matrix jobs’ artifacts into one `dist/` before the sums file is written over it. The input survives in v8, so the interface is compatible; the *behaviour* around it is not unchanged. v8 stops unzipping by Content-Type rather than always, and makes a digest mismatch a hard error where it used to warn. Both are improvements and neither has ever run on this project’s release path. **A release candidate exists to prove the exact path the release will take.** rc1 and rc2 were built with v4. Merging a major bump of the artifact actions after them would mean tagging v1.0 on a path no candidate has exercised, which is the failure this whole phase is built to prevent — and it would do it for a Node runtime deprecation warning, not a vulnerability. *So: after v1.0, and with an rc of their own.* The bumps are wanted; the ordering is the decision. *And one thing they settled that was worth knowing.* P6-29’s DCO gate was expected to block every bot pull request, since a bot cannot certify origin. It does not: Dependabot signs its own commits with a `Signed-off-by` trailer, so all three pass the gate on their own. That was checked against the real branches rather than assumed — the assumption was wrong in the safe direction.

**Why:** P6-30. PRs #1, #2, #3. *Revisit when* v1.0 is tagged: merge them, then cut an rc that runs the release path with the new actions before anything else is tagged.

## D59

*2026-08-27*

The declared policy of a run enters the flight recorder, and the views read it. Two additive event types — `session.policy` and `team.topology` — record what a machine and a team were permitted to do alongside what they did: every resource cap, the allowlist and its ports, bound credentials by name, the workspace, the tool surface, the image digest, the parent session, the edge list, the store ACLs and the fork lineage. A single fold (`internal/digest`) replaces the two that exist. The run map, the agent sheet and the reach matrix are then built as readers of that fold, in `kelyfos watch`, `kelyfos team ps --graph` and the exported report, with `--json` and an OTLP export as the outward surfaces. Opened as Phase 7 here rather than in PLAN-FEATURES.html, which is closed — F-D56’s redirect. **Encoding, decided by John on 2026-08-27 and not to be reopened by P7-0:** typed fields appended to `Event`’s frozen order, not compact JSON inside one string. It costs roughly twenty fields of struct surface and buys three things a string cannot: `tools/gendocs` generates a row for each, `TestSchemaFieldsExist` covers each, and a consumer filters without parsing twice. On a project whose stated thesis is that the schema is the product, the string is the cheaper thing to write and the worse thing to have shipped. **Boundaries.** `kelyfos team graph` reads `kelyfos.toml` and is a pre-flight lint in the category of `doctor`, not a monitor. The OTLP and audit-trail mappings are one-way, versioned apart from the chain, and never inputs to verification — both specifications they track are still moving (`gen_ai.*` is Development-status with no timeline; the IETF agent-audit-trail draft is an individual submission at `-01` expiring February 2027) and this record’s field order is hashed.

**Why:** The record holds behaviour and not policy, so a finished session cannot show its own caps, allowlist, image digest, topology, or a credential bound and never used. Putting the declaration in the chain is also what keeps every view a reader of the JSONL, which is D7’s line: `kelyfos.toml` is a file the user can edit afterwards, and `run/team.json` does not outlive the run. Six of the ten OWASP Agentic risks published 2025-12-09 are questions this record can then answer and today cannot; EU AI Act Article 12 came into force 2026-08-02 and asks for exactly this kind of recording.

## D60

*2026-08-27*

**The “no web dashboard” non-goal is renegotiated, by name, and narrowly.** Decided by John on 2026-08-27, which is the renegotiation PLAN-FEATURES §2 requires and D7 anticipated. `kelyfos view` (P7-12) is admitted: a *localhost read-only viewer*, which D7 already named as the absolute ceiling. What stays forbidden is unchanged and is restated here so the boundary does not drift: no fleet view, no persistence beyond the session files that already exist, no authentication system, no hosted service, and **no route on any page that can change a sandbox** — D7’s litmus test stands, and this is a reader. The demand condition D7 attached is *waived by the owner* rather than met: the repository had no community signal to read, and waiting for one would have parked a designed feature indefinitely. That waiver is the decision, and it is recorded as a waiver rather than dressed up as evidence.

**Why:** The security conditions in P7-12 are binding parts of this decision, not implementation notes: loopback only with no relaxing flag, a per-process token compared in constant time, a `Host`-header check against DNS rebinding, GET and HEAD only, a hash-pinned CSP, no `innerHTML`, a read-only file handle and an idle exit. Chrome 142’s Local Network Access prompt now gates public pages reaching loopback, which helps and changes nothing: it is one browser’s behaviour rather than a property of this server, and it does nothing about the other processes on the host. The honest residual is that loopback is shared with every local user, so the token separates them and the interface does not.

## D61

*2026-08-27*

Retention, pruning and tombstones are adopted as P7-5 rather than left as a papercut. A retention floor in `kelyfos.toml`, `kelyfos sessions prune`, a size warning, and an erasure path that writes a replacement record preserving chain integrity while keeping a content fingerprint.

**Why:** The session directory has never been pruned — the template cache has a bound and the records that outlive every sandbox do not — and the obligation this answers came into force on 2026-08-02, not at some future date: EU AI Act Article 12 requires automatic, tamper-evident recording, with a floor read alongside GDPR at twelve months from session close for Annex III systems and six for general-purpose, and Recitals 99 and 100 extend the boundary to every agent in a chain performing a high-risk function — which is per-agent records, which D59 supplies. KelyfOS shipped the tamper-evident half in v1.0 and has no retention policy at all, which is half a compliance story told confidently. The tombstone pattern is taken from the IETF agent-audit-trail draft and is cheap here for a reason particular to this design: `file.write` already records by digest rather than by content, so proving what was there without keeping it is native. It also dissolves a tension this plan had written off as unresolvable — that redaction breaks the verification that makes an export worth forwarding.

## D62

*2026-08-27*

**Phase 7 is worked by several agents in four lanes, which is a deliberate deviation from §8 rule 1.** Rule 1 takes work top-down by list position and assumes one worker. The lanes and the barrier: **Lane 1, the record** — P7-0, P7-2, P7-3, P7-5, *one agent, strictly serial*; **Lane 2, the fold** — P7-1, owning `host/watch.go` and `internal/report` until it lands; **Lane 3, the layout** — P7-6, a new package with no shared files; **Lane 4, the defects** — P7-4. Nothing in the second half starts until P7-1, P7-2, P7-3 and P7-6 are ticked *in this file*; a tick is the signal and a green local build is not. Then P7-7 and P7-8 in parallel, then P7-9, P7-10 and P7-11, then P7-12, then P7-13 last and by an agent that wrote none of it.

**Why:** Lane 1 is serial for a reason that is not scheduling: `Event`’s field order *is* the order the hash is computed over, so two agents appending fields concurrently produce two different orders and a chain neither can verify. That is why nobody outside Lane 1 opens `internal/recorder`. The lane boundaries are drawn on file ownership rather than on subject matter, which is what makes them enforceable: Lane 2 owns the two folds, Lane 3 owns a package nobody else imports yet, and Lane 4’s only overlap with Lane 1 is `host/team.go`, which is named so it is coordinated rather than discovered in a conflict.

## D63

*2026-08-27*

**§8 gains rule 10: verified by somebody who did not write it.** Every task touching the record, the proxy, the broker or a renderer is reviewed before its checkbox is ticked, by an agent that did not write the diff, adversarially and against the source rather than the description. The reviewer reports and does not push; the author fixes. Findings go in the Progress Log *including the rejected ones and the reason*. Four per-surface checklists are written into the rule so the review is a list rather than a judgement. `make test`, `make vuln` and the touched fuzz targets are run by the reviewer. P7-13 adds the whole-phase read-back before the exit checkpoint.

**Why:** This phase is the wrong one to verify casually. It adds roughly twenty fields to a structure whose field order is hashed, two renderers fed entirely by strings a prompt-injected agent chooses, and — under D60 — a listening socket. Each of those has a failure mode that is invisible in a diff: a field inserted rather than appended still compiles; a renderer that forgets one escape still renders; a viewer missing its `Host` check still serves the page. The precedent is Phase 6, where an external audit’s value came from reading current source rather than trusting its own summaries, and where the hostile corpus was given a ledger so a fixture has to fail before it passes. Splitting authorship from verification is the cheap half of that; recording the rejected findings is the half that keeps the record honest, because a review that lists only its wins reads identically to a review that did not happen.

## D64

*2026-08-27*

**§8 rule 8 is satisfied by local verification, not GitHub’s CI, while Actions stays disabled for this account.** Every `workflow_dispatch` call against `ci.yml` and `security.yml` returns `HTTP 422: Actions has been disabled for this user`; neither workflow has run since 2026-08-25T15:24:05Z, and `commits/b55103f/status` reads `pending` with zero check-runs — not a red main, an unverifiable one. Owner’s decision, 2026-08-27: for this session, run the equivalent of both workflows by hand against `origin/main` inside `kelyfos-dev`, this project’s own Lima VM, and log the result as the CI reconciliation of record. Rule 8 itself is not amended — the substitution is scoped to the outage.

**Why:** Rule 8 exists because a clean tree is not a green build, and the failure it was written to catch (P5-1’s three-task-late discovery) does not care why CI cannot be trusted, only that it cannot be skipped. But rule 8 assumes CI *can* run; here it cannot, at the account level, for a reason no commit in this repository can fix. The choice was between declaring `main` permanently unverifiable until a billing or account setting elsewhere is corrected, or running the same checks by hand on the one machine `ci.yml`’s own comments already name as authoritative for aarch64 boot verification (“aarch64 is build-only here and boot-verified on the dev machine”). Evidence and its scope limits are in the Progress Log entry beside this row. Real CI reconciliation resumes the session Actions is restored.

## D65

*2026-08-27*

**P7-4’s second silence — every sandbox reaching ports 80 and 443 only, with `egress.Policy.Ports` unreachable from any caller — is closed by documenting the fixed pair and exporting it (`egress.DefaultPorts()`, `Policy.EffectivePorts()`), not by promoting `Ports` to a `kelyfos.toml` key.** The task text offered both as equally valid (“the default is right either way”); this session chose the narrower one.

**Why:** Nothing has asked for a sandbox that can reach an arbitrary port, and widening what every sandbox in this product can reach is a bigger, more security-relevant change than fixing the fact that the existing, correct default was invisible — the same reasoning D60 applied when it kept `kelyfos view` to a narrow admission rather than the broadest shape that would satisfy the ask. A real `ports` key would also need range/overlap validation, four call sites wired (`host/run.go`, `host/team.go`, `host/servemcptools.go`, `host/snapshot.go`), a `docs/reference/config.md` row, its own hostile-input tests, and its own line in `docs/threat-model.md` — a proportionate amount of review for a capability nobody has requested. The chosen fix stays inside P7-4’s actual defect: `egress.DefaultPorts()` makes the fixed pair a named, tested fact instead of two bare integers inside `allowsPort`, and `Policy.EffectivePorts()` gives P7-2’s `session.policy` and P7-7/P7-8’s views a correct value to read — `Policy.Ports` alone is `nil` for every sandbox this product has ever booted, and `nil` reads as “nothing permitted” rather than “the fixed default applies”. Reopenable if a real demand for configurable ports appears; nothing here forecloses it, since `Policy.Ports` still exists as exactly the extension point promoting a `ports` key would use.

## D66

*2026-08-27*

**P7-4’s first silence, when refused rather than wired in, narrows a §2-stabilised surface (the `kelyfos.toml` schema, pinned by `reference/config.md`) with no decision row and no CHANGELOG entry — the independent review caught this before it shipped. Ruling: it is not** a real narrowing under `docs/compatibility.md` §1’s definition of a major change, and ships as a hard refusal in v1.1, a minor release. The reviewer’s own precedent check found the citation P7-4’s author gave for this pattern — `checkAgentPolicy`’s `idle_timeout` refusal, `b009476` — predates the v1.0 tag (`16d04a9`), so it does not establish a post-v1.0 precedent for narrowing a stabilised surface; that citation is retracted as support for the pattern, even though the ruling below reaches the same outcome on its own reasoning.

**Why:** `docs/compatibility.md` §1 defines a major release as one where “a surface in §2 changed or was removed in a way that requires somebody to edit something”, and a patch as one where “the fix does not change a documented behaviour”. A `kelyfos.toml` combining `[team]` with `[[plugin]]` or `[[forward]]` parsed and booted before this fix — but booted a team in which the plugin advertised no tools and the forward opened no port, because `packPlugins`/`resolveForwards` were never called from the team path. No change of behaviour a caller could have depended on is being removed: the plugin was never launched, the forward was never open, so nothing that a script or a person built against this combination's *effect* can break, because there was no effect. What changes is only that `kelyfos team up` now says so at plan time instead of staying silent about it — the same class of change §3 already carves out for guest confinement profiles (“allowed to narrow in a minor release”, because “a profile that could not be tightened without a major release would be a profile nobody tightens”) and the same shape a security-driven narrowing takes under §4’s exception, even though this is a defect fix rather than a vulnerability. If a real user is found to depend on the old silently-broken behaviour — which would mean depending on a plugin or a forward doing nothing at all — that is a conversation to have in an issue, per the same standard §3 sets for profiles, not a compatibility guarantee this product made. Required and done as part of this ruling: this row, and a `### Changed` entry under `## Unreleased` in `CHANGELOG.md`, in the voice the S6-S24 entries already use there.

## D67

*2026-08-27*

**P7-14 added mid-phase: a real, narrow defect in path-scoped credential matching, found as a byproduct of P7-4's re-verification and unrelated to any of the four lanes' actual work.** `internal/egress/scope.go`'s `covered()` only strips one trailing slash off a bound `Scope.Path`, so a scope configured with a doubled trailing slash approves a request that a real origin server's own normalization would resolve outside it — confirmed by `FuzzScopeCovers` and independently re-traced by the orchestrator against the actual fuzz property, not taken on the author's report. Owner's ruling, 2026-08-27: track it as a new Phase 7 task (P7-14) rather than a standalone fix outside the phase or a logged-and-deferred item, since `internal/egress` is already phase-adjacent (P7-4 touches it) and the fix is small and self-contained.

**Why:** Same family as S3 and the general path-scoping discipline already in `CHANGELOG.md`'s `Unreleased` section — this is a boundary case that fix did not cover, not a new class of problem. Not gated by D62's barrier: it touches no file any of the four lanes own, and nothing else in Phase 7 depends on it landing before the barrier or before v1.1's exit checkpoint.

## D68

*2026-08-27*

**The door-enumerating test for `session.policy` runs two mechanisms, not the one `docs/policy-record.md` §9.3 literally describes.** The review that reopened P7-2 (F3) found `host/policy_wiring_test.go`'s existing test starts from `WithPosture` call sites rather than from `session.start`, so a hypothetical door that appends `TypeSessionStart`/`TypeSessionReady` directly, skipping `WithPosture` entirely, would pass it silently — proven with a scratch fixture. §9.3 asks for a single test enumerating the nine `session.start` sites. Rather than replace the existing test, `TestEverySessionStartSiteHasAMatchingSessionPolicy` is added alongside it, and both now run.

**Why:** The existing `WithPosture`-based test is not redundant: it is mutation-tested at per-closure granularity (it caught P7-2's own `broker.OnSpawn` gap) and would catch a door that calls `WithPosture` and then forgets `NewSessionPolicy` in some scope other than the top-level function — a shape the new, coarser-grained `session.start`-based test does not reliably distinguish. Replacing it to match §9.3's "one test" phrasing exactly would trade away real, proven coverage to satisfy a word count. Keeping both means a tenth door is caught two independent ways: skip `WithPosture` and the new test catches it; call it and forget the policy, in any scope, and the old one does. The new test itself needed a second correction while being written: an earlier version recognised call sites named only `NewSessionPolicy`/`agentPolicyEvent` as evidence of wiring, and failed for real on `host/fork.go`'s `forkCmd`, which reaches `NewSessionPolicy` two calls away through a third helper, `recordFork` — the identical hand-maintained-list shape F1 found in `clipLargestField`, one file over. Fixed by a transitive call-graph reachability walk (`reachesSessionPolicy`) instead of a fixed name list, so a helper added at any depth is covered without this test needing to know its name.

## D69

*2026-08-28*

P7-15 added mid-phase: `FuzzAppendFieldValues` reproducibly OOM-kills its own worker once its corpus grows past roughly 260 entries, found during P7-3's review and confirmed independently on `main`. Same disposition as D67/P7-14: tracked as a new Phase 7 task rather than a standalone fix or a logged-and-deferred item, since `internal/recorder`'s fuzz harness is already phase-adjacent and the fix is expected to be small and self-contained.

**Why:** Not a correctness defect — every fixed-length run of the target passes clean — but a real gap in test-suite reliability: a target that kills its own process on a grown corpus is indistinguishable from one nobody ran, which is exactly the failure mode §8 rule 8 exists to catch for CI as a whole, one target at a time. Not gated by D62's barrier: it touches no lane's feature code, only the fuzz harness itself.

## D70

*2026-08-28*

P7-16 added mid-phase: two independent adversarial reviews, in separate worktrees on the same development VM, each hit a different instance of concurrent teams colliding over host-level singleton state (`run/team.json`; shared session-cache mutation from one team's teardown affecting another's live run) — unprompted, while stage two's agents worked in parallel. Same disposition as D67/P7-14 and D69/P7-15: tracked as a new Phase 7 task rather than absorbed into either reviewing task or left as a note, since two independent, unprompted reports of the same class is a real pattern, not a one-off.

**Why:** The same failure class already cost a fix once, in S20 (`0b3dfb8`), for exactly one symptom of it (`demo-team.sh`'s own teardown check false-failing on a shared host). It has now resurfaced in two more places under a usage pattern this project did not have when S20 landed: several agent-driven teams running concurrently on one development machine, which this phase's own multi-lane, multi-reviewer structure made routine rather than exceptional. Not gated by D62's barrier: it touches no lane's feature code, only host-level state shared across sessions and teams.

## D71

*2026-08-28*

The twenty-one findings of the independent security review of 2026-08-28 (`SECURITY-REVIEW-2026-08-28.html`, read at commit `6e55190`) are remediated as one block, **P7-17**, ahead of the remaining Phase 7 tasks — a deviation from §8 rule 1’s top-down order, logged here before implementation as rule 5 requires. Numbered P7-17 and not P7-15 as the remediation brief asked, because P7-15 is already D69’s fuzz-target OOM and §8 rule 2 makes task ids stable labels; branches are `p7-17/<workstream>` and commits `P7-17/F<n>`. Five workstreams with exclusive file ownership — guest, egress, record, integrity, surface — each reviewed by an agent that did not write it.

**Why:** Two of the fourteen findings added on verification are High, and both sit in areas that had been marked sound — by the review’s own first pass and by this project’s threat model. `supervisor/confine.go`’s re-entrancy guard keys on `cmd.Path`, which is the agent’s own argv[0]: a binary the agent names `kelyfos-confine` is started by PID 1 with no Landlock ruleset and no seccomp filter, against `docs/threat-model.md`’s written promise that every process the supervisor spawns is confined. The egress proxy binds the host’s TAP address and the input chain filters only by `iifname`, so a local connection is routed over `lo`, never inspected, and served with the operator’s bound credentials attached — against the comment above `Proxy.Listen` that says it is reachable from one sandbox and nothing else. A finding that contradicts a written guarantee is worse than one that fills a gap, because everything downstream was designed on the guarantee. The three Phase 7 tasks this jumps ahead of (P7-14, P7-15, P7-16) are already logged as deferred and non-blocking, and none of them is what an attacker reaches first.

## D72

*2026-08-29*

P7-17/F19 moves `sandbox.json` and the `paused` marker out of the jailer’s chroot, from `<base>/firecracker/<id>/root/` up to `<base>/firecracker/<id>/`. This is a **deliberate one-way compatibility break**: a `kelyfos` built before this cannot read a sandbox started after it, and a `kelyfos` built after cannot read one started before. The narrow consequence is during an upgrade — `RunningSessions()` loses the id→session mapping for machines started by the older binary, so `kelyfos sessions erase` and `prune` fall back to `hasLiveRunDir` for those. Recorded here rather than softened, and written into `docs/upgrading.md`.

**Why:** The obvious kindness — read the new location and fall back to the in-chroot copy when it is absent — *is the hole*. A compromised VMM writes the in-chroot copy, and a fallback path is a path an attacker can force by deleting the file above it. F19 exists because `host/sessions.go` trusts what it reads: `pause` copies `WorkspaceHost` into the session, `resume` runs `AdoptWorkspace` and `SyncBack` against it and ends in a rename of the guest’s tree over that host directory, and `snapshot save` copies `st.Workspace` — any host path — into the snapshot the next guest boots from. A boundary with a fallback is not a boundary. The cost is bounded and visible (one upgrade, one class of stale machine, a documented fallback for erase and prune); the alternative is unbounded and silent. The same reasoning the project already applied at D29 and at P5-1: depth is worth having, but not at the price of the boundary it sits behind.

## D73

*2026-08-29*

**GitHub Actions is disabled at the account level, so P7-17 proceeds on local evidence, bounded.** A push of 129 commits to `main` (`b55103f..e1055f5`) triggered **no workflow run**. The repository is not the cause — `repos/…/actions/permissions` returns `{"enabled":true,"allowed_actions":"all"}`, the repository is neither archived nor disabled, all seven workflows list as `active`, and githubstatus.com reports Actions operational. A manual dispatch names it: `HTTP 422: Actions has been disabled for this user.` Duration unknown. On the owner’s ruling of 2026-08-29 the remaining P7-17 work is merged on local evidence: `dev/ci-local.sh`, which reproduces `ci.yml`’s `checks` job step for step — the workflow’s own `run:` blocks, in its order, under its step names — pinning a SHA-256 of the job’s text and refusing to run when the two drift. Heads checked: `e1055f5`, `a4a70df` and `6e755a4`. The `build` job (Buildroot image) is not reproduced; the `boot` job is represented by an aarch64 stand-in (`make test-integration` + `dev/accept-seccomp.sh`) and labelled as one, not as the x86_64 run.

**P7-17 stays open and nothing is tagged until `ci.yml` and `security.yml` are both green on the final head.** This sentence is in this row so it cannot be forgotten: local evidence is what permits the merges, not what closes the task. A tag or a phase exit taken on this row alone would be the defect this row exists to record.

**Why:** Rule 8 exists because main was red from P5-1 to P5-2 while every session read the tree and none read the pipeline. This is that failure with the polarity reversed: the pipeline has not been readable for the whole of P7-17, the last genuine signal on `main` is from 2026-08-25 and 129 commits ago, and nothing in the rule required anyone to notice that *no run* is different from *a green run*. Merging on a reproduction of the job is defensible because the reproduction is the workflow’s own text under a digest pin, and because the alternative — holding twenty-one security findings, including two High ones already on `main`, behind an account restriction of unknown duration — is worse for the thing the findings are about. Closing on it would not be defensible, which is why the previous paragraph says so. Two limits are stated rather than discovered later: the `build` and `boot` jobs are not reproduced, and the local run is load-sensitive — `go test -count=1 ./...` failed on `internal/recorder` and `internal/report` at load average ~11 with five agents working, and both passed individually and together once the machine was quiet, so a red from this script is not a defect until it is reproduced on an idle machine.

## D74

*2026-08-29*

**The 30-second `ResponseHeaderTimeout` F15 added to both egress transports is raised to ten minutes, not removed, and the two transports keep the same value.** Logged before implementation (§8 rule 5) because it is product-facing: it changes what a sandbox can do rather than what the record says about it. F15 added the field at 30s (`internal/egress/dial.go`, `terminate.go`) on the review’s correct observation that neither `DefaultTransport` nor a zero value supplies one, so an origin that accepts, completes TLS and then says nothing held a goroutine, a socket and — on the terminated leg — the credential, indefinitely. The value was never argued and never documented. Thirty seconds is below the time a non-streaming completion from an LLM API legitimately takes to its first byte, and the terminated leg *is* the credentialed LLM-API path: the failure it produces is `timeout awaiting response headers` on a request that was going to succeed. **Chosen: ten minutes on both**, the same number as F16’s `maxTerminatedIdleTotal`, which is the cumulative idle budget that already bounds this leg.

**Removal was the other option offered and is rejected, with the reason.** On the terminated leg removal would be defensible — F16’s 10s rolling body stall, 10 min cumulative idle and 1 h connection ceiling already close everything a guest could drive with it. The forward transport has none of that machinery: `forwardHTTP` re-issues with `context.Background`, so no context covers it, and F15’s own row records that before it the upstream dial had no timeout at all. Removing the field there would reopen exactly what F15 closed, and giving the two legs different values would be a third number nobody can hold in their head — the shape this project has refused since the `jailed` bug.

**Why:** The bound that matters is the one on *idleness*, and that is F16’s, which charges header-read time against the same ten-minute budget it charges everything else against. A separate, shorter, undocumented header timeout adds nothing a hostile guest can reach that the cumulative budget does not already close, and it subtracts a legitimate use: the exact traffic KelyfOS exists to broker — an agent calling a model API with a bound credential, over the leg that termination and secret injection require. Ten minutes is also the honest ceiling to state, because it is the one already in force: a connection that spends ten minutes waiting for a first byte has spent the whole idle budget and would be closed by `notAfter` regardless, so this makes the transport agree with the leg it runs on rather than fail earlier for a different reason. The number is written into `docs/networking.md` and `CHANGELOG.md` rather than living only in a struct literal, which is the half of F15 that was missing.

[AMENDED 2026-08-29, the same day, by this row’s own adversarial review. The paragraph above is wrong about the fact it rests on, and the ruling is kept for a different reason.] “A connection that spends ten minutes waiting for a first byte has spent the whole idle budget and would be closed by `notAfter` regardless” was **false in both halves**, and the review measured it rather than argued it. The budget charged the gap between requests (`terminate.go`’s `idleSpent += time.Since(waitStart)`) and the reading of the header block, and `RoundTrip` sits between the two and was charged by neither; `notAfter` clamps to the one-hour *connection* ceiling, not to the idle budget, and during the wait no I/O happens on the guest connection at all, so no deadline can fire. A probe on a two-second idle budget was answered **after six seconds**, and a three-second connection ceiling did not release the goroutine, the socket or the slot while the proxy waited six.

So `ResponseHeaderTimeout` was the **only** bound on that wait, and raising it 30s → 10 min multiplied the hold twentyfold rather than aligning it with anything. Two changes rather than a retraction: `terminate` now **charges the `RoundTrip` to the idle budget**, which makes the sentence true going forward — one request may spend up to this long on a silent origin and the connection is then out of budget and does not get a second — and every place that stated the old reasoning says instead that this value *is* the bound, chosen deliberately, on the forward leg with nothing else behind it at all. The ruling stands: thirty seconds breaks a legitimate non-streaming completion on the one leg that carries a credential, and that is a real product defect, which the false justification did not need to be true for.

Recorded here rather than by rewriting the paragraph, because what a decision was argued from is part of what it is, and this one was argued from something that was not so.

## D75

*2026-08-29*

**`kelyfos connect` follows a leaf symlink again (P7-17/B1) — and a project-local configuration path that resolves outside both the project and `$HOME` is now refused by name.** Logged before implementation (§8 rule 5) and because B1’s own adversarial review found that the fix as the brief specifies it re-opens a property `docs/threat-model.md` states: “reading a stranger’s project should not be able to break the tool that is supposed to contain it”. Four of the six clients write a **project-local** file — `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.junie/mcp/mcp.json` — and a repository may commit any of those as a symlink. Following it, which is exactly what B1 restores, then puts the write wherever the repository chose.

**The rule, and it is narrow on purpose.** A path the operator named under their own `$HOME` may resolve anywhere: `$HOME` is theirs, a dotfiles repository at `/srv/dotfiles` or `/opt/dotfiles` is an ordinary layout, and nobody else planted that link. A path that is **project-local** may resolve inside the project or inside `$HOME` — the two places the operator is answering for — and anywhere else is refused with the file, the destination and the two things that work. That is the same shape F21 already gives a `[[plugin]] path`, whose own test is named `TestF21_ASymlinkOutOfTheTreeDoesNotGetAPluginIn`: a symlink inside the project pointing out of it is how a lexical check is walked around.

**And the mode is decided on the destination as well as on the name.** The same review found the inversion B1 was written to close reappearing through the write it adds: a *dangling* project-local link into `$HOME` cannot be resolved, so both readings of `underHome` answer “project-local” while the file is created under `$HOME` at `0644`. Three readings now, not two — the name as written, the name resolved, and the destination — and the strictest wins.

**Why:** Refusing rather than following is the smaller change and it is what the rest of this product already does with a path a file chose: F21 refuses an out-of-tree workspace and an out-of-tree plugin directory, each with a named escape hatch. There is no hatch here and none is added, because the two answers that work need no flag — point the link inside, or write the file directly — and a `--i-mean-it` on a command whose whole job is to write four lines of JSON would be more surface than the case is worth.

Scoped to the project-local half deliberately. The wider rule — refuse any destination outside the project and `$HOME` — would refuse a dotfiles repository that does not live under `$HOME`, which is a real layout and an operator’s own decision, and this project has spent two rounds learning that a false refusal costs a person their session (F17’s `node_modules` case, F18’s case-folding round). The narrow rule closes the case an adversary can reach and leaves the case only the operator can.

Not a breaking change under `docs/compatibility.md` §1: the behaviour being removed shipped for the first time in this same unreleased cycle, in `7b398cd`, and no release has ever followed a symlink out of a project on this path — before F5 the write followed the link, but F5 itself stopped following it, and B1 is what proposes to start again. Nothing a user has depended on is changing. A `### Fixed` entry says what is refused all the same, because a refusal somebody meets without warning is the defect this row exists to avoid.

## D76

*2026-08-29*

**A `serve-mcp` whose own audit chain has failed refuses every tool call except the three that only make the situation smaller** — `sandbox_stop`, `team_down` and `sandbox_list`. Logged because it narrows a refusal introduced two commits earlier in this same unreleased cycle (P7-17/A2), on its own adversarial review’s argument, and §8 rule 5 asks for the reasoning before the change rather than inside it.

A2 made the server refuse every tool call once its own chain latches, because a call nobody records is one the server does not make. The review agreed with the rule and showed the implementation cutting against its own justification. The comment says “each machine has its own chain and its own watcher, and those chains are intact; what is lost is the record of the CALLS” — and on three tools that is exactly why they should be allowed. A `sandbox_stop` *is* recorded: the sandbox’s own chain gets its `session.end`, in the chain the comment calls intact. Refusing it leaves an agent that has just been told its calls are unrecorded unable to stop, retire or even enumerate the machines it started, which burn memory until a person kills the process. **The refusal maximised the window it exists to bound.**

So: the three tools that can only reduce what is running stay open, and the nine that create, execute, read, write, snapshot, restore, fork or raise a team stay refused. The operator’s line also says how many sandboxes are still up and names them, which `len(s.boxes)` was always able to answer.

**Why:** The test is whether a call, run unrecorded on this lane, makes the unrecorded window *larger* or *smaller*. Everything that starts work makes it larger and stays refused. `sandbox_stop` and `team_down` end work and are recorded where it matters — in the machine’s own chain, which is what an auditor reads to learn what a sandbox did. `sandbox_list` starts nothing at all and is how an operator or an agent finds out what is still running; refusing a read that changes nothing buys nothing and costs the one question worth asking at that moment.

The cost is stated rather than hidden: those three calls are absent from the outward `mcp.host.*` lane, so a reader of a serve-mcp session whose chain broke sees the machines stop in their own chains and does not see the calls that stopped them. That is a smaller and more legible hole than a set of machines nobody can stop, and the chain’s last line — the recorder’s own epitaph, naming the event that was lost — already tells a reader that everything after it is missing. An auditor who reaches that line knows to stop trusting the lane; an operator whose agent cannot shut anything down has no equivalent signal and no way out.

Not a compatibility question: the refusal being narrowed shipped for the first time in `d1fee33`, in this cycle, and no release has ever had it.

## D77

*2026-08-29*

**The committed `ci.yml` now runs here, in a container, and it is the local evidence of record from this point — and it does not change what closes P7-17.** `make ci-act` (`dev/ci-act.sh`, on `main` at `a93384f`) runs a job of the workflow file itself under `nektos/act`, on a fresh clone of a named commit, rather than the copy of its commands `dev/ci-local.sh` keeps under a digest pin. A copy is evidence; the original is better evidence, and a Progress Log row should cite the better one. Built by a peer session on the owner’s instruction as relayed to this seat, which is recorded that way rather than as something this seat verified with the owner.

**What it covers, and the list is the point of this row.** The `checks` job: gofmt, vet, the vsock modprobe, the unit tests, the short fuzz pass, the hostile corpus, the plan checker, the changelog gate, the DCO range, the generated reference and the cookbook. **What it does not:** the `build` job (Buildroot, hours) and the `boot` job (a real microVM under KVM) do not run in Docker on macOS at all, and `security.yml` — the second workflow §8 rule 8 was amended in 2026-08-24 to include, whose whole purpose is to go red when nothing in this repository has changed — is not run by this at all. The container is `linux/arm64` and runs as **root**; GitHub’s `ubuntu-latest` is `amd64` and does not, and the container’s resolver answers `::1` for `localhost` where this VM answers `127.0.0.1`. Two tests were green natively and red under it, one for each of those two reasons rather than both for the same one, and both were hardened rather than excused (`TestARemovalThatUnlocksADirectoryPutsItsSetgidBack` forces a refused removal with a 0500 parent, which root ignores; `TestF14_TheResolvedAddressReachesTheRecorder` asserted the literal `127.0.0.1`).

**It does not close anything, and the sentence D73 put in its own row for this exact purpose is repeated here rather than cross-referenced.** `ci.yml` and `security.yml` green on the final head is the bar. Running the committed `ci.yml` is nearer to that than running a transcription of one of its jobs, and it is still a reproduction: a different architecture, a different user, one job of three, and one workflow of two. **A tag or a phase exit taken on this row would be the defect this row exists to prevent**, which is what D73 said about the weaker version of the same thing.

**Why:** The reason to prefer it is the reason the digest pin exists at all. `dev/ci-local.sh` is a hand copy that refuses to run when the job’s text moves, which catches the workflow drifting away from the script and cannot catch the script drifting away from itself — gutting a step there leaves the digest unchanged and every step green, which the B2/C review pointed out and which is written into that file’s own header now. Running the workflow file removes the copy, and with it that whole class.

The differences are kept in front of a reader rather than in a footnote, because the two that bit already are the two nobody predicts. Root is not a smaller user than the runner’s, it is a *different* one: a test that forces a permission to be refused does not fail under it, it silently stops testing anything, which is the same shape as a skipped fixture reading like a passing one. And arm64 is the architecture this project boots natively and *not* the one `ci.yml`’s `boot` job exists to cover, so a green `make ci-act` says nothing at all about the x86_64 path.

The scope of this row is evidence, not policy: it names what a Progress Log row should cite and what a reader may conclude from it. It amends neither §8 rule 8 nor D73, both of which stand exactly as written.

## D78

*2026-08-29*

**P7-14 is fixed by *refusing* a scope path that is not in normal form, not by normalising one — which is the opposite of what P7-14’s own text prescribes.** That text says “fix `covered()` to normalize away every trailing slash on both sides before comparing (not just one)”. The implementation on `main` at `312e3a9` does not: `canonicalScopePath` requires `path.Clean` normal form with the trailing slash that names a collection allowed back, `ParseSecretSpec` refuses anything else with the form to write, and `Scope.covers` withholds on a scope built past the parser. Owner’s fix ruling, as relayed to this seat.

**Recorded after the fact rather than before it, which rule 5 asks for and did not get.** The row is written by the seat that owns this document rather than by the one that made the change, and the alternative — ticking a task whose implementation contradicts its own text with nothing in the log saying so — is worse than a late row. Stated plainly so that a reader comparing the task text against the code is not left to wonder which is authoritative: the code is, and this row is why.

**Why:** Normalising is a guess at intent and refusing is not. A scope written `/repos//` is a typo, and the two readings of it — “they meant `/repos/`” and “they meant something this proxy will not match” — are not distinguishable from the string. Trimming picks one silently, on the field that decides which requests carry a credential; refusing hands it back to the person who typed it, at parse time, with the form to write. That is the ruling F17 and F18 both reached on their own inputs in this same phase: F18 declined the report’s prescribed `..` rule because it would have refused every pnpm workspace, and F17 substituted a free-space check for an enumerated ceiling because the prescribed rule would have refused every hardlinked `node_modules`. The direction here is the reverse — refusing where the text said repair — and the discipline is the same one: do not repair a name that was built wrong, because the repair is a guess about intent.

It is also the smaller change. Normalising both sides would have widened what `covered()` approves, on the function that decides credential attachment, to make a typo work; the refusal narrows what can exist, at one door, and leaves the comparison exactly as it was. The second lock in `covers` is there for a `Scope` built past the parser by a caller added later, which is the shape F7 and F21 both spent a commit on.

The cost is a refusal somebody can meet: a spec that parsed before now does not. It shipped for the first time in this same unreleased cycle’s `--secret` path grammar, so no release has ever accepted it, and a `### Fixed` entry says what is refused and what to write instead.

## D79

*2026-08-30*

**P7-16 is fixed by scoping a team's host-level state to the team's own recorder session id, and by making two teams on one host a supported state rather than a refused one.** `run/team.json` becomes `run/teams/<session>.json`, one file per live team; the team's cgroup parent stops being named `kelyfos-team-<name>` and becomes `kelyfos-team-<name>_<session prefix>`; and `kelyfos team up`'s "a team is already running" refusal is removed rather than made reliable. `kelyfos team ps` and `kelyfos team down` — and only those two — gain a selector, `--team <name|session>`, which is only ever needed when more than one team is up. `kelyfos watch` and the three `team_*` MCP tools deliberately gain nothing: the watch lane reads the session it is already tailing, and the tools are about the team that server raised, so a selector on either would be a way to reach a team the caller did not name. `kelyfos team up` gains one line of output, the session it just raised, because with two teams up the name may not be unique. Logged before implementation (§8 rule 5) and because it is user-visible: the refusal that goes away, the flag that arrives, the line that is printed, and the two layouts that move.

**The defect is not the file, it is the slot.** D70 opened this on `run/team.json`, and the file is only the visible half. `raiseTeam` refused to start when that path existed, so the design was *one team per host* — and the refusal was a `os.Stat` taken tens of seconds before the matching write, so two `team up` invocations that both passed it went on to boot, and the second's write replaced the first's state. After that, `team ps` described the wrong team, `team down` signalled the wrong process, and the first team's own teardown deleted the second team's file. The reproduction is two `kelyfos team up` in two worktrees, which is what two reviewers hit unprompted. Making the check atomic (`O_EXCL`) would have made the collision impossible by forbidding the concurrency instead, and the concurrency is the thing this project made routine — five agent-driven teams on one dev machine is how Phase 7 was built. So the slot is what goes.

**The key is the session id and not the team's name.** A name is what a person chose in `kelyfos.toml`, and the reproduction is two checkouts of *one project*: both teams are called the same thing. The recorder session id is minted per `team up` by `sandbox.NewID()`, is already in the state file, and is the identifier every other durable thing about that team is filed under, so keying on it costs no new concept. Where two live teams do share a name, the selector takes a session id as well, and says so.

**The team cgroup was the second instance, and it was not on the task's own inventory.** `sandbox.NewTeamSlice` derived its parent from the team's name alone, so two teams called `demo` shared one `kelyfos-team-demo.slice`. The second team's `set-property` overwrote the first's cap; worse, the second team's `Close()` ran `systemctl --user stop kelyfos-team-demo.slice`, which stops the slice *and every scope in it* — the first team's Firecrackers, killed by a teardown that was not theirs. On the direct path the same name meant one directory: `cpu.max` rewritten under a running team, and an `os.Remove` that either failed on a populated cgroup or removed the parent a live team was still accounted in. This is the same failure D70 describes and a strictly worse one than the state file, because the state file loses bookkeeping and this loses machines. It is fixed the same way: the parent is named for the team *instance*.

**What was audited, and the verdict for each.** The inventory is every `filepath.Join(Root(), …)` and `filepath.Join(RunRoot(), …)` in non-test code, plus the host resources a team allocates that are not files at all.

| state | keyed by | verdict |
| --- | --- | --- |
| `run/team.json` | the host | **the defect.** Now `run/teams/<session>.json`, written by rename. |
| the team cgroup parent | the team's name | **a second defect, found here.** Now carries the session prefix. |
| `named/<name>` | a name the operator chose | **correct, and deliberately so.** A paused session is a durable, user-named artifact, like a file, and `pause` already refuses a name that is taken — naming the directory and the command that frees it. Two pauses racing on one name have a window between that check and the write, which is a person typing one name at two terminals rather than two agents colliding over a slot neither chose. Left as it is. |
| `snapshots/<name>` | a name the operator chose, default `default` | **the same, with a caveat recorded rather than fixed.** Two concurrent `snapshot save` with no `--name` write one directory. It is the operator naming one thing twice, at a door they invoked twice; scoping it per session would make `snapshot restore -name mine` unable to find it, which is the whole point of the name. Left alone. |
| `audit-live/<id>` | the audit session id | correct — one empty file per live `serve-mcp`, minted by `NewID()`. |
| `workspaces/<id>.ext4` | the sandbox id | correct. (Orphans survive teardown on some paths — a leak, not a collision, and not this task's.) |
| `plugins/<id>.ext4` | the sandbox id | correct. |
| `templates/<hash>` | a content hash | correct, and already the best-behaved thing here: the key covers everything baked into the image, publication is an atomic rename, and losing the race is handled as the ordinary outcome. Eviction can in principle remove a template between `lookupTemplate` and the fork that uses it; `lookupTemplate` touches the mtime, so the just-chosen template is the *last* eviction candidate. Recorded, not fixed. **Read this row with the note further down about `dev/demo-team.sh`, which empties the whole directory for every team on the host** — the product's own handling is what this row is about, and a script does something the product does not. |
| `run/firecracker/<id>` | the sandbox id | correct — S20 relied on this and so does the fix's own reproduction. |
| `extract/` | `os.MkdirTemp` per invocation | correct. |
| `out/<arch>` | the architecture | genuinely shared, and read-only to everything but `make image`. |
| `sessions/<id>` | the recorder session id | correct. |
| the guest /30 and the TAP name | the sandbox id, with retry | correct, and the model the rest of this should have followed: derived rather than allocated, "so two concurrent `kelyfos run` invocations cannot race for the same range without a lock file neither of them would remember to clean up." |
| the egress proxy port | the kernel, per sandbox (`:0`) | correct. |
| a `[[forward]]` host port | the operator | genuinely shared, and refused where it can be reached — a second `kelyfos run` meets `bind: address already in use`, which names the resource and the conflict. A host port is one host port. Not reachable from a team at all: `host/team.go` never sets `Forwards` for a team member and says so, and `[[forward]]` beside `[team]` is refused at plan time (P7-4). The row is a verdict about a door a team does not have. |
| an agent's workspace host directory | the operator | **examined because removing the refusal newly allows it, and NOT fully handled — the first version of this row said it was.** `Commit` re-fingerprints immediately before the rename and diverts on a mismatch (P6-21), so a *sequential* second writer lands at `<dir>.kelyfos-out` with the path printed rather than on top of the first. That is what `planTeam` already relies on for two distinct agents of one team naming one directory. It is not a lock, and the independent review of this change found the interleave it does not cover: two teams committing the same directory at once can both take the not-diverted path, and the worst ordering has one team's `removeTree` delete the `.kelyfos-previous` the other had just renamed the operator's own directory into. The race predates this task — two concurrent `kelyfos run --workspace` on one directory could always reach it — and this change makes it reachable for teams too. Left unfixed and logged rather than claimed handled: a lock on `HostDir` is the fix, in a file this task does not otherwise touch, and it is a candidate the owner opens or declines. |
| the `.team-*.json` temporary file | `os.CreateTemp` per write | correct, and skipped by every reader on the dot prefix. |
| `Sandbox.teamSem` / `eventsSem` | — | not host state, but a real data race on the team channel: both were created inside the goroutine that serves them, while the goroutine that started it already held the `*Sandbox`. The `-race` detector reports it on every run of `internal/sandbox`'s own two concurrency fixtures, and those fixtures are today the only other readers of the field — so the losing outcome is bounded to a test binary rather than a shipping path, and this is stated because the first version of this row read as though a running sandbox was racing. It is still a race by the memory model, the next reader of the field would inherit it, and the fix is four lines in the team path this task is about. |

**The reproduction, measured on the parent rather than described.** Two `kelyfos team up` invocations started together on `5fb2605` both booted — the `os.Stat` refusal stopped neither — and `run/team.json` then named one of them. `kelyfos-team-review.slice` held **all four** scopes, both teams' machines, under one `cpu.max` of `200000 100000` where each team had asked for 200% of its own. One `kelyfos team down`, aimed at the team the file named, reported `stopping team review (pid 42568)` / `team down`, and afterwards all four Firecracker pids — 42605 and 42608, which were its own, and 42607 and 42606, which were the other team's — answered `kill -0` with "gone". `kelyfos team ps` then said "no team is running" while the second team's `team up` process was still alive holding nothing. That is the whole defect in one command, and it is worse than the sentence D70 opened this with.

**Two more things examined and left, both named by the independent review.** The direct-path cgroup parent leaks one directory per *run* where it used to leak one per team *name*: `TeamSlice.Close` reports rather than forces a removal that a populated cgroup refuses, and nothing sweeps `<root>/kelyfos-team-*_*`. That is a worse shape of an existing leak and a real cost of keying per instance; it is left because a sweeper is machinery for a directory that is empty and costs an inode, and because forcing the removal is what the reporting exists to avoid. And `run/teams/<session>.json` names a live session and is not one of the four guards `sessionIsLive` consults for `sessions prune`/`erase`. It looks like the natural fifth and is not: a team's state file does not exist until every agent is ready, so it is absent for exactly the window the other four already miss, and a guard that closes nothing while reading as coverage is worse than its absence. Both are candidates rather than fixes. A third, from the same review and outside this task entirely: running the `host` suite with `KELYFOS_CACHE` unset creates `~/.cache/kelyfos/extract` through `stagingRoot()`, from a workspace test that sets no cache. One empty directory, the same P7-18 class, pre-existing and not this change's — named here so it is not rediscovered.

**One more thing the fix could itself have got wrong, and the reasoning for the answer chosen.** `run/teams/` is a directory several teams write into, so a file in it that will not parse is a question about whose problem it is. Refusing every answer because a stranger's file is damaged would put one broken team in the way of stopping the others — the collision one layer out, re-created by the fix. Skipping it silently is the other wrong answer: if the damaged file is your own team's, an unqualified `team ps` would then confidently describe somebody else's team as yours. So an unusable file is skipped, carried out of `liveTeams`, and `selectTeam` refuses to answer an *unqualified* question while any exist, while a *named* team is answered past it. `TestAnUnreadableTeamFileNeitherHidesNorBlocksTheOthers` pins all three halves.

A file counts as unusable when it cannot be parsed **or when its name and its own `session` field disagree**, which the review asked for and which is worth more than it looks: `team down` takes the path it removes and polls from that field, so a file naming another team's session would clear or wait on *that* team's path, a copy of a state file under a second name would make one session permanently ambiguous, and a crafted `../..` would leave the directory. One string comparison closes all three, and everything that survives it is a file this product wrote. `TestAStateFileMustAgreeWithItsOwnName` pins it.

**Liveness is a signal 0 and nothing more, and that is a decision rather than an omission.** `teamProcessAlive` is `syscall.Kill(pid, 0)`, exactly what `internal/sandbox`'s own `alive` is, and it inherits both of that predicate's inaccuracies: a process this user may not signal answers EPERM and reads as gone, and a recycled pid reads as the team that recorded it. The first needs a team raised by another user against this user's cache, which the cache does not support — `Root()` is under `$HOME`, so `sudo kelyfos team up` writes root's cache and is not in this directory at all. The second is real and is why nothing with an irreversible effect narrows by it: a recycled pid can make a roster line say "up" and cannot make `team down` choose a team. Comparing `/proc/<pid>` start time against the file's `StartedAt` would close it and was rejected here: it is platform-specific code in a package that also builds for macOS, and two spellings of "is this process there" that can disagree would be worse than the case they disagree about. It is a candidate, and it applies equally to the `teamDown` that has signalled a pid from this file since E2-4.

**And a read may narrow to the live team where a stop may not.** `selectTeam` prefers the one team whose process is still there when several files are present, so a crashed team's leftovers cannot make a live team unreadable. `kelyfos team down` goes through `selectTeamToStop`, which never narrows: the failure the narrowing would buy is one this task exists to remove — my own `team up` was SIGKILLed and its file is still there with its machines running, a colleague's team is up, I type `kelyfos team down` with no argument, and the narrowing stops five machines that were not mine, with no undo and no warning beyond a line naming a team I did not raise. Found by the independent review of this change; the first version narrowed everywhere.

**And two instances of this class that are not product code, examined and left.** `dev/ci-act.sh` — the third instance, a fixed artifact-server port and a scratch directory keyed only by commit — was already fixed on `main` before this task started, and the fix is the shape recommended here: a pid lock, a private directory per run, and a port chosen free. **Fifteen scripts under `dev/` still kill every Firecracker on the host from a `trap cleanup EXIT` handler**, which is what stopped three suites from running for most of P7-17. They are named individually here, because the first version of this paragraph said "sixteen scripts, `dev/accept-*.sh`" — a right number on a wrong label, and the independent review pointed out the consequence: whoever picks this up will glob `dev/accept-*.sh`, fix those, believe the class closed, and leave the worst one untouched. The list, counted from the kill lines rather than from the file names:

- **Twelve of the fourteen `accept-*.sh`** — `denials`, `e1`, `e4`, `e5`, `forward`, `jail`, `notify`, `profile`, `runs`, `seccomp`, `shell`, `shim`. (`accept-e2.sh` and `accept-watch.sh` do not have it.)
- **`cookbook.sh`**, which is the worst of them and does it twenty-three times in a full run, once between every recipe.
- **`demo-record.sh`** and **`prove-caps.sh`**.

`demo-team.sh`, `prove-team.sh` and `prove-two-teams.sh` are fixed by this task and kill only the pids they recorded from their own sandboxes' run directories.

The fix is known — a private `KELYFOS_CACHE` per suite and a teardown that kills only what is under it, which is S20's own shape generalised — and it is left out of this diff deliberately: these scripts are the evidence base this task's own definition of done is checked against, a wrong scoping there does not fail loudly but silently stops killing anything, and re-earning fourteen suites on live microVMs is a task rather than a step. `cookbook.sh` additionally needs four recipes that read `$HOME/.cache/kelyfos/sessions` by hand to learn the variable first. **Closed by D83**, which did exactly that and found three things this paragraph did not count: 36 host-wide `pkill -f "kelyfos …"` lines on the same files, seven host-wide *reads* (`pgrep -n/-c/-f`) that answer about a peer's machine rather than this run's, and 27 hardcoded cache paths across 13 of the 15 files rather than four in one. The estimate of the work was right and the inventory was short.

**The fourth instance of the class happened during this task's own review, to the review.** While `dev/cookbook.sh` was running here, the reviewing agent's `make test` failed with three `internal/sandbox` integration failures — `firecracker exited before the guest was ready: signal: terminated`, and two of its consequences. `signal: terminated` is SIGTERM from outside the process, and the direction was established rather than assumed: `grep -rn "pkill\|pgrep\|killall" --include='*.go'` over the whole tree returns nothing, so the Go suite kills nothing host-wide and could not have been the source. `dev/cookbook.sh`'s `for p in $(pgrep firecracker); do kill "$p"; done` was. Neither party intended it, both were doing exactly what this repository asks of them, and the reviewer's first `make test` of the final head was red for a reason that had nothing to do with the code. That is what this deferral costs, dated and observed rather than predicted, and it is the strongest argument in this row for closing it.

**One thing that was in `cookbook.sh` and is not deferred**, because it was worse than a kill and removing it is subtractive: `rm -rf "${HOME:?}/.cache/kelyfos/run"/*`, run between every recipe. It deleted `run/teams` — every other team's state file on the host — and `run/firecracker/<id>` for every live sandbox. Killing a peer's machines is bad; deleting the state that names them takes the recovery away too, since `team down --team <session>` then has no file to find. It is gone: every recipe now stops the team and the machines it started, and a run directory whose process is gone is skipped by `sandbox.Load` and `RunningSessions` on the `alive(PID)` check, so a stale one cannot make the next recipe ambiguous.

**And one more, recorded rather than fixed:** `dev/demo-team.sh` removes `~/.cache/kelyfos/templates` wholesale before its cold-path run, because the measurement it takes needs an empty cache and the key is a content hash no caller can enumerate. That is a shared directory emptied for every team on the host. It cannot corrupt one — `lookupTemplate` misses cleanly and `storeTemplate` republishes by atomic rename — but it can pull a directory out from under another team's concurrent fork, and the `templates/<hash>` row above should be read with this beside it.

**Why:** D70's ruling was "either scope each one per-team/per-session, or add real locking". Locking was considered for the state file and rejected on the same ground the network already stands on: a lock over a directory that several long-lived, agent-driven processes contend for needs a documented holder, a released-on-crash story and a stale-lock takeover, and the alternative is to make the thing not shared at all. Nothing here needs two writers to agree; each team writes only about itself. Once the state is per team, the only remaining question is which team a command means, and that has a precedent in this codebase already — `sandbox.Load("")` returns the only running sandbox and refuses to guess when there is more than one. `team ps` and `team down` now do exactly that, so the single-team case, which is the common one, reads and behaves as it always did.

**It is a break, and it is written into `docs/upgrading.md` rather than only into a changelog line.** `run/team.json` is not a `docs/compatibility.md` §2 surface — it is internal layout, pinned by no generated page — but "not promised" is not the same as "nobody reads it", and the grep says who does: `dev/demo-team.sh` and `dev/prove-team.sh` (outside the promise under §3, and moved with this commit); cookbook recipes 5 and 20, which taught a reader to parse it and now ask `kelyfos team ps --json` instead; and `docs/integrating.md`, which named the path outright as *the* shell-facing form. That page was written before `team ps --json` existed (P7-10 added it in this same release), so the answer it should have given now exists, and it gives it. `docs/mcp-surface.md`, `docs/policy-record.md` and `docs/teams.md` mention the path in prose and are corrected. `docs/exam/` is deliberately not: `probe.sh` and `orchestrate.sh` are what a fresh agent wrote at commit `65be6c6` during the E3-5 exam, preserved as the record of that run, and editing them would falsify it. The cgroup parent's rename is in the same upgrading section, because a `systemctl --user` drop-in or a monitoring rule matching `kelyfos-team-<name>.slice` is the one thing outside this repository that could be watching it.

The refusal that goes away — `kelyfos team up` used to say "a team is already running" — is a capability arriving rather than one leaving, and needs nothing from anybody. `### Added`, `### Changed` and `### Fixed` entries say all of it.

## D80

*2026-08-31*

**P7-15 is a recording-integrity defect in v1.1 and not the test-harness problem D69 opened it as, and it is fixed by making the clip loop converge rather than by giving it more attempts.** `fitUnderMaxLine` reduced one field per attempt, by half, up to `maxClipAttempts`; it now reduces every field standing above the ceiling the budget allows, in a pass that runs *before* the first `json.Marshal` rather than after it. `clipLargestField` becomes `clipToBudget`, `largestStringField` becomes `eachStringField`, and the field enumeration both used moves out into `clippableFields`, which is now the one place a reader has to look to answer "what can be clipped." `MaxLine`, the field order, the digest and the on-disk format do not move; `FuzzAppendFieldValues`' seeds do not move either. Recorded after the fact rather than before it, which rule 5 asks for and did not get: the shape of the fix was not knowable until the caller audit came back, and the audit is half of what this row is for.

**The two symptoms are one defect, and the second one is the one that matters.** D69 recorded the visible half — the fuzz target OOM-kills its own worker once its corpus grows — and explicitly judged it "not a correctness defect ... but a real gap in test-suite reliability." That judgement was wrong, and the mechanism says why. Halving the largest field is a reduction of `S/2` per attempt only when there is one field; with the bulk spread across *n* fields, eight halvings of the largest leave roughly `S/2` of `S` behind at `n=8` and more beyond it. So an event whose size is spread wide cannot be brought under the limit at all, and `Append` fails closed — which means **the event vanishes from the record instead of being kept in truncated form**. That is F8's failure mode reached by breadth rather than by an uncovered field, and it is the failure mode this whole function exists to prevent. The memory is the same fact seen from the other end: a loop that cannot converge spends all nine of its marshals at nearly full size, so one `Append` of an event holding 340 MiB across its fields allocated 4.3 GiB and left a 4.4 GiB resident set. Converging fixes both, and nothing else fixes either.

**A real door can reach it, which is why this is `### Fixed` in a release and not a note.** The reachability question — can any non-test caller put oversized, guest- or peer-influenced bytes into *several* fields of *one* event, or only the fuzz target's synthetic all-fields event? — was the thing the fix's severity turned on, so it was audited across every one of the seventy-seven append sites rather than reasoned about. The answer is one door:

`host/mcpobserve.go`'s `command.start`, on the `kelyfos mcp` bridge. On a `tools/call` for `exec` it appends an event built entirely out of one client frame, and three of its fields have no length bound anywhere between the wire and `Append`: `Call` is `"m" + strings.Trim(string(req.ID), "\"")` and `req.ID` is a `json.RawMessage` copied out with no type check and no length check; `Cmd` is `execArgv(args)`; `Cwd` is `str(args["cwd"])`. The only ceiling on any of them is the tee scanner's own buffer, `proto.MaxMCPLine` — 16 MiB. The event is appended the moment the call is seen, before the guest has any say in it. Fill the three with `<` — which `encoding/json` escapes to six bytes per byte, and which an agent driving a shell through this bridge sends every time it redirects a file — and on `v1.1` `Append` answers `event 1 (command.start) is still 16765751 bytes after 8 clips — refusing to write a line no reader could read back`. Three halving candidates and eight clips leave the marshalled size roughly where it started, which is the arithmetic and also the measurement. `TestAppendKeepsTheCommandStartTheMCPBridgeCanBuild` is that fixture; it fails on `v1.1` and passes here, and it sizes itself from `proto.MaxMCPLine` rather than from a copy of the number.

The consequence is worse than one lost line. `Append` routes its failure through `failLocked` (F13): the recorder latches, `Broken` closes, every later `Append` is refused, and every run loop that keeps a machine alive selects on `Broken` and brings the machine down. So the reachable outcome on `v1.1` is that a long JSON-RPC id, a long `cwd` and a long argv in one ordinary tool call stop the recording and then stop the sandbox.

**What was audited and left alone.** The inventory is every non-test call site that appends an event, and for each the question was whether two or more of the fields it sets can simultaneously carry megabytes.

| door | what it can put on one event | verdict |
| --- | --- | --- |
| `host/mcpobserve.go:223` — `command.start` | `Call`, `Cmd`, `Cwd`, all from one ≤16 MiB frame, none bounded | **the defect.** Three unbounded fields on one event. |
| `host/servemcptools.go:554` — `command.start` | `Cmd` and `Cwd` from one ≤16 MiB frame; `Call` is `"s%d"` | **two candidates, which converged even on the parent** — eight halvings of two fields leave `S/16`, measured at a 6,289,105-byte line with 524 KB retained per field. One unbounded field is the whole difference between this door and the one above, and the difference was luck rather than design. It is covered now either way, and the review of this change checked that it does not go BACKWARDS here: 522 KB per field after the fix, against 36 bytes before the fix's own defect was found. |
| `internal/egress` — `egress.attempt`'s CONNECT host | named in the fuzz target's own comment as a motivating caller | **closed, and verified closed.** `splitTarget` refuses a host over `maxHostnameBytes` (253) before `plausibleHost` ever runs; `detailOf` caps `Error.Message` at `maxAttemptDetail` (200); `Mode` and `Reason` are enums, `Peer` and `ResolvedAddr` are socket addresses. Six string fields and not one of them can carry a megabyte. |
| `host/mcpobserve.go` — `command.output`'s `Data` | the other caller the fuzz target's comment names | **closed for `Data`**, which is chunked at `outputFlushAt` (8 KiB). The residual on those events is `Call`, alone, which converged. |
| `host/servemcpaudit.go` — `mcp.host.call` | `Call`, `Name`, `Agent`, `Args` | closed by hand at the door: `clipField` at 120 bytes on the identifiers, `MaxArgsBytes` at 4 KiB on the summary. |
| the guest event lane (`host/plugins.go`, `host/run.go`, `host/servemcp.go`) | `Name`, `Tool`, `Args`, `Reason`, `Comm` — several unbounded *in principle* | **bounded in aggregate**, which is the thing that matters: they all come out of one `proto.GuestEvent` and the whole frame is capped at `proto.MaxLine`, 1 MiB. Several fields sharing one small budget is not the shape that fails. |
| `internal/team/record.go` — `team.message` | `Agent`, `Peer`, `Reason`, `Data` | same shape: two guest-influenced fields sharing one 1 MiB frame. |
| the P7-2/P7-3 slices (`Allow`, `Secrets`, `Plugins`, `Forwards`, `Tools`, `Ports`, `Argv`, `Agents`, `Edges`, `StoreKeys`) | asked about specifically, because `clipToBudget` measures each separately | **each is ONE candidate, not several.** `clipStrings` replaces the whole slice with a single summarising element, so a `[]string` of a thousand megabyte elements behaves exactly like one string of the same total. (It no longer *joins* the whole slice to get there: `joinLimit` stops at the ceiling, because the pre-pass runs before the first marshal and joining 300 MiB to keep 8 MiB of it would be the cost the pre-pass exists to avoid, moved one function down.) Only `Allow` takes a client-chosen element *count* (`host/servemcptools.go` checks each value against the configured allow-list and not the length of the list, so duplicates inflate it freely) and being one candidate it collapses in one step. `Ports` is always two entries; the rest are config-resolved. |
| single fields built by concatenation — `Reason` at `host/snapshot.go:246`, `host/fork.go:166`, `host/servemcpstate.go:204`, `host/sessions.go:947` | one large field | correct as they are. One field converges under halving and under water-filling alike; they are listed so that a reader who greps for string concatenation into an event field does not have to re-derive that. |

**The one-line fix at the door was considered and declined.** Bounding `Call` in `host/mcpobserve.go` the way `servemcpaudit.go` already bounds its own client-chosen identifiers would drop that door from three unbounded fields to two, and two converged even on the parent. It is one line and it is the wrong line. The comment at `fitUnderMaxLine`'s call site already states the rule this project chose after S1: *"this guard is unconditional on purpose — the invariant is 'no writer of this file can produce a line its own readers cannot read,' not 'no *known* writer'."* Fixing the door leaves the loop unable to converge for the fourth unbounded field somebody adds next year, and this file's history is four separate instances of exactly that bet being lost. The door is left as it is, deliberately, and after the fix there is no defect left at it: the event is recorded, clipped, with all three fields carrying megabytes rather than a note saying something was dropped — `TestAppendKeepsTheCommandStartTheMCPBridgeCanBuild` asserts a floor on each of them for exactly that reason.

**Raising `maxClipAttempts` was the obvious repair and is the opposite of one, measured rather than argued.** Against one 340 MiB event at 8, 16, 32 and 64 attempts, a single `Append` allocated 4.3, 8.0, 14.2 and 23.0 GiB — and the event was refused at every setting, 64 included. More attempts at nearly full size buys more allocation and no convergence. The numbers are in the comment on the constant so the next person does not have to re-run the sweep to find out.

**Why a water level and not a flat ratio.** Scaling every field by the ratio needed also converges and is simpler to write. It is worse for a record: it takes bytes from fields that are not the problem, so `stream`, `via` and `agent` beside a multi-megabyte `data` all get shortened to buy the line nothing, and those are exactly the fields a reader needs in order to make sense of what was clipped. `capForBudget` finds the level at which the fields poking above it, cut off at the level, come to the budget; a field under the level keeps everything. The floor at `clipNoteBytes` falls out of the same reasoning from the other end — a field already shorter than the note a clip would add to it cannot be made smaller by clipping, and clipping it anyway would make the line longer.

**F8's guarantee is unchanged and is now easier to check.** `clippableFields` is the single enumeration: string fields by reflection over `Event` and any pointed-to struct, so a field added next month is covered the day it lands; slice fields by a list, because reflection over string-kinded fields cannot see a `[]string`. That list has failed twice — F8 for strings, F1 for `Tools` — so `TestClipToBudgetCoversEverySliceField` still walks `Event` for every slice-kind field and fails with the field's own name if the list has no entry for it. `docs/policy-record.md` §9.1's rule is unchanged; only the two function names in it moved, and the stale line numbers it carried (drifted by roughly eight hundred lines) are removed rather than corrected.

**The fuzz target's own tolerance was the reason nobody saw this, and it is closed.** `FuzzAppendFieldValues` discarded the error from all four of its `Append` calls and took its expected event count from `Verify`, on the stated ground that "Append is allowed to refuse a field it truly cannot bring under MaxLine." The bracketing was supposed to turn a refusal into a broken chain and does not: F13 latches the first failure and refuses every later `Append`, so a refused middle event leaves a chain that is merely SHORT, and a short chain verifies. The target watched `Append` drop the exact event class it was written to protect, on every run, and reported nothing. The errors are checked now and the count is fixed at four. The seeds are untouched — including the 20 MiB one — because shrinking a seed treats the symptom, and with the fix the whole 215-entry corpus that reproduced the kill replays in 60 seconds at a 392 MiB peak.

**What this does not change, checked rather than assumed.** `MaxLine` does not move, the field order does not move, the digest algorithm does not move, and `Verify`, `Read` and `digestOfLine` are untouched — so a chain written by `v1.1` reads back identically under `v1.1.1`, which is what `docs/compatibility.md` §5 pins. What *does* change is the text `Append` writes for an event it has to clip: more of the field is kept, and where several fields are oversized several now carry a note instead of one. Measured on a 20 MiB `data`, written line as a fraction of `MaxLine`: filler that does not escape, 62.8% on `v1.1` and 99.9% here; a shell transcript with one `"` per 200 bytes, 62.8% and 99.9%; 20 MiB of `<`, which `encoding/json` escapes six-for-one, 15.6% and 74.7%. That is not a §2 surface — the note is an in-band string this file writes in place of a schema field, and `docs/compatibility.md` pins the field *order* and the digest, not the contents of a clipped value — and it is stated here rather than decided quietly. A `### Fixed` entry says it.

**Two things found on the way that are not fixed here.** `docs/policy-record.md` §9.1's line numbers had drifted by about eight hundred lines and nothing checks them, which is a fact about every line number in this project's prose and not about that section; they are removed there and left everywhere else. And `actions/setup-go`'s cache never lets a fuzz corpus accumulate in CI, which was inferred and is now verified: `cache: true` caches `go env GOCACHE` — where `$GOCACHE/fuzz` lives — under a key hashing the dependency file, and the post step returns early with "Cache hit occurred on the primary key, not saving cache" whenever that key matched on restore. `security.yml`'s Wednesday search runs with an unchanged `go.mod`, so it hits, so it never saves, so its corpus is discarded at the end of every run. The developer machine's own cache shows the same thing from the other side: 27 fuzz corpora under `github.com/ikapa-dev/kelyfos` and **no `FuzzAppendFieldValues` directory at all**, while the 215 entries that reproduce the kill sit under the pre-migration module path. Hosted CI was never going to find this and still will not; that is a property of how fuzzing is cached and not something this change repairs.

**The adversarial review found a blocker in the first version of this fix, and it was in the one line the fix is about.** `fitUnderMaxLine`'s step down from one budget to the next read `next := budget - (len(b) - lineBudget); if half := budget / 2; next > half { next = half }`, with a comment saying *"halving is a floor under that."* The comment was right and the code was a **ceiling**: `min`, not `max`. Two things followed, and both were worse than the code being replaced. An excess larger than the budget — which is ordinary, not pathological, because `encoding/json` escapes `<`, `>` and `&` six bytes for one — sent `next` deeply negative, past the `> half` test, into the `next < 0` clamp and therefore to **zero**, so the second pass reduced every field to its own clip note: the reachable `command.start` came back as a 249-byte line with no argv, no cwd and no call id. And because the clamp was a `min`, *any* overshoot at all forced exactly `budget/2`, so ordinary command output with one `"` per two hundred bytes retained 50.2% of `MaxLine` where `v1.1` retained 62.8%. The fix that was supposed to stop halving had reintroduced halving and then made it worse. One operator, and the whole point of the change inverted.

It is fixed to the floor the comment always described, and the bound now carries the proof it was missing rather than an assertion: if the excess is at most half the budget, subtracting it converges on the next marshal, because removing a byte of content removes at least a byte of line; if it is more than half, the step halves, and since a line is at most six times its content plus a fixed framing, three halvings put the excess back under half whatever the input. Four passes worst case, out of eight.

**Both "keeps what it can" tests were blind to it, which is the more useful finding.** `TestClippingKeepsWhatItCanRatherThanHalvingUntilItFits` used `strings.Repeat("d", 20<<20)`, and `d` does not escape, so the event fit on the first marshal and the correction loop the test is named after never ran. `TestAppendKeepsTheCommandStartTheMCPBridgeCanBuild` asserted only that its three fields were non-empty, and three 36-byte notes are non-empty. A test that cannot fail is the thing this repository has been bitten by fourteen times in one phase, and it was reintroduced twice in one commit by choosing filler that does not exercise the path. Both now use `<` and `"` fillers and assert retained bytes rather than presence; both fail against the broken clamp and pass here.

**Three further defects the review found, all fixed.** A field clipped on more than one pass derived its note from the intermediate value, so a 5.6 MB `Cwd` reported *"clipped from 2793807 bytes"* and a three-element `Cmd` reported *"across 1 argv elements"* — the record's own account of what it lost, wrong by the factor it had already been reduced by. Every pass now clips from a shallow snapshot of the original event, which costs one struct copy and makes the note true by construction; recovering the original by parsing the note back out of the field was the alternative and is not an option, because that field is one a guest can write. The `clipNoteBytes` floor guarded on `bytes > clipNoteBytes` when the condition for actually shrinking is `bytes > keep + clipNoteBytes`, so a 65-byte field at `keep=64` grew to 96 — the line getting longer inside the function whose job is to shorten it. And `agentsBytes` borrowed `secretsPerElementOverhead`, whose comment derives 22 from `EvSecret`'s framing; `EvAgent` has three fields and frames at 25, so a zero-value `Agents` slice measured 12% under. Under-measuring is the direction that costs a pass rather than the one that breaks the invariant, but a constant whose comment justifies it for a different struct is the kind of thing that stays wrong.

**Two the review raised and this change does not fix, with the reason.** `Append` mutating the caller's `*EvError` through the shared pointer is real and predates this change — `largestStringField` handed out `&e.Error.Message` too — and the copy is three lines, so it is fixed here rather than argued about; that one is *not* on this list. What is: `FuzzAppendFieldValues` still collapses to **0 execs/sec about ten seconds into a run** and stays there. The OOM is gone (peak worker RSS ~320 MiB against 4.4 GiB), the 215-entry corpus replays, and the target passes — but after the baseline it is not searching, because the fuzzer's own mutation of multi-megabyte seeds is what costs the time. That is a fact about the seeds at `fuzz_test.go`'s `f.Add(strings.Repeat("x", 20<<20), ...)`, which this change deliberately did not touch: shrinking them was available and is exactly the "treat the symptom" move P7-15 was opened to avoid, and doing it in the same commit as the convergence fix would have made the reproduction unfalsifiable. So it is recorded rather than fixed, and it is a candidate the owner opens or declines: this target's post-baseline coverage value is near zero, and `security.yml`'s Wednesday three minutes on it buys less than the line item suggests. Second, `CHANGELOG.md` gets a `## v1.1.1` section directly rather than an `## Unreleased` one that is renamed at release time, which is what CONTRIBUTING describes; `tools/changelog.py --check` passes either way, and the section is written the way the release is actually being cut.

**What the review checked and found correct, which is the half a review that reports only problems cannot be distinguished from.** The `MaxLine` invariant holds structurally and under 120 randomised hostile events — every field kind, sizes from 0 to 30 MiB, slice lengths to 200,000, alphabets including `\x00`, `\xff`, `"`, `\`, astral planes and invalid UTF-8 — with zero refusals, zero over-length lines (worst 8,382,714, 99.93% of `MaxLine`) and `Verify` clean on all of them. `joinLimit`'s handoff to `clipUTF8` was property-tested and overshoots by exactly `utf8.UTFMax` at worst, never returning more than `keep` and never splitting a rune. The hash ordering is intact and nothing between `fitUnderMaxLine` and `hashOf` touches a clippable field. F8's guarantee was checked by construction *and* by deletion: removing the `Tools` entry from `clippableFields` in a throwaway copy made `TestClipToBudgetCoversEverySliceField/Tools` fail with the field's own name. No secret value is reachable by any path — `Event` has no secret-value field and the three struct-slice clips emit counts and byte totals only. The erase lane is untouched in substance and its whole suite, including `FuzzEraseRoundTrip`, passes.


## D81

*2026-08-31*

**The release SBOM is a document about KelyfOS, and everything in it that KelyfOS did not write passes through as the bytes it arrived as.** Two rules, one defect each, in the same thirty lines of `tools/sbom`. The document now carries a `metadata.component` naming the product, the version and the architecture; `-arch` stops being a label and becomes an assertion checked against every binary's own `GOARCH`; the serial number covers the subject as well as the components; Buildroot's components, its metadata and its dependency graph are copied rather than re-encoded; deduplication moves from name-and-version to `bom-ref`; and the document declares CycloneDX 1.6, which is what its largest half was generated as. Nothing about the on-disk chain format, the CLI surface, `kelyfos.toml` or the guest image moves, and the SBOM is not a section 2 surface of `docs/compatibility.md` — it has never been one. Recorded after the fact rather than before it, which rule 5 asks for and did not get: the shape of the change was not knowable until the published artifacts had been read, and reading them is half of what this row is for.

**Found by downloading the release rather than by reading the code.** `sbom-aarch64.cdx.json` and `sbom-x86_64.cdx.json` are byte-identical in v1.1 (`sha256:fcb447b7cf827184845d999accaa17a5c574421530a0bf8a3b5e0ca82f2e9c26`) and again in v1.1.1 (`sha256:022aff8913f08118f3b086cd4311126c0fac2efad51f2374f86aa8669332cb09`), confirmed with `cmp` against the published assets. Neither names an architecture anywhere: the strings `aarch64`, `x86_64`, `arm64` and `amd64` appear zero times in either file. Both declare their subject to be `{"name": "buildroot", "version": "2025.02.17", "type": "firmware"}`, because `merged.Metadata = br.Metadata` copied Buildroot's metadata verbatim and nothing replaced it. `-arch` was declared, checked non-empty, printed to stderr and discarded; `-version` reached nothing but the same progress line. Every unit test in the package passed on all of it, and that is the finding underneath the finding — each of them was true about a function and none of them was true about the file a stranger downloads.

**The attestation is where it stops being cosmetic.** `release.yml` cuts a second and third attestation over the SBOMs, one per architecture, and its comment states the reason: *"there is one SBOM per architecture and an attestation that pointed at both sets of artifacts would be claiming that either SBOM describes either image."* `subject-path: dist/*aarch64*` takes `sbom-path: dist/sbom-aarch64.cdx.json` and the `x86_64` pair likewise — but the two paths held identical bytes, so both attestations attached one document to both sets of artifacts. The separation the comment defends was doing nothing. No workflow change fixes that and none is made here: the fix is that the two documents now differ, which is what the workflow always assumed.

**The architecture comes from the binaries, not from the flag, because the binaries know and the flag is a claim.** `debug/buildinfo` reports `GOOS` and `GOARCH` for every binary the merge opens — it survives the `-s -w` these are stripped with, which is the same property the dependency list already relied on. Each Go application component records its platform in its `purl`, its `bom-ref` and a pair of properties, and `-arch` is compared against all three binaries: a mismatch writes no document. That is also what makes the two architectures' documents differ *in their components* and not only in their metadata, which matters because the alternative — an architecture in metadata alone — would have left the two sharing a component list and required the subject to carry the whole difference. It carries part of it either way: the serial is a digest of the whole marshalled document with the field left empty, so two documents over one component list cannot share a serial number, which is the one field whose entire job is to tell two BOMs apart.

**Determinism was the constraint the whole design had to fit through, and it is measured rather than argued.** Two builds of one commit produce byte-identical artifacts (P6-9), so a random serial or a `metadata.timestamp` would have broken that quietly. `metadata.timestamp` is the obvious CycloneDX field to reach for and is deliberately absent; `TestTheSameArchitectureTwiceProducesTheSameBytes` asserts both the byte identity and the absence — and it is the *only* thing that asserts it, which is worth saying because the sentence before it is not quite true and was inherited without being checked. `repro-check.yml` builds `make release-cli` and compares `dist/kelyfos-*` and the image directory; it never runs `make release-sbom`, and `dist/sbom-*.cdx.json` matches no glob in it. The SBOM's byte-identity has never been measured by that workflow. Widening it to cover the SBOM would mean building Buildroot twice in a job that already builds it once, which is a change to that workflow and is left as an owner's call rather than made here. One less obvious hazard was found on the way: `sort.Slice` is not stable, and passing Buildroot's components through means `libzlib` and `host-libzlib` — one name at one version — are both in the list, so the comparator needed a total order or two runs of one commit could have ordered them differently. It sorts by name, then version, then `bom-ref`.

**The larger defect was underneath the first one and is the same mistake.** `tools/sbom` decoded every Buildroot component into a struct modelling seven fields and wrote that struct back out. Buildroot's generator emits `licenses`, `cpe`, `externalReferences` with the SHA-256 of each source tarball, a `pedigree` carrying the text of every applied patch, and a `BR_TYPE` property; the merge deleted all of it, every release, along with Buildroot's `dependencies` graph. Measured on this project's own `aarch64-dev` tree: 333 KB of Buildroot output published as 11 KB. A bill of materials without licences is not one, and a component without a CPE is one no scanner can match a CVE against — so the brief's observation that "no component carries a hash, so nothing ties the document to the artifacts it describes" had the right symptom and the wrong cause. Forty of them carried a source hash before this tool removed it. Components this tool did not author are now `json.RawMessage` from the moment they are read to the moment they are written, and the struct that remains is for *reading* the three fields needed to sort and deduplicate a component. Not byte for byte, and the difference is worth stating rather than glossed: `encoding/json` escapes `<`, `>` and `&` inside a `json.RawMessage` on the way out, so 509 `<` and 186 `&` in Buildroot's output are spelled `\u003c` and `\u0026` in this project's. That changes the spelling of a value and never its content, it decodes back identically, and it is the only difference: nothing is dropped, which is the property that was missing. The same rule applies to `metadata.tools`, which is why Buildroot's generator keeps its GPL-2.0 licence: this tool models no licence field to put it back into.

**Deduplicating on name and version was silently choosing the wrong build of five packages.** `libzlib` and `host-libzlib` are the target and the host builds of one package at one version; so are `libopenssl`, `libffi`, `python3` and `gcc-final`. The published v1.1.1 SBOM lists `host-libopenssl`, `host-libzlib`, `host-libffi` and `host-python3` — the build machine's copies — and not the ones in the guest image, and `gcc-final` went the other way. Which of each pair survived was decided by the order Buildroot happened to emit them in. That is the most consequential of the four defects and the least visible: a reader asking this SBOM which OpenSSL is in the image gets an answer about a different binary on a different machine. Deduplication is on `bom-ref` now — the identifier CycloneDX gives a component for exactly this purpose, and the one its dependency graph refers to — falling back to name and version only for a component that has none. The Go halves keep collapsing as they did: two binaries sharing a module produce one `go:<path>@<version>` ref.

**CycloneDX 1.6, and the mismatch was load-bearing rather than pedantic.** Buildroot's `generate-cyclonedx` sets `CYCLONEDX_VERSION = "1.6"`; this tool wrote `"specVersion": "1.5"` over the top of its components. That was harmless for exactly as long as the 1.6-only fields were being deleted — the published v1.1.1 document validates cleanly against the 1.5 schema. The same document with its components intact does not: it fails in **42 places**, every one of them `externalReferences[].type: "source-distribution"`, which 1.5's enumeration does not contain. So the pass-through forced the version to be correct rather than merely honest. The output validates against the official CycloneDX 1.6 schema, both architectures, and the merge refuses a Buildroot input whose own `specVersion` is not the one it writes, so a Buildroot bump that changes it fails at SBOM-generation time in CI instead of relabelling somebody else's components years later.

**What was audited and rejected, with the grounds.**

| considered | verdict |
| --- | --- |
| **Component hashes over the released binaries** — the brief's own open question, and the obvious way to tie the document to bytes | **Declined, and the premise was wrong anyway.** Forty components already carried a SHA-256 and this tool was deleting it; restoring the pass-through is the fix, and it is in. Computing *new* hashes over `dist/kelyfos-*` is a different proposition and is refused on the workflow's shape: `release-sbom` runs in the per-architecture `images` job, which then deletes the four CLIs it built, and the `publish` job cross-builds the four it actually ships. A hash recorded in the SBOM would therefore describe a *different build of the same source* than the bytes a stranger downloads — true only while the build reproduces, which `repro-check` measures monthly and nothing checks at release time. Recording it would be a release asserting something nothing had checked, which is the failure this whole row is about. The binding a reader needs already exists: `SHA256SUMS` covers every published artifact including both SBOMs, and `actions/attest` records the subject digests. Doing it properly means either producing the SBOM in the job that produces the published binaries, or a release-time check that the recorded hashes match what is staged — both are `release.yml` changes that cannot be verified without dispatching a fifty-minute release run, and this change is not permitted to. Left as an owner's call with the design written down. |
| **One SBOM naming both architectures, instead of one per architecture** — also the brief's question | **Rejected.** The release publishes per-architecture artifact sets and attests each against its own; a single document would make `subject-path: dist/*aarch64*` and `dist/*x86_64*` collapse into one attestation over everything, which is precisely the claim `release.yml`'s comment refuses to make. The per-architecture split was never the problem. Two files with the same bytes was. |
| **Buildroot's `vulnerabilities` array** — 18 entries, passed through as easily as the components were | **Deliberately not passed through, and this is a decision rather than an omission.** Every one of the eighteen is `"state": "resolved_with_pedigree"` with the detail *"has been marked as ignored by Buildroot"* — an upstream ignore-list, not an assessment this project has made. Copying it into a document GitHub then signs would have KelyfOS assert that eighteen CVEs in shipped packages are resolved, on somebody else's triage, under its own attestation. That is a security claim and it is the owner's to make. The half that matters to a reader is restored either way: the CPEs are back, so anyone can run their own match rather than take ours. |
| **Buildroot's `dependencies` graph** | **Passed through, and not extended.** It is rooted at Buildroot's own `bom-ref`, so it states how Buildroot's packages relate and claims nothing about this document's subject. Synthesising a graph rooted at KelyfOS from `debug/buildinfo`'s flat dependency list was available and declined: a graph rooted at the product that named only half the components would be a worse statement than the honest partial one. Every `ref` and `dependsOn` in the produced document resolves, verified by hand on this project's own `aarch64-dev` tree and **not** enforced by the tool. That is deliberate: Buildroot builds `dependsOn` from its *unfiltered* package dictionary while the components array is filtered, so a legal configuration may name a package filtering removed, and a tool that died on that would fail a release on a correct input. The produced document has no duplicate `bom-ref` either, by two different means: components are deduplicated *on* it, and a component carrying the document's own subject ref — the one ref that does not go through deduplication — is refused outright. Two Buildroot components sharing a ref are therefore collapsed rather than refused, which is worth stating exactly because the outcome and the mechanism are not the same sentence. |
| **`metadata.timestamp`** | **Rejected on P6-9.** It is the field a reader of the CycloneDX specification reaches for first and it would make every build differ from every other, so `repro-check` would report a difference that means nothing. A test asserts its absence. |
| **A `docs/roadmap.md` row** | **Not added.** The roadmap carries the task IDs the source cites, and this source cites `D81` and no task ID. Whether this becomes one is the owner's tracker's business, not this document's. |

**One existing guard test was changed rather than left alone, which is worth stating plainly.** `TestTheSerialNumberIsPresentAndDerivedRatherThanRandom` called `serialFor(components)`, and `serialFor` now takes the marshalled document, so the test could not compile unchanged. Both of its original assertions survive — the serial is a URN UUID, and two calls over one input agree — and the "different content, different serial" case is now made twice rather than once: over a component's licence, buried in a field no identifier names, and over the subject's architecture. Those are the two ways this has actually been got wrong, one of them by this change. The other two guards in that file, `TestEverySBOMSubjectIsABinaryTheSBOMRead` and `TestEveryReleasedCLIBinaryIsMeasuredForReproducibility`, read the Makefile and the workflows rather than this program and are byte-identical to `v1.1.1` and passing.

**The evidence, because a test that never failed is not evidence.** `tools/sbom/identity_test.go` builds the tool, cross-builds a fixture Go binary for all four platforms the release ships, runs the one against the other and reads the documents that come out. Against `v1.1.1` three of its four tests fail: the two architectures' documents are byte-identical and share the serial `urn:uuid:d0e5fe5d-a90d-40b2-860b-c2503edae318`; both declare their subject to be `buildroot 2025.02.17` and name no architecture at all; `host-libzlib` is absent from the merged document and `libzlib` has lost its licences, its CPE, its external references, its pedigree and its properties; Buildroot's dependency graph is gone; and an SBOM for `x86_64` is written out of `arm64` binaries with nothing objecting. The fourth, determinism, passes on both, which is the point of having it. Built for real rather than only in a unit test: two full runs of `make release-sbom ARCH=aarch64 KELYFOS_VERSION=v1.1.2` over this project's own Buildroot tree are byte-identical at `sha256:a9eb3c7c3f024a45…`, and the `aarch64` and `x86_64` documents built from the *same* Buildroot half — held constant on purpose, so that only the architecture can be doing the work — differ, at `sha256:24619a2b5171c3fd…` and `sha256:cf3a04e543661400…`, with serials `urn:uuid:966ea878-…` and `urn:uuid:ff202ab6-…`. Both validate against the published CycloneDX 1.6 schema. Seventy-one components each, no duplicate `bom-ref`, no dangling dependency reference, and all five target-and-host pairs present where the published release carries one of each.

**The adversarial review found a blocker, and it was in the field this row spends a paragraph on.** `serialFor` hashed five identifying fields per component — type, name, version, purl, bom-ref — and its own comment said "same subject and same components, same serial, and a change to any of them changes it." That was a content digest for exactly as long as those five fields were nearly all a component had, which is to say until the pass-through in this same change landed. After it, they are about **three per cent** of a 339 KB document: the licence, the CPE, the SHA-256 of every source tarball, the text of every applied patch, the dependency graph and `metadata.tools` all sat outside the hash. The reviewer took the real Buildroot input, changed busybox's licence to MIT, pointed its CPE at a different product, zeroed its source-tarball hash and repointed its download URL at `https://evil.invalid/backdoor.tar.gz`, and got **two materially different documents under one serial number**. That is precisely the condition the architecture paragraph above calls "worse than the identical documents it would replace" — reintroduced by the fix, through content instead of through architecture, and wider. The same hole would have shipped a different SBOM under an unchanged serial on any Buildroot bump that moved only licence or hash data. It is fixed to what the comment always described: the document is marshalled once with `serialNumber` empty, that is what is hashed, and the result goes back in. `TestAChangeBuriedInAComponentChangesTheSerialNumber` is the reviewer's reproduction, and `TestTheSerialNumberIsPresentAndDerivedRatherThanRandom` now covers the buried-change case beside the architecture one.

**Three further defects the review found, all fixed, all reachable only because of the pass-through.** A component carrying invalid UTF-8 produced a document that exits 0 and that **no JSON parser can read**: `encoding/json` escapes what it must inside a `json.RawMessage` and does not validate UTF-8 in it, where the old struct round-trip had quietly replaced the bytes with U+FFFD. That is P6-20's shape with a different field — a published, attested artifact nothing can consume — and the merged document is now checked with `utf8.Valid` before it is written. The subject's `bom-ref` was the bare token `kelyfos`, the only ref this tool authors without a namespace, so a Buildroot package of that name would have produced two components sharing one `bom-ref` — which CycloneDX forbids and which no schema catches, because the schema does not cross-check `metadata.component` against the components array; it is `kelyfos:os` now and the collision is refused outright rather than merely made unlikely. And `dedupe`'s fallback key for a component with no `bom-ref` was `name@version`, in the same namespace as the `bom-ref` keys, so a component whose ref was literally the string `name@version` collided with it and one of two genuinely different things was dropped. Buildroot always emits refs, so that branch is dead today; the keys are namespaced apart anyway, because a deduplication that merges two different things is the defect this row is about.

**Two shapes of Buildroot input that would have failed a release confusingly, both now legible.** `"component": null` decodes to four bytes rather than none, so it reached `passedThrough` and died with "a component has no name"; it is recognised as absent. And `metadata.tools` in CycloneDX's older array-of-tools form — still legal in 1.6, deprecated in it — failed with `json: cannot unmarshal array into Go struct field`, which tells a reader nothing. It is refused by name now, and deliberately not converted: a `tool` has a `vendor` where a component has a `publisher` and has no `type`, so copying those entries into a components array would produce a document that fails validation, which is worse than stopping.

**The attested payload is 31 times larger and that is the one risk this change cannot test.** `sbom-aarch64.cdx.json` goes from 10,963 bytes to about 339 KB — 339,193 measured, and the exact figure moves with the length of the version string — because that is what Buildroot computed and this tool was deleting. `actions/attest` embeds the file as the in-toto predicate; the three fields it tests for are present, and both documents validate against the published CycloneDX 1.6 schema, but a payload-size limit at that step cannot be exercised without a release run and P6-20 is the record of what that step costs when it is wrong. Stated here rather than discovered: if the SBOM attestation fails on size, that is where to look, and the fix is to drop `pedigree` — the full text of every applied patch, carried by twenty components — which is **87% of the growth** and the least load-bearing part of it. Measured rather than guessed, and by this tool rather than around it — `pedigree` stripped from the Buildroot input and the document rebuilt: about 54 KB against about 339 KB, both figures moving with the length of the version string. Dropping it recovers almost all of the size and keeps every licence, every CPE and every source hash.

**What the review checked and found correct, which is the half that a review reporting only problems cannot be distinguished from.** The sort comparator is a strict total order on the deduped set, and structurally cannot be otherwise: `dedupe` runs first and keys on `bom-ref`, so two entries with equal name, version and `bom-ref` can never both survive to be compared. Determinism holds — two runs byte-identical, no map iteration reaching output, no clock, no randomness, no filesystem ordering, `metadata.timestamp` genuinely absent. Both architectures validate against the official 1.6 schema with **zero** errors, with no dangling `ref`, no duplicate `bom-ref`, and `metadata.component` correctly absent from the components array. The new required flags break no caller: `release-sbom` is the only one in the repository and already passed `-version` and three `-binary` flags, and `release.yml` runs `make release-cli` immediately before it. No legitimate release build now fails the architecture check — `GOOS` is deliberately not compared, so the darwin CLI passes, and `unameArch` covers exactly the pairs `release-cli` loops over. Eleven hostile `-buildroot` inputs — `components` as an object, a component that is a string, a number or `null`, a missing `specVersion`, no `components` key — are all refused cleanly with no output file. `TestEverySBOMSubjectIsABinaryTheSBOMRead` and `TestEveryReleasedCLIBinaryIsMeasuredForReproducibility` are byte-identical to `v1.1.1` and passing. Every number in this row and in the changelog was recomputed independently and every one of them held, including the two the reviewer could not verify because they came from a build with a different pseudo-version.

**One the review raised and this change does not fix, with the reason.** A failing run leaves a previous good document in place rather than removing it. The only caller writes per-architecture paths and a failed step fails the job, so nothing stale is ever published; deleting the previous output at the start of every run would trade a harmless case for a destructive one, and is not done.

**The review's second pass found a second blocker, and it was in the test harness the first pass's fix shipped with.** Splitting `release` into `release` and `runTool` moved the standard Buildroot fixture from a variable read inside the helper's body to an argument at its call site — and Go evaluates a call's arguments before the call, while the fixtures are built *inside* the call. So the first `release()` of any process passed `-buildroot ""`, which this tool does not treat as an error: it means "no Buildroot input", and it produced a 2 KB Go-only document where a 339 KB one was expected. Two guard tests failed outright when run alone — `TestTheSameArchitectureTwiceProducesTheSameBytes` reporting a determinism failure that was not one, under the message naming P6-9, which is the worst possible false alarm for this file to carry. The full suite passed, because by the time those two ran the fixtures existed, and `make ci-act` runs the full suite: **it would not have caught this**. Worse, the flagship test passed *for the wrong reason* — its two central assertions, that the two documents differ and that their serials differ, were being satisfied by a missing Buildroot half rather than by the architecture, which is the one thing this row says was held constant on purpose. And `TestAChangeBuriedInAComponentChangesTheSerialNumber`, the guard for the blocker above, passed in isolation with the blocker's fix reverted. Fixed by removing the class rather than the instance: the fixture path is unreachable except through `buildrootFixtureAt(t)`, which builds the fixtures first, and the architecture test now asserts that both documents actually carry a Buildroot half before it compares them. Every test in the package now passes run alone as well as together, which is how they are checked from here.

**Every fix in this row is now checked by neutering it and watching the test that names it fail.** The serial's coverage: with the digest truncated at the components array, `TestAChangeBuriedInAComponentChangesTheSerialNumber` fails *in isolation*. The UTF-8 guard: removed, and the document is written with the invalid bytes in it and the tool exits 0, which is the branch the test names. The subject `bom-ref`: both halves guarded — reverting the ref to the bare token fails the test, and so does removing the collision check. The deduplication keys: reverting the namespacing fails `TestDedupeKeepsThingsThatOnlyLookAlike`. That last test exists because the second pass found the key change was the one fix in the commit with nothing guarding it, and the case it prevents is unreachable through the Buildroot fixture — so it is a unit test over `dedupe` itself, covering both the namespace collision and a second one the review turned up: the fallback key joined name and version with `@`, so `{name: "a", version: "b@c"}` and `{name: "a@b", version: "c"}` produced one key. It is length-prefixed now.

**Three more the second pass corrected in this row rather than in the code.** The claim that duplicate `bom-ref`s "are refused" was true of the subject collision and false of two Buildroot components sharing a ref, which are deduplicated; the row now separates the outcome from the mechanism. `pedigree` was called 60% of the size growth and is **85%** of it — measured by stripping it and re-marshalling, 53,641 bytes against 339,193 — which matters because that sentence exists to tell whoever hits an attestation size limit what to drop. And the byte count itself was three bytes stale, from a measurement taken before `kelyfos:os` replaced `kelyfos` in the same commit; it is quoted as a rounded figure now, because it moves with the length of the version string. `identity` also lost the two fields nothing reads any more — `type` and `purl` were needed only while the serial was computed from them.

**Two residuals the second pass raised and this change does not fix, with the reason.** A lone surrogate written as `"\ud800"` is valid UTF-8 *bytes*, so `utf8.Valid` passes it through; the guard is a byte-level check on the document and does not claim to be a check on JSON string contents, and every JSON reader tried accepts it. And a failing run still leaves a previous good document in place, which is unchanged from the first pass and unchanged for the same reason.

**A reproducibility hazard found on the way, which is not this tool's and is not fixed here.** The two `make release-sbom` runs above pin `KELYFOS_VERSION` because, unpinned, they produced two different documents — and the difference was `v1.1.1-4-ge74699a0` against `v1.1.1-4-ge74699a`. `KELYFOS_VERSION` is `git describe --tags --dirty --always`, `core.abbrev` is unset, and git's automatic abbreviation length is computed from the repository's object count: a commit followed by an automatic repack moved it from eight hex digits to seven between two invocations seconds apart. That is not an SBOM problem. It is stamped into every CLI binary through `-X main.Version`, into the guest's generated `/etc/os-release`, and into the SBOM alike, so **two builds of one commit can differ for no reason but how many objects were in `.git` at the time** — which is the property P6-9 measures and `repro-check` reports on. It cannot happen at a tag, where `git describe` returns the tag name and no abbreviation at all, so no release is affected and this is a hazard for development builds and for any measurement taken off one. The fix is one word — `--abbrev=12` on that line in the Makefile — and it was left to the owner because it changes the version string stamped into every artifact of a dev build, which is more than a release-metadata change is entitled to decide. **Taken, on 2026-08-31, after v1.1.2 shipped**, so that the change that found the hazard and the change that fixes it stay separable and neither has to be read through the other. The line now reads `git describe --tags --dirty --always --abbrev=12`, and the reasoning sits beside it in the Makefile rather than only here, because the next person to shorten that line will be reading the Makefile.

**The third pass found no blocker and four things worth fixing, two of which were tests that had stopped testing anything.** `TestDedupeKeepsThingsThatOnlyLookAlike`'s namespace case spelled its colliding `bom-ref` as `a@1` — which was the fallback key until the length prefix landed *in the same commit*, after which nothing could collide with it. The case passed on an implementation with the `ref:`/`nv:` namespacing removed entirely, so of the two collisions its own comment names, only one was guarded. It takes its spelling from `fallbackKeyFor` now, which is the function the code uses, so the two cannot drift apart again. And narrowing `identity` to three fields — correct in itself, since nothing had read `type` or `purl` since the serial stopped being computed from them — **made this tool more permissive about somebody else's bytes**: a component whose `type` was a number or an array used to fail the decode and be refused, by accident, and afterwards passed straight through into a document that fails CycloneDX validation. The accidental guard is replaced by a deliberate one that covers what the specification actually requires: a component with no readable `type` is refused, `type` is back on `identity` for that reason and no other, and `TestAComponentWithNoUsableTypeIsRefused` covers all three spellings. The remaining two were a comment naming `buildrootFixture` where it meant `buildrootFixtureAt`, and a package comment still saying the identity struct is hashed.

**Each fix in this change now fails a test that names it when it is taken away, checked one at a time and in isolation rather than in suite.** The serial's coverage, the UTF-8 check, both halves of the subject `bom-ref` collision, the deduplication namespacing, the length prefix, and the component-type refusal — six neuterings, six named failures. The review's own instrument for that is worth recording beside them: `go test -shuffle` over eight seeds, which is what would have caught the ordering defect that the full suite, and therefore `make ci-act`, hid.

**Why:** the published v1.1 and v1.1.1 artifacts, read on 2026-08-31. P6-10 for the merge, P6-11 and D39 for the attestations it feeds, P6-20 for the three fields `actions/attest` tests, P6-9 and D38 for the determinism every part of this had to fit through, D50 for the changelog section that cuts the release notes. *Revisit when* the SBOM can be produced in the same job that produces the binaries it describes, which is what would make recorded component hashes a true statement rather than a probable one.

## D82

*2026-08-31*

**`FuzzAppendFieldValues`' seeds stay as they are, because the thing they were
going to be shrunk to fix is not caused by them.** D80 left this open as a
candidate — "this target still collapses to 0 execs/sec about ten seconds into
a run and stays there ... because the fuzzer's own mutation of multi-megabyte
seeds is what costs the time" — and named shrinking the seeds as the fix it was
deliberately not making yet. The measurement says the second half of that
sentence is wrong, so the fix it implies would have cost the P7-15 reproduction
and bought nothing. The seeds do not move. What moves is the explanation.

**The symptom reproduces exactly as D80 describes it.** On v1.1.2, in the Lima
VM, six workers, a cold fuzz cache and `-fuzztime 60s`: 41,587 execs at 9
seconds, 41,587 at 60 seconds, `0/sec` from 12 seconds onward. (D80's own run
read 82,243; the absolute number is machine- and cache-dependent and the shape
is not.)

**Removing every multi-megabyte seed does not fix it.** With the 20 MiB, the
10/15 MiB multibyte pair and the 9 MiB seed all deleted, so that no seed exceeds
1 KiB, the same run reads 46,181 execs at 6 seconds and 46,181 at 61 seconds —
`0/sec` for the last 52 seconds of a 60-second run. That single measurement
falsifies the stated cause, and it is the one D80 did not take.

**The target is not idle during the stall, which is the finding.** A counter
incremented inside the fuzz body and dumped per worker says the body is called
**210,459** times over a run in which the coordinator reported **100,070 execs
and did not move for the last 28 seconds**. The workers are at 95% CPU
throughout, not blocked. `execs` is a count of what workers report back when an
RPC returns; a worker that keeps fuzzing inside one long call reports nothing,
and the line goes to `0/sec` while the target underneath it runs at roughly
5,000 executions a second. **`0 execs/sec` here is a reporting artifact of Go's
fuzzing coordinator, not a description of the target.**

**What is genuinely wasted is repetition, and it is partial.** The same
instrumentation, hashing each `(data, host)` pair, shows most workers
re-executing a small set: one worker reached 105,768 calls against 4,559
distinct inputs, a 23x repetition, and two others froze their distinct count
early while their call count kept climbing. One worker of the six kept finding
new distinct inputs for the whole run. So the target searches, less efficiently
than the headline suggests and considerably better than "not at all".

**The body is not slow, at any size or any content.** Timed directly:
50–73 ms for the whole `f.Fuzz` body — open, four Appends, Close, re-read,
`Verify`, `Read` — at every value size from 1 KiB to 16 MiB, flat, because
after P7-15 `clipToBudget` runs before the first `json.Marshal` and the
800 MiB intermediate D80 removed is never built. Multibyte, invalid UTF-8,
quote-heavy and control-character values at 1 MiB cost at most 224 ms. Over a
whole 40-second run, exactly one execution exceeded 200 ms, and it was the
10 MiB/15 MiB seed at 554 ms. And the engine is not at fault either: the same
package, same machine, with a fuzz target whose body does nothing, sustains
250,074 execs/sec for 30 seconds and never reads `0/sec`.

**What was rejected, and why.**

| candidate | verdict |
| --- | --- |
| Shrink the seeds | **Rejected on measurement.** It does not fix the symptom: with every seed under 1 KiB the collapse is unchanged. It is not free either — D80's reason for keeping them is that the P7-15 reproduction is only falsifiable while the seeds that produced its 215-entry corpus are intact — so this is a real cost for no measured gain. |
| A size bound inside the fuzz function | **Rejected.** It treats the same wrong cause, and it would refuse exactly the inputs the target exists to accept: an oversized value must be clipped and kept, never skipped (D80, F8). |
| A second target carrying the large cases | **Rejected.** It answers "the large seeds are expensive", which is false here, and it splits one property across two targets for no benefit. |
| Correct `security.yml`'s comment | **Rejected, and this is the one worth stating.** That comment calls the Wednesday run "the one that searches", and the brief for this task assumed it had been made false. It has not: the target does search for the whole three minutes. The comment is accurate and stays. The file is therefore untouched, which also means this change does not start a `security.yml` run on push. |
| Leave it alone and say nothing | **Rejected.** D80's paragraph is what the next reader will find, and it names a cause that is wrong and a fix that would remove evidence. A wrong explanation left standing is what this row exists to prevent. |

**What was audited and left alone.** The corpus is not bloated, which D69 and
D80 both say and which holds: 182 committed entries, largest 230 bytes.
`setAllStringFields` reaches **40** string fields on `Event`, so a value of only
256 KiB already puts the event over `MaxLine` and through `clipToBudget` — the
20 MiB seed reaches no clip path a 256 KiB one misses, and the covered-block
set is byte-identical between the seeds as they stand, the same seeds shrunk,
and the same seeds shrunk with the 9 MiB one dropped (105 blocks, all three).
That is recorded because it is the measurement someone will want before
reopening this, not because it argues for a change: it says shrinking would be
*coverage-neutral*, and the rest of this row says it would also be *pointless*.

**The P7-15 reproduction is untouched and was checked rather than assumed.**
The seeds do not move, so the 215-entry fixture at `$HOME/p715-cache` replays
as it did. Separately, against P7-15's parent `9594d24`, the defect reproduces
at every value from 384 KiB upward — `Append` refuses the event with "still
12190577 bytes after 8 clips" — and does not reproduce at 256 KiB. So the
reproduction never needed 20 MiB to work, which is worth knowing and is still
not a reason to change the seeds.

**Why:** D69 opened P7-15 as a harness problem and was wrong; D80 corrected that
and left one harness-shaped sentence behind it that was also wrong. The cost of
the second error is larger than it looks, because the fix it implies is
subtractive and lands on the evidence for the fix that shipped. Recorded after
the fact, which rule 5 asks not to happen: nothing was implemented here, and the
row is the whole change apart from a comment at the seeds pointing to it.

## D83

*2026-08-31*

**D79's deferred class is closed: all fifteen `dev/` suites now run against a
private `KELYFOS_CACHE` and tear down only the machines under it.** The shape is
the one D79 named and S20 established — stop asking "is any Firecracker running
on this host" and ask "are this run's own sandboxes gone" — implemented once in
`dev/scope.sh` rather than fifteen times, with `tools/scope` as the cheap check
that runs on every commit. Each suite was re-earned on live microVMs against a
peer worktree's sandbox raised before it and inspected after.

**The list, derived independently, and both of D79's traps sprung.** A naive
`grep -l 'pgrep firecracker' dev/*.sh` returns fifteen files — the right count
and the wrong set, exactly as D79 predicted: `prove-team.sh` matches on the
comment that says a host-wide kill is how a peer loses its microVMs, and
`accept-e1.sh` hides behind `pgrep -x`. Grepping for the kill idiom with its
flags, excluding comment lines, returns D79's enumeration exactly: twelve
`accept-*.sh` (`denials`, `e1`, `e4`, `e5`, `forward`, `jail`, `notify`,
`profile`, `runs`, `seccomp`, `shell`, `shim`), `cookbook.sh` with its two kill
sites, `demo-record.sh` and `prove-caps.sh`. `accept-e2.sh` and
`accept-watch.sh` never had it; `demo-team.sh`, `prove-team.sh` and
`prove-two-teams.sh` were fixed by P7-16. Nothing was added to or removed from
D79's list.

**Three things on those same files that D79 did not count, because it counted
kill lines.**

| what | scale | why it is the same defect |
| --- | --- | --- |
| host-wide `pkill -f "kelyfos …"` | 36 lines, several *mid-run* rather than in teardown | The same question one layer up. It matches a peer worktree's `kelyfos run`, and it matches the shell running the suite — `pkill -f "kelyfos run"` typed at a terminal killed this author's own session mid-task, which is the shortest possible demonstration. |
| host-wide *reads* | `pgrep -n` ×4, `pgrep -c` ×1, `pgrep -f` ×2 | `pgrep -n firecracker` is "the host's newest Firecracker" where the suite meant "the VMM I just booted". `accept-jail` and `accept-seccomp` then read that pid's `/proc/<pid>/mountinfo` and `/proc/<pid>/cgroup` and check *its* jail. Worse, `accept-seccomp` asserts `pgrep -c firecracker` is zero to show a refused machine was torn down, so a peer's sandbox made it fail outright — F18's shape, which S20 fixed the same way. |
| hardcoded `~/.cache/kelyfos` reads | 27, across 13 of the 15 | D79 says `cookbook.sh` "additionally needs four recipes" to learn the variable. It is 13 files, not one, and the four cookbook recipes are a fifth of it. Paths under `out/` are excluded and deliberately so — see below. |

**The design, and the one thing a private cache must not have its own copy of.**
`sandbox.Root()` reads `KELYFOS_CACHE`, so setting it puts every run directory,
session and template under a directory this run owns, and `scope_pids` reading
`run/firecracker/<id>/root/firecracker.pid` under it enumerates this run's
machines and nobody else's. But `ImageDir` is `Root()/out/<arch>`, so a wholly
private cache has no guest image and `make image` is thirty-five minutes on a
cold machine. `out/` is therefore symlinked to the shared cache — it is
read-only to everything but `make image`, which is the row `templates/<hash>`
would want and does not get — and the suites' `image.json` reads are left
pointing at the shared path, because for `out/` the shared path is the correct
one.

Processes are matched by `KELYFOS_CACHE` in `/proc/<pid>/environ` rather than by
name. A peer has a different one; `environ` is readable only for this user's own
processes, which is exactly the set we are entitled to signal; and it survives
the `( kelyfos run & )` double-fork these suites use, which reparents to init
and puts the process beyond a process-tree walk.

**Two defects this change introduced, both invisible to review and caught only
by running it.** They are recorded because they are the argument for D79's "a
task rather than a step", and neither would have failed where a reader was
looking.

- **The cache directory's own name.** `accept-notify.sh` checks that a run
  without `--notify` "does not mention notifications at all", with `grep -q
  notify quiet.log`. `KELYFOS_CACHE` is printed in a run's own output as the
  vsock and jail paths, and the cache was at `/tmp/kelyfos-accept-notify.XXXXXX`
  — so the suite's name in the directory's name turned the suite's own assertion
  red. The directory is now `/tmp/kelyfos-cache.XXXXXX`, using only the two
  words the shared path `$HOME/.cache/kelyfos` already contributed, so no suite
  can begin matching on a word it did not match before; the suite name goes in a
  `.suite` file inside.
- **A `halt` that killed more than the one it replaced.** `pkill -f "kelyfos
  run"` by construction leaves a `kelyfos snapshot restore` alone, and
  `accept-profile.sh` calls `halt` after a restore and then execs into the
  machine that restore brought up. Mapping `halt` onto "stop every kelyfos
  process this run owns" took that machine with it: 33 passed and 2 failed,
  against the 35 and 0 the unmodified suite gets. So `scope_kill_kelyfos` and
  `scope_kill_machines` take the subcommands to match, every mid-run caller
  names the ones its `pkill` named, and only the EXIT teardown stops everything.

**A suite passing is not evidence, and one of them was being propped up by the
bug.** `accept-e5.sh` asked `pgrep -f 'kelyfos run'` to confirm "every kelyfos
process was killed before the resume" — a host-wide read that fails on an
unmodified v1.1.2 run and passed historically only because the teardown beside
it had just killed every Firecracker on the machine. Removing the kill exposed
the read. The general form: **fixing these kills can turn a green check red
without anything getting worse, because the kill was the thing making it green.**
That is why every suite here was re-earned *with a peer up* rather than merely
re-run.

**And a suite that had been passing on somebody else's history.** `accept-e5`'s
"every event type this epic added was written by *this run*" scans every session
directory in the cache for six event types. The shared cache on this machine
holds **2996 session directories**, 67 of them carrying a `shell.start` from
some earlier unrelated run, so the check reported "none missing" without this
run having written any of them. Scoped, it reports `shell.start shell.end
run.review` missing, which is true and consistent with the suite's own
pre-existing shell/PTY failures here. It is left failing: the check now measures
what its sentence says, and what it exposes is a separate defect. This is a
second thing a private cache buys beyond not killing peers, and it was not
anticipated.

**What was audited and found already failing, so that nobody reads these as
regressions.** Every failing suite was run at `v1.1.2`, alone on the machine,
rather than assumed about.

| suite | scoped | v1.1.2 alone | verdict |
| --- | --- | --- | --- |
| `accept-notify` | 21 passed, 1 failed | 21 passed, 1 failed | pre-existing; "the one question this product asks is notified before it is asked" |
| `accept-e1` | 12 passed, 1 failed | 12 passed, 1 failed | pre-existing; 0.00 Mbps against a 10 Mbps cap, this nested host |
| `prove-caps` | 6 passed, 1 failed, 1 skipped | 6 passed, 1 failed, 1 skipped | pre-existing; the same measurement, and the suite already skips its cpu-quota check on a nested host (D15) |
| `accept-e5` | 25 passed, 8 failed | 25 passed, 8 failed | same totals, better composition — see above |

The other eleven are clean: `accept-shell` 13/0, `accept-denials` 12/0,
`accept-forward` 21/0, `accept-runs` 18/0, `accept-jail` 19/0, `accept-seccomp`
15/0, `accept-profile` 35/0, `accept-e4` 22/0, `accept-shim` 35/0, `cookbook`
23/0, and `demo-record` ran to completion (it is a demo and keeps no score).
Every one of the fifteen left exactly one Firecracker running afterwards, which
was the peer.

**What was rejected.**

| candidate | verdict |
| --- | --- |
| Fifteen self-contained copies of the teardown | **Rejected.** It matches this directory's convention, and the convention is wrong for this specifically: D79's whole warning is that a wrong scoping here is silent, and fifteen copies is fifteen chances to get it silently wrong with no single place to test. One file is testable, and `tools/scope` tests it. |
| `HOME` instead of `KELYFOS_CACHE` | **Rejected**, though it is tempting: it would have made the four cookbook recipes correct with no edit, since `$HOME/.cache/kelyfos` would be the private cache. It also moves the Go build cache, git and ssh configuration and everything else a recipe might touch, to fix a path. |
| Killing by process group | **Rejected.** These suites background with `( kelyfos run & )`, which double-forks and reparents to init, so the group is gone by the time the trap runs. |
| Fixing `accept-e5`'s newly-red check | **Rejected.** It is red because it became correct. Making it green again means either restoring the shared-cache scan, which is the defect, or fixing the shell/PTY failures under it, which is a different change. |
| `sudo pkill -f "http.server"` in `accept-e1` and `prove-caps` | **Left alone, deliberately.** It is a different program, the port makes it exclusive anyway, and it is not the class D79 is about. Named here so it is not read as an oversight. |

**A methodological note worth more than it looks.** `kill -0` is not a liveness
check for this: a Firecracker that has just been killed sits as a zombie until
its parent reaps it, and `kill -0` reports a zombie as alive. The first
peer-survival measurement taken for this change recorded a peer as *survived*
when it had in fact been killed seconds earlier. Everything here reads the state
field of `/proc/<pid>/stat` instead, and `tools/scope`'s own helper says why in
a comment. S20's `kill -0` check and `prove-two-teams.sh` inherit the same
inaccuracy in the other direction — they can report a killed machine as still
alive — which is a candidate rather than a fix.

**Why:** D79 left this open with the reason stated plainly — these scripts are
the evidence base every other change is checked against, a wrong scoping does
not fail loudly but silently stops killing anything, and re-earning fourteen
suites on live microVMs is a task rather than a step. All three held. The two
defects above were found by running, not by reading; the `accept-e5` check was
found to have been wrong for as long as the cache has had history; and the cost
D79 dated — a reviewer's `make test` going red with three `internal/sandbox`
failures while `cookbook.sh` ran beside it — is the thing this closes.

**The independent review, and what it cost.** Adversarial, by an agent that did
not write the diff, reading `dev/scope.sh` and the fifteen suites against
`internal/sandbox` rather than against this row. It earned its keep in the way
CONTRIBUTING says a review should: it found the failure D79 predicted this fix
could itself become, in the two files this row cites as evidence.

**Accepted and fixed.**

| # | finding | what it was |
| --- | --- | --- |
| 1 | **`scope_pids` was blind to every `--no-jail` machine** | `firecracker.pid` is written by the *jailer*; `internal/sandbox/sandbox.go` says "Absent or unreadable is not an error: `--no-jail` writes none." So the teardown walked past unjailed machines and reported success, and two assertions became structurally unfailable: `accept-seccomp`'s count of what was "torn down rather than left running" was always 0, and `accept-jail`'s `vmm2` was empty immediately after `boot --no-jail`, so a check on that VMM's root passed without reading a process. **Both suites scored 19/0 and 15/0 either way**, which is the whole point: a vacuous check and a passing one are indistinguishable from the score. Now both sources are read — the jailer's file, and `"pid"` from the sandbox's own `sandbox.json`, which `sandbox.go` writes from `cmd.Process.Pid` for the unjailed case. |
| 2 | **`scope_init`'s failure was unchecked** | `mktemp -d … \|\| return 1`, which no caller checked. Carrying on leaves `KELYFOS_CACHE` unset, so `Root()` falls back to the *shared* cache, every guard here short-circuits on the empty variable, and the teardown kills nothing and returns 0 — the silent failure, reached by the function that exists to prevent it. It now refuses to run. |
| 3 | **`rm -rf` cannot remove what the jailer leaves** | `jail.go` exists to say so — "A plain RemoveAll fails half way and leaves the rest, which over a few hundred runs is a disk full of abandoned chroots" — and falls back to `sudo`. Without the same fallback this change made tidiness *worse*: one known shared cache became an anonymous per-run directory that can never be fully removed, with the `.suite` breadcrumb naming the culprit deleted first because it is the one file we own. |
| 4 | **`scope_init` discarded an inherited `KELYFOS_CACHE`** | A relocated cache is supported — the Makefile's `KELYFOS_CACHE ?=` and `kelyfos doctor`'s own advice — so `KELYFOS_CACHE=/data/kelyfos bash dev/accept-jail.sh` worked at v1.1.2 and would have failed here with a missing image naming nothing about the cause. |
| 5 | **`dev/cookbook.sh`'s trade comment described deleted behaviour** | It still said the kills were host-wide and bounded the litter at "every sandbox on this host … whoever it belonged to". Rewritten, including *why* its `hasLiveRunDir` consequence stopped applying. |
| 6 | **`scope_live_pids \| head -1` is not `pgrep -n`** | `scope_pids` sorts, so with two of this run's machines live it returned an arbitrary one, and the cgroup and `cpu.max` checks then read a machine that was never given the quota under test. `scope_newest_pid` picks by run-directory mtime. |
| 8 | **`accept-e1` killed `http.server` as root with no port in the pattern** | It matched any `python3 -m http.server` on the host — a colleague's docs preview on `:8000` included — and fired from an unconditional EXIT trap even on runs that started none. This row had rejected fixing these on the ground that "the port makes it exclusive", which is true of `prove-caps.sh` (`http.server 80`) and was false of this one. |
| 10 | **`tools/scope` tested 2 of 8 functions** | And the one defect this row had already recorded as caught only by running lived in the untested half. Four tests added, each verified by reverting the fix it covers and confirming it goes red. |
| 11 | **The subcommand filter used `grep -qw` over the whole command line** | So `run` matched a path component — `kelyfos fork --workspace /srv/run/x` answered to it — and the argument was a regex rather than a fixed string. It compares `argv[1]` exactly now, which is where a subcommand is, and this is the mechanism keeping `halt` from killing a `kelyfos snapshot restore`. |

**And the fix for finding 1 was itself wrong, which a live run said and reading
did not.** The jailer writes `firecracker.pid` with **no trailing newline**, so
reading it and then the same sandbox's `sandbox.json` pid produced
`110887110887` — one token that is not a pid. `accept-jail` fell to 10 passed
and 9 failed, `accept-seccomp` to 9 and 3, and the runs left machines alive. It
was latent in the *first* version of this change too: two jailed sandboxes, two
newline-less files, one `cat` loop, and the teardown gets `111222`. It stayed
hidden only because one machine at a time reads back correctly. Both readers now
go through one framing helper. **That is the fourth defect in this change found
by running rather than reading**, after the cache directory's name, the
over-broad `halt`, and this — against one found by reading — and it is the
strongest single argument in this row for D79's "a task rather than a step".

**Rejected, with the reason.**

| # | finding | why not |
| --- | --- | --- |
| 7 | Moving the cache to `/tmp` defeats `linkInto`'s hard-link path | **Not rejected — accepted and fixed**, and it is listed here because the review was right that nothing in this row mentioned it. `jail.go` states the invariant: "images and jails both live under the cache root", and copying a 128 MiB rootfs per sandbox "would make `fork -n 4` cost half a gigabyte". A cache under `/tmp` with `out/` under `$HOME` breaks it silently wherever `/tmp` is tmpfs, which is the systemd default on Fedora, Arch and Ubuntu 24.10+. The private cache now sits beside the shared one. Invisible on this machine, where `/tmp` and `$HOME` are one ext4 device — a defect a live run here could not have found, and reading did. |
| 9 | A failing suite now destroys its own evidence | **Real, and left.** The cache goes at teardown, so `kelyfos log --session <id>` after a red run no longer finds anything. Keeping it on failure means every suite's trap inspecting `$?`, in fifteen files, to preserve a directory whose value is occasional; `SCOPE_TMPDIR` already lets someone put the cache where they can watch it. Recorded as a trade rather than fixed. |
| 12 | `accept-e5`'s check asserts more than its `killall_kelyfos` kills | **Left.** `killall_kelyfos` names `run resume`; the check asks whether *any* kelyfos process of this run survives. The comment above it says "Every kelyfos process, gone. Nothing is holding this in memory anywhere", so the broader question is the one the suite means, and it passes. |
| 13 | `tools/scope` starts processes named `firecracker`, which a peer still on v1.1.2 could kill | **Accepted as inherent.** The stand-in has to be matched by a host-wide `pgrep firecracker` or the test stops discriminating, which is the property it exists for. The exposure is a ~2 s window against a worktree that has not taken this change. |
| 14 | An untracked corpus entry under `internal/recorder/testdata/fuzz/` | **Neither committed nor deleted here.** It is an artifact of D82's instrumented runs, it passes, and it is not evidence of anything. Deleting it was refused by this environment's permissions, so it is named for the owner to remove rather than committed to make the tree clean. |

**A note on the last full run, which was better evidence than the harness.**
Throughout the final fifteen-suite pass an unrelated `kelyfos-audit` workload
was running its own microVMs on this host out of the shared cache — not started
by this work, and discovered only because the harness reported "1 firecracker
already running before we start". Every one of the fifteen suites left it alone.
Before this change every one of them would have killed it, which is the
reviewer's `make test` in D79's last paragraph happening to somebody else.

## D84

*2026-08-31*

**`kelyfos run` prints a machine-readable `sandbox=<id>` line, because every
piece of automation that ever attached to a sandbox broke at least once on
capturing its id.**

The independent audit's scenarios (SECURITY-AUDIT-independent-2026-08-31.html)
each improvised the same first step — boot a sandbox, learn its id — and each
improvisation failed in its own way. The only source today is the human boot
banner, `sandbox <id> ready in … ms` (`host/run.go:697`), and scraping it has
already cost a session an afternoon: a log carrying bytes `grep` considers
binary needs `grep -a`, which is the kind of detail that survives until the one
run that omits it. `kelyfos log --list` is the other door, and it answers with
the newest *session directory*, not the machine just booted — on a shared host
that is a race between this run and everybody else's. The security suites
(ST-1.2…1.9) commit the audit's scenarios as permanent suites, which means
committing the id capture once instead of once per suite.

**The shape: one additive line on stdout, printed at the same point in the boot
as the banner it annotates.**

```
sandbox=<id>
```

| candidate | verdict |
| --- | --- |
| Fold it into the banner: `sandbox=<id> ready in …` | **Rejected.** It rewrites a line existing scripts and `ci.yml`'s boot job already match (`grep "ready in"`), and buys nothing the extra line does not. The human banner stays exactly as it was. |
| A `--json` boot banner | **Rejected for now.** A second output mode is a surface to keep stable under `docs/compatibility.md` §2, where one stable line is enough. Adding a JSON banner later takes nothing away from this line. |
| Print the id earlier — at `sandbox.New` | **Rejected.** An id without a ready sandbox is not attachable, and the line's promise is "you can exec into this now". Printing it before ready invites a script to race the boot it just won. |
| Emit from `fork`/`resume`/`restore` too | **Rejected without a consumer.** `run` is what the suites and the audit drive; the other commands print their own lines and nothing parses them. Surface added without a consumer is surface maintained for nobody. |

**stdout, and the same stream as the banner.** A warning on stdout corrupts a
pipeline (`docs/compatibility.md` §3), but this is not a warning — it is the
line's payload, which is why it is on the same stream the banner is on and
where a script that captures stdout already has its answer. The session
directory is where the id already lives, but reading the directory from the
process that just booted the machine is the indirection this line exists to
delete, and it is internal layout the compatibility promise deliberately does
not cover.

**Where the promise lands.** The line is documented in `run`'s own help text;
`docs/integrating.md` §4 shows the capture; a cookbook recipe runs the
two-line script, and CI executes it; and `docs/compatibility.md` §2 names the
line among the surfaces a script may build on. The generated
`reference/cli.md` carries a command's flags and one-line summary but not its
usage prose, so the line's home in the generated set is the compatibility
promise's own paragraph rather than a flag row — a stdout line is not a flag,
and pretending otherwise would put it in a table nothing fills in.

**Why:** the audit's every automation broke on id capture, the suites inherit
that step, and the fix is one line that changes nothing an existing script
matches. A form a script can `sed` out is the difference between a harness that
reads the product and one that reads tea leaves.

## D85

*2026-08-31*

**`kelyfos doctor` reports orphaned KelyfOS machines, and `--reap-orphaned`
removes them — and the line it will not cross is proof: it reaps only what the
scan can attribute to this product *and* to no live process (ST-0.2, the
doctor half of IA-M1).**

The audit killed a `run` process and watched the machine it booted outlive it
indefinitely — Firecracker, its TAP, its nftables table, its jail directory,
all unreachable (the vsock channel died with the process), `doctor` noticing
nothing. A reconciliation sweep belongs in the command that already inspects
the machine rather than a session.

**What the scan accepts as proof, and why each layer exists.** On a machine
where several worktrees run sandboxes at once, "a firecracker with a dead
parent" is not proof of anything.

- *KelyfOS's.* A jailed VMM's argv is chroot-relative (`/firecracker --api-sock
  /fc.sock`) and its `/proc/<pid>/root` readlink resolves to `/` from outside
  the jail — the id and the cache survive only on the `sudo -n jailer --id
  <id> … --chroot-base-dir <run root>` wrapper's argv, which stays alive for
  exactly as long as the VMM it started. An unjailed VMM is known by its
  api-sock path under a run directory. A bare `firecracker` somebody is
  running by hand matches neither and is never listed, let alone signalled.
- *Orphaned.* No live `kelyfos` process anywhere in the ancestor chain — the
  chain, not one ppid, because a peer worktree's boot in progress has one and
  reading one ppid is how a doctor kills a peer's machine. A zombie in the
  chain does not claim its child: a zombie supervises nothing.
- *Leftover.* A TAP `kelyfos<id>` or table `kelyfos_<id>` whose id no live VMM
  carries and no live `kelyfos` process's run directory names — the second
  condition keeps a machine that is mid-boot (TAP up, VMM milliseconds away)
  from being reported by a doctor that ran inside the window.

| candidate | verdict |
| --- | --- |
| Reap automatically at startup | **Rejected.** Doctor is read-only by default and stays that way; stopping a VMM is a judgement somebody asks for. `--reap-orphaned` is the ask. |
| Match `pgrep firecracker` and check ppid | **Rejected.** It is the exact question D83 closed — host-wide, answered with a kill — and it claims every firecracker on the machine, ours or not. |
| `prctl(PR_SET_PDEATHSIG)` in this change | **Rejected here, tracked as ST-5.3.** A reaper reconciles what already happened; PDEATHSIG prevents the next one. Both are wanted; they are different tasks. |
| Orphans fail doctor's exit code | **Rejected.** This file's own S3 rule: advisory checks do not flip "can this machine run KelyfOS". The orphan check is `warn` for the same reason the session-size one is. |

**Known gap, stated.** A jailed VMM whose *wrapper* was killed while the VMM
lives has neither wrapper argv nor a matching root link nor a host-side socket
path — the scan cannot attribute it, so it does not list it. Its TAP and table
are still caught by the leftover path. Closing the gap means recording the
VMM's pid in the session dir at boot (IA-M1's own fix sketch) — ST-5.3's
territory, not this check's.

**The audit's own residue.** IA-I4 left a foreign nftables table
(`kelyfos_741d2ffa`) on the shared dev VM, named "never delete it" because
nothing could attribute it. The reaper is the attribution mechanism: a table
whose id no live machine claims is exactly what it reaps, with the evidence
printed. The trap was audit-time caution, not a permanent prohibition — but it
binds anything *but* the reaper: no suite, no script, no agent cleanup may
delete residue it did not prove.

**Why:** the audit's second finding is a lifecycle defect with no verification
path — nothing noticed, nothing reaped, nothing asserted it. A doctor check
with evidence lines, an opt-in reaper whose scoping is proven rather than
pattern-matched, and a suite (ST-1.9) that creates a real orphan and asserts
this exact behaviour close it.

## D86

*2026-08-31*

**A signal to the `run` process itself now ends a run with a trailing command,
because the investigation ST-0.3 asked for found the select that had no case
for it.**

§6.1 of the security testing plan was right to rescope this from "add signal
handlers" — the handlers exist (`signal.NotifyContext` in every command) and
CI proves they work in the no-command shape on every push. Reproduced both
shapes side by side on the dev VM against the same binary: with no trailing
command, `kill -TERM <run pid>` printed "stopping..." and tore the machine
down within a second; with `-- sleep 300` the same signal left the run, the
sleep, the VMM, its TAP and its table all alive 14 seconds later — the audit's
observation, exactly. **Not an artifact of how the signal was sent.** The
cause is three lines of structure, not a missing handler: the
trailing-command path waits in a `select` on the child's exit, the budget and
a broken recorder — and nothing else. The context `NotifyContext` cancels was
cancelled; nothing in that select listened for it. `stopChild` existed and
worked — the budget path uses it — it was simply unreachable from a signal.
The audit's "SIGTERM/SIGINT are ignored" was real, and narrower than
"handlers are missing": one select case.

**The fix is that case.** `case <-ctx.Done(): interrupted = true; err =
stopChild(…)` — the same TERM, grace, KILL escalation the budget uses, then
the ordinary deferred teardown. The record's `session.end` says
`interrupted`, not `command_exited`: the command did not choose to exit. The
exit code is the command's own fate, 143 for a child killed by the TERM —
which is also where the second defect this change found fell out: a child
that dies by signal used to be reported as `exited -1` (Go's internal
convention leaking into a human line); it is now 128+n, the shell's.

| candidate | verdict |
| --- | --- |
| Kill the child from a goroutine watching the context, leave the select alone | **Rejected.** Two mechanisms racing to stop one child — the budget path and the watcher — for no gain over one more case in a select that already handles exactly these situations. |
| Have the signal handler kill the whole process group | **Rejected.** The run may be a process group leader or not; killing a group from the run is the host-wide-kill class D83 closed, with the run's own children as collateral. |
| Exit 0 like the no-command path does | **Rejected for this path.** The trailing-command form's promise is "exit with the command's status", and the command was stopped, not finished: 143 says what happened. Changing the no-command path's long-standing exit-0 is a different change with different blast radius, and CI's boot job depends on it today. |
| Treat it as a timeout | **Rejected.** A timeout is a budget the operator set; an interrupt is one they sent. The record keeps them apart because they answer different questions — "why did it stop" and "who decided". |

**The grace is `childGrace`'s 5 s**, the same one a budget allows its child,
plus the VM teardown that always follows — the acceptance's "stated grace" is
those two, and ST-1.9 asserts both shapes against them.

**Why:** the audit's tooling, CI timeouts and any process manager that signals
a run pid orphaned the machine deterministically (IA-M1's second trigger), and
the fix is one case in the select that was already there to be extended —
with the record now able to tell the three ways a run with a command can end
apart: the command finished, the budget stopped it, the operator did.

## D87

*2026-08-31*

**The security egress suite's offline battery runs everywhere; its online
battery declares its network dependency and skips loudly, by name, when the
network is not there — a flake is neither absorbed silently nor allowed to
read as a regression (ST-1.2).**

Six existing dev suites reach example.com, and none of them runs in CI, so
ST-1.2 would be the first. Its online battery additionally makes nip.io — a
third party's wildcard resolver — load-bearing for the resolved-address
assertions. The warn box in the plan offered two doors: gate behind a flag
CI does not set, or accept the flake and say so. The third door taken here is
the one that keeps the suite honest in both directions: a reachability probe
at suite start (`curl https://example.com` from the VM host, 10 s budget) and
a named SKIP when it fails, with the skip counted and printed in the summary.
A network outage therefore reads as "this was not measured today", never as
"the wall broke" and never as "the wall held". The offline battery — the
no-allow machine with no interface, no routes, no resolver and no proxy —
needs nothing from the internet and is never skipped.

| candidate | verdict |
| --- | --- |
| Flag-gated (`SLAB_NET=1`), CI never sets it | **Rejected as the default**, because a suite whose most important battery cannot run unless somebody remembers a variable is a suite that silently stops measuring — D79's lesson about teardown scoping applies to assertion scoping too. The probe keeps the battery on by default wherever the network actually exists. |
| Accept the flake, retry or fail red | **Rejected.** A red main is a blocker fixed before new work (CONTRIBUTING); a third party's resolver must not own that lever. |
| Self-hosted origin inside the VM | **Rejected for this suite.** The resolved-address check needs names that resolve to metadata and RFC1918 addresses from a resolver the guest trusts; a local origin cannot answer that without becoming a DNS spoofer, which is its own project. The controlled-origin lab (ST-2.1) is where a self-hosted origin belongs, pending the owner's approval. |

Two transcription corrections the machine forced, recorded here because the
audit's summary was looser than its own evidence: curl reports `%{http_code}`
as 000 for a 403 that answers a CONNECT — the suite asserts refusals over raw
sockets, where the wall's answer is actually visible; and the audit's
"no-Host 400; evil Host 403" are the **origin-form** shapes — on the plain
absolute-URI path the proxy rebuilds the request with the URI's host (IA-I5),
so no-Host and a lying Host both answer 200 there, which is correct by
construction and now pinned as a named behaviour rather than an observation.

## D88

*2026-08-31*

**The workspace write-back's actual contract, pinned by ST-1.8's suite — and
where the audit's summary was broader than the machine, the machine wins
(ST-3.3/1.8).**

| shape | the audit said | the machine does | the suite pins |
| --- | --- | --- | --- |
| fifo in /work | refused whole-image, entry named | refused whole-image: "the workspace image contains an entry this host will not use: /pipe is neither a file, a directory nor a symlink (mode 10644)" | the exact message + host dir untouched |
| absolute / climbing symlinks | "host dir untouched" (implying refusal) | dropped SILENTLY: nothing lands, "workspace written back" still printed | nothing lands — and the honesty gap is named, not hidden |
| setuid | "host dir untouched" | lands with the setuid bit STRIPPED (4755 → 755) — safeMode strips setuid/setgid/sticky by design, extract.go documents it | bit gone, file present |
| world-write | "host dir untouched" | lands sanitised (666 → 664; group-write deliberately left) | no world-write bit |
| newline filename | "host dir untouched" | dropped silently, nothing lands | nothing lands |
| 40-deep path | "host dir untouched" | lands — the refusal threshold is 128 (listImage) | the file arrives |

Two consequences worth more than the table. First, the audit's "host dir
untouched" rows for setuid/world-write/deep-path were the IA-H1 loss
speaking: its runs had no flush, so nothing landed at all — hostile or
otherwise — which reads as a refusal until you run the same shapes WITH a
guest-side sync. Second, the silent drop of escaping symlinks prevents the
escape but keeps the false success: the run reports "written back" while an
entry the agent created is quietly gone. That is IA-H1's honesty failure at
lower amplitude, and it rides with ST-5.2's flush fix rather than being
solved by it.

**Why:** the plan's ST-1.8 asked the suite to transcribe the audit's
scenario list; running it produced a more precise contract than either the
audit's summary or the plan's paraphrase, and the difference is now the
suite's assertions instead of a footnote.

## D89

*2026-08-31*

**The security suites' CI home, proposed under §3's constraint that this
account has already had Actions disabled once: a fast subset inside
`ci.yml`'s existing boot job, the heavier suites behind `workflow_dispatch`
and one weekly slot on a day nothing else uses, the full lab run locally
before a release — and nothing merges until the maintainer approves the
minutes (ST-1.10).**

This row is a proposal, not a landed change: no workflow on this machine's
pushes moves until the cost below is approved. The suites themselves are
local-first — `make accept-security` runs all of them in the dev VM — so the
decision being deferred costs nothing but the hosted evidence.

| tier | what runs | where | cost | when |
| --- | --- | --- | --- | --- |
| fast subset | `accept-security-record.sh` (offline, no network) + the offline battery of `accept-security-egress.sh` + `accept-security-caps.sh` | `ci.yml`'s existing boot job, beside `accept-seccomp.sh` (the precedent at `ci.yml:463`) | ≈ +4–6 runner-minutes per push (three boots at ~90 s hosted-KVM each, the boot job already pays the KVM/udev setup) | every push, if approved |
| heavy suites | secrets, surfaces, workspace (full), team, lifecycle | a `security-lab.yml` job — `workflow_dispatch` + one weekly schedule on **Thursday**, the day nothing else uses (ci.yml Monday, cookbook.yml Tuesday, security.yml Wednesday) | ≈ 25–35 runner-minutes weekly | weekly + on demand |
| full lab | all of the above + the controlled-origin battery (ST-2.2) if ST-2.1 is approved | locally, in the Lima VM, before each release | host time only | pre-release |

| candidate | verdict |
| --- | --- |
| A new workflow that boots microVMs on every relevant PR | **Rejected** — revision 1's design, and the single most dangerous thing in this document (§3): sustained CI load is the likely cause of the earlier disablement. |
| The heavy suites weekly without a dispatch door | **Rejected.** A schedule nobody can trigger is a suite nobody re-runs when it matters — the dispatch input costs nothing. |
| Wiring the fast subset into `ci.yml` in this same commit | **Rejected pending approval.** Every push pays the minutes forever; that is exactly the decision the maintainer owns. The suites are green locally (§11) and the wiring is a three-line change when approved. |
| One combined job for suites and advisories | **Rejected.** A suite failure (someone's machine broke) and an advisory (security.yml found something) must never share a red X — separate jobs keep the meanings apart. |

**The udev note, carried from the plan.** Hosted KVM needs the grant step
`bench.yml`/`caps.yml`/`cookbook.yml` already carry (`udevadm trigger
--name-match=kvm`, and the `99-kvm.rules` fallback where the runner user is
outside the `kvm` group). Any new job copies it; forgetting it produces a
permission error that looks like a Firecracker bug and costs an afternoon.

**Why:** the suites exist and are green locally; what separates a local suite
from a gate is hosted minutes, and hosted minutes on this account are the
maintainer's budget to set. The row prices the tiers so the choice is a
number, not a vibe.

**Approved 2026-09-01: both tiers — and the fast tier needed a fix this row
did not see.**

The pricing above was right about minutes and wrong about images. The fast
subset cannot run in `ci.yml`'s boot job as written, because that job's guest
image is the **base** flavor and every suite in the subset needs **dev**:

- `Makefile:81` sets `IMAGE_DIR ?= $(KELYFOS_CACHE)/out/$(ARCH)`, which does
  not vary with `FLAVOR`. The flavor is recorded in `image.json` alone, and
  `checkManifest` (`internal/sandbox/sandbox.go:264`) refuses a machine whose
  manifest names a different one. Two flavors cannot coexist in one cache.
- `ci.yml`'s build matrix runs `make image FLAVOR=${{ inputs.flavor || 'base' }}`,
  so every push produces base and the boot job downloads base.
- `image/flavors/base/buildroot.fragment` describes itself: "BusyBox and musl
  and nothing else. No TLS client, no interpreters." The subset needs what
  only `dev` carries — the egress suite asserts on `curl` inside the guest,
  `dev/accept-security-caps.sh:72` names `-image dev` outright, and the
  harness defaults to `-image "${SLAB_IMAGE:-dev}"`.

Wired as priced, the first hosted run would have failed the manifest check and
turned main red — on this repository, where a red main is a blocker before any
new task, that is not a small cost.

**The fix is a download, not a build.** The release images are the dev flavor
— `image-x86_64.json` in v1.1.2 reads `"flavor": "dev"` — and
`dev/fetch-image.sh` honours `KELYFOS_CACHE`, so the subset gets its own cache
beside the job's:

    KELYFOS_CACHE=$HOME/.cache/kelyfos-sec dev/fetch-image.sh x86_64 <tag>

A second cache rather than the same one, because overwriting
`~/.cache/kelyfos/out/x86_64` would replace the base image the boot job's own
smoke test boots two steps earlier. The added cost per push is one ~100 MB
download and three boots, not the ~35 minutes a second flavor in the build
matrix would cost — which is rejected for exactly the load reason §3 exists.

**The trade this accepts, stated:** the subset boots the last *release's* dev
image rather than one built from the commit under test. It is therefore a
guard on the host side of the boundary — the CLI, the proxy, the recorder,
teardown — and not on guest changes, which the weekly tier and the local
`make accept-security` still cover. A guest-image change that breaks a suite
is caught on Thursday, not on the push.

| candidate | verdict |
| --- | --- |
| Rewrite the subset to run on `base` | **Rejected.** The egress battery's subject is a guest with a TLS client; running it against an image with no TLS client tests the harness, not the boundary. |
| Add `dev` to the build matrix | **Rejected.** ~35 minutes of extra build on every push is the load pattern §3 is written against, to make a per-push gate marginally more exact. |
| Pin the fetched tag to `latest` | **Rejected.** A workflow whose behaviour changes when a release is published is a workflow that fails for reasons the commit cannot explain; the tag is written down and bumped deliberately. |

## D90

*2026-08-31*

**The controlled-origin egress lab (ST-2.1, ST-2.2) is proposed and NOT
provisioned: it needs a small VPS with a wildcard domain — recurring spend
and a piece of externally reachable infrastructure — which is the
maintainer's decision and the maintainer's money.**

The audit could not test redirect handling, upstream request smuggling,
compression torture or leaf-cache reuse because the proxy's
post-resolution address check (`internal/egress/dial.go:73–89`, the RFC1918
and link-local prefixes) rightly refuses private upstreams. Answering those
questions needs an origin on a public IP this project controls, with a
wildcard domain pointed at it, running a scriptable origin with modes:
302-chain, chunked, gzip/brotli echo-suppression torture, smuggling
payloads, header echo.

**The shape, so approval is all that is missing:**

- one cheap VPS (2–5 USD/month, any provider), Debian, nothing but the
  origin script and an SSH port open;
- one wildcard domain (`*.origin.<domain>`), free with most DNS providers;
- one origin script (a small Go server or mitmproxy config, committed under
  `dev/origin/`), started by systemd, logging to the instance;
- setup documented in `dev/security-lab-origin.md` **with the monthly cost
  stated at the top**, per the plan's own requirement;
- the battery (`dev/accept-security-egress-origin.sh`, ST-2.2) runs against
  it: credential-follows-redirect (a 302 from the bound host to an attacker
  host must not carry the credential), upstream request smuggling,
  gzip echo-suppression torture at a size the audit's compressed test could
  not reach, TLS mismatch and leaf-cache reuse across two runs on one
  session, path-scope probing (`%2f`, matrix params, unicode, `/..`), and
  431-drain versus fast and slow writers — pinning the real behaviour and
  fixing the doc to match (IA-L1(c)).

| candidate | verdict |
| --- | --- |
| Point the proxy at a host-local origin | **Rejected.** The private-range refusal is correct and is itself under test; undermining it to test the proxy is cutting the fence to measure it. |
| Use somebody else's public sandbox/echo service | **Rejected.** Redirects, smuggling and compression torture against a service you do not run is abusing a stranger's machine and proves less. |
| Skip Phase 2 | **Rejected as a default.** These are the four proxy questions the audit could not answer, and the proxy is the product's security headline. |

**Why:** the work is a script and a suite; the blocker is a monthly invoice
and a hostname only the owner can authorise. Everything below the invoice is
ready to be written the moment the row is approved.

**Approved 2026-09-01.** The maintainer authorised the spend. The decisive
question is credential-follows-redirect: whether a 302 from a bound host to
an attacker's host carries the credential the proxy attached. Nothing in the
tree answers it today, and it is a credential-leak question rather than a
hardening nicety.

Provisioning is the owner's act — the VPS, the wildcard record and the SSH
key are theirs — so ST-2.1's committed half (`dev/origin/`, and
`dev/security-lab-origin.md` with the monthly cost at the top) lands first
and ST-2.2's battery is written and verified against the box once it exists.
Until then the four rows stay UNCHECKED in `docs/security-assertions.md`,
which is the honest state: approved is not provisioned, and a suite that has
never run against a real origin proves nothing.

## D91

*2026-08-31*

**The guest flushes the workspace BEFORE answering the shutdown handshake,
and the write-back refuses an image that comes back empty against a manifest
that says it held files — IA-H1's two halves closed together (ST-5.2).**

The audit reproduced 2/2 here before any fix: a file written in the guest,
teardown immediately after, `workspace written back to <dir>` on stdout, the
host directory empty. The reproduction also found where the loss actually
lives, and it was not quite where the plan sketched it. The halt path
already flushed — `syncWorkspace()` before the TERM sweep and a final
`unix.Sync()` after it — so the missing flush was not the whole story. What
the flush could not cover was the teardown that never asked the guest at
all: an INT delivered to the run's sudo child is a power cut, and a power
cut loses whatever the ext4 commit had not reached. The audit's own harness
and this suite's first harness both did exactly that.

**The fix is two halves.**

- *Deterministic flush.* On OpShutdown the supervisor now runs syncfs(2)
  against /work — blocking until that filesystem's writes are on the device —
  BEFORE writing the response, and refuses the shutdown if the flush fails.
  The ack the host reads now means "your files are on the disk", which is the
  control-channel guarantee the audit asked for. The old order — ack, then
  halt, then flush — told the host it could read the image while the ext4
  commit was still in flight.
- *Honest write-back.* The extraction cross-checks the pack manifest: an
  image that comes back with zero entries while the manifest names a
  non-empty pack refuses with "the machine's last writes were lost, and
  nothing was written back or removed" — syncResumedWorkspace's shape, as
  the plan directed. The false success is what turned a data-loss bug into
  an integrity finding.

| candidate | verdict |
| --- | --- |
| Remount /work read-only before poweroff | **Rejected.** The supervisor's own seccomp refusal list contains mount; the machine that most needs the flush cannot perform it. |
| fsync every file in /work from the supervisor | **Rejected.** syncfs does the whole filesystem in one syscall the kernel completes, and walking a tree the agent may still be writing invents new races. |
| 0-entries-vs-manifest as a warning, not a refusal | **Rejected.** A warning beside "workspace written back" is the false success wearing a hat. The refusal keeps the host directory untouched and says why. |
| Only fix the harness (INT the command, never the VMM) | **Rejected as sufficient.** The harness fix is real and landed with this row — but the product's promise cannot depend on who was polite enough to signal gently. |

**The trade the cross-check makes, stated.** An agent that genuinely deletes
everything in /work hits the refusal: the run says the writes were lost and
leaves the host directory as it was. That is a false refusal in a rare case
against a silent destruction in a common one — the direction the RECORD
checklist points. The refusal names the manifest, so the evidence survives
for whoever needs to know what the pack held.

**The harness learned the same lesson.** dev/security-lab.sh's adown now
INTs the trailing command child by name and never the sudo/firecracker
children — §8 trap 2's `pkill -INT -P <run-pid>` recipe is imprecise in
exactly this way, and a teardown that power-cuts the VMM measures nothing.

**Why:** the audit's HIGH finding was silent data destruction with a false
success message, in the single most common pattern there is — write results,
exit. The fix makes the durable write a precondition of the handshake and
makes the write-back refuse when its own precondition failed, and the
regression test that reproduced the loss twice now asserts the survival
twice.

## D92

*2026-08-31*

**The VMM's parent death is now a signal instead of a state: a watchdog
re-exec stops the machine and frees its network names when the kelyfos
process dies without its teardown, and the direct children carry
PDEATHSIG — IA-M1's prevention half (ST-5.3).**

The chain is kelyfos → sudo → jailer(exec) → firecracker, and the reason a
one-line PDEATHSIG cannot cover it is structural: prctl(PR_SET_PDEATHSIG) is
set on the child at spawn, fires when that child's parent dies, and the
jailer is Firecracker's binary — it execs into the VMM without setting one.
So the direct child (sudo jailed, firecracker unjailed) carries
`Pdeathsig: SIGKILL` from its spawn — the unjailed VMM dies with its parent
outright — and the jailed chain gets a watchdog: a re-exec of the binary,
spawned once the VMM's pid is known, carrying `Pdeathsig: SIGTERM` and
pointed at the run directory. Its whole life is one branch: parent dead
while the VMM lives → SIGKILL the VMM, free the TAP and table, remove the
jail directory, exit.

| candidate | verdict |
| --- | --- |
| PDEATHSIG on the firecracker process | **Rejected as unreachable.** It must be set by the jailer before exec, the jailer offers no hook, and clearing rules for privileged binaries make it fragile at best. |
| A Go goroutine watching the VMM | **Rejected.** It dies with the process whose death it is supposed to notice. |
| Rely on the doctor reaper alone | **Rejected as the whole answer.** The reaper reconciles residue after the fact; a watchdog shrinks the window from forever to milliseconds, which is the difference between "cleaned up later" and "never existed". |
| Register the watchdog as a real subcommand | **Rejected.** It has no argv, no flags and no clients; surface added for a process nobody invokes is surface maintained for nobody. It rides an environment marker checked before dispatch. |

**Lifecycle, stated so nobody debugs it twice.** On a normal teardown the
VMM exits first and the watchdog exits on its next 300 ms tick — its cleanup
never runs. On an abnormal parent death the watchdog acts within one tick or
on the signal. A watchdog that was SIGKILLed itself cannot act, and that
residue is what the doctor reaper sweeps — the two mechanisms are layers,
not alternatives, and ST-1.9's suite now exercises both: a restore orphaned
with its watchdog alive is taken down with no orphan ever forming, and a
restore orphaned with the watchdog SIGKILLed first is listed and reaped by
doctor.

**Why:** the audit's M-1 was "immortal orphaned microVMs, no reaper"; the
reaper alone answers what already happened, PDEATHSIG answers what the
kernel can do for free, and the watchdog bridges the gap between them. The
machine outlives its supervisor for at most a third of a second.

## D93

*2026-08-31*

**The truncation attack is closed for every report the operator signs, and
the unsigned path carries its TODO honestly (ST-5.4).**

The audit's IA-M2 asked for any of three mechanisms; the one the product
already had was export-time signing — `kelyfos log --export --sign-key` —
which the record suite now exercises as the regression test the fix owed:
a signed export verifies and names its signer; truncating it is a MISMATCH
(the stale claims disagree with the record); and truncating it *with the
claims recomputed* is still a MISMATCH, because ed25519 does not renegotiate.
What remains open is signing at SESSION end rather than export end — the P6-7
direction — which would close the unsigned path's TODO(IA-M2); that is a
product decision about where keys live, and it stays flagged in the suite
rather than silently accepted.

**Why:** the plan's flip — "ST-1.4's truncation expectation flips from
'verifies' to 'fails'" — turns out to be one `--sign-key` away for every
operator who names a key, and the suite proves it live. The unsigned path's
verifies-clean is now the documented exception rather than the whole story.

## D94

*2026-08-31*

**The fuzz budget is proposed at three tiers, priced, and NOT applied to
`security.yml` — editing that workflow is one of the three paths that starts
a run on push, and the nightly proposal needs the maintainer's minutes first
(ST-4.1).**

**Correction, 2026-09-01.** This row opened by calling the scheduled budget "a
smoke test: 29 targets × 10 seconds weekly", which conflated two different
budgets and understated the existing one by 18×. `ci.yml` runs 10 seconds a
target on every push (`ci.yml:181`); `security.yml`'s Wednesday cron already
runs **three minutes** a target — `FUZZTIME: schedule && '3m' || '30s'` at
`security.yml:119`, and its own comment says "3m x 29 = 87 min weekly". The
scheduled hunt exists and is 87 minutes. What follows was priced against a
budget that was never 10 seconds. The corrected target list (§6.3 of the
plan) splits what a larger budget buys:

| tier | targets | budget | cost | when |
| --- | --- | --- | --- | --- |
| per-push | all 29+ (dev/fuzz.sh discovers them — the new chain-link target included) | 10 s each | unchanged | every push, already in ci.yml |
| weekly hunt | the chain extractor (internal/report), the four proto framing targets, FuzzExtractImageLinks, FuzzAppendFieldValues | 5 min each ≈ 35 min | ≈ 35 runner-minutes weekly | Saturday, the one day no workflow uses, behind `workflow_dispatch` too |
| pre-release | the same, 30 min each | ≈ 3.5 hours | host time | locally, before a release |

Targets that need a target WRITTEN first stay out of the budget until written:
the workspace enumeration is covered by FuzzExtractImageLinks as of ST-3.3;
MCP framing (internal/mcp) still has none and is named as the gap rather than
hidden by a schedule. The proxy request parser keeps its two targets and no
new budget — duplicate coverage is not coverage.

**Nightly is deliberately not proposed.** Seven times the current cost for a
codebase whose fuzz targets are the same nine every night is spend without a
hypothesis; weekly hunting plus per-push seeds answers what a night would.
If the maintainer wants nightly, the row's Saturday slot moves to daily and
the price is the only thing that changes.

| candidate | verdict |
| --- | --- |
| Apply the schedule to security.yml in this commit | **Rejected pending approval** — §3's rule, the same one D89 applied to the suites. The row prices it; the maintainer decides it. |
| One shared 60-minute pool instead of per-target minutes | **Rejected.** A pool silently spends everything on whichever target a corpus lucky-streak favours; per-target minutes are the budget a person can audit. |

**Why:** a fuzz budget nobody priced is a budget nobody can defend, and a
schedule nobody approved is §3's incident happening politely.

**Decided 2026-09-01: the Saturday slot is DECLINED; nothing changes.** Once
the correction above is applied the proposal reads as a second scheduled day
buying five minutes instead of three on nine targets that Wednesday already
hunts for three. That is a small marginal gain on an account whose Actions
were disabled once for sustained load, and the row's own argument against
nightly — "spend without a hypothesis" — applies to it with more force. The
per-push 10 s and Wednesday's 87 minutes stand as they are.

The two things that survive the refusal, because neither costs a run:
`internal/mcp` still has no fuzz target and stays named as a gap rather than
hidden by a schedule; and if a crasher ever escapes to a release, the cheap
answer is to raise Wednesday's `FUZZTIME` for the named targets, not to add a
day.

## D95

*2026-08-31*

**Semgrep rules for the four checklists are proposed as a LOCAL gate first —
wired into `ci.yml`'s checks job only if the tool download keeps
`make ci-act` green and offline-tolerant (ST-4.3).**

RECORD/PROXY/BROKER/RENDER are precise enough to lint: `template.HTML`
outside the chain blob, `os.Create` in report paths, unescaped writes,
post-effect ACL checks. The rules themselves are a day's work and are not
the gate here; the gate is §3's again — CI minutes and, new for this tool,
the Docker image `make ci-act` runs in, which would need semgrep present or
would download it per run (a download in a job that is currently
network-light, and a supply-chain surface of its own: the rules' semantics
pin to a semgrep version that must be pinned in versions.mk like everything
else).

| candidate | verdict |
| --- | --- |
| Land the rules in ci.yml's checks job now | **Rejected pending approval** — the tool download changes what `make ci-act` needs, and the plan's own §3 makes that the maintainer's call. |
| Rules without version pinning | **Rejected.** A lint whose findings move with an unpinned tool version is a lint that cannot be argued with. |
| Skip semgrep entirely | **Rejected.** The four checklists are prose today; a mechanical pass over the exact constructs they name — even locally, even advisory — is the cheapest way to keep them read. |

**Why:** the checklists are the product's security vocabulary and nothing
executes them; a local advisory pass is the honest first step, and the CI
wiring is D89's decision wearing a different tool.

## D97

*2026-08-31*

**The security cadence proposed to the maintainer, assembling D89's suite
tiers, D94's fuzz tiers and D95's lint gate into one calendar (ST-6.2) —
proposed, not adopted; every schedule in it is the maintainer's to move.**

| what | cadence | where |
| --- | --- | --- |
| per-push | ci.yml's checks + boot jobs (unchanged), + the fast security subset if D89 is approved | hosted CI |
| fuzz hunt | weekly hunt tier (D94) | hosted CI, Saturday |
| security suites | heavy suites via workflow_dispatch + Thursday weekly (D89) | hosted CI / local |
| lint gate | local advisory pass until D95 is approved | local |
| full lab | locally, `make accept-security` + the origin battery if D90 is approved | local, pre-release |
| fresh-agent exam | after each epic that touches recorder, egress, broker or renderers (ST-6.3) | local |
| audit re-run | after each such epic, fresh eyes, the audit's own scope | owner-arranged |

A red lab run is a blocker under the existing "CI is the gate" rule — the
cadence proposal does not soften that, it schedules it.

**Why:** ST-6.2 was "proposed to the maintainer, not adopted unilaterally" in
the plan's own words, and every row above cites the decision that prices it.
What is adopted locally is adopted: the suites run, the exams run, the gates
are red or green on this machine regardless.

## D98

*2026-08-31*

**The eight audit findings, tracked to their outcomes (ST-5.1) — one row per
finding, the decision or suite that closed it, and what remains open. This is
the map a future reader uses instead of archaeology across nine rows and
eight suites.**

| finding | outcome | where |
| --- | --- | --- |
| IA-H1 (HIGH): silent workspace data loss with a false success | **Fixed.** syncfs before the shutdown ack; the write-back refuses an empty image against a non-empty pack manifest; reproduced 2/2 before, surviving 2/2 after | D91; ST-5.2; the workspace suite's IA-H1 regression |
| IA-M1 (MED): immortal orphaned microVMs, no reaper | **Fixed in layers.** The doctor scan + `--reap-orphaned` (the aftermath); PDEATHSIG on the direct children and the VMM watchdog (the prevention); a restore orphaned with its watchdog alive forms no orphan at all | D85, D92; ST-0.2, ST-5.3; the lifecycle suite's two batteries |
| IA-M1's second trigger: signals to the run pid ignored with a trailing command | **Fixed.** The select that had no `ctx.Done()` case has one; the record says `interrupted`; the child is announced 128+TERM | D86; ST-0.3; the lifecycle suite's signal battery |
| IA-M2 (MED): export truncation with recomputed claims verifies clean | **Closed for signed reports.** A signed export detects the truncation twice (stale claims, unforgeable signature); the unsigned path keeps its TODO(IA-M2) — session-end signing is P6-7's remaining decision | D93; ST-5.4; the record suite's signed battery |
| IA-L1 (LOW): doc/help drift in five places | **Fixed.** The shim help teaches the minted token (a); the 431-drain and header-deadline claims scoped to what the code does (c, d); the serve-mcp rhetoric states the real defaults behaviour (e); the syscall-count prose states the policy/filter distinction (b, via ST-3.1) | ST-5.5 + ST-3.1 |
| IA-L2 (LOW): gitleaks false positive; stale .audit artifact | **Fixed.** .gitleaksignore carries the verified fingerprint; the surfaces suite's fixture de-literalised; `.audit/` regenerated by a script whose own artifacts cannot document absence as a result | ST-5.6; `dev/audit-local.sh` |
| IA-I1 (INFO): credential host scope covers subdomains | **Pinned.** The secrets suite asserts it as-is; `docs/networking.md` states it | ST-1.3, ST-5.5 |
| IA-I5 (INFO): plain-HTTP Host rewrite undocumented | **Pinned.** The egress suite's parser matrix asserts both rewrite shapes; `docs/networking.md` states it | ST-1.2, ST-5.5 |
| IA-I2 (INFO): `restore -allow` overrides the frozen allowlist | **Documented.** The restore path records the override honestly; the docs sentence rides the lifecycle suite's coverage of the restore path | noted in the lifecycle suite header |
| IA-I3 (INFO): guest python has no `_ssl` | **Documented.** The CA-environment section now says five of six variables are inert for Python | ST-5.5 |
| IA-I4 (INFO): foreign nftables residue on the shared VM | **Converted to mechanism.** The reaper attributes and removes exactly this class; the audit's "never delete it" caution became a scoping rule (D85) | D85; the orphan scan |
| IA-M2's unsigned half, IA-L1's dynamic pins, Phase 2's four questions | **Open, and visible.** `docs/security-assertions.md` (ST-6.4) carries the UNCHECKED rows rather than letting a green suite list stand in for them | ST-6.4 |

**Why:** ST-5.1 asked for decision-row drafts and task entries so the
maintainer approves findings rather than archaeology. The draft rows were
written before their implementations (D84–D93), the tasks were executed under
their own IDs, and this row is the index. The two open halves — session-end
signing and the controlled-origin lab — are decisions awaiting the
maintainer, not work nobody noticed.

## D96

*2026-08-31*

**This number is intentionally unused.** D94, D95, D97 and D98 were drafted
as one batch in a single session and the sequence skipped a number on the
way through; renumbering published decisions to close the gap would break
every citation to them, and an unused number documented here is honest in a
way a silent gap is not. The next decision takes D99.

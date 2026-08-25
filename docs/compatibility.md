# The compatibility promise

**Status:** normative from v1.0. This is the document that makes the number mean
something.

A 1.0 is a promise made to a stranger: that the surfaces they build against will
not move under them, and that where something *is* allowed to move they were told
in advance which. Until this page, the words "semver" and "deprecated" appeared
nowhere in this repository.

What follows is short because most of the work was already done. Six of the seven
surfaces in §2 already have a machine-readable source of truth and a CI-enforced
generated page, so this promise **cites** rather than re-lists — and those six
cannot go stale by the mechanism that already keeps the reference honest (F-D4).
The seventh, the host↔guest protocol, is pinned by a hand-written specification
that no drift gate checks.

---

## 1. What a version number attaches to

Three independent version constants describe surfaces somebody builds against,
and their relationship has never been stated. It is stated here.

| constant | what it versions | moves when |
| --- | --- | --- |
| the release tag (`v1.0`) | **the product** — the CLI, the image, the documented behaviour | this document says so |
| `proto.Version` (`1`) | the host↔guest wire protocol | a message's meaning changes |
| `recorder.Version` (`1`) | the flight-recorder record | an existing field's meaning changes |

They are **not** kept in lockstep and never have been: every release so far has
shipped `proto.Version = 1` and `recorder.Version = 1`, and that is correct — the
product has changed a great deal and those two contracts have not.

`mcp.ProtocolVersion` is a fourth thing and not a version of ours at all: it is
the MCP revision KelyfOS speaks, which somebody else numbers. §6 covers it.

Other numbers in the tree version something else and are not what the table is
about: the `schema` field written into a workspace manifest and into an image's
`image.json`, both `1` and both on disk where a reader finds them — the workspace
one is checked on read, so a manifest from an older kelyfos is recognised rather
than misread; the guest supervisor's own `Version`, stamped at build time and
printed on the boot line, which SECURITY.md asks a reporter to quote alongside
`kelyfos version`; and the shim's `EnvdVersion`, which is the number the E2B SDK
gates features on. None of them is a surface §2 pins.

**The release tag is what the rest of this page is about.** When it says "a minor
release may", it means the number in the git tag.

### What the parts mean here

- **Major** — a surface in §2 changed or was removed in a way that requires
  somebody to edit something. A major release is the only kind that may do this,
  and only after the deprecation in §4.
- **Minor** — something was added. New commands, new flags with defaults, new
  `kelyfos.toml` keys, new MCP tools, new event types, new denial identifiers.
  Everything that worked before still works.
- **Patch** — a defect was fixed, and the fix does not change a documented
  behaviour. **A security fix that must narrow a surface is not a patch**; it is
  §3's exception, and it says so in its release note.

---

## 2. What stabilises

All but the last have a generated page, produced from the code that implements
it, which CI fails on drift. The protocol's page is hand-written rather than
extracted, so no drift gate compares it against `internal/proto`; it is a
specification, and where the code disagrees with it the code is wrong. The
promise is that these do not change incompatibly outside a major release.

| surface | the page that pins it | source of truth |
| --- | --- | --- |
| the `kelyfos.toml` schema | [`reference/config.md`](reference/config.md) | `internal/config` |
| the CLI: commands and flags | [`reference/cli.md`](reference/cli.md) | the binary's own usage |
| exit codes | [`reference/exit-codes.md`](reference/exit-codes.md) | `internal/exitcode` |
| denial identifiers | [`reference/denials.md`](reference/denials.md) | `internal/denial` |
| the MCP tool surface | [`reference/tools.md`](reference/tools.md) | the servers themselves |
| the flight-recorder record | [`reference/events.md`](reference/events.md), [`events.md`](events.md) | `internal/recorder` |
| the host↔guest protocol | [`protocol.md`](protocol.md) | `internal/proto` |

**A denial identifier is part of the promise**, which is unusual and deliberate:
scripts branch on them, and an identifier that changed meaning would break a
caller silently rather than loudly. The *text* beside one may be improved at any
time; the identifier may not.

**Exit codes are shell convention rather than a private numbering**, so a script
wrapping `kelyfos` can branch on them the way it already branches on `timeout(1)`.
That is a promise about the numbers, not only about the list.

---

## 3. What does not stabilise, and why

Saying this explicitly is the other half of the promise. A surface that is
silently in is worse than one that is openly out.

- **Guest confinement profiles.** [`reference/profiles.md`](reference/profiles.md)
  is generated and accurate, and the profiles are **allowed to narrow in a minor
  release**. They are a security surface: a profile that could not be tightened
  without a major release would be a profile nobody tightens. If your agent
  depends on a syscall the profile refuses, that is a conversation to have in an
  issue, not a compatibility guarantee.
- **The E2B-compatible shim.** It has always described itself as a best-effort
  subset of somebody else's API, and it tracks that API rather than this promise.
  See [`e2b-shim.md`](e2b-shim.md) for what is implemented.
- **Client configuration formats.** `kelyfos connect` writes files whose shapes
  belong to Cursor, VS Code, Codex and the rest. **These are external surfaces:
  outside the drift gate, outside this promise, re-verified on their own cadence**
  — which is why every supported client carries the tool and the date it was
  checked against, and three of the six the exact version as well. There is no
  universal standard coming, and per-client writers are permanent infrastructure
  rather than a temporary shim (D41).
- **Anything under `dev/`.** Scripts for people working *on* KelyfOS. Three of
  them are also run by people working *with* it: `install-firecracker.sh`,
  `install-kelyfos.sh` and `fetch-image.sh` are the README's install path, and
  the posture warning on a pre-v0.9 image names `dev/fetch-image.sh` as the fix.
  They are outside the promise anyway.
- **Timing figures.** The boot and restore numbers are measurements, not
  contracts. They are re-measured per release and reported as measured.

---

## 4. Deprecation

None existed before v1.0, and two configuration spellings have been kept "for
compatibility" since v0.4 with no removal path — which is how a codebase acquires
things nobody can remove because nobody wrote down when they could.

The mechanism, from v1.0:

1. **Announced** in a release note, and marked in the generated reference where
   the surface appears. It keeps working, unchanged.
2. **Warned** on use, to stderr, naming the replacement — for at least one minor
   release. Never to stdout: a warning on stdout corrupts a pipeline, which is
   the deprecation causing the outage it was meant to avoid.
3. **Removed** in the next major release, and named in its release note.

A surface may not skip a step, and the minimum between announcement and removal
is one minor release **and** thirty days. Security is the exception: a surface
that must be narrowed to close a vulnerability is narrowed, in whatever release
does it, and the note says so plainly rather than calling it a patch.

---

## 5. Three questions the record raises, settled

**Does a new event *type* break a consumer?** No, and a consumer that breaks on
one is wrong. `docs/events.md` §3 has always said a reader must ignore what it
does not recognise; that applies to `type` as much as to fields. New event types
arrive in minor releases — v1.0 alone added `secret.withheld`, `secret.scrubbed`
and `team.store`'s `delete` kind. A consumer switching on `type` needs a default
that skips, not one that fails.

**Is the record's field order frozen ABI?** **Yes**, and until v1.0 nothing
checked it. A digest is computed over the struct marshalled in declaration order,
so reordering the fields changes every digest KelyfOS has ever written — every
existing chain would report as modified, which is tamper detection firing on
legitimate records. `TestTheEventFieldOrderIsFrozen` pins the order and fails
with an explanation rather than a diff. **Adding a field at the end is safe** and
stays safe, because P6-6 made verification work from the bytes as written, so a
reader tolerates a field it has never heard of.

**What about `hash` itself?** The algorithm — SHA-256 over the line with the
digest emptied in place — is frozen with the rest of §2. Changing it is a major
release and a `recorder.Version` bump, together.

---

## 6. The MCP revision, which is not ours to promise

KelyfOS speaks MCP revision **2025-11-25**. The current published revision is
2026-07-28, and it removes the `initialize` handshake.

**The policy is that KelyfOS speaks a revision it has implemented, and says which
one.** It does not claim the latest, and it does not follow every revision as it
lands: an agent sandbox that changed its wire protocol whenever somebody else's
specification moved would be a sandbox nobody could depend on.

Moving to a newer revision is a **minor** release when clients of the old one
still work, and a major one when they do not. `kelyfos connect --check` is
written dual-era from the first line — it probes and falls back — so the check
itself needs no rewrite when this moves.

---

## 7. Where this promise is not yet a promise

Named rather than left to be discovered:

- **Windows and WSL2 are post-1.0.** WSL2 is documented as a way to run the Linux
  layer; it is not covered by anything here.
- **macOS is supported for what it does**: `doctor`, `verify`, `version` and
  `help`. The rest of the CLI needs Linux, refuses on macOS with the way in, and
  "the same commands everywhere" is explicitly not promised — it needs a
  transport across `limactl shell` that an interrupt does not survive.
- **`kelyfos snapshot restore` reads no policy file.** A restored machine gets no
  ceilings, no allowlist and no secrets from `kelyfos.toml`. That is current
  behaviour and it is a gap rather than a promise; fixing it will be a minor
  release, because it only ever adds enforcement.

# The MCP surface, examined from the documents alone

*E4's exit requirement, run the way E3-5 ran: two readers were given the
documentation and nothing else — no Go source, no plan files — and asked to do
something real with it. One was told to drive KelyfOS from an MCP client. The
other was told to ship a plugin that runs inside a sandbox.*

*Date: 2026-08-23. Corpus: `docs/mcp-surface.md`, the four generated pages,
`docs/events.md`, `docs/integrating.md`, `docs/protocol.md`, cookbook recipes
9–11, and both README files.*

---

## Why this exists

E3-5 established that generation gives you *consistency*, not *truth*: a page
built from a table is exactly as correct as the table, and CI cannot tell the
difference. The only thing that finds a true-looking falsehood is a reader who
has no other source and is trying to get something done.

That exam found ten defects in a documentation set that had just passed every
mechanical gate. This one found twenty in a surface that had just passed nine
tasks of tests and live proofs.

## Verdicts

Both readers said **no**: neither could complete their task from the documents
alone. The outward reader could connect a client and got no further without
guessing; the inward reader could not get past the first field of the
declaration.

Every finding below was then checked against the running product. The column
that matters is the last one, because a finding that turns out to be right about
the documents and wrong about the product is still a finding — it means the
documents describe a thing that does not exist.

---

## Outward: driving KelyfOS from an MCP client

| # | Finding | Checked | Verdict |
| --- | --- | --- | --- |
| 1 | The invariant "`serve-mcp` can never widen policy" is stated unconditionally in three documents, and §2.3 says a server launched outside the project "finds no policy and runs with no ceiling at all". Recipe 11 uses the bare invocation. | `serve-mcp` with no policy file grants whatever a call asks for. | **Confirmed, and the worst of the twenty.** The invariant is conditional and was written as absolute. Recipe 11 taught the unsafe form. |
| 2 | `sandbox_run`'s result key is `id` in §2.2 and `sandbox` in both recipes. | The product returns `sandbox`. | **Confirmed: §2.2 is false.** Written before the code and never reconciled. |
| 3 | `docs/README.md` and `README.md` both say the MCP surface is "not yet built" while the generated reference documents its tools. | Nine tasks built it. | **Confirmed.** The entry map — the first page a reader is sent to — was a release behind. |
| 4 | §2.5 opens by promising `log --export` "renders the client's lane beside the guest's"; the same section and §4.1 then explain there are two chains. | Two chains, by design (F-D43). | **Confirmed.** E4-4 rewrote the section and left its first sentence alone. |
| 5 | The cross-link from a sandbox to the server that made it is promised in prose and named in no schema. | It is in `session.start`'s `reason`. | **Confirmed.** The field exists; nothing said which field. |
| 6 | Nothing says whether a `serve-mcp` sandbox gets the policy's `[sandbox] workspace`, and both recipes write to `/work` under policies that declare none. | **`serve-mcp` never attaches a workspace.** A declared `workspace` key is silently ignored. | **Confirmed, and a product finding.** `/work` in those recipes is a directory in the guest's own overlay, which is not what a reader would assume. |
| 7 | `sandbox_fork` and `sandbox_restore` have no documented return shape and no documented relationship to `max_sandboxes`. | Forks count against the limit; both return structured content nothing documents. | **Confirmed.** |
| 8 | `mcp.host.call`'s `args` is typed `string` with no example of what a redacted value looks like. | `content=<19 bytes>`. | **Confirmed.** |
| 9 | `sandbox_exec`'s tool description — the text a model reads — says "A non-zero exit is a result, not an error", while `isError` is set for exactly that case. | Both true; together, misleading. | **Confirmed.** An orchestrator branching on `isError` retries every `grep` that matched nothing. |
| 10 | `team_ps` has no documented output shape, and `integrating.md` says the agent→sandbox-id mapping "has no command behind it". | `team_ps` returns it. That sentence is now false. | **Confirmed.** |

## Inward: shipping a plugin

| # | Finding | Checked | Verdict |
| --- | --- | --- | --- |
| 1 | `command` is documented as "resolved inside that plugin's directory", and both worked examples are `node` and `python3`, which are not in it. | A bare name resolves on `PATH`; a name with a slash resolves against the plugin's directory. | **Confirmed.** The first field a reader must get right is the one they cannot get right by reading. |
| 2 | Recipe 11 reads `sc["sandbox"]`, which §2.2 says is `id`. | Same as outward #2. | **Confirmed.** |
| 3 | A plugin that fails to start, and a tool refused at boot, have no documented signal. Nothing anywhere says where a plugin's stderr goes. | A failed start is a `plugin.crash` saying "did not start"; a refused tool is a console line; stderr goes to the console with the plugin's name. | **Confirmed as a documentation gap.** All three signals exist and none is written down — the single most likely place a first-time plugin author stalls. |
| 4 | The `name` rule is stated three times, three different ways: the regex in §3.2, "at most 24 characters" only in the generated config page, and a permissive paraphrase in the cookbook. | All three constraints are real. | **Confirmed.** |
| 5 | A plugin's own tool names are unconstrained by the documents, so the collision §3.2 exists to close is still open — and nothing forbids a plugin named `read` exporting `file`. | Tool names *are* constrained in the product and it is undocumented. **A plugin named `read` exporting `file` produces a second `read_file` in `tools/list`, shadowed by the built-in.** | **Confirmed, and a product finding.** |
| 6 | `docs/events.md` says `plugin.call` carries `agent` in a team; the generated reference does not list it. | The product sets it. The schema table is missing it. | **Confirmed, and a generation finding** — the table the page is built from was wrong, which is exactly E3-5's central lesson recurring. |
| 7 | "a transcript says which plugin was asked to do what" — `plugin.call` carries no arguments and no error text, while the outward `mcp.host.call` carries both. | True. | **Confirmed as overstated wording**, and a real parity gap. |
| 8 | §3.1's "behind the same absent network" reads as "a plugin cannot reach the network", two paragraphs after the section granting it the sandbox's proxy variables. No plugin section links to `docs/networking.md`, which never mentions plugins. | Both statements true; the pairing misleads. | **Confirmed.** |
| 9 | No timing or size contract: no plugin start timeout, no call timeout, no statement of whether the supervisor↔plugin pipe has the MCP channel's 16 MiB limit, no bound on a plugin directory's size. | 20 s to answer `initialize`, 120 s per call, the same 16 MiB frame limit, and the device is sized from the directory. | **Confirmed as a documentation gap.** Every number exists and none is written down. |
| 10 | The working directory is never named as a guest path, and where a plugin may write is never scoped. The fixture's `where` tool exists to answer a question the documents should answer. | `/plugins/<name>`, read-only. | **Confirmed.** |

---

## What was done about it

Fixed before the tag, because they are what the exam is for — the documents
saying things that are not so:

outward 1, 2, 3, 4, 5, 7, 8, 10 and inward 1, 2, 3, 4, 5 (the documentation
half), 6, 8, 9, 10. Two of these are words inside the product rather than in a
document, and were fixed with the documents because they are the same defect:
the `sandbox_exec` tool description (outward 9), and the missing `agent` field in
the event schema (inward 6), which is a table a generated page is built from.

Routed to a hardening batch immediately after the tag, following the ruling
E3-5's findings got — product defects surfaced by a docs epic do not reopen it:

- **`serve-mcp` silently ignores a declared `[sandbox] workspace`** (outward 6).
  Either attach it or refuse it, and say which; silently dropping a key a person
  wrote in a file is the failure F-D27 already named once.
- **A plugin tool that collides with a built-in is shadowed rather than refused**
  (inward 5). The name rule closes half the collision; this closes the rest.
- **`plugin.call` carries no arguments** (inward 7), where `mcp.host.call`
  carries a redacted summary. The inward door should record what the outward
  door records.

## What the machines could not sit

Everything above is a reader with the documents. The other half of E4-8 is a
reader with a *client*, and it was run separately, by hand, in a signed-in Claude
Code session on macOS — a thing no agent here can do. It found what twenty
document findings, nine tasks of tests, eleven recipes and a nineteen-check
acceptance run had all missed:

**`sandbox_read_file` returned nothing usable.** The file's bytes were in the
result's text block and only `{path, bytes}` in `structuredContent`. A client is
entitled to prefer one form or the other, and that one prefers the structured
form — so the tool's entire payload disappeared, and the session fell back to
`sandbox_exec cat`.

Nothing here could have caught it, and the reason is worth stating: every test
and every recipe in this repository reads the text block, because they were all
written by the same author as the tool. The generated reference documents a
tool's *inputs*; nothing described its result, so there was nothing for
generation to be consistent with.

That is the third form of E3-5's lesson. First: a generated page can be
perfectly consistent with its source and still be false. Second (outward #3
above): the pages a generator cannot reach are the ones that go stale. Third:
**the part no page describes is the part nothing checks.**

The fix and the rule it establishes are F-D47 — both forms carry the payload,
`encoding` says how, and a test plus the acceptance run check it for every tool
that returns data. The same session also found that the repository's own
`.mcp.json` was two epics out of date and unusable on macOS (F-D48).

## The finding worth keeping

Outward #3. `docs/README.md` — the page whose entire job is telling a reader
where to start — said the MCP surface was "not yet built", in a repository whose
CI had just executed eleven recipes that drive it. Nothing mechanical could
catch that: the sentence is prose, it was true when written, and no generator
touches it.

E3-5's lesson was that a generated page can be consistent and false. This one
adds the other half: the pages a generator *cannot* reach are the ones that go
stale, and the entry map is the first of them a reader meets.

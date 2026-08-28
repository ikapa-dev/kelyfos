# OTLP export — mapping the chain to a standard, without adopting it

*Mixed, written after the code rather than before it, the way `docs/retention.md`
was at P7-5: this is a projection off an already-frozen record, not a new
field on it, so there was nothing to specify ahead of a real mapping the way
`docs/policy-record.md` specified `session.policy` and `team.topology` before
either existed.*

## 1. What this is, and what it deliberately is not

`kelyfos log --export-otlp <path>` writes one session's flight recorder chain
as an [OTLP-JSON][otlp-json] trace export: the shape every existing tracing
backend — Jaeger, Grafana Tempo, an OpenTelemetry Collector's file receiver,
any vendor that speaks OTLP — already knows how to read. It exists because
those tools exist and this project would rather export *to* them than ask
anyone to build a KelyfOS-specific viewer for one more format.

It is **not** a second flight recorder. `internal/recorder`'s `Event` struct,
its frozen field order and the hash chain computed over it are untouched by
anything in this package — D59 settles this: the OTLP mapping is versioned
apart from the chain and is never an input to `kelyfos verify`. Concretely,
that means:

- `internal/otlp` (the package doing the mapping) imports `internal/recorder`
  to *read* events and `internal/digest` to fold them, and imports nothing
  the other direction — no door that writes a `session.policy` or a
  `command.start` event knows this package exists.
- The export is one-way and lossy. It is not read back by `kelyfos verify`,
  by `kelyfos log`, or by anything else in this repository. A reader who
  wants the record itself, tamper-evidence included, wants `kelyfos log
  --export` (recipe 6, `docs/cookbook.md`) — a different flag, a different
  file, a different promise.
- As of the OpenTelemetry GenAI semantic conventions this mapping targets
  (v1.42; the agent/tool span conventions have since moved out of the core
  `semantic-conventions` repository into a dedicated
  `semantic-conventions-genai` one, confirmed by reading both directly rather
  than assumed), every `gen_ai.*` attribute this package writes still carries
  the "Development" stability badge with no stabilisation timeline. A future
  revision can rename or restructure any of them and the
  fix is a change to `internal/otlp` alone — never a migration of anything
  hashed.

Because of that boundary, this document — unlike `docs/policy-record.md` for
`session.policy`/`team.topology` — carries no obligation to `tools/gendocs`
or `TestSchemaFieldsExist`: nothing here is a field on `Event`, so there is
nothing for either to cover. `kelyfos log -h` and `docs/reference/cli.md`
(generated) are where `--export-otlp` itself is documented as a flag.

[otlp-json]: https://github.com/open-telemetry/opentelemetry-proto/blob/main/docs/specification.md#json-protobuf-encoding

## 2. The shape

One `ExportTraceServiceRequest`, one resource (`service.name = "kelyfos"`,
`kelyfos.session.id`), one instrumentation scope (`name = "kelyfos"`,
`version` = the recording binary's own version off `session.start`), and a
flat list of spans that nest by `parentSpanId` rather than by JSON structure
— OTLP's own shape, not this project's choice:

```
kelyfos.session                         (root span, this package's own name — not gen_ai.*)
├── invoke_agent                        one per agent (or the sole implicit
│   │                                   agent of a non-team session)
│   ├── kelyfos.egress.attempt/refused  span *events*, not child spans
│   └── execute_tool <tool>             one per command.start, child of its
│                                       agent's own invoke_agent span
└── invoke_agent <other-agent>
    └── execute_tool <tool>
```

`gen_ai.operation.name` is `invoke_agent` on the agent spans and
`execute_tool` on the command spans — the two enum values named in the task
text, and the two [GenAI agent-span conventions][genai-agent-spans] whose own
"internal" variant (not the "client" one, which is for a call to a remote
hosted-agent service such as the OpenAI Assistants API or AWS Bedrock
Agents — not what a locally-spawned sandbox is) this package follows for
span kind (`SPAN_KIND_INTERNAL`) and the attributes it sets:

| Span | `gen_ai.*` attributes set | Also set |
| --- | --- | --- |
| `invoke_agent` | `operation.name`, `agent.name` (when named), `agent.id` (the member's own sandbox id, off `team.topology`) | — |
| `execute_tool` | `operation.name`, `tool.name` (the command's `argv[0]`), `tool.call.id` (the command's own correlation id), `agent.name` (inside a team) | `error.type` and `status` — only on failure, see §4 |

Two attributes this package could plausibly have used and deliberately does
not: `gen_ai.provider.name`, because the [conventions][genai-agent-spans]
require it on the *client* invoke-agent span and its whole well-known-value
list (`openai`, `anthropic`, `aws.bedrock`, …) names a GenAI *inference*
provider, which is not a fact KelyfOS has an honest answer for — a sandboxed
process's own choice of model, if it makes one, is invisible to the host that
records it. `gen_ai.tool.type` (`function`/`extension`/`datastore`)
similarly has no honest mapping for an arbitrary shell command. Both are
skipped rather than guessed, the same discipline that keeps this a
projection *to* the standard rather than a claim of full conformance with
it.

`server.address`/`server.port` on an egress span event are the stable,
generic OTel network attributes (not `gen_ai.*`), reused for `egress.attempt`'s
own `host`/`port` fields rather than inventing a KelyfOS-specific pair for the
same two facts.

Every other attribute is namespaced `kelyfos.*` and is exactly what
`docs/events.md` already documents for the field it is taken from —
`kelyfos.command.argv`, `.cwd`, `.via`, `.exit_code`, `.exited`;
`kelyfos.egress.allowed`, `.mode`, `.reason`, `.bytes_in`, `.bytes_out`;
`kelyfos.session.end_reason`; `kelyfos.arch`, `kelyfos.image`,
`kelyfos.team`, `kelyfos.served`.

[genai-agent-spans]: https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md

## 3. What is not mapped, and why

Deliberately, the same way `docs/policy-record.md` §8 lists what
`session.policy` omits:

- **`file.write`, `secret.use`, `team.message`/`team.refused`/`team.store`/
  `team.spawn`, `resource.*`, `plugin.*`, `mcp.host.*`.** The task text names
  three things this mapping owes: one `invoke_agent` span per agent, one
  `execute_tool` span per command, and egress attempts/refusals as span
  events. Everything else stays out rather than being folded in by
  extension — a mapping that grows attributes nobody asked for is exactly
  the kind of scope creep this phase's own non-goals discipline exists to
  catch, and every one of these event types is still fully available in the
  record itself (`kelyfos log`, `kelyfos log --json`) for a reader who
  wants it. `session.policy` and `team.topology` get no span or attribute
  set of their own for the same reason — but two of their fields are read
  regardless, because they answer questions the mapping already has to ask:
  `team.topology`'s `Agents[].Sandbox` is `gen_ai.agent.id` (§2), and
  `session.policy`'s `traceparent` seeds trace continuity (§5). Reading a
  field to answer a question already being asked is not the same thing as
  mapping the event.
- **Token usage, model parameters, chat history** (`gen_ai.usage.*`,
  `gen_ai.request.*`, `gen_ai.input.messages`, `gen_ai.output.messages`,
  `gen_ai.system_instructions`, …). KelyfOS has none of these facts —
  it records that a sandboxed process ran a command, not what a model inside
  that process was asked or told. Populating them with invented values would
  be worse than omitting them.
- **`gen_ai.tool.call.arguments`/`gen_ai.tool.call.result`.** Both are
  Opt-In, schema'd as structured objects, and explicitly flagged as likely
  to carry sensitive content by the conventions themselves. The command's
  own argv is still present as `kelyfos.command.argv`, in the same place
  `docs/events.md` already puts it, without machinery that reaches back into
  a schema this project does not control.

## 4. Errors

Per [`docs/general/recording-errors.md`][recording-errors]: a span's status
is left **unset** when nothing went wrong. `STATUS_CODE_OK` is never written
by this package — only `STATUS_CODE_ERROR`, with `error.type` and a message,
and only on a command that exited non-zero or never exited before the chain
did (`error.type = "incomplete"`), or a session whose own `session.end`
reason was `error` or `timeout`.

[recording-errors]: https://github.com/open-telemetry/semantic-conventions/blob/main/docs/general/recording-errors.md

## 5. Trace continuity

`session.policy`'s `traceparent` field (`docs/policy-record.md` §8.7) is
stored opaque — decomposing it was left as "a P7-11 concern if it turns out
to be one." It is one: when an inbound [W3C `traceparent`][traceparent]
parses, this session's OTLP export continues that trace (its `trace-id`
seeds every span in the export; its `parent-id` becomes the root
`kelyfos.session` span's own parent) instead of starting a new one. A
missing or malformed header — the common case, and the only one a session
opened directly rather than as a hop from another traced system will ever
carry — falls back to a trace id derived deterministically from the session
id, so re-exporting the same session twice is byte-identical.

[traceparent]: https://www.w3.org/TR/trace-context/#traceparent-header

## 6. Bounded output, considered rather than assumed

Unlike `internal/digest`'s `Domains`/`Store`/`Pairs`/`Secrets`/`PeerOnly`
maps — each capped at `MaxDistinctKeys` because the *key itself* is
guest-influenced and a compromised sandbox can mint an unbounded number of
distinct ones (a domain per connection attempt, a store key per request) —
this package caps nothing on its own, deliberately rather than by omission.
The number of `execute_tool` spans an export carries is exactly the number
of `command.start` events the chain holds, and that count is already what
every existing reader of the chain shows without a cap: the flat replay
(`kelyfos log`), the report's lane view, and `internal/digest.Timeline`
itself. A session that ran a hundred thousand real commands produces a
hundred thousand real spans in every one of those views, this one included
— that is the record being accurate, not the record growing without bound
the way a `Domains` map keyed on guest-chosen strings could. Capping span
*count* here, where nothing else in the product caps event count, would be
a new and inconsistent promise ("this export is a sample, not the whole
session") that nothing asked for and `kelyfos verify`'s own event-count
report would then contradict.

## 7. The IETF `agent-audit-trail` mapping: ready, not shipped

The task text asks for the machinery to be *ready* for a second mapping, to
the IETF `draft-sharif-agent-audit-trail-01` individual submission (expires
February 2027), and says explicitly that having it ready is "worth having…
rather than shipping." It is not shipped, and the reasons are worth stating
rather than leaving as a silent gap:

The draft's own record shape is considerably further from this project's
than OTLP's is. Every record needs a fresh UUIDv4 `record_id`; `agent_id` is
a URI matching a companion "Agent Passport" specification (MCPS) this
project does not implement; `trust_level` is a five-level (`L0`–`L4`)
cryptographic-attestation scale with no KelyfOS equivalent at any level;
`action_type` is a closed enum (`tool_call`, `tool_response`, `decision`,
`delegation`, `escalation`, `error`, `lifecycle`) that does not line up
one-to-one with this project's own event vocabulary — a `team.spawn` is
*something like* a delegation and is not one; hashing is over RFC 8785 JSON
Canonicalization (JCS), a different canonicalisation from `internal/recorder`'s
own struct-order hashing. Populating `trust_level` or `action_type` with a
value chosen to make a KelyfOS event fit the closest enum member would be
inventing a fact the record does not have — exactly the trap D59 already
names for OTLP's own `gen_ai.*` attributes, and a taller one here because the
draft's fields have no honest "leave it out" escape hatch the way
`gen_ai.provider.name` does.

What *is* ready: `internal/otlp.Build`'s own two-step shape —
`d := digest.Walk(events)` once, then one pass over `d.Timeline` grouping
entries by agent and by command — is generic to "walk the fold, group by
agent, group by command," not specific to OTLP's own span/event vocabulary.
A future `internal/aat` package mapping to the IETF draft would start from
the identical two steps and diverge only in what it builds from each
group — the same reuse this project's own `internal/digest` exists to buy
every reader of the chain (P7-1). Building that package now, against a
draft one individual submission away from its own next revision, would risk
exactly the "migration rather than an argument" `docs/policy-record.md` §8.8
warns a schema decided too early becomes — except here it is not even this
project's own schema to decide.

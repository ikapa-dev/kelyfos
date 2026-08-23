# Agent teams

**Status:** normative for `v0.5`. Written at task E2-0, before any broker code
exists; E2-1 through E2-9 implement it. If code and this document disagree, the
code is wrong.

A team is several KelyfOS sandboxes on one host, declared in a file, with the
paths between them enumerated and enforced. Think *docker-compose for agent
teams*: you write down who exists and who may talk to whom, and `kelyfos team
up` boots that graph.

What KelyfOS supplies is the substrate — isolation, enforced edges, a
permissioned shared store, and one audit record covering the whole team. What it
does not supply is any opinion about delegation: which agent asks which other
agent for what is the agent framework's business, and stays there.

Single-host only, permanently (F-D3). Multi-host scheduling, hosted control
planes and work queues as a product are the fleet layer, and that is somebody
else's product.

---

## 1. The shape of the thing

```toml
[team]
name = "reviewers"

[[team.agent]]
name  = "master"
image = "dev"
allow = ["github.com"]
secrets = ["GITHUB_TOKEN@api.github.com"]

  [team.agent.resources]        # exactly the [resources] keys of a single run
  cpus      = 2
  mem       = "2G"
  cpu_quota = "150%"

[[team.agent]]
name  = "worker"
image = "dev"
count = 3                       # worker-1, worker-2, worker-3

  [team.agent.resources]
  cpus = 1
  mem  = "1G"

[[team.edge]]
from = "master"
to   = "worker-*"               # every worker; master↔worker, bidirectional

[team.store]
enabled = true
```

Five VMs boot. Each has its own kernel, its own memory, its own egress policy
and its own resource caps. `master` may message any worker and any worker may
message `master`. No worker may message another worker — not because a rule
forbids it, but because there is nothing to send it over.

### 1.1 `[team]`

| key | type | meaning |
| --- | --- | --- |
| `name` | string | Identifies the team in the audit record and in `kelyfos team ps`. Required. |

### 1.2 `[[team.agent]]`

| key | type | meaning |
| --- | --- | --- |
| `name` | string | Unique within the team. Required. Becomes the address other agents use. |
| `image` | string | Flavor, as `kelyfos run --image`. |
| `count` | integer | Boot this many, named `<name>-1` … `<name>-N`. Default 1. |
| `allow` | array | Egress allowlist for this agent alone. |
| `secrets` | array | `NAME@domain`, names only, exactly as a single run. |
| `workspace` | string | Host directory for this agent's `/work`. |
| `[team.agent.resources]` | table | The `[resources]` keys of `docs/resources.md`, per agent. |

Every agent's egress and every agent's caps are its own. There is no team-wide
allowlist, and adding one would be a mistake: the reason to run a worker in its
own VM is that it gets its own answer to "what may this reach", and a shared
list would quietly hand the least trusted agent the most trusted agent's
network.

### 1.3 `[[team.edge]]`

| key | type | meaning |
| --- | --- | --- |
| `from` | string | Agent name, or a `name-*` glob over a `count` group. |
| `to` | string | Same. |
| `bidirectional` | bool | Default `true`. |

The edge list **is** the topology. A star is one edge from the master to a
worker glob; a mesh is the edges you write; a pipeline is a chain of
unidirectional edges. There is no `topology = "star"` keyword and there will not
be one — a keyword is a summary of the edge list, and a summary is a second
place for the truth to live.

### 1.4 `[team.store]`

| key | type | meaning |
| --- | --- | --- |
| `enabled` | bool | Whether the team has a store at all. Default `false`. |
| `[[team.store.key]]` | table | Per-key access rules; see §4. |

---

## 2. There is no guest-to-guest network

This is the property everything else rests on, so it is worth stating flatly
before the mechanics.

**No sandbox in a team has a network path to any other sandbox.** Each guest has
at most one NIC, on its own TAP, and two nftables rules decide what that TAP can
do (`docs/networking.md` §3, installed per sandbox by `applyFirewall`):

```
chain kelyfos_guest_in {
        ip daddr <host TAP address> tcp dport <proxy port> accept
        counter drop
}
chain forward {
        iifname "<tap>" counter drop
        oifname "<tap>" counter drop
}
```

The first says the only destination the guest may reach is this sandbox's own
egress proxy. The second says nothing is forwarded into or out of that interface
at all — which is precisely the hook a packet from one guest to another would
have to traverse. So guest-to-guest is not merely unrouted, it is dropped on a
rule that exists for that reason, and a team of five sandboxes has five separate
such rulesets.

Every inter-agent message therefore travels the path it already had: the guest's
existing vsock channel to the host, into the broker in the `kelyfos` process, and
out over the recipient's vsock channel. The host is not a convenience in the
middle; it is the *only* thing in the middle, and it is where the edge list is
checked.

That gives three things at once, and none of them are separately implemented:

- **A message that no edge permits cannot be delivered**, because delivery is a
  host function and the host consults the edge list first.
- **Every message is auditable**, because every message passes through the
  process that writes the audit log.
- **A compromised agent gains nothing by looking**, because there is no network
  neighbour to find. Scanning its own subnet finds the proxy and stops.

---

## 3. Broker semantics

The guest sees the team as MCP tools (E2-2), which is how the guest sees
everything else. Six of them.

### 3.1 `team_send(to, body)`

Deliver `body` to agent `to`. Returns when the broker has accepted or refused
it, not when the recipient reads it.

**Delivery is at-most-once.** A message is delivered zero or one times, never
twice. If the recipient's channel is gone, `team_send` fails with an explicit
error — the message is not queued for a machine that may never come back, and
KelyfOS does not become a message broker with durability guarantees it would
then have to keep. An agent that needs a message to arrive should ask for an
answer (§3.3) rather than assume.

**Delivered messages are FIFO per edge.** Two messages from A to B arrive in the
order A sent them. Nothing is promised about the interleaving of A→B with C→B:
those are different edges and the recipient sees whichever the broker took
first.

### 3.2 `team_recv(timeout)`

Take the next message addressed to this agent, waiting up to `timeout`. Returns
the sender and the body, or nothing if the window closed empty.

### 3.3 `team_ask(to, body, timeout)` and `team_reply(id, body)`

`team_ask` is a question with a correlated answer: the broker tags it, delivers
it, and blocks the asker until the recipient calls `team_reply` with the same
tag or the timeout expires. It exists because it is the primitive agents
actually need — "worker asks the master which of two readings of the ticket is
right, and waits" is the shape of nearly every real multi-agent exchange, and
building it out of `send` plus `recv` plus a correlation scheme is a thing every
user would otherwise write once, badly.

On the receiving side a question arrives as an ordinary MCP tool event, so
answering it is natural for a model: it sees a question and a reply tool.

**A reply needs no edge of its own.** It travels the return path of the ask that
provoked it, which the broker is already holding open. This matters for
unidirectional edges: `A → B` lets A ask B a question and lets B answer it,
without letting B start a conversation.

### 3.4 `team_peers()`

The agents this one may **initiate** to. On a unidirectional `A → B` edge, A
sees B and B does not see A. An agent cannot enumerate the team, only its own
reach — a worker in a star learns that a master exists and learns nothing about
its siblings.

### 3.5 `team_store_get(key)` / `team_store_put(key, value)`

The shared-knowledge mechanism, §4.

### 3.6 How an agent is told which agent it is

On the kernel command line, as `kelyfos.agent=<name>`, for the same reason the
proxy address arrives that way: it is the one thing inside the guest that the
guest did not write. An agent cannot rename itself into another agent's edges,
and the host does not have to trust a name a guest asserts.

A sandbox with no `kelyfos.agent` is not in a team, and the six tools above are
not listed for it at all. A tool that is always advertised and always fails
teaches a model to ignore failures.

### 3.7 Errors are explicit

Every refusal is an error the calling agent receives and can act on, never a
silent drop:

| error | when |
| --- | --- |
| `no_edge` | The topology does not permit this pair. Audited. |
| `no_such_agent` | The name is not in this team. |
| `unreachable` | The recipient exists but its channel is gone. |
| `timeout` | An `ask` expired, or a `recv` window closed empty. |
| `denied` | Store access this agent does not have, or a spawn it may not make. |

---

## 4. The team store

A host-side key/value store, one per team, with per-key access rules:

```toml
[team.store]
enabled = true

  [[team.store.key]]
  name  = "findings/*"
  write = ["worker-*"]
  read  = ["master"]

  [[team.store.key]]
  name  = "plan"
  write = ["master"]
  read  = ["*"]
```

Unlisted keys are readable and writable by the whole team. A listed key is
readable and writable only by what it lists. Every access — permitted or not —
is an event in the flight recorder, which is the difference between shared state
and shared state you can account for afterwards.

### 4.1 Why a store rather than shared memory or a shared disk

Two separate facts, with two separate reasons, because they get conflated:

- **Cross-VM shared RAM is impossible here.** Firecracker ships no shared-memory
  device. That is not an oversight to route around; the minimal device model is
  the security posture, and the same restraint that makes a KelyfOS guest worth
  trusting is what makes shared memory unavailable (F-D1's sibling fact).
- **Two guests cannot mount one ext4 read-write.** ext4 is not a cluster
  filesystem. This is true on any hypervisor and has nothing to do with
  Firecracker; mounting the same block device read-write from two kernels
  corrupts it.

Read-only multi-mounting is fine, and KelyfOS already does it: every fork shares
one rootfs image. The store is the safe equivalent for state that has to change,
and unlike either alternative every access to it is permissioned and recorded.

---

## 5. The topology is fixed for the run

The graph you declared is the graph you get, from `team up` to `team down`.
There is no live rewiring: no tool adds an edge, no tool removes one, and no
tool changes another agent's caps or allowlist. A topology that can be edited by
the agents inside it is not an enforced topology, it is a suggestion with extra
steps.

**One sanctioned exception**, and only one: an agent whose policy grants
`team.spawn` may ask for a worker at runtime (E2-5). The new worker attaches
with **exactly one edge, to its spawner**, plus whatever store access the spawn
budget's template grants. It cannot be given any other edge, and nothing about
any existing agent changes. Spawns are bounded by a budget the user wrote down
before the run:

```toml
[team.agent.spawn]
max        = 4              # at any one time
image      = ["dev"]        # nothing else may be booted
lifetime   = "10m"
  [team.agent.spawn.resources]
  cpus = 1
  mem  = "1G"
```

The decision *to* spawn stays agent-side; KelyfOS enforces only what the user
pre-authorised. A spawn beyond the budget is refused and audited, as is a spawn
by an agent with no `team.spawn` at all.

---

## 6. What the record contains

Every team event goes into the same hash-chained flight recorder a single
session uses (`docs/events.md`), so a team produces one verifiable transcript
rather than five that have to be correlated afterwards.

| type | meaning |
| --- | --- |
| `team.message` | One delivery: from, to, size, body hash, and whether it was an ask, a reply or a send. |
| `team.refused` | A message the edge list did not permit. Its own type, because it is the interesting one. |
| `team.store` | A store access: key, agent, read or write, permitted or not. |
| `team.spawn` | A worker spawned or refused, with the budget it was checked against. |

Payload capture is a per-team switch:

```toml
[team]
record_payloads = false      # default: metadata and a hash, never the body
```

Off by default. A team passing customer data between agents should be able to
prove what moved without keeping a second copy of it, and a hash lets a claim
about a message be checked later without the message being stored.

### 6.1 The recorder is not a delivery buffer

These two facts are orthogonal and are stated together because they look
contradictory at a glance:

- **Delivery is at-most-once.** A message to a machine that has gone is an error
  to the sender, not a promise kept later.
- **The audit log is durable.** Every attempt is recorded, including the ones
  that failed.

The recorder logs *outcomes*. It is not a queue, nothing is ever redelivered
from it, and a message appearing in the log is not evidence it was received —
that is what the outcome field is for.

---

## 7. Conformance

| Requirement | Task |
| --- | --- |
| This schema and these semantics | E2-0 |
| Host broker enforcing the edge list, every message an event | E2-1 |
| The six MCP tools in the guest | E2-2 |
| The permissioned team store | E2-3 |
| `kelyfos team up \| ps \| down` | E2-4 |
| Spawn under a declared budget | E2-5 |
| Team-level cgroup hierarchy, per-agent slices beneath it | E2-6 |
| `log --verify` over the whole team, `log --export team.html` | E2-7 |
| Multi-lane `kelyfos watch` | E2-8 |
| The committed demo, including a refused edge | E2-9 |

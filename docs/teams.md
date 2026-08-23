# Agent teams

**Status:** normative for `v0.5`. Written at E2-0 before any broker code
existed; E2-1 through E2-9 implemented it and F-D26 revised how a team boots.
The spec-wins rule it carried through the epic has expired with the epic: the
shipped behaviour is now the reference, and a disagreement between this file and
the code is a bug in this file.

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
| `record_payloads` | bool | Whether message bodies are captured. Default `false`; see §8. |
| `[team.resources]` | table | The collective cap the whole team shares. One key, `cpu_quota`; see §6. |

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

What each key actually does, because for one release these were parsed and then
silently dropped:

- `allow` builds this agent a TAP, an egress proxy bound on it, and the nftables
  table that makes the proxy the only reachable destination — the same order and
  the same machinery `kelyfos run` uses. **An agent with no `allow` gets no
  network interface at all**, which is why a worker in `kelyfos team ps` shows
  `EGRESS none` rather than an empty allowlist.
- `secrets` binds a host credential to a domain for this agent alone. The value
  stays on the host, the proxy terminates TLS for that domain and attaches the
  header, and the guest is handed the per-run trust anchor and nothing else
  (D6). A secret bound to a domain outside **this agent's** `allow` is refused
  at the file: a credential that can never be spent is a policy mistake, not a
  runtime condition.
- `workspace` packs that host directory as this agent's `/work` before it boots,
  and `kelyfos team down` writes it back — every agent's own, in the reverse of
  the order they started. One directory behind a `count` group is refused: two
  machines writing one directory back is a race whose loser's work disappears.
- `[team.agent.resources]` applies per agent exactly as `[resources]` applies to
  a run, including `cpu_quota`, which puts that agent's Firecracker process in
  its own cgroup v2 slice. One exception, written down rather than left to be
  discovered: `idle_timeout` is **refused** per agent (F-D20, and
  `docs/resources.md`), because a team shares one flight recorder and the host
  cannot yet tell which agent went quiet. `max_runtime` is per agent and works.

Every one of these is enforced host-side (F-D2). Nothing in the guest is asked
to respect any of it, and a guest that tried could not: it has no interface to
bring up, no credential to withhold and no cgroup to leave.

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
everything else. Seven, plus `team_spawn` for an agent whose policy granted a
budget — eight in total, and the eighth is listed only where it would work
(§3.6, F-D18).

Every argument named `timeout_ms` is an **integer number of milliseconds** and
defaults to **60000** when it is absent or not positive.

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

### 3.2 `team_recv(timeout_ms)`

Take the next message addressed to this agent, waiting up to `timeout_ms`.
Returns the sender and the body — and, when the message is a question, the
`correlate` tag to answer it with.

An empty window is an **error**, kind `timeout`, not an empty result. That is
deliberate: a model that receives "nothing" reasonably concludes there is
nothing to do, while a model that receives a timeout knows only that nothing has
arrived *yet*, which is the true statement and the one that leads it to wait
again.

### 3.3 `team_ask(to, body, timeout_ms)` and `team_reply(correlate, body)`

`team_ask` is a question with a correlated answer: the broker tags it, delivers
it, and blocks the asker until the recipient calls `team_reply` with the same
tag or `timeout_ms` expires. It exists because it is the primitive agents
actually need — "worker asks the master which of two readings of the ticket is
right, and waits" is the shape of nearly every real multi-agent exchange, and
building it out of `send` plus `recv` plus a correlation scheme is a thing every
user would otherwise write once, badly.

On the receiving side a question arrives as an ordinary MCP tool event, so
answering it is natural for a model: it sees a question and a reply tool. The
argument is called `correlate`, and it is the value `team_recv` returned in its
`correlate` field — one name for one thing, on both sides.

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

### 3.6 `team_spawn(image)`

Listed only for an agent whose policy granted a spawn budget (§5). It returns
the new worker's name, `<spawner>-spawn-N`, and the worker is ready — a booted
machine, not a promise of one. A spawn outside the budget is an error the
asking agent receives, with the budget in the message so a model can adjust
rather than retry blindly:

    denied: master already has 2 of its 2 spawned workers running
    denied: master may not spawn the "base" image; its budget permits [dev]

An agent with no budget does not see the tool. The check that matters is
host-side either way: an agent that calls a tool it was never shown still gets a
refusal, and that refusal is in the record (F-D18).

**A spawned worker has no egress, no secrets and no workspace — ever.** A spawn
budget can declare a count, an image whitelist, a lifetime and resource caps,
and there is nowhere in it to declare a network. So a worker created at runtime
is always a machine with no NIC, which is the conservative reading of
"pre-authorized by the user": the user authorized capacity, not reach. A worker
that needs the network has to be declared as a `[[team.agent]]` with its own
`allow`.

### 3.7 How an agent is told which agent it is

On the kernel command line, as `kelyfos.agent=<name>`, for the same reason the
proxy address arrives that way: it is the one thing inside the guest that the
guest did not write. An agent cannot rename itself into another agent's edges,
and the host does not have to trust a name a guest asserts.

A sandbox with no `kelyfos.agent` is not in a team, and the tools above are
not listed for it at all. A tool that is always advertised and always fails
teaches a model to ignore failures.

### 3.8 Errors are explicit

Every refusal is an error the calling agent receives and can act on, never a
silent drop:

| error | when |
| --- | --- |
| `no_edge` | The topology does not permit this pair. Audited. |
| `no_such_agent` | The name is not in this team. |
| `unreachable` | The recipient exists but its channel is gone. |
| `timeout` | An `ask` expired, or a `recv` window closed empty. |
| `denied` | Store access this agent does not have, a spawn it may not make, a `team_reply` with a `correlate` tag that is missing or not its own, or any call on a team with no store. |
| `bad_request` | The call itself was malformed — a body that is not valid base64, an unknown operation. |
| `internal` | The host failed at something it had already permitted. |

**The kind an agent receives and the reason the record carries are two different
vocabularies, deliberately.** An agent branches on a small set it can act on; the
transcript records the specific thing that happened. A `team_reply` with a tag
nobody is waiting for returns `denied` to the agent and is recorded with
`reason: unknown_correlation`; one with no tag at all returns `denied` and is
recorded `missing_correlation`. If you are writing an orchestrator, branch on the
kind and read the record for the detail.

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
readable and writable only by what it lists, so **adding a rule can only narrow
access, never widen it** — the direction a policy file should be able to move a
permission in. The first rule whose key matches decides, so a reader can stop at
the first line that mentions the key.

Every access — permitted or not — is an event in the flight recorder, which is
the difference between shared state and shared state you can account for
afterwards.

Two limits, neither of them a security boundary (the sandbox is that): a value
is at most 1 MiB and a team's store at most 64 MiB. A store with no bound is a
way for one agent to make the host hold an unbounded amount of data on the
team's behalf, and a team that hits a limit gets an error rather than a host that
has quietly swallowed a gigabyte.

**Absence is not a refusal.** Reading a key that was never written is
`not_found`; reading one you may not read is `denied`. An agent that cannot tell
the two apart retries the wrong problem.

Nothing in the tool surface enumerates keys. A key *name* can itself be
information one agent has and another does not.

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
with **exactly one edge, to its spawner** — and nothing else. It cannot be given
another edge, nothing about any existing agent changes, and its store access is
only whatever the policy's key rules already grant a name like its own
(`master-spawn-1` matches `master*`, and matches nothing it was not already
going to match). Its caps come from the budget's `[team.agent.spawn.resources]`,
never from its spawner's: an agent that could spawn copies of itself would
otherwise multiply its own ceiling. Spawns are bounded by a budget the user wrote down
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
by an agent with no `team.spawn` at all — the host decides, so a refusal always
reaches the log even when the asking agent was never shown the tool.

`lifetime` is enforced by the host, not asked of the worker: when it expires the
worker is shut down, a `despawn` is recorded, and its place in the budget comes
back. `kelyfos team ps` lists spawned workers alongside declared ones, so the
team you can see is the team that exists.

---

## 6. The team budget

`[team.resources]` is the collective cap: what the team as a whole may consume,
whatever any one agent's own ceiling says.

```toml
[team]
name = "reviewers"

  [team.resources]
  cpu_quota = "200%"        # two cores' worth, for all five agents together

[[team.agent]]
name = "master"
  [team.agent.resources]
  cpu_quota = "150%"        # and no more than one and a half on its own
```

One key, deliberately. `cpu_quota` is the only cap a team can meaningfully
share, because it is the only one the kernel will divide for us: cores, RAM and
disk are each agent's own machine, and a parent cannot pool hardware that was
handed out at boot. A per-agent key written here is refused by name and line,
with the answer to the question actually being asked — it is a wrong mental
model rather than a typo, and F-D16's promise is that the file says which.

**This is not the team-wide allowlist §1.2 argues against, and the difference is
the direction.** A shared allowlist would *give* every agent the union of what
each was trusted with — it hands the least trusted agent the most trusted one's
network. A shared cap *takes away*: it is a ceiling above the ceilings, and no
agent gains anything from another's presence in it.

### 6.1 How it is enforced

One cgroup v2 slice per team, with each agent's own E1-2 slice as a child of it
(E2-6). The kernel then composes the two ceilings and the host does no
arithmetic: an agent may never exceed its own `cpu.max`, and the team may never
exceed the parent's. Every child carries `cpu.weight = 100` — an equal share,
which is what "divides contention fairly" means: nothing is privileged, and the
parent's bandwidth splits evenly among whichever agents are actually competing
for it.

The distinction between the two knobs is the same one `docs/resources.md` draws
between `cpus` and `cpu_quota`, one level up:

- **`cpu.max` is a ceiling.** It binds even on an idle machine.
- **`cpu.weight` is a share.** It only decides anything when siblings contend.
  With no contention it changes nothing.

So a team at `cpu_quota = "200%"` with five equally weighted agents gives one
busy agent up to 200% (or its own lower ceiling), and five busy agents 40% each.

**The sum is deliberately not checked.** Five agents at `100%` under a team cap
of `200%` is legal, and is the configuration worth writing: each may burst to
its own ceiling while the others idle, and the parent holds the total. Refusing
oversubscription would forbid the only reason a shared budget exists. What *is*
refused is a single agent asking for more than the team — a ceiling written
above another ceiling and then ignored is a number a reader would later trust.

A team that declares no `cpu_quota` anywhere — not at team level, not on any
agent — gets no cgroup machinery at all, and so needs neither a systemd user
session nor a delegated cgroup to run.

### 6.2 Where the cap is applied

The host applies it the same two ways E1-2 applies a single sandbox's quota
(F-D11), and the difference between them is worth knowing:

- **Directly**, as root or with a delegated cgroup root: KelyfOS creates the
  parent, writes its `cpu.max`, delegates the cpu controller to its children,
  and each agent's Firecracker is placed inside at clone time. The cap is in
  place before any agent exists.
- **Through the user manager**, under a systemd user session: the parent is a
  slice, `kelyfos-team-<name>.slice`, and its cap is set with
  `systemctl --user set-property --runtime` **before the first agent starts** —
  which creates the slice and every level above it, so there is likewise no
  window in which the team runs uncapped. Each agent is then started into it
  with `systemd-run --slice`. Writing the slice's `cpu.max` by hand instead was
  measured and rejected: systemd applies the unit's own properties when it
  materialises the slice, so a value written into a directory systemd has not
  started yet is discarded.

The team's name becomes exactly one component of that slice path, whatever it
contains: `-` is systemd's hierarchy separator, so a team called `foo-bar` would
otherwise silently add a level and cap something other than the team.

`kelyfos team ps` prints the parent's own accounting — CPU used and CPU
throttled — read from the cgroup the cap is written on, so the number and the
limit cannot be about different things. Each agent's row carries its own
consumption beside its own ceiling, for the same reason: a figure without the
cap it was measured against is half a figure.

---

## 7. How a team boots

`kelyfos team up` starts its agents by one of two paths, chosen per agent from
the policy file before anything runs.

An agent whose policy grants it **egress** is **cold-booted**, concurrently with
every other agent. It cannot be forked, and the reason is physics rather than
effort: a fork resumes from a memory image, and the guest's address and default
route live *inside* that image — so N networked forks would be N machines each
believing it is the same host. `kelyfos fork` refuses a networked snapshot for
exactly this reason.

An agent granted **no egress** has no network identity to collide with, so it
*can* be forked. Whether it is depends on one more thing: whether a template for
its exact machine already exists.

**Cold-first, fork-warm.** With no cached template, every agent boots cold —
concurrently, and that is all that happens. The template is built afterwards, in
the background, while the team is already working; the next `team up` of the
same shape forks its no-egress workers from it. The reason is measured rather
than assumed: on the reference environment — a bare-KVM x86_64 CI runner, which
is the only machine any timing claim in this project is made about — a cold boot
is 109–134 ms and writing a 384 MiB memory image is 927 ms, so a "fast path"
that builds its own template first is slower than not having one. Paying that
write once is what makes forking worth having: after it a fork is 57–61 ms
there, and it beats the cold boot on every machine tested (F-D25, F-D26).

**Expect entirely different numbers on a laptop**, and do not read them as a
regression. Under nested virtualisation — a Lima or WSL2 layer on a developer's
machine — a cold boot is measured in seconds rather than milliseconds, because
every device access is serviced by a hypervisor inside another hypervisor. The
ratio between the two paths survives, which is the part that matters: forking is
still much cheaper than booting there, and more so than on the reference.

The template is a mould: it is never in the roster, never appears in the
transcript as an agent, has no team channel of its own, and is stopped as soon
as its image is on disk.

**The cache.** Templates live in `~/.cache/kelyfos/templates/<key>`, where the
key is a digest of everything baked into a memory image *and the identity of the
image itself* — architecture, flavor, the kernel and rootfs `sha256` from
`image.json`, vCPUs, memory, scratch, the I/O rates, and whether the agent has a
spawn budget. Rebuilding an image changes its rootfs digest and therefore the
key, so a stale template can never be served for a new image: it is simply never
looked up again, and ages out. A template is written to a temporary directory
and renamed into place, so a half-written one is never a cache hit.

The cache is bounded at **2 GiB**, evicted least-recently-used, and it says so
on stderr when it evicts. Delete the directory to clear it; the next team-up
will be a cold one and will fill it again.

`cpu_quota` deliberately does not enter the key: it is a host-side cgroup on the
VMM process rather than anything inside the machine, so forks of one template can
hold different quotas and each gets its own slice. A `workspace` disqualifies an
agent from forking for a different reason: a fork copies the template's disk, and
handing agent B a copy of agent A's files is worse than a slower boot. A group of
one is cold-booted too — a template exists to be copied, and copying it once is
not a saving.

**A fork is not told who it is by its own image.** Every fork of one template
carries that template's kernel command line, including its `kelyfos.agent=`
name. This does not matter, because the host has always been the side that
decides which agent a channel belongs to: the broker is called with the name the
*host* bound to that machine's team channel, and a guest's opinion of its own
name is never read off the wire. The one place a guest used to answer that
question for itself — the `agent` field `team_peers` returns — now comes back
from the host with the peers.

Which path each machine took is not left to be inferred. It is printed by
`team up`, carried in `kelyfos team ps` under `BOOT`, and written into the
team's chain as a `session.ready` event per agent with `via: "fork"` or
`via: "cold"`.

---

## 8. What the record contains

Every team event goes into the same hash-chained flight recorder a single
session uses (`docs/events.md`), so a team produces one verifiable transcript
rather than five that have to be correlated afterwards.

| type | meaning |
| --- | --- |
| `team.message` | One delivery: from, to, size, body hash, and whether it was an ask, a reply or a send. |
| `team.refused` | A message the edge list did not permit. Its own type, because it is the interesting one. |
| `team.store` | A store access: key, agent, read or write, permitted or not. |
| `team.spawn` | A worker spawned or refused, with the spawner, the worker's name and the reason on a refusal. |

Payload capture is a per-team switch:

```toml
[team]
record_payloads = false      # default: metadata and a hash, never the body
```

Off by default. A team passing customer data between agents should be able to
prove what moved without keeping a second copy of it, and a hash lets a claim
about a message be checked later without the message being stored.

### 8.1 Reading it back

`kelyfos log --verify` over a team session verifies the whole team, because
there is only one chain to verify. It says how many agents it covered and names
them, so the claim can be checked against the team that was declared:

```
$ kelyfos log --session 269043fa --verify
session 269043fa: chain intact, 44 events verified across 3 agents (master, worker-1, worker-2)
```

`kelyfos log --export team.html` renders that same chain as **one lane per
agent**, in boot order, with a message between two agents drawn as a bar
spanning exactly the columns it connects — an ask points forward, a reply points
back, a refusal is flagged and still drawn, because what was attempted is the
part worth seeing. Store accesses sit inline in the lane of the agent that made
them; commands, files, egress attempts, OOM kills and each member's usage
receipt sit in that member's lane. Events that belong to the team rather than to
any member span every lane.

While the team is up, `kelyfos log --session <agent's sandbox id>` redirects to
the team's record and says so. After `team down` the run directories are gone,
so that redirect no longer works and the team session is found by its own id or
with `kelyfos log --list`, which marks the sessions that hold a team. The record
itself is unaffected: with no `--session` at all, `kelyfos log` still takes the
most recent session, which immediately after a `team down` is the team's.

### 8.2 Watching it live

`kelyfos watch` on a team session shows one lane per agent, side by side: each
agent's commands and their output, its files, its egress attempts, and what it
is consuming against its own caps. The team's collective budget sits above them
and the messages between agents run in a ticker underneath — a message belongs
to two agents, so it belongs in neither lane.

There is no flag and no second command. A team is one session, so the same file
feeds both views, and the events' own `agent` field is what splits it into
lanes. It is still only a reader: it never opens a channel to a guest, and
quitting it leaves the team running (D7).

Lanes need room. Below about twenty-two columns each, the view stops laying out
columns, says how wide the terminal would have to be, and shows one column with
each line labelled by the agent it came from — the information without the
layout, rather than the layout without the information.

### 8.3 The recorder is not a delivery buffer

These two facts are orthogonal and are stated together because they look
contradictory at a glance:

- **Delivery is at-most-once.** A message to a machine that has gone is an error
  to the sender, not a promise kept later.
- **The audit log is durable.** Every attempt is recorded, including the ones
  that failed.

The recorder logs *outcomes*. It is not a queue, nothing is ever redelivered
from it, and a message appearing in the log is not evidence it was received —
that is what the outcome field is for.

One consequence worth stating, because the outcome vocabulary invites the wrong
guess. `outcome: timeout` is **an ask that nobody answered in time**. A
`team_recv` whose window closes empty returns a `timeout` error to the agent and
writes *no event at all*, because nothing happened: no message was sent, none was
delivered, and a recorder of message outcomes has no outcome to record. An
orchestrator waiting on a quiet agent should not expect the record to say so.

---

## 9. Conformance

| Requirement | Task |
| --- | --- |
| This schema and these semantics | E2-0 |
| Host broker enforcing the edge list, every message an event | E2-1 |
| The team MCP tools in the guest | E2-2 |
| The permissioned team store | E2-3 |
| `kelyfos team up \| ps \| down` | E2-4 |
| Spawn under a declared budget | E2-5 |
| Team-level cgroup hierarchy, per-agent slices beneath it | E2-6 |
| `log --verify` over the whole team, `log --export team.html` | E2-7 |
| Multi-lane `kelyfos watch` | E2-8 |
| The committed demo, including a refused edge | E2-9 |

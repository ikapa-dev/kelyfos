package team

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/denial"
)

// Budget is what an agent with team.spawn may ask for at runtime. It is the
// user's, written before the run; the decision to spawn is the agent's.
//
// KelyfOS enforces only what was pre-authorised, which is the whole shape of
// this feature: an agent that decides to spawn is doing its job, and an agent
// that decides to spawn a hundred of something is doing its job badly. The
// budget is what makes the second harmless.
type Budget struct {
	Max       int
	Images    []string
	Lifetime  time.Duration
	Resources any // opaque here; the host knows what a resource cap is
}

// SpawnRequest is what the host is asked to boot. The broker has already
// decided that it may exist, what it is called, and what it may reach.
type SpawnRequest struct {
	Name     string
	Spawner  string
	Image    string
	Lifetime time.Duration
	Budget   *Budget
}

// Spawn types for the record.
const (
	TypeSpawn = "team.spawn"

	KindSpawn   = "spawn"
	KindDespawn = "despawn"
)

// GrantSpawn gives an agent a spawn budget. Called once per agent at team-up,
// from the policy file; there is no tool that grants one, because a topology
// that can widen its own permissions is not an enforced topology.
func (b *Broker) GrantSpawn(agent string, budget Budget) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.budgets == nil {
		b.budgets = map[string]Budget{}
	}
	b.budgets[agent] = budget
}

// Spawn adds a worker at the request of an agent that was granted a budget.
//
// This is the single sanctioned exception to a topology being fixed for the run
// (docs/teams.md §5), and it is narrow on purpose: the new worker attaches with
// exactly one edge, to its spawner, and nothing about any existing agent
// changes. It cannot be given another edge afterwards, because there is no tool
// that adds one.
func (b *Broker) Spawn(spawner, image string) (SpawnRequest, error) {
	b.mu.Lock()
	budget, ok := b.budgets[spawner]
	if !ok {
		b.mu.Unlock()
		b.record(Event{Type: TypeSpawn, From: spawner, Kind: KindSpawn,
			Outcome: OutcomeRefused, Reason: "no_spawn_budget"})
		return SpawnRequest{}, &Error{Kind: "denied",
			Message: denial.TeamSpawnNone.Render(denial.V{"agent": spawner})}
	}
	live := b.spawnedBy[spawner]
	if len(live) >= budget.Max {
		b.mu.Unlock()
		b.record(Event{Type: TypeSpawn, From: spawner, Kind: KindSpawn,
			Outcome: OutcomeRefused, Reason: "budget_exhausted"})
		return SpawnRequest{}, &Error{Kind: "denied",
			Message: denial.TeamSpawnBudget.Render(denial.V{"agent": spawner,
				"live": strconv.Itoa(len(live)), "max": strconv.Itoa(budget.Max)})}
	}
	if image == "" && len(budget.Images) > 0 {
		image = budget.Images[0]
	}
	if !allowedImage(budget.Images, image) {
		b.mu.Unlock()
		b.record(Event{Type: TypeSpawn, From: spawner, Kind: KindSpawn,
			Outcome: OutcomeRefused, Reason: "image_not_permitted"})
		return SpawnRequest{}, &Error{Kind: "denied",
			Message: denial.TeamSpawnImage.Render(denial.V{"agent": spawner, "image": image,
				"permitted": strings.Join(budget.Images, ", ")})}
	}

	b.spawnSeq++
	name := fmt.Sprintf("%s-spawn-%d", spawner, b.spawnSeq)
	// The minted name has to be free before it is used, because taking one that
	// is not is not a naming collision — it is a merge. The mailbox below would
	// replace the sitting agent's, both machines would then race on one channel,
	// and attach would leave that agent's *whole* edge set in place under the
	// name and add the spawner's on top — so the worker would inherit every edge
	// it had, against the "exactly one edge, to its spawner" this one exception
	// to a fixed topology rests on (docs/teams.md §5). Store access follows the
	// name too, and the name would appear twice in `team ps`, until the first
	// despawn removed the edges of both.
	//
	// Refused rather than bumped along until a free name turns up, in the shape
	// P6-24 settled for names generally: a team that reaches this has a config to
	// fix, and a worker quietly renamed out of the way hides it. The sequence
	// stays spent, so the agent's next attempt mints a different name and works.
	if _, taken := b.boxes[name]; taken || b.topo.Exists(name) {
		b.mu.Unlock()
		b.record(Event{Type: TypeSpawn, From: spawner, To: name, Kind: KindSpawn,
			Outcome: OutcomeRefused, Reason: "name_taken"})
		return SpawnRequest{}, &Error{Kind: "denied",
			Message: name + " is already an agent in this team, so a spawned worker " +
				"cannot be called that; rename that agent in the team file"}
	}
	b.spawnedBy[spawner] = append(live, name)
	b.boxes[name] = make(chan Message, mailbox)
	b.mu.Unlock()

	// One edge, to its spawner, in both directions — which is what a
	// [[team.edge]] between two agents means by default, and what makes a
	// spawned worker able to answer the agent that asked for it.
	b.topo.attach(name, spawner)

	b.record(Event{Type: TypeSpawn, From: spawner, To: name, Kind: KindSpawn,
		Outcome: OutcomeDelivered})
	return SpawnRequest{Name: name, Spawner: spawner, Image: image,
		Lifetime: budget.Lifetime, Budget: &budget}, nil
}

// Despawn removes a spawned worker, freeing its place in its spawner's budget.
// The host calls it when the worker's lifetime expires or the team comes down.
func (b *Broker) Despawn(name string) {
	b.mu.Lock()
	spawner := ""
	for who, list := range b.spawnedBy {
		for i, n := range list {
			if n == name {
				spawner = who
				b.spawnedBy[who] = append(list[:i:i], list[i+1:]...)
				break
			}
		}
	}
	// Nothing is removed until the name is known to belong to a worker somebody
	// spawned. The delete used to come first, so a despawn of a name this broker
	// never minted took a declared agent's mailbox with it and then returned
	// before touching the topology — leaving that agent in the team, with its
	// edges, and unable to receive: senders would be told it is not reading its
	// messages, and the agent itself that it is not in this team. No caller
	// passes such a name today, which is why this was latent; it is the ordering
	// that keeps it that way if one ever does.
	if spawner == "" {
		b.mu.Unlock()
		b.record(Event{Type: TypeSpawn, To: name, Kind: KindDespawn,
			Outcome: OutcomeRefused, Reason: "not_a_spawned_worker"})
		return
	}
	delete(b.boxes, name)
	b.mu.Unlock()
	b.topo.detach(name)
	b.record(Event{Type: TypeSpawn, From: spawner, To: name, Kind: KindDespawn,
		Outcome: OutcomeDelivered})
}

// Spawned lists the workers an agent currently has running, for `team ps`.
func (b *Broker) Spawned(agent string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.spawnedBy[agent]...)
}

func allowedImage(permitted []string, image string) bool {
	if len(permitted) == 0 {
		// A budget that names no image permits none. A spawn budget is a
		// whitelist, and an empty whitelist is empty rather than universal —
		// the other reading turns a half-written policy into an open door.
		return false
	}
	for _, p := range permitted {
		if p == image {
			return true
		}
	}
	return false
}

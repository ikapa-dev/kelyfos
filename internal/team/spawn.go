package team

import (
	"fmt"
	"time"
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
			Message: spawner + " has no spawn budget; one is granted in the policy file, not at runtime"}
	}
	live := b.spawnedBy[spawner]
	if len(live) >= budget.Max {
		b.mu.Unlock()
		b.record(Event{Type: TypeSpawn, From: spawner, Kind: KindSpawn,
			Outcome: OutcomeRefused, Reason: "budget_exhausted"})
		return SpawnRequest{}, &Error{Kind: "denied",
			Message: fmt.Sprintf("%s already has %d of its %d spawned workers running",
				spawner, len(live), budget.Max)}
	}
	if image == "" && len(budget.Images) > 0 {
		image = budget.Images[0]
	}
	if !allowedImage(budget.Images, image) {
		b.mu.Unlock()
		b.record(Event{Type: TypeSpawn, From: spawner, Kind: KindSpawn,
			Outcome: OutcomeRefused, Reason: "image_not_permitted"})
		return SpawnRequest{}, &Error{Kind: "denied",
			Message: fmt.Sprintf("%s may not spawn the %q image; its budget permits %v",
				spawner, image, budget.Images)}
	}

	b.spawnSeq++
	name := fmt.Sprintf("%s-spawn-%d", spawner, b.spawnSeq)
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
	delete(b.boxes, name)
	b.mu.Unlock()
	if spawner == "" {
		return
	}
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

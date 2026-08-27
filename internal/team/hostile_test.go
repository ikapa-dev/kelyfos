package team

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/hostile"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// The hostile corpus for the team broker (P6-22, findings H-3, H-4 and H-5).
//
// Every number and every byte here comes from the guest. The broker is the host
// side of a channel an agent speaks on, and until this file nothing in the tree
// called Broker.Serve at all — the entry point the untrusted side reaches was
// the one with no tests behind it.
//
// None of these need a VM, an image or mke2fs. They run everywhere.

// H-3. A timeout the guest chooses, and what the host is willing to hold open.
//
// Serve had a floor and no roof: a value of zero or less became a minute, and
// anything above that was taken as given. 1<<40 milliseconds is about
// thirty-five years, and the frame that carries it is one an agent writes. The
// parked call holds a goroutine and a mailbox slot for the life of the process,
// so this was not one agent hurting itself — it was a team member spending the
// host's memory, as fast as the host would accept frames.
//
// The assertion is on the clamp rather than on the wait, and deliberately: a
// fixture that watched for a fifteen-minute ceiling by sitting through one is a
// fixture nobody runs, and one that watched for a *short* ceiling would be
// pinning a number chosen to make the test quick.
func TestHostileTimeoutIsClamped(t *testing.T) {
	for _, tc := range []struct {
		key  string
		op   string
		ms   int64
		want time.Duration
	}{
		{"team/timeout-recv", proto.OpTeamRecv, 1 << 40, MaxWait},
		{"team/timeout-ask", proto.OpTeamAsk, 1 << 40, MaxWait},
	} {
		t.Run(strings.TrimPrefix(tc.key, "team/"), func(t *testing.T) {
			// The frame as it arrives on the wire, decoded by the product's own
			// reader rather than built as a struct — so the fixture also shows
			// that nothing between the guest and the broker rejects the number
			// or truncates it on the way.
			frame := fmt.Sprintf(`{"v":1,"id":"h3","op":%q,"to":"worker-1","timeout_ms":%d}`+"\n", tc.op, tc.ms)
			var req proto.TeamRequest
			if err := proto.NewReader(strings.NewReader(frame)).Read(&req); err != nil {
				t.Fatalf("the product's own reader refused the frame: %v", err)
			}
			if req.TimeoutMS != tc.ms {
				t.Fatalf("the frame lost the value on the way in: %d", req.TimeoutMS)
			}

			problem := ""
			if got := waitFor(req.TimeoutMS); got != tc.want {
				problem = fmt.Sprintf("timeout_ms=%d becomes %s, which the host will hold a goroutine "+
					"and a mailbox open for", tc.ms, got)
			}
			hostile.Holds(t, tc.key, problem)
		})
	}

	// The clamp must bound the number without breaking the ordinary use of it:
	// zero still means the default, and a legitimate short wait is honoured
	// exactly. A ceiling that quietly became a floor would be worse than none.
	for _, tc := range []struct {
		ms   int64
		want time.Duration
	}{
		{0, time.Minute},
		{-1, time.Minute},
		{-1 << 62, time.Minute},
		{500, 500 * time.Millisecond},
		{int64(MaxWait / time.Millisecond), MaxWait},
	} {
		if got := waitFor(tc.ms); got != tc.want {
			t.Errorf("waitFor(%d) = %s, want %s", tc.ms, got, tc.want)
		}
	}

	// And the whole path still works: a frame with a real timeout goes through
	// Serve and comes back.
	topo, err := NewTopology([]string{"master", "worker-1"},
		[]Edge{{From: "master", To: "worker-1", Bidirectional: true}})
	if err != nil {
		t.Fatal(err)
	}
	b := New(topo, false, nil)
	done := make(chan proto.TeamResponse, 1)
	go func() {
		done <- b.Serve("worker-1", proto.TeamRequest{Op: proto.OpTeamRecv, TimeoutMS: 200})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("a 200 ms recv had not returned after five seconds")
	}
}

// H-4. The store counts bytes of values, and nothing else.
//
// MaxStoreBytes is 64 MiB and it is measured against len(value) alone. The key
// is never measured, the number of keys is never counted, and there is no
// Delete anywhere on the guest's path — the store is append-only for the life
// of the team. So an agent grows the host's memory with keys, which cost
// nothing against the only limit there is.
func TestHostileStoreCountsWhatTheGuestSpends(t *testing.T) {
	t.Run("many-keys", func(t *testing.T) {
		s := hostileStore(t)
		// One past the stated ceiling, one byte of value each. Against the byte
		// budget that is a few kilobytes; against the host it is a map entry and
		// a key string per call, which is what nothing was counting.
		//
		// The count comes from the constant rather than from a number typed
		// here, so a ceiling that moves does not leave this asserting against
		// the old one.
		keys := MaxStoreKeys + 1
		var refused error
		for i := 0; i < keys; i++ {
			if err := s.Put("master", fmt.Sprintf("k/%d", i), []byte("x")); err != nil {
				refused = err
				break
			}
		}
		problem := ""
		if refused == nil {
			problem = fmt.Sprintf("%d keys went in without a word; nothing counts keys", keys)
		}
		hostile.Holds(t, "team/store-key-count", problem)

		// And the ceiling is a ceiling rather than a wall: removing a key makes
		// room for another. A limit an agent cannot get back under would turn
		// one greedy moment into a dead store.
		if err := s.Put("master", "k/0", nil); err != nil {
			t.Fatalf("removing a key: %v", err)
		}
		if err := s.Put("master", "after-the-delete", []byte("x")); err != nil {
			t.Errorf("the store stayed full after a key was removed: %v", err)
		}
	})

	t.Run("long-keys", func(t *testing.T) {
		s := hostileStore(t)
		// A key just under the per-value ceiling, holding one byte of value.
		// The value is what the ceiling weighs, so this is a megabyte of host
		// memory bought with one byte of budget.
		key := strings.Repeat("A", MaxValueBytes-256)
		problem := ""
		if err := s.Put("master", key, []byte("x")); err == nil {
			problem = fmt.Sprintf("a %d-byte key was accepted against a %d-byte value budget; "+
				"the key is never measured", len(key), MaxValueBytes)
		}
		hostile.Holds(t, "team/store-key-length", problem)
	})

	t.Run("no-delete", func(t *testing.T) {
		s := hostileStore(t)
		if err := s.Put("master", "temporary", []byte("x")); err != nil {
			t.Fatal(err)
		}
		// Writing an empty value is the only thing resembling a delete that the
		// guest's own vocabulary offers. It leaves the key, so nothing an agent
		// can say ever makes the store smaller.
		if err := s.Put("master", "temporary", nil); err != nil {
			t.Fatal(err)
		}
		problem := ""
		for _, k := range s.Keys() {
			if k == "temporary" {
				problem = "an agent has no way to remove a key: the store only grows"
			}
		}
		hostile.Holds(t, "team/store-no-delete", problem)
	})
}

func hostileStore(t *testing.T) *Store {
	t.Helper()
	topo, err := NewTopology([]string{"master", "worker-1"},
		[]Edge{{From: "master", To: "worker-1", Bidirectional: true}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(topo, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// H-5. The record keeps the body of a message it refused.
//
// describe computes the digest and, when the team asked for capture, also keeps
// the payload — and it does not look at the outcome while deciding. So a message
// the broker rejected is written to the chain in full, at whatever size the
// sender chose, as many times as the sender cares to try. An agent with no edges
// at all can fill the host's disk with the contents of messages that were never
// delivered to anybody.
//
// The digest beside it is the reason this is a defect and not a trade-off: the
// record already has a way to say what the message was without holding a second
// copy of it, and on the refused path that is the whole of what a reader needs.
func TestHostileRefusalsDoNotWriteTheirPayloads(t *testing.T) {
	topo, err := NewTopology([]string{"loner", "victim"}, nil) // no edges at all
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	rec, err := recorder.Open(root, "hostile-h5")
	if err != nil {
		t.Fatal(err)
	}
	// capture on: what a team gets by asking for record_payloads.
	b := New(topo, true, func(e Event) { _ = rec.Append(e.Record()) })

	const sends = 20
	payload := bytes.Repeat([]byte("Z"), 700<<10)
	for i := 0; i < sends; i++ {
		if err := b.Send("loner", "victim", payload); err == nil {
			t.Fatal("the fixture is wrong: this send was supposed to be refused")
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(recorder.Path(root, "hostile-h5"))
	if err != nil {
		t.Fatal(err)
	}
	// A refusal needs to say who, to whom, how big and why. That is a few
	// hundred bytes. Anything approaching the payload is the payload.
	perRefusal := info.Size() / sends
	problem := ""
	if perRefusal > int64(len(payload))/2 {
		problem = fmt.Sprintf("%d refused messages wrote %d bytes — %d per refusal, against a %d-byte payload; "+
			"the body is kept beside the digest that would have done",
			sends, info.Size(), perRefusal, len(payload))
	}
	hostile.Holds(t, "team/refusal-keeps-payload", problem)
}

// And the same message, refused, must not be recorded before the broker has
// decided to refuse it. describe is called from inside the refusal branch, so
// this holds today; it is here because the ordering is the half of H-5 that
// would be easy to break while fixing the other half.
func TestHostileRefusalIsDecidedBeforeItIsDescribed(t *testing.T) {
	topo, err := NewTopology([]string{"loner", "victim"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var c collector
	b := New(topo, true, c.record)
	if err := b.Send("loner", "victim", []byte("never delivered")); err == nil {
		t.Fatal("the fixture is wrong: this send was supposed to be refused")
	}

	problem := ""
	events := c.all()
	switch {
	case len(events) != 1:
		problem = fmt.Sprintf("a single refused send wrote %d events", len(events))
	case events[0].Outcome != OutcomeRefused:
		problem = fmt.Sprintf("a refused send was recorded as %q", events[0].Outcome)
	case events[0].Reason == "":
		problem = "a refusal was recorded without saying why"
	}
	hostile.Holds(t, "team/refusal-says-why", problem)
}

// The frame layer carries these unchanged, which is what makes the numbers
// above the guest's rather than the host's. Serve is the door; this is the
// proof it is the same door the fixtures above knocked on.
func TestHostileStoreFrameReachesTheStoreUnexamined(t *testing.T) {
	topo, err := NewTopology([]string{"master"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(topo, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := New(topo, false, nil)
	b.Store = s

	key := strings.Repeat("K", 64<<10)
	resp := b.Serve("master", proto.TeamRequest{
		Op:   proto.OpTeamStorePut,
		Key:  key,
		Body: base64.StdEncoding.EncodeToString([]byte("x")),
	})

	problem := ""
	if resp.OK {
		problem = fmt.Sprintf("a %d-byte key arrived through Serve and was stored", len(key))
	}
	hostile.Holds(t, "team/store-key-length", problem)
}

// S5b. Put already redacted an oversized key once its OWN length check fired
// — but that check ran after mayWrite's denial check, so a key that was ALSO
// going to be denied by an unrelated write rule reached the record whole,
// before its length was ever examined. Get had no length check anywhere, so
// it always recorded an oversized key in full. Both are fixed the same way:
// the length check now runs first, so an oversized key is redacted no matter
// what an unrelated rule would otherwise have decided about it.
func TestHostileOversizedKeyIsNeverRecordedWhole(t *testing.T) {
	topo, err := NewTopology([]string{"master", "worker-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A rule that denies worker-1 both read and write on this namespace for a
	// reason that has nothing to do with the key's length — so an oversized
	// key inside it is refused twice over, and what matters is which refusal
	// the record shows.
	rules := []Rule{{Name: "K*", Read: []string{"master"}, Write: []string{"master"}}}
	key := strings.Repeat("K", MaxKeyBytes+1)

	whole := func(events []Event) string {
		for _, e := range events {
			if strings.Contains(e.To, "KKKK") {
				return fmt.Sprintf("a %d-byte event.To carries the oversized key: %q", len(e.To), e.To)
			}
		}
		return ""
	}

	t.Run("put", func(t *testing.T) {
		var c collector
		s, err := NewStore(topo, rules, c.record)
		if err != nil {
			t.Fatal(err)
		}
		problem := ""
		if err := s.Put("worker-1", key, []byte("x")); err == nil {
			problem = "an oversized key denied by an unrelated write rule was accepted"
		}
		if p := whole(c.all()); p != "" && problem == "" {
			problem = p
		}
		hostile.Holds(t, "team/store-put-oversized-key-recorded-whole", problem)
	})

	t.Run("get", func(t *testing.T) {
		var c collector
		s, err := NewStore(topo, rules, c.record)
		if err != nil {
			t.Fatal(err)
		}
		problem := ""
		if _, err := s.Get("worker-1", key); err == nil {
			problem = "an oversized key denied by an unrelated read rule returned a value"
		}
		if p := whole(c.all()); p != "" && problem == "" {
			problem = p
		}
		hostile.Holds(t, "team/store-get-oversized-key-recorded-whole", problem)
	})
}

// M-5 at the other layer: the topology refuses the name outright.
//
// This is the check a person actually meets — it fires when their kelyfos.toml
// is read, with the name and the character in the message, rather than leaving
// them to discover that their agent silently lost its identity. The guard in
// bootArgs is the one that holds if something ever gets past this.
func TestHostileAgentNameIsRefusedAtTheTopology(t *testing.T) {
	for _, name := range []string{
		"worker init=/bin/sh",
		"w\tkelyfos.spawn=1",
		"w quiet console=ttyS1",
		"w\nkelyfos.flavor=base",
		"../escape",
		"has/a/separator",
		"a\x00b",
		strings.Repeat("x", 65),
		"",
	} {
		if err := ValidAgentName(name); err == nil {
			t.Errorf("the agent name %q was accepted", name)
		}
		if _, err := NewTopology([]string{"master", name}, nil); err == nil {
			t.Errorf("a topology accepted the agent name %q", name)
		}
	}

	// The names people actually use keep working. A rule that refused these
	// would have made the check the problem.
	for _, name := range []string{"master", "worker-1", "worker_2", "api.v2", "A1"} {
		if err := ValidAgentName(name); err != nil {
			t.Errorf("the ordinary agent name %q was refused: %v", name, err)
		}
	}
}

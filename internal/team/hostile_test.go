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

// H-3. A timeout the guest chooses, with no ceiling on it.
//
// Serve has a floor and no roof: a value of zero or less becomes a minute, and
// anything above that is taken as given. 1<<40 milliseconds is about thirty-five
// years, and the frame that carries it is the one an agent writes. The parked
// call holds a goroutine and a mailbox slot for the life of the process, so this
// is not one agent hurting itself — it is a team member spending the host's
// memory, and a plain loop spends it as fast as the host will accept frames.
func TestHostileTimeoutIsClamped(t *testing.T) {
	// Long enough that a clamped timeout would have fired, short enough to run
	// on every push. Anything the broker means to honour here is under a
	// minute; a call still parked after this is parked for years.
	const budget = 2 * time.Second

	for _, tc := range []struct {
		key string
		op  string
		as  string // the agent the frame arrives from
		ms  int64
	}{
		// recv parks on an empty mailbox; ask parks waiting for an answer that
		// never comes. The asker has to be an agent with an edge to the target,
		// or the broker refuses on the edge and returns before the timeout is
		// ever consulted — which would make the case pass for the wrong reason.
		{"team/timeout-recv", proto.OpTeamRecv, "worker-1", 1 << 40},
		{"team/timeout-ask", proto.OpTeamAsk, "master", 1 << 40},
	} {
		t.Run(strings.TrimPrefix(tc.key, "team/"), func(t *testing.T) {
			topo, err := NewTopology([]string{"master", "worker-1"},
				[]Edge{{From: "master", To: "worker-1", Bidirectional: true}})
			if err != nil {
				t.Fatal(err)
			}
			b := New(topo, false, nil)

			// The frame as it arrives on the wire, decoded by the product's own
			// reader rather than built as a struct — so the fixture also shows
			// that nothing between the guest and the broker rejects the number
			// or truncates it.
			frame := fmt.Sprintf(`{"v":1,"id":"h3","op":%q,"to":"worker-1","timeout_ms":%d}`+"\n", tc.op, tc.ms)
			var req proto.TeamRequest
			if err := proto.NewReader(strings.NewReader(frame)).Read(&req); err != nil {
				t.Fatalf("the product's own reader refused the frame: %v", err)
			}
			if req.TimeoutMS != tc.ms {
				t.Fatalf("the frame lost the value on the way in: %d", req.TimeoutMS)
			}

			done := make(chan proto.TeamResponse, 1)
			go func() { done <- b.Serve(tc.as, req) }()

			problem := ""
			select {
			case <-done:
			case <-time.After(budget):
				problem = fmt.Sprintf("Serve is still parked after %s on timeout_ms=%d (about %s); "+
					"the goroutine and its mailbox are held until the process ends",
					budget, tc.ms, (time.Duration(tc.ms) * time.Millisecond).Round(time.Hour))
			}
			hostile.Holds(t, tc.key, problem)
		})
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
		// Ten thousand keys, one byte each. Against the byte ceiling that is
		// ten kilobytes; against the host it is ten thousand map entries and
		// ten thousand key strings, none of which anything counts.
		const keys = 10000
		var refused error
		for i := 0; i < keys; i++ {
			if err := s.Put("master", fmt.Sprintf("k/%d", i), []byte("x")); err != nil {
				refused = err
				break
			}
		}
		problem := ""
		if refused == nil {
			problem = fmt.Sprintf("%d keys went in without a word; nothing counts keys and there is no Delete", keys)
		}
		hostile.Holds(t, "team/store-key-count", problem)
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

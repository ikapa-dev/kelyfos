package sandbox

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/proto"
)

// The events channel has to be listening before the VM starts, so this tests it
// the way the guest uses it: bind, dial, write frames, see them arrive.
func TestEventsChannelDeliversGuestReports(t *testing.T) {
	dir := t.TempDir()
	got := make(chan proto.GuestEvent, 4)
	s := withCredential(&Sandbox{
		State: State{UDSPath: filepath.Join(dir, "v.sock")},
		opts:  Options{OnGuestEvent: func(ev proto.GuestEvent) { got <- ev }},
	})
	if err := s.listenEvents(); err != nil {
		t.Fatal(err)
	}
	defer s.eventsLn.Close()

	conn := dialGuestChannel(t, s, proto.PortEvents)

	w := proto.NewWriter(conn)
	sent := proto.GuestEvent{
		V: proto.Version, Type: proto.GuestEventOOM,
		PID: 57, Comm: "python3", RSSKiB: 230016, MonotonicNS: 4941890000,
	}
	if err := w.Write(sent); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-got:
		if ev != sent {
			t.Errorf("got %+v, want %+v", ev, sent)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the event never arrived")
	}

	// A second frame on the same connection, because the guest keeps it open
	// for the life of the sandbox rather than dialling per event.
	if err := w.Write(proto.GuestEvent{V: proto.Version, Type: proto.GuestEventOOM, PID: 58}); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-got:
		if ev.PID != 58 {
			t.Errorf("second event pid = %d, want 58", ev.PID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the second event never arrived")
	}
}

// The guest runs untrusted code, so the channel must survive whatever it sends.
// Deciding what to record is the caller's job; not falling over is this one's.
func TestEventsChannelSurvivesRubbish(t *testing.T) {
	dir := t.TempDir()
	got := make(chan proto.GuestEvent, 4)
	s := withCredential(&Sandbox{
		State: State{UDSPath: filepath.Join(dir, "v.sock")},
		opts:  Options{OnGuestEvent: func(ev proto.GuestEvent) { got <- ev }},
	})
	if err := s.listenEvents(); err != nil {
		t.Fatal(err)
	}
	defer s.eventsLn.Close()

	conn := dialGuestChannel(t, s, proto.PortEvents)

	// Not JSON at all, then a valid frame of an unknown type. Neither may stop
	// the channel; the unknown type is passed on and dropped upstream, where the
	// decision about what enters the hash chain belongs.
	if _, err := conn.Write([]byte("this is not json\n")); err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(map[string]any{"v": 1, "type": "not.a.real.type"})
	if _, err := conn.Write(append(blob, '\n')); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-got:
		if ev.Type != "not.a.real.type" {
			t.Errorf("type = %q", ev.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the channel stopped reading after a bad frame")
	}
}

// A sandbox with no handler must not panic when the guest reports something —
// the guest can connect the moment the supervisor is up, which on the run path
// is before the flight recorder has been opened.
func TestEventsChannelToleratesNoHandler(t *testing.T) {
	dir := t.TempDir()
	s := withCredential(&Sandbox{State: State{UDSPath: filepath.Join(dir, "v.sock")}})
	if err := s.listenEvents(); err != nil {
		t.Fatal(err)
	}
	defer s.eventsLn.Close()

	conn := dialGuestChannel(t, s, proto.PortEvents)
	if err := proto.NewWriter(conn).Write(proto.GuestEvent{V: 1, Type: proto.GuestEventOOM}); err != nil {
		t.Fatal(err)
	}
	// Nothing to assert but survival: give the reader a moment to mishandle it.
	time.Sleep(200 * time.Millisecond)
}

// serveEvents had the same gap serveTeam did — no cap before Accept, no read
// deadline on an accepted connection — for the same reason: this listener is
// also reachable by any process inside the guest directly over vsock (F5).
// Same proof as team's: the cap holds while every slot is taken by a silent
// connection, and a legitimate one queued behind it is still served once
// guestFirstFrameTimeout reclaims those slots.
func TestSilentEventsConnectionsAreCappedAndReclaimed(t *testing.T) {
	dir := t.TempDir()
	got := make(chan proto.GuestEvent, 1)
	s := withCredential(&Sandbox{
		State: State{UDSPath: filepath.Join(dir, "v.sock")},
		opts:  Options{OnGuestEvent: func(ev proto.GuestEvent) { got <- ev }},
	})
	if err := s.listenEvents(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.eventsLn.Close() })
	addr := fmt.Sprintf("%s_%d", s.State.UDSPath, proto.PortEvents)

	for i := 0; i < maxConcurrentGuestConnections; i++ {
		c, err := net.Dial("unix", addr)
		if err != nil {
			t.Fatalf("silent connection %d: %v", i, err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(s.eventsSem) < maxConcurrentGuestConnections && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(s.eventsSem); n != maxConcurrentGuestConnections {
		t.Fatalf("only %d of %d silent connections filled the cap", n, maxConcurrentGuestConnections)
	}

	conn := dialGuestChannel(t, s, proto.PortEvents)
	sent := proto.GuestEvent{V: proto.Version, Type: proto.GuestEventOOM, PID: 99}
	if err := proto.NewWriter(conn).Write(sent); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
		t.Fatal("an event past the cap reached the handler while every slot was held by a silent connection")
	case <-time.After(500 * time.Millisecond):
	}

	select {
	case ev := <-got:
		if ev != sent {
			t.Errorf("got %+v, want %+v", ev, sent)
		}
	case <-time.After(guestFirstFrameTimeout + 20*time.Second):
		t.Fatal("the legitimate connection was never served once the silent ones' deadline passed")
	}
}

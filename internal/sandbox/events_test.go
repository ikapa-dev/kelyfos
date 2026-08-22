package sandbox

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
)

// The events channel has to be listening before the VM starts, so this tests it
// the way the guest uses it: bind, dial, write frames, see them arrive.
func TestEventsChannelDeliversGuestReports(t *testing.T) {
	dir := t.TempDir()
	got := make(chan proto.GuestEvent, 4)
	s := &Sandbox{
		State: State{UDSPath: filepath.Join(dir, "v.sock")},
		opts:  Options{OnGuestEvent: func(ev proto.GuestEvent) { got <- ev }},
	}
	if err := s.listenEvents(); err != nil {
		t.Fatal(err)
	}
	defer s.eventsLn.Close()

	conn, err := net.Dial("unix", fmt.Sprintf("%s_%d", s.State.UDSPath, proto.PortEvents))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

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
	s := &Sandbox{
		State: State{UDSPath: filepath.Join(dir, "v.sock")},
		opts:  Options{OnGuestEvent: func(ev proto.GuestEvent) { got <- ev }},
	}
	if err := s.listenEvents(); err != nil {
		t.Fatal(err)
	}
	defer s.eventsLn.Close()

	conn, err := net.Dial("unix", fmt.Sprintf("%s_%d", s.State.UDSPath, proto.PortEvents))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

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
	s := &Sandbox{State: State{UDSPath: filepath.Join(dir, "v.sock")}}
	if err := s.listenEvents(); err != nil {
		t.Fatal(err)
	}
	defer s.eventsLn.Close()

	conn, err := net.Dial("unix", fmt.Sprintf("%s_%d", s.State.UDSPath, proto.PortEvents))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := proto.NewWriter(conn).Write(proto.GuestEvent{V: 1, Type: proto.GuestEventOOM}); err != nil {
		t.Fatal(err)
	}
	// Nothing to assert but survival: give the reader a moment to mishandle it.
	time.Sleep(200 * time.Millisecond)
}

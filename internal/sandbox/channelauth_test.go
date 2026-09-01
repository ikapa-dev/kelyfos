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

// The guest-initiated channels take a per-session credential as their first
// frame (audit 2026-09-01, A2/A3). These tests drive the gate the way each
// side of it meets the other: the supervisor's presentation (a hello, then
// channel frames), and everything else — a same-uid process that found the
// socket, a guest process that dialled the port raw — which gets refused
// before one frame past the hello is read.

// testCredential is what the fixtures mint: same shape as a real one, fixed so
// the wrong-credential case has a value to be wrong about.
const testCredential = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// withCredential gives a fixture Sandbox the credential New would have minted.
func withCredential(s *Sandbox) *Sandbox {
	s.channelAuth = testCredential
	return s
}

// dialGuestChannel dials a host-side channel the way the supervisor does:
// credential hello first, then the connection is the caller's.
func dialGuestChannel(t *testing.T, s *Sandbox, port uint32) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", fmt.Sprintf("%s_%d", s.State.UDSPath, port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := proto.NewWriter(conn).Write(channelHello{V: proto.Version, Auth: testCredential}); err != nil {
		t.Fatal(err)
	}
	return conn
}

// refusedConnections collects what the gate reported to the caller.
type refusedLog struct {
	ports  []uint32
	reason string
}

func TestChannelRefusesAConnectionWithoutTheCredential(t *testing.T) {
	for _, port := range []uint32{proto.PortReady, proto.PortEvents, proto.PortTeam} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			dir := t.TempDir()
			log := refusedLog{}
			s := withCredential(&Sandbox{
				State: State{UDSPath: filepath.Join(dir, "v.sock")},
				opts: Options{
					OnGuestEvent: func(proto.GuestEvent) {
						t.Error("a frame without a credential reached the event handler")
					},
					// listenTeam binds only when the sandbox has a team to
					// answer with; the fixture gives it a trivial one.
					OnTeamRequest: func(proto.TeamRequest) proto.TeamResponse {
						return proto.TeamResponse{OK: true}
					},
					OnChannelRefused: func(port uint32, reason string) {
						log.ports = append(log.ports, port)
						log.reason = reason
					},
				},
			})
			switch port {
			case proto.PortEvents:
				if err := s.listenEvents(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = s.eventsLn.Close() })
			case proto.PortTeam:
				if err := s.listenTeam(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = s.teamLn.Close() })
			case proto.PortReady:
				s.readyLn, _ = net.Listen("unix", fmt.Sprintf("%s_%d", s.State.UDSPath, port))
				t.Cleanup(func() { _ = s.readyLn.Close() })
				go s.serveReady()
			}

			conn, err := net.Dial("unix", fmt.Sprintf("%s_%d", s.State.UDSPath, port))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			// The audit's A2 repro, in shape: a frame that would have become
			// a guest-attributed record entry, sent with no credential. The
			// gate reads the frame as the credential hello it expected, finds
			// none, and refuses — which reason it refuses with is not the
			// point here, only that nothing got past.
			if err := proto.NewWriter(conn).Write(proto.GuestEvent{
				V: proto.Version, Type: proto.GuestEventOOM,
				PID: 1, Comm: "forged", RSSKiB: 999999,
			}); err != nil {
				t.Fatal(err)
			}
			// The gate closes the connection; a read back sees it end.
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			var ignore json.RawMessage
			if err := proto.NewReader(conn).Read(&ignore); err == nil {
				t.Fatal("the connection stayed open after a frame without a credential")
			}
			if len(log.ports) != 1 || log.ports[0] != port {
				t.Errorf("the refusal was not reported for port %d: %+v", port, log.ports)
			}
		})
	}
}

// The credential is compared in constant time, but the honest first test of
// that property is the simple one: the wrong credential gets the same refusal
// the absent one does, and no frame.
func TestChannelRefusesTheWrongCredential(t *testing.T) {
	dir := t.TempDir()
	log := refusedLog{}
	s := withCredential(&Sandbox{
		State: State{UDSPath: filepath.Join(dir, "v.sock")},
		opts: Options{
			OnGuestEvent: func(proto.GuestEvent) { t.Error("a forged frame reached the handler") },
			OnChannelRefused: func(port uint32, reason string) {
				log.ports = append(log.ports, port)
			},
		},
	})
	if err := s.listenEvents(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.eventsLn.Close() })

	conn, err := net.Dial("unix", fmt.Sprintf("%s_%d", s.State.UDSPath, proto.PortEvents))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := proto.NewWriter(conn).Write(channelHello{
		V: proto.Version, Auth: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}); err != nil {
		t.Fatal(err)
	}
	_ = proto.NewWriter(conn).Write(proto.GuestEvent{
		V: proto.Version, Type: proto.GuestEventOOM, PID: 1, Comm: "forged", RSSKiB: 1,
	})
	// The refusal happens on the serving goroutine, which may not have read
	// the hello the instant the writes return.
	deadline := time.Now().Add(5 * time.Second)
	for len(log.ports) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(log.ports) != 1 {
		t.Errorf("the wrong credential was not refused: %+v", log.ports)
	}
}

// And the supervisor's own path, unharmed: hello, then frames, delivered.
func TestChannelAcceptsTheCredentialAndDelivers(t *testing.T) {
	dir := t.TempDir()
	got := make(chan proto.GuestEvent, 2)
	s := withCredential(&Sandbox{
		State: State{UDSPath: filepath.Join(dir, "v.sock")},
		opts:  Options{OnGuestEvent: func(ev proto.GuestEvent) { got <- ev }},
	})
	if err := s.listenEvents(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.eventsLn.Close() })

	conn := dialGuestChannel(t, s, proto.PortEvents)
	sent := proto.GuestEvent{V: proto.Version, Type: proto.GuestEventOOM, PID: 57, Comm: "python3"}
	if err := proto.NewWriter(conn).Write(sent); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-got:
		if ev != sent {
			t.Errorf("got %+v, want %+v", ev, sent)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a credentialled connection was not served")
	}
}

// A fixture Sandbox with no credential at all — the shape of forgetting to
// mint — refuses everything rather than everything-without-a-credential.
func TestChannelWithoutAMintedCredentialRefusesEverything(t *testing.T) {
	dir := t.TempDir()
	s := &Sandbox{
		State: State{UDSPath: filepath.Join(dir, "v.sock")},
		opts:  Options{OnGuestEvent: func(proto.GuestEvent) { t.Error("an uncredentialled sandbox served a frame") }},
	}
	if err := s.listenEvents(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.eventsLn.Close() })

	conn, err := net.Dial("unix", fmt.Sprintf("%s_%d", s.State.UDSPath, proto.PortEvents))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The server may close the connection before this write lands — it refuses
	// without reading anything — and a broken pipe here is the refusal itself.
	_ = proto.NewWriter(conn).Write(channelHello{V: proto.Version, Auth: testCredential})
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ignore json.RawMessage
	if err := proto.NewReader(conn).Read(&ignore); err == nil {
		t.Fatal("a sandbox that minted no credential served a connection")
	}
}

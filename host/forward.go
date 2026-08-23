package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/denial"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// Inbound port forwarding, host side (E5-5, docs/qol.md §4).
//
// A listener on this machine, one vsock connection per connection it accepts,
// and the supervisor dialling the guest's own loopback at the other end. No
// packet crosses the TAP in either direction, which is the entire reason this
// feature is allowed to exist: the network layer's guarantee is that nothing
// reaches the guest from outside, it is enforced by nftables, and a forward
// that added a rule would be a hole in it. `nft list ruleset` is the same with
// a forward as without one (F-D7).

// loopback is where a forward binds unless somebody says otherwise, in the
// session, out loud. A LAN exposure is a thing to type rather than a line in a
// file somebody inherited (docs/qol.md §4.3).
const loopback = "127.0.0.1"

// forwardConnectTimeout bounds opening the vsock channel for one accepted
// connection. It is not the guest's dial timeout, which is the supervisor's.
const forwardConnectTimeout = 10 * time.Second

// parseForwardSpec reads one -p argument: host:guest.
func parseForwardSpec(spec string) (config.Forward, error) {
	h, g, ok := strings.Cut(spec, ":")
	if !ok {
		return config.Forward{}, fmt.Errorf("-p %s: expected host:guest, as in -p 8080:80", spec)
	}
	host, err := forwardPort(h, spec)
	if err != nil {
		return config.Forward{}, err
	}
	guest, err := forwardPort(g, spec)
	if err != nil {
		return config.Forward{}, err
	}
	return config.Forward{Host: host, Guest: guest}, nil
}

func forwardPort(s, spec string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("-p %s: %q is not a port number", spec, strings.TrimSpace(s))
	}
	return n, nil
}

// resolveForwards decides what this run forwards.
//
// A -p on the command line replaces the file's list rather than adding to it,
// which is how `allow` already behaves and for the same reason: a file
// describes the project's usual shape, and somebody who names ports on the
// command line is describing this run instead. Adding to it would make
// "forward only this" impossible to say without editing the file.
func resolveForwards(specs []string, cfg *config.Config) ([]config.Forward, error) {
	if len(specs) > 0 {
		out := make([]config.Forward, 0, len(specs))
		seen := map[int]bool{}
		for _, spec := range specs {
			f, err := parseForwardSpec(spec)
			if err != nil {
				return nil, err
			}
			if seen[f.Host] {
				return nil, fmt.Errorf("-p %s: host port %d is already forwarded; "+
					"one host port carries one guest port", spec, f.Host)
			}
			seen[f.Host] = true
			out = append(out, f)
		}
		return out, nil
	}
	if cfg == nil {
		return nil, nil
	}
	if err := cfg.CheckForwards(); err != nil {
		return nil, err
	}
	return cfg.Forwards, nil
}

// forwarder owns the listeners for one sandbox.
type forwarder struct {
	uds     string
	bind    string
	rec     *recorder.Recorder
	agent   string // which team member's sandbox, for the record
	blocked *blockedOnce

	mu        sync.Mutex
	listeners []net.Listener
	closed    bool
}

func newForwarder(uds, bind string, rec *recorder.Recorder, agent string) *forwarder {
	if bind == "" {
		bind = loopback
	}
	return &forwarder{uds: uds, bind: bind, rec: rec, agent: agent,
		blocked: newBlockedOnce(os.Stderr)}
}

// start binds every listener and reports what it bound.
//
// A listener that cannot bind ends the run. The alternative — carry on with a
// forward that silently is not there — is the failure this feature would be
// most often blamed for and least often suspected of.
func (f *forwarder) start(fwds []config.Forward) error {
	for _, fw := range fwds {
		addr := net.JoinHostPort(f.bind, strconv.Itoa(fw.Host))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			f.close()
			return fmt.Errorf("forward %d:%d: cannot listen on %s: %w\n"+
				"    choose another host port, or stop what is using that one",
				fw.Host, fw.Guest, addr, err)
		}
		f.mu.Lock()
		f.listeners = append(f.listeners, ln)
		f.mu.Unlock()
		fmt.Printf("  forward     %s -> guest %d\n", addr, fw.Guest)
		if f.bind != loopback {
			// Every time, and loudly. A LAN exposure that was mentioned once
			// at the top of a long run is a LAN exposure nobody remembers.
			fmt.Fprintf(os.Stderr, "kelyfos: -p %d:%d --p-bind %s exposes this sandbox's port %d "+
				"to every machine that can reach this one.\n    There is no authentication on it.\n",
				fw.Host, fw.Guest, f.bind, fw.Guest)
		}
		go f.serve(ln, fw)
	}
	return nil
}

func (f *forwarder) serve(ln net.Listener, fw config.Forward) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // the listener was closed at teardown, which is not an error
		}
		go f.carry(conn, fw)
	}
}

// carry moves one accepted connection through the guest.
func (f *forwarder) carry(conn net.Conn, fw config.Forward) {
	defer conn.Close()
	peer := conn.RemoteAddr().String()

	ch, err := sandbox.Connect(f.uds, proto.PortForward, forwardConnectTimeout)
	if err != nil {
		f.record(fw, peer, "the sandbox's forward channel did not answer")
		return
	}
	defer ch.Close()

	if err := proto.WriteForwardOpen(ch, fw.Guest); err != nil {
		f.record(fw, peer, "the open was not delivered")
		return
	}
	// The reader that read the reply carries on as the reader for the stream:
	// a second reader would drop whatever this one had already buffered, which
	// for a server that speaks first is the beginning of its greeting.
	br := bufio.NewReader(ch)
	reply, err := proto.ReadForwardReply(br)
	if err != nil {
		f.record(fw, peer, "the sandbox did not answer the open")
		return
	}
	if !reply.OK {
		f.record(fw, peer, reply.Error)
		// Nothing useful can be said to the peer: this is a byte pipe for a
		// protocol we do not know, and inventing an error inside it would
		// corrupt whatever it actually is. The person who set the forward up is
		// the one who can fix it, so they are the one told.
		f.blocked.sayText(denial.ForwardClosed.Render(denial.V{
			"guest": strconv.Itoa(fw.Guest), "host": strconv.Itoa(fw.Host)}))
		return
	}

	f.record(fw, peer, "")
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(ch, conn); halfCloseWrite(ch); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, br); halfCloseWrite(conn); done <- struct{}{} }()
	<-done
	<-done
}

func (f *forwarder) record(fw config.Forward, peer, reason string) {
	if f.rec == nil {
		return
	}
	_ = f.rec.Append(recorder.Event{
		Type: recorder.TypeForwardAccept, Agent: f.agent,
		Port: fw.Host, GuestPort: fw.Guest, Peer: peer, Reason: reason,
	})
}

// close stops every listener. A port that outlives its sandbox is a port that
// answers for a machine that no longer exists.
func (f *forwarder) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	for _, ln := range f.listeners {
		_ = ln.Close()
	}
	f.listeners = nil
}

func halfCloseWrite(c net.Conn) {
	if h, ok := c.(interface{ CloseWrite() error }); ok {
		_ = h.CloseWrite()
	}
}

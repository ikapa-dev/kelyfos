package egress

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The audit of 2026-09-01's A12/H3: a tunnel had no clock at all — 128 idle
// CONNECTs pinned the proxy's whole semaphore for the sandbox's life, and a
// guest dribbling one byte a minute defeated idle-timeout reaping while it held
// the slot. The tunnel now carries one tunnel-wide activity clock: any byte in
// either direction re-arms both sides, so a tunnel gone silent both ways closes
// at the stall while a one-way transfer that keeps moving is not cut, and a
// ceiling clamps every arm.

// a12Origin is a TCP listener that echoes what it receives, which is enough
// for a tunnel to carry bytes without any HTTP in it.
func a12Origin(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return port, func() { <-done }
}

// a12StreamOrigin sends n single bytes, one every gap, and never reads — a
// receive-only stream from the guest's point of view. If the proxy half-closes
// its read side (the per-direction clock's FIN to a "silent" upload side), it
// stops sending: that is the behaviour the tunnel-wide clock removes, and the
// guest counting bytes is how the test tells the two apart.
func a12StreamOrigin(t *testing.T, n int, gap time.Duration) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		stop := make(chan struct{})
		go func() { _, _ = io.Copy(io.Discard, conn); close(stop) }()
		for i := 0; i < n; i++ {
			select {
			case <-stop:
				return
			case <-time.After(gap):
			}
			if _, err := conn.Write([]byte{'y'}); err != nil {
				return
			}
		}
		select {
		case <-stop:
		case <-time.After(gap):
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return port
}

// a12SinkOrigin reads and discards forever, counting bytes, and never sends —
// a send-only stream from the guest's point of view.
func a12SinkOrigin(t *testing.T) (int, func() int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var count int
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		for {
			n, err := conn.Read(buf)
			mu.Lock()
			count += n
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return port, func() int { mu.Lock(); defer mu.Unlock(); return count }
}

func a12Proxy(t *testing.T, stall time.Duration, ports ...int) string {
	t.Helper()
	p := &Proxy{Policy: Policy{Allow: []string{"127.0.0.1"}, Ports: ports}, tunnelStall: stall}
	port, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve()
	t.Cleanup(p.Close)
	return "127.0.0.1:" + itoa12(port)
}

func itoa12(n int) string { return strconv.Itoa(n) }

// a12Connect opens one tunnel through the proxy and returns the client side
// after the 200, ready to carry bytes.
func a12Connect(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("no CONNECT answer: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("the tunnel was refused: %s", strings.TrimSpace(line))
	}
	// Drain the rest of the answer's headers — the empty line — or the bufio
	// buffer hands them to the first Read below as if the origin had spoken.
	for {
		l, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(l) == "" {
			break
		}
	}
	// Return a reader that still owns the bufio buffer (the answer was read
	// through it) over the same conn, so the raw bytes below are not lost.
	return &bufferedConn{Conn: c, r: br}
}

// bufferedConn pairs a bufio.Reader with the conn it reads from.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func TestA12_AnIdleTunnelIsClosedByTheStallClock(t *testing.T) {
	originPort, _ := a12Origin(t)
	stall := 150 * time.Millisecond
	addr := a12Proxy(t, stall, originPort)

	c := a12Connect(t, addr, "127.0.0.1:"+strconv.Itoa(originPort))
	// Nothing is written and the origin says nothing: the stall clock is the
	// only thing that ends this tunnel. The client's own deadline is generous,
	// so a read that ends well inside it is the clock's doing, not the
	// deadline's — the elapsed bound is what makes this non-vacuous (M4).
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	start := time.Now()
	if _, err := c.Read(buf); err == nil {
		t.Fatal("the idle tunnel delivered bytes; the stall clock did not fire")
	}
	if elapsed := time.Since(start); elapsed > stall*10 {
		t.Errorf("the idle tunnel closed after %v, far past the stall — the client deadline ended it, not the clock", elapsed)
	}
}

func TestA12_AnActiveTunnelCarriesBytesAndIsCutWhenBothSidesFallSilent(t *testing.T) {
	originPort, _ := a12Origin(t)
	stall := 300 * time.Millisecond
	addr := a12Proxy(t, stall, originPort)

	c := a12Connect(t, addr, "127.0.0.1:"+strconv.Itoa(originPort))
	// Active: bytes cross and the echo comes back, so the clock's progress is
	// not cutting a working tunnel.
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("the tunnel did not carry bytes: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("got %q, want the echo", buf)
	}

	// Then both sides fall silent: no bytes either way for the stall window
	// closes the tunnel, within a bound of the stall rather than the client's
	// own 5-second deadline — which is what makes this non-vacuous (M4).
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := c.Read(buf); err == nil {
		t.Fatal("the silent tunnel kept delivering; the stall clock did not fire")
	}
	if elapsed := time.Since(start); elapsed > stall*10 {
		t.Errorf("the tunnel was cut after %v, far past the stall — the client deadline ended it, not the clock", elapsed)
	}
}

func TestA12_TheTunnelCeilingClampsTheStall(t *testing.T) {
	originPort, _ := a12Origin(t)
	stall := time.Hour
	ceiling := 200 * time.Millisecond
	var mu sync.Mutex
	var attempts []Attempt
	p := &Proxy{
		Policy:        Policy{Allow: []string{"127.0.0.1"}, Ports: []int{originPort}},
		tunnelStall:   stall,
		tunnelCeiling: ceiling,
		OnEvent:       func(a Attempt) { mu.Lock(); attempts = append(attempts, a); mu.Unlock() },
	}
	port, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve()
	t.Cleanup(p.Close)

	c := a12Connect(t, "127.0.0.1:"+strconv.Itoa(port), "127.0.0.1:"+strconv.Itoa(originPort))
	// A stall an hour away: the ceiling is what must fire, which is the property
	// that separates a clamp from a suggestion. Under a generous client
	// deadline the read still ends — with io.EOF, within a bound of the
	// ceiling — and the record names the ceiling (M4).
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	start := time.Now()
	_, err = c.Read(buf)
	if err == nil {
		t.Fatal("the tunnel outlived its ceiling")
	}
	if !errors.Is(err, io.EOF) {
		t.Errorf("the ceiling close was %v, want io.EOF", err)
	}
	if elapsed := time.Since(start); elapsed > ceiling*10 {
		t.Errorf("the tunnel closed after %v, far past the ceiling", elapsed)
	}
	// The tunnel's record names the ceiling, not a bare close. report runs
	// before the client is closed, so it is already in by the time the read
	// above returned; a short poll covers the goroutine handoff.
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		found := false
		for _, a := range attempts {
			if a.Mode == ModeTunnelled && a.Reason == ReasonCeilingReached {
				found = true
			}
		}
		snapshot := append([]Attempt(nil), attempts...)
		mu.Unlock()
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the tunnel attempt did not record ceiling_reached: %+v", snapshot)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestH3_AReceiveOnlyStreamOutlivesTheStall(t *testing.T) {
	stall := 200 * time.Millisecond
	const n = 6
	originPort := a12StreamOrigin(t, n, stall/2)
	addr := a12Proxy(t, stall, originPort)

	c := a12Connect(t, addr, "127.0.0.1:"+strconv.Itoa(originPort))
	// The guest sends nothing and only receives. On the per-direction clock the
	// silent guest→origin side fired at the stall and half-closed the origin,
	// which stopped sending, cutting the download mid-stream. On the
	// tunnel-wide clock each received byte re-arms both sides, so the stream
	// runs to completion.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := 0
	buf := make([]byte, 64)
	start := time.Now()
	for got < n {
		nr, err := c.Read(buf)
		got += nr
		if err != nil {
			break
		}
	}
	if got < n {
		t.Fatalf("the receive-only stream delivered %d of %d bytes; the tunnel was cut at the stall", got, n)
	}
	if elapsed := time.Since(start); elapsed < stall {
		t.Errorf("the stream finished in %v, under one stall window — it never risked the clock", elapsed)
	}
}

func TestH3_ASendOnlyStreamOutlivesTheStall(t *testing.T) {
	stall := 200 * time.Millisecond
	sinkPort, received := a12SinkOrigin(t)
	addr := a12Proxy(t, stall, sinkPort)

	c := a12Connect(t, addr, "127.0.0.1:"+strconv.Itoa(sinkPort))
	// Upload past the stall, a byte every stall/2, so the upload's own bytes
	// keep re-arming both directions. On the per-direction clock the silent
	// origin→guest side fired at the stall and half-closed the client — an
	// upload to a silent origin "got EOF", the finding's own words. On the
	// tunnel-wide clock the read side stays open.
	const n = 6
	writeErr := make(chan error, 1)
	go func() {
		for i := 0; i < n; i++ {
			time.Sleep(stall / 2)
			if _, err := c.Write([]byte{'x'}); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()

	// The read side must not see EOF while the upload is in flight: two stall
	// windows in, require a timeout (tunnel open, no data) — not EOF (cut).
	_ = c.SetReadDeadline(time.Now().Add(2 * stall))
	buf := make([]byte, 1)
	_, rerr := c.Read(buf)
	if errors.Is(rerr, io.EOF) {
		t.Fatal("the send-only stream's read side hit EOF at the stall; the tunnel was cut")
	}
	var ne net.Error
	if !errors.As(rerr, &ne) || !ne.Timeout() {
		t.Fatalf("expected a timeout (tunnel open, no data), got %v", rerr)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("the upload failed mid-stream: %v", err)
	}
	// The last byte may still be in the proxy's pipe when the upload goroutine
	// returns; poll the origin's count rather than read it once.
	deadline := time.Now().Add(2 * time.Second)
	for received() < n && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := received(); got < n {
		t.Errorf("the origin received %d of %d uploaded bytes", got, n)
	}
}

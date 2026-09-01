package egress

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The audit of 2026-09-01's A12: a tunnel had no clock at all — 128 idle
// CONNECTs pinned the proxy's whole semaphore for the sandbox's life, and a
// guest dribbling one byte a minute defeated idle-timeout reaping while it
// held the slot. The tunnel now carries the terminated leg's apparatus: a
// stall clock per direction and a ceiling every arm is clamped by.

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
	addr := a12Proxy(t, 150*time.Millisecond, originPort)

	c := a12Connect(t, addr, "127.0.0.1:"+strconv.Itoa(originPort))
	// Nothing is written and the origin says nothing: the stall clock is the
	// only thing that will end this tunnel. Under the deadline machinery the
	// read below gets an EOF or a timeout within a bound of the stall; before
	// the fix it hung until this test's own timeout.
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("the idle tunnel delivered bytes; the stall clock did not fire")
	}
}

func TestA12_AnActiveTunnelCarriesBytes(t *testing.T) {
	originPort, _ := a12Origin(t)
	addr := a12Proxy(t, 300*time.Millisecond, originPort)

	c := a12Connect(t, addr, "127.0.0.1:"+strconv.Itoa(originPort))
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
}

func TestA12_TheTunnelCeilingClampsTheStall(t *testing.T) {
	originPort, _ := a12Origin(t)
	// A stall far above the ceiling: the ceiling is what must fire, which is
	// the property that separates a clamp from a suggestion.
	p := &Proxy{Policy: Policy{Allow: []string{"127.0.0.1"}, Ports: []int{originPort}}, tunnelStall: time.Hour, tunnelCeiling: 200 * time.Millisecond}
	port, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve()
	t.Cleanup(p.Close)

	c := a12Connect(t, "127.0.0.1:"+strconv.Itoa(port), "127.0.0.1:"+strconv.Itoa(originPort))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("the tunnel outlived its ceiling")
	}
}

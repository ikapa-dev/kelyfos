package egress

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"
)

// The audit of 2026-09-01's M4, plain-leg half: forwardHTTP bounded the whole
// exchange by the connection ceiling but had no stall clock on the request body
// the guest streams up, so a guest that opened a request, declared a body and
// then stopped sending held one of maxConcurrentConnections slots for the full
// ceiling. The request body now reads through a stall clock on the client conn,
// and the close carries a reason: stalled (408) for a body that stopped,
// ceiling_reached (504) for one that never ends.

// a12PlainOrigin accepts, reads and discards everything, and never answers —
// enough for the request-body clock to have something to stream toward while
// the guest controls when the body stalls or how long it runs.
func a12PlainOrigin(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return port
}

func a12PlainProxy(t *testing.T, bodyStall, ceiling time.Duration, originPort int) (string, func() []Attempt) {
	t.Helper()
	var mu sync.Mutex
	var attempts []Attempt
	p := &Proxy{
		Policy: Policy{Allow: []string{"127.0.0.1"}, Ports: []int{originPort}},
		// A plain dialer so the loopback origin is reachable: the
		// resolved-address guard the per-proxy transport carries is orthogonal
		// to the request-body clock this measures.
		UpstreamPlain: &http.Transport{},
		bodyStall:     bodyStall,
		tunnelCeiling: ceiling,
		OnEvent:       func(a Attempt) { mu.Lock(); attempts = append(attempts, a); mu.Unlock() },
	}
	port, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve()
	t.Cleanup(p.Close)
	return "127.0.0.1:" + strconv.Itoa(port), func() []Attempt {
		mu.Lock()
		defer mu.Unlock()
		return append([]Attempt(nil), attempts...)
	}
}

// readStatus reads whatever the proxy answered, tolerating a reset that may
// follow the status once the proxy closes on the guest's unread upload: the
// status line arrives in order before the reset, so a blocked read returns it
// first.
func readStatus(t *testing.T, c net.Conn) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var acc []byte
	buf := make([]byte, 512)
	for {
		n, err := c.Read(buf)
		acc = append(acc, buf[:n]...)
		if i := bytes.IndexByte(acc, '\n'); i >= 0 {
			return string(acc[:i])
		}
		if err != nil {
			return string(acc)
		}
	}
}

func waitForReason(t *testing.T, attempts func() []Attempt, reason string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, a := range attempts() {
			if a.Reason == reason {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no attempt recorded reason %q: %+v", reason, attempts())
}

func TestA12_APlainRequestBodyThatStallsIsClosedAndRecorded(t *testing.T) {
	originPort := a12PlainOrigin(t)
	stall := 200 * time.Millisecond
	addr, attempts := a12PlainProxy(t, stall, 30*time.Second, originPort)

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	origin := "127.0.0.1:" + strconv.Itoa(originPort)
	// A POST declaring a large body, of which only a few bytes are sent before
	// the guest goes silent. Without the request-body clock this held the slot
	// to the ceiling; with it, the stall closes it and the record says stalled.
	fmt.Fprintf(raw, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000000\r\n\r\n", origin, origin)
	_, _ = raw.Write([]byte("partial"))
	// ... then nothing more.

	if status := readStatus(t, raw); !bytes.Contains([]byte(status), []byte("408")) {
		t.Errorf("a stalled request body was answered %q, want 408", status)
	}
	waitForReason(t, attempts, ReasonStalled)
}

func TestA12_ThePlainLegCeilingCutsAnEndlessBodyAndSaysSo(t *testing.T) {
	originPort := a12PlainOrigin(t)
	ceiling := 300 * time.Millisecond
	// A stall far above the ceiling, so the endless body never stalls — the
	// ceiling is what must fire.
	addr, attempts := a12PlainProxy(t, 10*time.Second, ceiling, originPort)

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	origin := "127.0.0.1:" + strconv.Itoa(originPort)
	fmt.Fprintf(raw, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n", origin, origin)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := io.WriteString(raw, "5\r\nhello\r\n"); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	defer close(stop)

	if status := readStatus(t, raw); !bytes.Contains([]byte(status), []byte("504")) {
		t.Errorf("an endless request body was answered %q, want 504", status)
	}
	waitForReason(t, attempts, ReasonCeilingReached)
}

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/proto"
)

// Inbound port forwarding, from inside the guest (E5-5, docs/qol.md §4).
//
// One connection is one forwarded TCP connection. The supervisor reads which
// guest-local port the host wants, dials it on the guest's own loopback, says
// whether that worked, and then copies bytes until one side is done.
//
// Loopback and not the guest's NIC, and that is the whole reason this design is
// permitted at all: the packet is already inside the machine when it is
// created, so nothing arrives across the TAP, and the nftables ruleset that
// makes the network egress-only never has to make an exception (F-D7).

// forwardDialTimeout bounds the dial to loopback inside this machine. It is
// short because the destination is a socket on this kernel: a server that is
// listening answers immediately, and one that is not fails immediately.
const forwardDialTimeout = 3 * time.Second

func serveForward(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			logf("forward accept: %v", err)
			return
		}
		go func() {
			defer conn.Close()
			if err := runForward(conn); err != nil {
				logf("forward: %v", err)
			}
		}()
	}
}

func runForward(conn net.Conn) error {
	// The buffered reader used for the handshake carries on as the reader for
	// the stream. Reading the handshake with one reader and the payload with
	// another would drop whatever the first had already buffered, which for a
	// client that speaks first is the beginning of its request.
	br := bufio.NewReader(conn)
	open, err := proto.ReadForwardOpen(br)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(open.Port))
	upstream, err := net.DialTimeout("tcp", addr, forwardDialTimeout)
	if err != nil {
		// The host turns this into the refusal a person reads. What it needs
		// from here is which port and what the kernel said, not a guess about
		// why: "connection refused" and "no route" are different problems.
		_ = proto.WriteForwardReply(conn, fmt.Sprintf(
			"nothing answered on port %d inside the sandbox: %v", open.Port, err))
		return nil
	}
	defer upstream.Close()
	if err := proto.WriteForwardReply(conn, ""); err != nil {
		return err
	}

	// Both directions, and the connection ends when either does. A half-close
	// is passed on rather than swallowed: a client that has finished sending
	// and is waiting to read — which is most of HTTP/1.0 and all of a plain
	// TCP request/response — needs the server to see EOF.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, br)
		halfCloseWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		halfCloseWrite(conn)
		done <- struct{}{}
	}()
	<-done
	<-done
	return nil
}

func halfCloseWrite(c net.Conn) {
	if h, ok := c.(interface{ CloseWrite() error }); ok {
		_ = h.CloseWrite()
	}
}

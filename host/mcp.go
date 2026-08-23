package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// mcpCmd bridges an MCP client's standard streams to the sandbox's MCP channel.
//
// It is a byte copier, not a translator. Both ends already speak the same
// framing — newline-delimited JSON-RPC — so there is nothing to convert, and
// converting anyway would only add a place for messages to be reordered,
// re-chunked or silently dropped (docs/protocol.md §6.1).
//
// Its one protocol responsibility is the CONNECT acknowledgement: consume it,
// and never let it reach stdout, because the spec forbids writing anything to
// stdout that is not a valid MCP message.
func mcpCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos mcp", flag.ExitOnError)
	var (
		id      = fs.String("sandbox", "", "sandbox id (default: the only running one)")
		timeout = fs.Duration("timeout", 15*time.Second, "how long to wait for the sandbox channel")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos mcp [flags]

Bridges this process's stdin and stdout to a running sandbox's MCP server, so
any MCP client can attach to it. Intended to be launched by the client, not run
by hand:

    {"command": "kelyfos", "args": ["mcp"]}

Diagnostics go to stderr, which the MCP specification reserves for logging and
which clients are required not to treat as failure.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	st, err := sandbox.Load(*id)
	if err != nil {
		return err
	}
	conn, err := sandbox.Connect(st.UDSPath, proto.PortMCP, *timeout)
	if err != nil {
		return fmt.Errorf("attach to sandbox %s: %w", st.ID, err)
	}
	defer conn.Close()

	fmt.Fprintf(os.Stderr, "kelyfos: attached to sandbox %s\n", st.ID)

	// Observation is a tee, not a filter: each direction is copied through
	// byte-for-byte while a duplicate is parsed for the flight recorder. The
	// bridge stays a pass-through and the session still gets an audit trail.
	rec, err := recorder.Open(sandbox.Root(), st.RecordSession())
	if err != nil {
		return err
	}
	defer rec.Close()
	obs := newObserver(rec, st.Agent)

	// Two copies, and the first one to end takes the bridge down with it.
	errc := make(chan error, 2)

	go func() {
		_, err := io.Copy(conn, tee(os.Stdin, obs.fromClient))
		// The client closing stdin means "no more requests". Half-close so the
		// guest sees EOF and can finish, rather than waiting on a peer that is
		// never going to speak again.
		if hc, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
		errc <- err
	}()
	go func() {
		_, err := io.Copy(os.Stdout, tee(conn, obs.fromGuest))
		errc <- err
	}()

	err = <-errc
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

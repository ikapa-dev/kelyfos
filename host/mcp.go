package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/mcp"
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

	// Two copies. The client's ending means "no more requests" and must not
	// end the bridge: a blocking tool answers when the other side acts, so
	// tearing down the moment stdin closes throws away an answer that is
	// already on its way. The guest's ending is what finishes the session.
	fromClient := make(chan error, 1)
	fromGuest := make(chan error, 1)

	go func() {
		_, err := io.Copy(conn, tee(os.Stdin, obs.fromClient))
		// Half-close so the guest sees EOF and can finish, rather than waiting
		// on a peer that is never going to speak again.
		if hc, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
		fromClient <- err
	}()
	go func() {
		_, err := io.Copy(os.Stdout, tee(conn, obs.fromGuest))
		fromGuest <- err
	}()

	select {
	case err = <-fromGuest:
	case err = <-fromClient:
		// The client stopped talking. Give the guest a bounded chance to
		// answer what is already outstanding before deciding nobody will.
		select {
		case err = <-fromGuest:
		case <-time.After(mcpDrainGrace):
		}
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return answerOutstanding(os.Stdout, obs)
}

// mcpDrainGrace is how long the bridge waits for the guest to answer calls that
// were still in flight when the client stopped talking. Long enough for a tool
// that was about to return, short enough not to hang a script.
const mcpDrainGrace = 5 * time.Second

// answerOutstanding answers, on the bridge's own behalf, every tool call the
// guest never got to answer.
//
// The alternative is silence, and silence is the worst of the three possible
// outcomes: a caller told nothing concludes the call is still running, or that
// it succeeded and returned nothing. Both are wrong, and neither is
// recoverable. An error result is something a model can act on and a script can
// branch on (F-D33).
func answerOutstanding(w io.Writer, obs *observer) error {
	pending := obs.outstanding()
	if len(pending) == 0 {
		return nil
	}
	enc := json.NewEncoder(w)
	for _, p := range pending {
		_ = enc.Encode(mcp.NewResponse(json.RawMessage(p.ID), mcp.Errorf(
			"kelyfos: the bridge to this sandbox closed before %s answered. "+
				"The call may or may not have run inside the guest; the flight recorder is "+
				"the account of what did. A blocking tool answers when the other side acts, "+
				"so keep the channel open at least as long as its timeout_ms.", p.Tool)))
	}
	fmt.Fprintf(os.Stderr, "kelyfos: %d tool call(s) were unanswered when the bridge closed; "+
		"each was answered with an error rather than left silent\n", len(pending))
	// A bridge that closes with calls still outstanding is not a clean
	// shutdown, whatever ended the connection to the guest — the sandbox
	// tearing down, or a guest MCP session giving up on a frame it could not
	// parse (F6). The client got the synthetic answer above either way, but
	// this used to return nil regardless, so the one signal that would tell a
	// wrapper script or supervisor process something went wrong — $? — said
	// success. The diagnostic above is what a person reads; this is what a
	// script checks.
	return &exitError{code: 1}
}

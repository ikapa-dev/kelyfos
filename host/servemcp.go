package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
	"github.com/p4r4n0rm4l/KelyfOS/internal/mcp"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// kelyfos serve-mcp — KelyfOS as a tool for any MCP client (E4-1).
//
// The opposite of `kelyfos mcp`, which fronts one guest's supervisor and is a
// byte copier. This is a real MCP server over its own standard streams, and the
// tools it offers are the host's: boot a sandbox, run something in it, stop it.
// An agent gets a microVM to be reckless in without the client ever learning
// what a microVM is.
//
// Everything it does is bounded by the project's kelyfos.toml, and there is no
// tool that changes that (F-D5, docs/mcp-surface.md §1). A client may ask for
// less than the policy allows and never for more.
//
// defaultMaxSandboxes is small deliberately. Each one is a real machine with
// real RAM, four at the default 512 MiB is 2 GiB, and an agent that wants a
// fleet should have to say so in a file a person reads.
const defaultMaxSandboxes = 4

func serveMCPCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos serve-mcp", flag.ExitOnError)
	arch := fs.String("arch", sandbox.HostArch(), "guest architecture (aarch64|x86_64)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos serve-mcp [flags]

Serves KelyfOS itself as an MCP server on standard input and output, so any MCP
client gains sandbox_run, sandbox_exec, sandbox_stop and sandbox_list. Point a
client at it with one line of configuration:

    { "mcpServers": { "kelyfos": { "command": "kelyfos", "args": ["serve-mcp"] } } }

Every sandbox it creates is held to this project's kelyfos.toml, and no tool can
widen that. A request above a ceiling is refused, naming the ceiling and the
line it came from. See docs/mcp-surface.md.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	srv, err := newHostServer(*arch, argv)
	if err != nil {
		return err
	}
	defer srv.closeAll()

	// The policy banner goes to stderr: stdout is the protocol.
	fmt.Fprintf(os.Stderr, "kelyfos serve-mcp — %s\n", srv.describe())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		// Closing stdin ends the read loop, which unwinds through closeAll and
		// stops every sandbox this server made.
		_ = os.Stdin.Close()
	}()

	return srv.serve(os.Stdin, os.Stdout)
}

// hostServer is one `serve-mcp` process: the resolved policy, and the sandboxes
// it has created.
type hostServer struct {
	arch   string
	argv   []string
	policy *config.Config
	max    int

	mu    sync.Mutex
	boxes map[string]*servedBox

	wmu sync.Mutex // one writer, because tool calls may be concurrent
	out *json.Encoder
}

// servedBox is a sandbox this server owns, and everything that comes down with
// it. The recorder is per sandbox because a sandbox created through this door is
// a session like any other — no entry path skips the record (F-D33).
type servedBox struct {
	sb      *sandbox.Sandbox
	rec     *recorder.Recorder
	net     *sandbox.Network
	proxy   *egress.Proxy
	slice   *sandbox.Slice
	image   string
	allow   []string
	created time.Time
}

func (b *servedBox) close(reason string) {
	// A box can be half-built: a restore that failed after its network was up
	// has everything here except a machine.
	if b.sb != nil {
		_ = b.sb.Shutdown(5 * time.Second)
	}
	if b.proxy != nil {
		b.proxy.Close()
	}
	if b.net != nil {
		b.net.Down()
	}
	if b.slice != nil {
		b.slice.Close()
	}
	if b.rec != nil {
		_ = b.rec.Append(recorder.Event{
			Type: recorder.TypeSessionEnd, Reason: reason,
			DurationMS: b.rec.Since().Milliseconds(),
		})
		_ = b.rec.Close()
	}
}

func newHostServer(arch string, argv []string) (*hostServer, error) {
	cfg, err := loadPolicy()
	if err != nil {
		return nil, err
	}
	s := &hostServer{
		arch:   arch,
		argv:   append([]string{"kelyfos", "serve-mcp"}, argv...),
		policy: cfg,
		max:    defaultMaxSandboxes,
		boxes:  map[string]*servedBox{},
	}
	if cfg != nil {
		if cfg.Arch != "" {
			s.arch = cfg.Arch
		}
		if cfg.MCPMaxSandboxes > 0 {
			s.max = cfg.MCPMaxSandboxes
		}
	}
	return s, nil
}

func (s *hostServer) describe() string {
	where := "no kelyfos.toml found; defaults apply"
	if s.policy != nil {
		where = "policy " + s.policy.Path
	}
	return fmt.Sprintf("%s · arch %s · at most %d sandbox(es) at once", where, s.arch, s.max)
}

func (s *hostServer) closeAll() {
	s.mu.Lock()
	boxes := make([]*servedBox, 0, len(s.boxes))
	for _, b := range s.boxes {
		boxes = append(boxes, b)
	}
	s.boxes = map[string]*servedBox{}
	s.mu.Unlock()
	for _, b := range boxes {
		b.close("shutdown")
	}
}

// serve reads newline-delimited JSON-RPC and answers it. Requests are handled
// on their own goroutines: MCP assumes a client may have several in flight and
// nothing orders them, and a `sandbox_run` that takes a second must not block a
// `sandbox_list` behind it (docs/mcp-surface.md §2.3).
func (s *hostServer) serve(in io.Reader, out io.Writer) error {
	s.out = json.NewEncoder(out)
	r := proto.NewReaderLimit(in, proto.MaxMCPLine)
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		var req mcp.Request
		if err := r.Read(&req); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				return nil
			}
			s.write(mcp.NewError(nil, mcp.CodeParseError, err.Error()))
			return nil
		}
		// Everything except a tool call answers immediately and in order; a
		// tool call is the only thing that can take time.
		if req.Method != "tools/call" || req.IsNotification() {
			if resp := s.dispatch(&req); resp != nil {
				s.write(resp)
			}
			continue
		}
		wg.Add(1)
		go func(req mcp.Request) {
			defer wg.Done()
			if resp := s.dispatch(&req); resp != nil {
				s.write(resp)
			}
		}(req)
	}
}

func (s *hostServer) write(v any) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_ = s.out.Encode(v)
}

func (s *hostServer) dispatch(req *mcp.Request) *mcp.Response {
	switch req.Method {
	case "initialize":
		return mcp.NewResponse(req.ID, mcp.InitializeResult{
			ProtocolVersion: mcp.ProtocolVersion,
			Capabilities:    mcp.Capabilities{Tools: &mcp.ToolsCapability{}},
			ServerInfo:      mcp.Info{Name: "kelyfos", Title: "KelyfOS", Version: Version},
			Instructions: "KelyfOS runs commands inside hardware-isolated microVMs. Boot one with " +
				"sandbox_run, work in it with sandbox_exec and the file tools, and stop it with " +
				"sandbox_stop. A sandbox worth keeping can be frozen with sandbox_snapshot and " +
				"brought back in milliseconds with sandbox_restore, or forked into several copies " +
				"of one prepared state with sandbox_fork. Anything you run in a sandbox cannot " +
				"reach this machine, and cannot reach the network unless the project's policy " +
				"allows it. That policy is a file and no tool here can change it: a request for " +
				"more than it permits is refused and says so.",
		})

	case "notifications/initialized", "notifications/cancelled":
		return nil

	case "ping":
		return mcp.NewResponse(req.ID, struct{}{})

	case "tools/list":
		return mcp.NewResponse(req.ID, mcp.ToolsListResult{Tools: hostToolDefinitions()})

	case "tools/call":
		if req.IsNotification() {
			return nil
		}
		var p mcp.CallToolParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return mcp.NewError(req.ID, mcp.CodeInvalidParams, err.Error())
		}
		return mcp.NewResponse(req.ID, s.callTool(&p))

	default:
		if req.IsNotification() {
			return nil
		}
		return mcp.NewError(req.ID, mcp.CodeMethodNotFound, "unknown method "+req.Method)
	}
}

// callTool answers one tool call. A tool that ran and failed comes back as a
// result with isError set, never as a JSON-RPC error: the model is meant to see
// it and adapt (docs/mcp-surface.md §2.4). Only an unknown tool or an
// unparseable argument object is a protocol error.
func (s *hostServer) callTool(p *mcp.CallToolParams) *mcp.CallToolResult {
	args := p.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	switch p.Name {
	case "sandbox_run":
		return s.toolRun(args)
	case "sandbox_exec":
		return s.toolExec(args)
	case "sandbox_stop":
		return s.toolStop(args)
	case "sandbox_list":
		return s.toolList()
	case "sandbox_read_file":
		return s.toolReadFile(args)
	case "sandbox_write_file":
		return s.toolWriteFile(args)
	case "sandbox_snapshot":
		return s.toolSnapshot(args)
	case "sandbox_restore":
		return s.toolRestore(args)
	case "sandbox_fork":
		return s.toolFork(args)
	}
	return mcp.Errorf("unknown tool %q", p.Name)
}

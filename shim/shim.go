// Package shim serves an E2B-compatible REST subset in front of KelyfOS
// sandboxes, so code already written against the E2B SDK can point at a
// self-hosted box (P3-4).
//
// It is a **best-effort subset**, not a reimplementation. E2B's control API and
// envd file endpoints are ordinary HTTP and are implemented here; command
// execution in the current SDK goes over Connect RPC with protobuf streaming,
// which is a different protocol stack and is deliberately out of scope. What
// works is documented in docs/e2b-shim.md; what does not returns a clear error
// rather than a confusing one.
package shim

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sessionpolicy"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// EnvdVersion is what the shim reports to the SDK. The SDK gates features on
// it, so this claims a version whose feature set the shim actually implements
// rather than the newest one.
const EnvdVersion = "0.1.0"

// Policy is the project's kelyfos.toml, resolved once by the CLI and applied to
// every sandbox this shim creates (F-D33).
//
// It exists because an entry path that skips the policy file is a hole in the
// wall, not a convenience. F-D5 already says an MCP tool can never widen policy
// because the toml is the ceiling; the same rule has to hold here, or "the
// policy travels with the project" is true of `kelyfos run` and false of the
// door an SDK comes through.
type Policy struct {
	Arch   string
	Flavor string

	// Allow is the egress allowlist, and Secrets the credentials bound to
	// domains inside it. Both come from the file unless the operator who
	// started the shim named them on the command line.
	Allow   []string
	Secrets []*egress.Secret

	// The caps, exactly as [resources] declares them. There are no per-request
	// knobs: an SDK client cannot ask for a bigger machine, which is the point.
	Vcpus        int
	MemMiB       int
	CPUQuota     int
	IO           sandbox.IOLimits
	ScratchBytes int64

	// Argv and Version are what session.start records about how this shim was
	// launched, so a reader of the chain can reproduce it.
	Argv    []string
	Version string
	// PolicyPath is the file the above came from, empty when there was none.
	PolicyPath string
}

// box is one sandbox the shim owns, with everything that has to come down with
// it. The recorder is per sandbox because a shim sandbox is a session like any
// other: it gets its own chain, opened before the VM starts and closed after it
// stops.
type box struct {
	sb    *sandbox.Sandbox
	rec   *recorder.Recorder
	net   *sandbox.Network
	proxy *egress.Proxy
	slice *sandbox.Slice
}

func (b *box) close(reason string) {
	// A box can be half-built: boot unwinds through here when it fails, and it
	// can fail before there is a machine to stop — nil-guarded for the same
	// reason serve-mcp's servedBox.close is.
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

// Server owns the sandboxes it created. It deliberately does not adopt
// sandboxes started by `kelyfos run`: the SDK's lifecycle expects to own what
// it creates, and killing someone else's interactive session because an SDK
// call said so would be a nasty surprise.
type Server struct {
	Policy Policy

	mu    sync.Mutex
	boxes map[string]*box
}

func New(p Policy) *Server {
	return &Server{Policy: p, boxes: map[string]*box{}}
}

// MaxSandboxes is how many machines one shim will hold at once.
//
// A sandbox is a microVM: memory, a disk image, a TAP device, a process. The
// policy carries a ceiling for each of those per machine and, until P6-25, none
// for the number of machines — so the arithmetic was whatever the caller asked
// for times whatever the policy allowed, and the shim is the one door in this
// product another machine can knock on (finding H-6).
//
// Sixteen because the shim is a developer's stand-in for a hosted API on one
// host, not a fleet. A caller that wants more deletes one first, which is a
// request it already has.
const MaxSandboxes = 16

// tokenEnv names the credential the shim requires when it is set.
//
// Unauthenticated is the documented default and stays the default: the shim is
// a tool for a machine you already trust, and turning it into a service with
// mandatory credentials would be answering a question nobody asked. What was
// missing is the choice — there was no way to require one at all. Set it and
// every route asks; leave it and the shim says out loud, once, what it is.
const tokenEnv = "KELYFOS_SHIM_TOKEN"

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// envd routes
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /files", s.readFile)
	mux.HandleFunc("POST /files", s.writeFile)
	// control-plane routes
	mux.HandleFunc("POST /sandboxes", s.createSandbox)
	mux.HandleFunc("GET /sandboxes", s.listSandboxes)
	mux.HandleFunc("DELETE /sandboxes/{id}", s.killSandbox)
	mux.HandleFunc("/", s.notImplemented)
	return logging(authenticated(mux))
}

// authenticated gates every route on a bearer token, when one is configured.
//
// The comparison is constant-time. A token checked with == leaks its length and
// its prefix to anything that can time a request, and a credential compared
// carelessly is the kind of thing this repository spends a whole document
// refusing to do elsewhere.
func authenticated(next http.Handler) http.Handler {
	want := os.Getenv(tokenEnv)
	if want == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			writeErr(w, http.StatusUnauthorized,
				"this shim requires a bearer token; it was started with "+tokenEnv+" set")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Close stops every sandbox the shim created.
func (s *Server) Close() {
	s.mu.Lock()
	boxes := make([]*box, 0, len(s.boxes))
	for _, b := range s.boxes {
		boxes = append(boxes, b)
	}
	s.boxes = map[string]*box{}
	s.mu.Unlock()
	for _, b := range boxes {
		b.close("shutdown")
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// --- control plane ---

type sandboxResponse struct {
	TemplateID  string `json:"templateID"`
	SandboxID   string `json:"sandboxID"`
	ClientID    string `json:"clientID"`
	EnvdVersion string `json:"envdVersion"`
}

func (s *Server) createSandbox(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TemplateID string `json:"templateID"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	// Before the machine is built rather than after, because the cost this is
	// bounding is the building of it.
	s.mu.Lock()
	live := len(s.boxes)
	s.mu.Unlock()
	if live >= MaxSandboxes {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf(
			"this shim holds %d sandboxes and its limit is %d; delete one before asking for another",
			live, MaxSandboxes))
		return
	}

	b, err := s.boot(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.mu.Lock()
	s.boxes[b.sb.State.ID] = b
	s.mu.Unlock()

	template := req.TemplateID
	if template == "" {
		template = s.Policy.Flavor
	}
	sb := b.sb
	writeJSON(w, http.StatusCreated, sandboxResponse{
		TemplateID:  template,
		SandboxID:   sb.State.ID,
		ClientID:    "kelyfos",
		EnvdVersion: EnvdVersion,
	})
}

// boot brings up one sandbox under the project's policy, with its own flight
// recorder, its own egress path when the policy grants any, and its own cgroup
// slice when the policy caps CPU time.
//
// The order is the order `kelyfos run` uses and it is load-bearing: the TAP
// first, then the proxy bound on it, then the firewall that makes the proxy the
// only reachable destination, and only then a machine that can send a packet
// anywhere (docs/networking.md). Anything that fails part way unwinds what it
// already built rather than leaving a TAP behind.
func (s *Server) boot(parent context.Context) (*box, error) {
	id, err := sandbox.NewID()
	if err != nil {
		return nil, err
	}
	b := &box{}
	ok := false
	// The one teardown, not a copy of it. This defer used to hand-roll a strict
	// subset of close() — proxy, network, slice, recorder, and no machine — so a
	// failure after the VM was running left a microVM nothing could reach: it
	// never entered s.boxes, so `killSandbox` could not find it and the census
	// that bounds this shim under-counted it forever. The refusal that reaches
	// it is the guest's to make (finding M-1): InstallTrustAnchor fails when the
	// guest answers no.
	defer func() {
		if !ok {
			b.close("error")
		}
	}()

	opts := sandbox.Options{
		ID:           id,
		Arch:         s.Policy.Arch,
		Flavor:       s.Policy.Flavor,
		VcpuCount:    s.Policy.Vcpus,
		MemMiB:       s.Policy.MemMiB,
		IO:           s.Policy.IO,
		ScratchBytes: s.Policy.ScratchBytes,
		Quiet:        true,
	}
	if s.Policy.CPUQuota > 0 {
		if b.slice, err = sandbox.NewCPUSlice(id, s.Policy.CPUQuota); err != nil {
			return nil, err
		}
		opts.CPUSlice = b.slice
	}

	var ca *egress.CA
	if len(s.Policy.Allow) > 0 {
		opts.Allow = s.Policy.Allow
		if b.net, err = sandbox.NewNetwork(id); err != nil {
			return nil, err
		}
		opts.Net = b.net
		pol := egress.Policy{Allow: s.Policy.Allow, Secrets: s.Policy.Secrets}
		if len(pol.Secrets) > 0 {
			if ca, err = egress.NewCA(); err != nil {
				return nil, err
			}
		}
		b.proxy = &egress.Proxy{Policy: pol, CA: ca}
		port, err := b.proxy.Listen(b.net.HostIP.String() + ":0")
		if err != nil {
			return nil, err
		}
		if err := b.net.Restrict(port); err != nil {
			return nil, err
		}
		go b.proxy.Serve()
	}

	if b.sb, err = sandbox.New(opts); err != nil {
		return nil, err
	}

	// Opened before the VM starts and closed after it stops, so the record
	// brackets the thing it describes — the same contract every other entry
	// path holds to (docs/events.md).
	if b.rec, err = recorder.Open(sandbox.Root(), id); err != nil {
		return nil, err
	}
	_ = b.rec.Append(recorder.Event{
		Type: recorder.TypeSessionStart, Image: s.Policy.Flavor, Arch: s.Policy.Arch,
		Kelyfos: s.Policy.Version, Argv: s.Policy.Argv,
		Reason: "created through the E2B shim",
	})
	s.wireEgressAudit(b)

	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	if err := b.sb.Start(ctx); err != nil {
		_ = b.sb.Shutdown(2 * time.Second)
		return nil, err
	}
	ready, err := b.sb.WaitReady(ctx)
	if err != nil {
		_ = b.sb.Shutdown(2 * time.Second)
		return nil, err
	}
	if ca != nil {
		if err := b.sb.InstallTrustAnchor(ca.AnchorPEM()); err != nil {
			return nil, err
		}
	}
	overlay := ready.Overlay
	_ = b.rec.Append(recorder.Event{
		Type: recorder.TypeSessionReady, BootMS: b.sb.State.BootReadyMS,
		Kernel: ready.Kernel, Supervisor: ready.Supervisor, Overlay: &overlay,
	}.WithPosture(b.sb.State.Jailed, b.sb.State.Profile))

	// What this machine was permitted (P7-2, docs/policy-record.md §5).
	// Workspace, plugins, forwards, max_runtime and idle_timeout are all
	// genuinely absent from the E2B-compatible surface — docs/e2b-shim.md's
	// own "what it deliberately omits" — not values this task invented.
	rootfsSHA, kernelSHA := sessionpolicy.Digests(sandbox.ImageDir(s.Policy.Arch))
	_ = b.rec.Append(recorder.NewSessionPolicy("", recorder.PolicyFields{
		VcpuCount: s.Policy.Vcpus, MemMiB: s.Policy.MemMiB, CPUQuota: s.Policy.CPUQuota,
		ScratchBytes: s.Policy.ScratchBytes,
		NetMbpsRx:    s.Policy.IO.NetMbpsRx, NetMbpsTx: s.Policy.IO.NetMbpsTx,
		DiskIOPS: s.Policy.IO.DiskIOPS, DiskMbps: s.Policy.IO.DiskMbps,
		Allow: s.Policy.Allow, Ports: sessionpolicy.Ports(s.Policy.Allow),
		Secrets:      sessionpolicy.Secrets(s.Policy.Secrets),
		Tools:        sessionpolicy.ToolsForCLI(false),
		RootfsSHA256: rootfsSHA,
		KernelSHA256: kernelSHA,
	}))
	ok = true
	return b, nil
}

// wireEgressAudit points the proxy's reports at this sandbox's chain. Every
// connection attempt is recorded, allowed or blocked, and a bound credential is
// recorded by name — never by value (docs/events.md §4).
func (s *Server) wireEgressAudit(b *box) {
	if b.proxy == nil {
		return
	}
	b.proxy.OnSecret = func(name, host string) {
		_ = b.rec.Append(recorder.Event{Type: recorder.TypeSecretUse, Name: name, Host: host})
	}
	b.proxy.OnWithheld = func(name, host, reason string) {
		_ = b.rec.Append(recorder.Event{
			Type: recorder.TypeSecretWithheld, Name: name, Host: host, Reason: reason,
		})
	}
	b.proxy.OnScrubbed = func(name, host string) {
		_ = b.rec.Append(recorder.Event{
			Type: recorder.TypeSecretScrubbed, Name: name, Host: host,
		})
	}
	b.proxy.OnEvent = func(a egress.Attempt) {
		allowed := a.Allowed
		_ = b.rec.Append(recorder.Event{
			Type: recorder.TypeEgressAttempt, Host: a.Host, Port: a.Port,
			Allowed: &allowed, Reason: a.Reason, Mode: a.Mode,
			BytesIn: a.BytesIn, BytesOut: a.BytesOut,
		})
	}
}

func (s *Server) listSandboxes(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sandboxResponse, 0, len(s.boxes))
	for id := range s.boxes {
		out = append(out, sandboxResponse{
			TemplateID: s.Policy.Flavor, SandboxID: id, ClientID: "kelyfos", EnvdVersion: EnvdVersion,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) killSandbox(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	sb, ok := s.boxes[id]
	delete(s.boxes, id)
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "no sandbox "+id+" created by this shim")
		return
	}
	sb.close("shutdown")
	w.WriteHeader(http.StatusNoContent)
}

// --- envd files ---

// only returns the single sandbox to act on. The SDK addresses envd by URL
// rather than by id, and the shim serves one address, so a single running
// sandbox is unambiguous and several are not.
func (s *Server) only() (*box, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch len(s.boxes) {
	case 0:
		return nil, fmt.Errorf("no sandbox has been created through this shim")
	case 1:
		for _, b := range s.boxes {
			return b, nil
		}
	}
	return nil, fmt.Errorf("%d sandboxes are running; the E2B shim addresses envd by URL and "+
		"cannot tell them apart — create one at a time", len(s.boxes))
}

func (s *Server) readFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeErr(w, http.StatusBadRequest, "path is required")
		return
	}
	sb, err := s.only()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// base64 keeps the round trip binary-safe over a channel that carries text.
	res, err := sandbox.Exec(sb.sb.State.UDSPath,
		[]string{"/bin/sh", "-c", "base64 " + shellQuote(path)}, nil, 30*time.Second)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if res.Code != 0 {
		writeErr(w, http.StatusNotFound, strings.TrimSpace(string(res.Stderr)))
		return
	}
	data, err := decodeBase64Lines(res.Stdout)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) writeFile(w http.ResponseWriter, r *http.Request) {
	sb, err := s.only()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	path := r.URL.Query().Get("path")

	var body []byte
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "multipart/") {
		name, data, err := firstMultipartFile(r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		body = data
		if path == "" {
			path = name
		}
	} else {
		body, err = io.ReadAll(io.LimitReader(r.Body, 64<<20))
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if path == "" {
		writeErr(w, http.StatusBadRequest, "path is required")
		return
	}

	script := "mkdir -p \"$(dirname " + shellQuote(path) + ")\" && base64 -d > " + shellQuote(path)
	res, err := sandbox.Exec(sb.sb.State.UDSPath, []string{"/bin/sh", "-c", script},
		[]byte(encodeBase64(body)), 60*time.Second)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if res.Code != 0 {
		writeErr(w, http.StatusInternalServerError, strings.TrimSpace(string(res.Stderr)))
		return
	}
	// A file that arrived through this door is recorded exactly as one that
	// arrived through an MCP tool: by path, size and digest, never by content
	// (docs/events.md §4). Reads are not recorded here for the same reason they
	// are not recorded there — the record is of what was changed.
	sum := sha256.Sum256(body)
	_ = sb.rec.Append(recorder.Event{
		Type: recorder.TypeFileWrite, Path: path, Bytes: len(body),
		SHA256: hex.EncodeToString(sum[:]), Via: "shim",
	})
	writeJSON(w, http.StatusOK, []map[string]any{{"name": path, "path": path, "type": "file"}})
}

// notImplemented answers the parts of E2B's surface the shim does not cover —
// principally command execution, which the current SDK performs over Connect RPC
// with protobuf streaming. Saying so plainly beats a 404 that looks like a bug.
func (s *Server) notImplemented(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusNotImplemented, fmt.Sprintf(
		"the KelyfOS E2B shim is a best-effort subset and does not implement %s %s. "+
			"Sandbox lifecycle and file transfer are supported; command execution uses Connect RPC "+
			"in the E2B SDK and is not. Use the MCP interface (kelyfos mcp) for commands. "+
			"See docs/e2b-shim.md", r.Method, r.URL.Path))
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"code": code, "message": msg})
}

func firstMultipartFile(r *http.Request) (string, []byte, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return "", nil, err
	}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return "", nil, fmt.Errorf("multipart body carried no file")
		}
		if err != nil {
			return "", nil, err
		}
		if part.FileName() == "" {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(part, 64<<20))
		return part.FileName(), data, err
	}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func encodeBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// decodeBase64Lines joins the wrapped output of base64(1) before decoding.
func decodeBase64Lines(out []byte) ([]byte, error) {
	joined := strings.Join(strings.Fields(string(out)), "")
	return base64.StdEncoding.DecodeString(joined)
}

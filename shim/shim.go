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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// EnvdVersion is what the shim reports to the SDK. The SDK gates features on
// it, so this claims a version whose feature set the shim actually implements
// rather than the newest one.
const EnvdVersion = "0.1.0"

// Server owns the sandboxes it created. It deliberately does not adopt
// sandboxes started by `kelyfos run`: the SDK's lifecycle expects to own what
// it creates, and killing someone else's interactive session because an SDK
// call said so would be a nasty surprise.
type Server struct {
	Arch   string
	Flavor string
	Allow  []string

	mu    sync.Mutex
	boxes map[string]*sandbox.Sandbox
}

func New(arch, flavor string, allow []string) *Server {
	return &Server{Arch: arch, Flavor: flavor, Allow: allow, boxes: map[string]*sandbox.Sandbox{}}
}

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
	return logging(mux)
}

// Close stops every sandbox the shim created.
func (s *Server) Close() {
	s.mu.Lock()
	boxes := make([]*sandbox.Sandbox, 0, len(s.boxes))
	for _, b := range s.boxes {
		boxes = append(boxes, b)
	}
	s.boxes = map[string]*sandbox.Sandbox{}
	s.mu.Unlock()
	for _, b := range boxes {
		_ = b.Shutdown(5 * time.Second)
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

	opts := sandbox.Options{Arch: s.Arch, Flavor: s.Flavor, Quiet: true, Allow: s.Allow}
	sb, err := sandbox.New(opts)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := sb.Start(ctx); err != nil {
		_ = sb.Shutdown(2 * time.Second)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := sb.WaitReady(ctx); err != nil {
		_ = sb.Shutdown(2 * time.Second)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.mu.Lock()
	s.boxes[sb.State.ID] = sb
	s.mu.Unlock()

	template := req.TemplateID
	if template == "" {
		template = s.Flavor
	}
	writeJSON(w, http.StatusCreated, sandboxResponse{
		TemplateID:  template,
		SandboxID:   sb.State.ID,
		ClientID:    "kelyfos",
		EnvdVersion: EnvdVersion,
	})
}

func (s *Server) listSandboxes(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sandboxResponse, 0, len(s.boxes))
	for id := range s.boxes {
		out = append(out, sandboxResponse{
			TemplateID: s.Flavor, SandboxID: id, ClientID: "kelyfos", EnvdVersion: EnvdVersion,
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
	_ = sb.Shutdown(5 * time.Second)
	w.WriteHeader(http.StatusNoContent)
}

// --- envd files ---

// only returns the single sandbox to act on. The SDK addresses envd by URL
// rather than by id, and the shim serves one address, so a single running
// sandbox is unambiguous and several are not.
func (s *Server) only() (*sandbox.Sandbox, error) {
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
	res, err := sandbox.Exec(sb.State.UDSPath,
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
	res, err := sandbox.Exec(sb.State.UDSPath, []string{"/bin/sh", "-c", script},
		[]byte(encodeBase64(body)), 60*time.Second)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if res.Code != 0 {
		writeErr(w, http.StatusInternalServerError, strings.TrimSpace(string(res.Stderr)))
		return
	}
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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// The six clients `kelyfos connect` writes, and one writer each (P6-13, D41).
//
// One template with a swapped key is impossible, and that is the survey's real
// finding rather than a preference. VS Code's top-level key is `servers` and not
// `mcpServers`, which is the most common integration mistake anywhere. Codex is
// TOML with `mcp_servers` in snake_case, and `codex mcp add` physically cannot
// target project scope, so a direct merge-write is the primary path rather than
// a fallback. Claude Code's user-scoped file holds a live sign-in session and is
// never hand-edited. Each of those is a different writer or a different file,
// and a shared snippet would get half of them subtly wrong.
//
// Every entry carries the tool and version it was verified against and the date.
// D41 requires it because a client's configuration format is an **external**
// surface: outside the drift gate, outside the semver promise, re-verified on
// its own cadence. The honest thing to publish about one is when somebody last
// looked.

func clients() []client {
	return []client{
		{
			Name:     "claude-code",
			Label:    "Claude Code (project .mcp.json)",
			Verified: "verified against Claude Code v2.1.241 on 2026-08-24",
			// The project file, written directly. The user-scoped
			// ~/.claude.json is deliberately not touched: it holds the live
			// sign-in session, and a corrupt parse triggers a recovery flow —
			// `claude mcp add-json` is the only safe way in, and that is a
			// command to print rather than a file to edit.
			Path:   func(project, home string) string { return filepath.Join(project, ".mcp.json") },
			Write:  jsonServerWriter("mcpServers"),
			Remove: jsonServerRemover("mcpServers"),
		},
		{
			Name:     "codex",
			Label:    "OpenAI Codex CLI (config.toml)",
			Verified: "verified against Codex CLI 0.149.1 on 2026-08-24",
			Path:     func(project, home string) string { return filepath.Join(home, ".codex", "config.toml") },
			Write:    codexWrite,
			Remove:   codexRemove,
		},
		{
			Name:     "cursor",
			Label:    "Cursor (.cursor/mcp.json)",
			Verified: "verified against Cursor on 2026-08-24",
			// A file dedicated to MCP, so a rewrite cannot clobber unrelated
			// settings — which is why this one is cheap and Zed's is not.
			Path:   func(project, home string) string { return filepath.Join(project, ".cursor", "mcp.json") },
			Write:  jsonServerWriter("mcpServers"),
			Remove: jsonServerRemover("mcpServers"),
		},
		{
			Name:     "vscode",
			Label:    "VS Code (.vscode/mcp.json)",
			Verified: "verified against VS Code on 2026-08-24",
			Path:     func(project, home string) string { return filepath.Join(project, ".vscode", "mcp.json") },
			// `servers`, not `mcpServers`. The most common integration mistake
			// there is, and this repository already gets it right in recipe 9 —
			// which is why the key is a parameter and not a constant.
			Write:  jsonServerWriter("servers"),
			Remove: jsonServerRemover("servers"),
		},
		{
			Name:     "gemini",
			Label:    "Gemini CLI (~/.gemini/settings.json)",
			Verified: "verified against Gemini CLI v0.56.0 on 2026-08-24",
			Path:     func(project, home string) string { return filepath.Join(home, ".gemini", "settings.json") },
			// Never emits Gemini's `trust` flag. It bypasses every tool-call
			// confirmation, which for a server whose tools boot microVMs is
			// exactly backwards — and it is precisely the field a later "make
			// setup smoother" change would reach for (D41, binding).
			Write:  jsonServerWriter("mcpServers"),
			Remove: jsonServerRemover("mcpServers"),
		},
		{
			Name:     "junie",
			Label:    "JetBrains Junie (.junie/mcp/mcp.json)",
			Verified: "verified against JetBrains Junie on 2026-08-24",
			Path:     func(project, home string) string { return filepath.Join(project, ".junie", "mcp", "mcp.json") },
			Write:    jsonServerWriter("mcpServers"),
			Remove:   jsonServerRemover("mcpServers"),
		},
	}
}

// jsonServerWriter builds a writer for the clients whose configuration is JSON
// with a map of servers under one key.
//
// The key differs and everything else does not, so the key is the parameter.
// Decoded into a map rather than a struct so that **every key the file already
// had survives** — a configuration file belongs to the person whose machine it
// is, and this command is a guest in it.
func jsonServerWriter(key string) func([]byte, command) ([]byte, error) {
	return func(existing []byte, cmd command) ([]byte, error) {
		doc := map[string]any{}
		if len(bytes.TrimSpace(existing)) > 0 {
			if err := json.Unmarshal(existing, &doc); err != nil {
				return nil, fmt.Errorf("this file is not valid JSON, so kelyfos will not rewrite it: %w", err)
			}
		}
		servers, _ := doc[key].(map[string]any)
		if servers == nil {
			servers = map[string]any{}
		}
		// Replaced rather than merged into: an entry named kelyfos is this
		// command's, and a half-updated one — a new binary path beside an old
		// policy — is worse than either.
		servers[serverKey] = map[string]any{
			"command": cmd.Bin,
			"args":    cmd.Args,
		}
		doc[key] = servers
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(out, '\n'), nil
	}
}

func jsonServerRemover(key string) func([]byte) ([]byte, bool, error) {
	return func(existing []byte) ([]byte, bool, error) {
		doc := map[string]any{}
		if len(bytes.TrimSpace(existing)) > 0 {
			if err := json.Unmarshal(existing, &doc); err != nil {
				return nil, false, fmt.Errorf("this file is not valid JSON, so kelyfos will not rewrite it: %w", err)
			}
		}
		servers, _ := doc[key].(map[string]any)
		if _, ok := servers[serverKey]; !ok {
			return existing, false, nil
		}
		delete(servers, serverKey)
		// An empty map left behind is tidier than a removed key for a client
		// that expects the key to exist, and harmless for one that does not.
		doc[key] = servers
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return nil, false, err
		}
		return append(out, '\n'), true, nil
	}
}

// Codex is TOML, and its table is `mcp_servers` in snake_case rather than
// `mcpServers`.
//
// Written by line surgery rather than by a TOML round-trip, and deliberately:
// this is the user's whole-product configuration file, it may carry comments,
// and no TOML library in the standard library preserves them. Replacing only
// this project's own table leaves every other line exactly as it was — which is
// the same rule as the JSON writers, applied to a format that cannot express it
// as cleanly.
func codexWrite(existing []byte, cmd command) ([]byte, error) {
	block := codexBlock(cmd)
	body, _, err := codexStrip(existing)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimRight(string(body), "\n")
	if trimmed == "" {
		return []byte(block), nil
	}
	return []byte(trimmed + "\n\n" + block), nil
}

func codexRemove(existing []byte) ([]byte, bool, error) {
	body, found, err := codexStrip(existing)
	if err != nil {
		return nil, false, err
	}
	return body, found, nil
}

// codexStrip removes this project's table and returns everything else.
func codexStrip(existing []byte) ([]byte, bool, error) {
	lines := strings.Split(string(existing), "\n")
	var out []string
	inOurs, found := false, false
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			// Any new table ends ours. The check is on the exact header rather
			// than a prefix, so a table called mcp_servers.kelyfos-something-else
			// is somebody else's and is left alone.
			inOurs = t == "[mcp_servers."+serverKey+"]"
			if inOurs {
				found = true
			}
		}
		if !inOurs {
			out = append(out, line)
		}
	}
	return []byte(strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n"), found, nil
}

func codexBlock(cmd command) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[mcp_servers.%s]\n", serverKey)
	fmt.Fprintf(&b, "command = %q\n", cmd.Bin)
	quoted := make([]string, len(cmd.Args))
	for i, a := range cmd.Args {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	fmt.Fprintf(&b, "args = [%s]\n", strings.Join(quoted, ", "))
	return b.String()
}

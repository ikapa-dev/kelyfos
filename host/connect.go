package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// `kelyfos connect <client>` — one command instead of a paragraph of JSON
// (P6-13, D41).
//
// Attaching an agent used to be a paragraph of hand-edited configuration per
// client, and every lesson this project paid for lives in the details of that
// paragraph: the policy path explicit rather than discovered (F-D44), the
// surface `serve-mcp` rather than `mcp` (F-D48), the binary named absolutely
// because a non-interactive shell has a minimal PATH. A person copying a snippet
// gets those right by luck.
//
// Four rulings this command makes rather than assumes, as the task required.
//
// **A client that is not installed is a plain failure, not a catalog refusal.**
// The catalog is for things KelyfOS *decided* to deny, and its IDs are part of
// the surface P6-14 freezes — six client-specific IDs would freeze six
// third-party product names into a stable compatibility promise. "You do not
// have Cursor" is a fact about a machine, not a decision about a policy. It gets
// an error with a fix line, which is what it needs.
//
// **The policy path is written absolute, always.** F-D44 and recipe 9 answer
// this differently and D41 settles it: the working-directory and expansion
// matrix is asymmetric across all six clients — Claude Code has no `cwd` field
// at all, Cursor pins with its own workspace variable, Codex and VS Code and
// Gemini document expansion differently or not at all, Junie has neither. Half
// of them would silently attach the wrong policy under a shared snippet, which
// is F-D44's failure once per client. An absolute path cannot be expanded
// wrongly by anybody.
//
// **A file that already holds other servers keeps them.** This repository has no
// precedent — nothing here has ever merged into a file the product did not
// create — so the rule is set here: read, change only KelyfOS's own key, write
// back. Unknown keys at every level survive, because a config file is the user's
// and this command is a guest in it.
//
// **The write is redirectable**, by `KELYFOS_CONNECT_HOME`, because a test that
// wrote into a developer's real `~/.claude.json` would be a test nobody dares
// run — and because somebody generating a configuration for a container has the
// same need.

// connectHome is where per-user configuration lives.
//
// The override exists for tests and for anybody generating a configuration for
// a machine that is not this one. It falls back to the real home, so the common
// case needs nothing.
func connectHome() (string, error) {
	if v := os.Getenv("KELYFOS_CONNECT_HOME"); v != "" {
		return v, nil
	}
	return os.UserHomeDir()
}

// client is one editor or agent this command knows how to configure.
type client struct {
	// Name is what a person types.
	Name string
	// Label is what it is called in the world.
	Label string
	// Verified records the tool and version this writer was checked against,
	// and when. D41 requires it on every supported entry: a client format is an
	// external surface, outside the drift gate and outside the semver promise,
	// and the only honest thing to publish about one is when somebody last
	// looked.
	Verified string
	// Path is where the configuration lives, given the project root and home.
	Path func(project, home string) string
	// Write puts KelyfOS into the file's existing content, preserving
	// everything else. It receives nil when the file does not exist yet.
	Write func(existing []byte, cmd command) ([]byte, error)
	// Remove takes KelyfOS out again, and reports whether anything changed.
	Remove func(existing []byte) ([]byte, bool, error)
}

// command is what every client is being told to run.
type command struct {
	Bin    string
	Args   []string
	Policy string
}

// serverKey is the name KelyfOS goes under in every client's configuration.
const serverKey = "kelyfos"

func connectCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos connect", flag.ExitOnError)
	var (
		remove  = fs.Bool("remove", false, "take KelyfOS out of this client's configuration")
		check   = fs.Bool("check", false, "spawn the server this configuration names and complete a real MCP handshake")
		project = fs.String("project", ".", "the project the configuration is written for")
		policy  = fs.String("policy", "", "the kelyfos.toml to hold the server to (default: the one in the project)")
		binPath = fs.String("bin", "", "the kelyfos binary the client should run (default: this one)")
		list    = fs.Bool("list", false, "list the clients this command knows how to configure")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos connect <client> [flags]

Writes a client's own MCP configuration, in its own format and its own location,
so attaching an agent is one command rather than a paragraph of hand-edited JSON.

The policy path is written absolutely and explicitly: a server that searches for
one can find none and run with no ceiling at all.

`)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), "\nclients:\n")
		for _, c := range clients() {
			fmt.Fprintf(fs.Output(), "  %-12s %s\n", c.Name, c.Label)
		}
		fmt.Fprint(fs.Output(), "  generic      print the snippet for anything else\n")
	}
	args, err := parseAround(fs, argv)
	if err != nil {
		return err
	}
	if *list {
		for _, c := range clients() {
			fmt.Printf("%-12s %-28s %s\n", c.Name, c.Label, c.Verified)
		}
		return nil
	}
	if len(args) != 1 {
		fs.Usage()
		return &exitError{code: 2}
	}
	name := args[0]

	root, err := filepath.Abs(*project)
	if err != nil {
		return err
	}
	cmd, err := serverCommand(root, *policy, *binPath)
	if err != nil {
		return err
	}

	if name == "generic" {
		return printGeneric(cmd)
	}
	c, ok := findClient(name)
	if !ok {
		return fmt.Errorf("kelyfos does not know how to configure %q.\n"+
			"    It writes: %s\n"+
			"    For anything else: kelyfos connect generic — which prints the snippet to paste",
			name, strings.Join(clientNames(), ", "))
	}

	home, err := connectHome()
	if err != nil {
		return err
	}
	path := c.Path(root, home)

	if *remove {
		return removeFrom(c, path, home)
	}
	if err := writeTo(c, path, home, cmd); err != nil {
		return err
	}
	if *check {
		return checkHandshake(cmd)
	}
	fmt.Printf("  check it with: kelyfos connect %s --check\n", name)
	return nil
}

// serverCommand works out what the client should actually run.
//
// Absolute, both of them. A bare `kelyfos` is not on the PATH a client gives a
// server it spawns — a non-interactive shell has a minimal one — and a policy
// found by searching is a policy that can be missing (F-D44).
func serverCommand(project, policy, bin string) (command, error) {
	if bin == "" {
		self, err := os.Executable()
		if err != nil {
			return command{}, err
		}
		bin = self
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		return command{}, err
	}
	if policy == "" {
		policy = filepath.Join(project, "kelyfos.toml")
	}
	policy, err = filepath.Abs(policy)
	if err != nil {
		return command{}, err
	}
	if _, err := os.Stat(policy); err != nil {
		return command{}, fmt.Errorf("no policy at %s.\n"+
			"    A server with no ceiling is not worth attaching: whatever an agent asks for, it gets.\n"+
			"    Write one, or name another with --policy", policy)
	}
	// serve-mcp, not mcp. F-D48 found and fixed that exact mistake once in this
	// repository's own configuration: `mcp` bridges a client to one sandbox's
	// guest, and what a fresh user wants is KelyfOS itself as a server.
	return command{Bin: abs, Args: []string{"serve-mcp", "--policy", policy}, Policy: policy}, nil
}

// underHome decides how a configuration file is protected, and it decides by
// path prefix rather than by client name (P7-17/F5).
//
// Two of the six targets live under $HOME — ~/.codex/config.toml and
// ~/.gemini/settings.json — and both are files that commonly grow credentials
// later. os.WriteFile only applies its perm on creation, so the exposure is the
// case where KelyfOS is the first thing to create the file, which is the common
// case for a fresh setup: the client that later writes an API key into it keeps
// the mode it found. The project-local files (.mcp.json, .cursor/mcp.json,
// .vscode/mcp.json, .junie/mcp/mcp.json) are meant to be committed and shared
// and keep the ordinary umask-derived mode.
//
// By prefix, so a client added to the catalog later inherits the rule without
// anybody remembering to apply it — which is what a rule enforced per name
// would ask for, and what F7 in this same review is about somebody forgetting.
func underHome(path, home string) bool {
	if home == "" {
		return false
	}
	// Resolved on both sides before the comparison (P7-17/F5, second review
	// round). A textual prefix is walked around by a symlink — a project's
	// .cursor pointing into $HOME, which is how somebody shares one MCP
	// configuration across checkouts — and the file that lands there is the
	// one that grows an API key. It is the same lesson F18 taught the
	// extractor and F21's two scope rules already apply.
	//
	// The leaf need not exist yet, so the deepest ancestor that does is what
	// gets resolved.
	return insideTree(home, resolvePath(path, home))
}

// configModes is the file and directory mode for a path, before the existing
// file is consulted.
func configModes(path, home string) (file, dir os.FileMode) {
	if underHome(path, home) {
		return 0o600, 0o700
	}
	return createMode() & 0o666, 0o777 &^ processUmask()
}

func writeTo(c client, path, home string, cmd command) error {
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Before anything is created or replaced: a file this writer will not
	// rewrite must leave no directory, no temp file and no half-written
	// content behind.
	updated, err := c.Write(existing, cmd)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	mode, dirMode := configModes(path, home)
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return err
	}
	if err := writeConfigAtomic(path, updated, mode); err != nil {
		return err
	}
	verb := "wrote"
	if len(existing) > 0 {
		verb = "updated"
	}
	fmt.Printf("%s %s\n", verb, path)
	fmt.Printf("  %s %s\n", cmd.Bin, strings.Join(cmd.Args, " "))
	return nil
}

// writeConfigAtomic replaces path with body, through a sibling temp file, an
// fsync and a rename — the pattern host/log.go's exports already use
// (atomicWriteReport), for a stronger reason here: this is a read-modify-write
// of a file another program may be editing at the same moment, and a rename is
// the only atomic replacement available. A partial write over a client's
// configuration is not a lost KelyfOS entry, it is a client that no longer
// starts.
//
// The mode is the stricter of what the caller asked for and what the file
// already has. Somebody who tightened their own configuration, or a client that
// created it 0600 itself, must not have that undone by `kelyfos connect` —
// this command is a guest in that file, which is the same rule the JSON writers
// already follow for its contents.
func writeConfigAtomic(path string, body []byte, mode os.FileMode) error {
	if fi, err := os.Stat(path); err == nil {
		mode &= fi.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".kelyfos-connect-*")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		_ = os.Remove(tmp.Name()) // a no-op once the rename has happened
	}()
	if _, err := tmp.Write(body); err != nil {
		return err
	}
	// Before the rename, not after: a rename is atomic with respect to a
	// reader, not with respect to a power cut, and a configuration file that
	// comes back as zero bytes is a client that no longer starts.
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// os.CreateTemp makes a 0600 file and a rename carries that mode with it,
	// so a project-local file needs this to be readable at all.
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	// And the DIRECTORY, because the rename is a directory operation and
	// fsyncing the file does not commit it (P7-17/F5, second review round).
	// Without this the comment above claimed a durability the code did not
	// provide: the old file survives either way, so nothing was ever lost —
	// but a comment that overstates is how the next reader stops checking.
	// Best-effort: some filesystems refuse to sync a directory, and failing a
	// write that has already landed would be the worse answer.
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func removeFrom(c client, path, home string) error {
	existing, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Printf("%s does not exist; nothing to remove\n", path)
		return nil
	}
	if err != nil {
		return err
	}
	updated, changed, err := c.Remove(existing)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if !changed {
		fmt.Printf("%s does not mention kelyfos; nothing to remove\n", path)
		return nil
	}
	mode, _ := configModes(path, home)
	if err := writeConfigAtomic(path, updated, mode); err != nil {
		return err
	}
	fmt.Printf("removed kelyfos from %s\n", path)
	return nil
}

func findClient(name string) (client, bool) {
	for _, c := range clients() {
		if c.Name == name {
			return c, true
		}
	}
	return client{}, false
}

func clientNames() []string {
	var out []string
	for _, c := range clients() {
		out = append(out, c.Name)
	}
	sort.Strings(out)
	return out
}

func printGeneric(cmd command) error {
	body, err := json.MarshalIndent(map[string]any{
		"mcpServers": map[string]any{
			serverKey: map[string]any{"command": cmd.Bin, "args": cmd.Args},
		},
	}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println("Most MCP clients take a block of this shape. The key is usually `mcpServers`;")
	fmt.Println("VS Code calls it `servers`, and Codex uses TOML with `mcp_servers`.")
	fmt.Println()
	fmt.Println(string(body))
	fmt.Println()
	fmt.Println("Both paths are absolute on purpose. A bare `kelyfos` is not on the PATH a")
	fmt.Println("client gives a server it spawns, and a policy found by searching is a policy")
	fmt.Println("that can be missing — which means a sandbox with no ceiling at all.")
	return nil
}

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
		return removeFrom(c, path, root, home)
	}
	if err := writeTo(c, path, root, home, cmd); err != nil {
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
	// BOTH readings, and the stricter answer wins (P7-17/B1).
	//
	// Resolved: a textual prefix is walked around by a symlink — a project's
	// .cursor pointing into $HOME, which is how somebody shares one MCP
	// configuration across checkouts — and the file that lands there is the one
	// that grows an API key. That was F5's second review round, and it is the
	// same lesson F18 taught the extractor and F21's two scope rules already
	// apply. The leaf need not exist yet, so the deepest ancestor that does is
	// what gets resolved.
	//
	// Literal: and resolving ALONE inverted the finding. A dotfiles-managed
	// ~/.codex/config.toml is a link out of $HOME — that is what stow and
	// chezmoi do — so the resolved path is outside, the file was judged
	// project-local, and it got 0644 at the one path F5 exists to protect. The
	// name the user gave is a fact about intent that resolution throws away.
	//
	// Neither reading is a superset of the other, so the file is home-scoped if
	// either says so. That is the same "never widen" rule writeConfigAtomic
	// already applies to a mode it finds.
	//
	// The literal reading is answered LEXICALLY, on both sides (P7-17/B1,
	// review round). insideTree resolves its root and not its path, which is
	// right for a path that has already been resolved and wrong for one that
	// deliberately has not: with $HOME itself behind a symlink — /home on a
	// mounted volume, or a KELYFOS_CONNECT_HOME pointed through one — it
	// compared a resolved root against an unresolved path and answered false,
	// so the whole literal half quietly stopped working on exactly the layouts
	// where it is hardest to notice.
	if lexicallyInside(home, litAbs(path, home)) {
		return true
	}
	return insideTree(home, resolvePath(path, home))
}

// litAbs is the path as written, made absolute and lexically cleaned, with no
// symlink followed. resolvePath's own base handling, minus the resolution.
func litAbs(p, root string) string {
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	return filepath.Clean(p)
}

// lexicallyInside is insideTree with neither side resolved: purely about the
// names. It exists so that "the path the user wrote" can be judged as the
// string the user wrote, which is the whole point of asking that question
// separately from where it resolves to.
func lexicallyInside(root, p string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// maxConfigLinkHops is how many links resolveLeafLink will follow. Real
// dotfiles managers make one and occasionally two; past this it is a loop or an
// attempt at one, and a refusal is the right answer either way. The number is
// the same order as the kernel's own 40 and deliberately smaller: this walk
// exists to find a file a person meant to edit, not to survive an adversary.
//
// It is a count of LINKS FOLLOWED and the loop is written so that it is
// (P7-17/B1, review round). The first version was `hop < maxConfigLinkHops`
// around a body that follows one link and then fell through to the error, so N
// permitted N−1: a chain of exactly eight was refused by a message that said
// "more than eight", and both docs/integrating.md and the commit message
// repeated the wrong boundary. It also refused chains the kernel resolves
// happily, which is a capability regression against the os.WriteFile behaviour
// this is restoring.
const maxConfigLinkHops = 8

// resolveLeafLink is the file a write has to land on: what a leaf symlink
// names, or the path itself when it is not one (P7-17/B1).
//
// Readlink rather than filepath.EvalSymlinks, for two reasons that both matter
// here. EvalSymlinks refuses a DANGLING link — and a dangling
// ~/.codex/config.toml pointing into a dotfiles repository that has not been
// cloned yet is exactly the state `kelyfos connect` should write into, creating
// the target. And EvalSymlinks resolves every component, which would relocate a
// write that only ever needed its last name followed.
func resolveLeafLink(path string) (string, error) {
	seen := path
	// <= so that maxConfigLinkHops links are followed and the (N+1)th is what
	// is refused, which is what the constant and the message both say.
	for hop := 0; hop <= maxConfigLinkHops; hop++ {
		fi, err := os.Lstat(path)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			// Not there, or not a link. Either way this is where the write goes;
			// an unreadable path is the caller's error to report, with its own
			// message, from the write itself.
			return path, nil
		}
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		path = filepath.Clean(target)
	}
	return "", fmt.Errorf("%s is a symlink chain more than %d links deep, so kelyfos will not "+
		"guess which file you meant.\n"+
		"    That is either a loop or something a configuration file should not be. Point the\n"+
		"    link at the file, or write to the file directly", seen, maxConfigLinkHops)
}

// configModes is the file and directory mode for a path, before the existing
// file is consulted.
//
// THREE readings, not two (P7-17/B1, review round): the name as written, the
// name resolved, and the destination the write actually lands on. The strictest
// wins. The third is the one the review found missing, and it is F5's own hole
// reached through the write-through B1 adds: a project-local path that is a
// DANGLING link into $HOME cannot be resolved, so resolvePath falls back to the
// deepest existing ancestor — the project — and both of the first two readings
// answer "project-local" while the file is created under $HOME at 0644. A
// dangling link is not an edge case here; it is the state B1 deliberately added
// support for.
func configModes(path, dest, home string) (file, dir os.FileMode) {
	if underHome(path, home) || underHome(dest, home) {
		return 0o600, 0o700
	}
	return createMode() & 0o666, 0o777 &^ processUmask()
}

func writeTo(c client, path, project, home string, cmd command) error {
	// The destination first, before anything is read or created (P7-17/B1,
	// review round). Three things depend on knowing it this early: the scope
	// rule below refuses on it, configModes reads it, and the loop refusal in
	// resolveLeafLink is only reachable at all if it runs before the
	// os.ReadFile — a genuine cycle returns ELOOP from the kernel, and the
	// carefully written message never got a chance to say anything.
	dest, err := resolveLeafLink(path)
	if err != nil {
		return err
	}
	if err := checkConfigScope(path, dest, project, home); err != nil {
		return err
	}

	existing, err := os.ReadFile(dest)
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
	mode, dirMode := configModes(path, dest, home)
	// The DESTINATION's directory, and it is resolved too. Making the named
	// path's parent is what the ordinary case needs and it is not enough for
	// the case B1 exists for: `~/.codex` may itself be a dangling link into a
	// dotfiles repository that has not been cloned — stow's default is to fold
	// the tree and link the directory rather than the file — and MkdirAll on a
	// dangling symlink fails with "file exists" while MkdirAll on a target
	// nobody created fails with "no such file or directory". Both were
	// reachable, and both were the scenario the commit message described as
	// working.
	destDir, err := resolveLeafLink(filepath.Dir(dest))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destDir, dirMode); err != nil {
		return err
	}
	if err := writeConfigAtomic(dest, destDir, updated, mode); err != nil {
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

// checkConfigScope refuses a project-local configuration path whose leaf
// symlink lands outside both the project and the user's home (D75, P7-17/B1,
// review round).
//
// B1 makes `kelyfos connect` follow a leaf symlink again, which is right for a
// dotfiles-managed file and wrong for a file a REPOSITORY chose. Four of the
// six clients write a project-local path — .mcp.json, .cursor/mcp.json,
// .vscode/mcp.json, .junie/mcp/mcp.json — and any of those can be committed as
// a symlink. Following it then puts the write wherever the repository pointed,
// which is the property docs/threat-model.md states as "reading a stranger's
// project should not be able to break the tool that is supposed to contain it".
// It is the same shape F21 already refuses for a [[plugin]] path, whose own
// test is named TestF21_ASymlinkOutOfTheTreeDoesNotGetAPluginIn.
//
// Narrow on purpose, and D75 has the argument. A path the operator named under
// their OWN home may resolve anywhere: $HOME is theirs, a dotfiles repository
// at /srv/dotfiles is an ordinary layout, and nobody else planted that link.
// Only the project-local half is bounded, and it is bounded to the two places
// the operator is answering for.
//
// No escape hatch, and none is needed: the two answers that work take no flag.
func checkConfigScope(path, dest, project, home string) error {
	if path == dest {
		return nil // not a link; there is nothing to have been redirected
	}
	if underHome(path, home) {
		return nil // the operator's own home, and their own link
	}
	if underHome(dest, home) || lexicallyInside(project, dest) ||
		insideTree(project, resolvePath(dest, project)) {
		return nil
	}
	return fmt.Errorf("%s is a symlink to %s, which is outside both this project (%s) and your "+
		"home directory.\n"+
		"    kelyfos connect follows a symlink so that a dotfiles-managed configuration keeps\n"+
		"    working, and a project-local file is one a repository can choose. Writing through\n"+
		"    this one would put the entry somewhere neither you nor this project describes.\n"+
		"    Point the link inside the project or inside your home directory, or remove it and\n"+
		"    let kelyfos write the file itself", path, dest, project)
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
//
// One limit on that phrase, stated rather than left to be discovered: a rename
// needs write permission on the DIRECTORY, not on the file, so a target the
// operator deliberately made read-only is replaced anyway and comes back at the
// mode it had. os.WriteFile refused that; the atomic replacement F5 introduced
// does not, for plain paths since F5 and now across a symlink too. Kept, because
// the alternative — refusing to update a configuration whose file bit says
// read-only while its directory says otherwise — is a refusal nobody would be
// able to act on, and the mode the file comes back with is its own.
// path is the DESTINATION — already resolved through any leaf symlink by the
// caller — and dir is the directory the temp file is made in, which is that
// destination's own directory and is likewise already resolved.
//
// Through a leaf symlink rather than over it (P7-17/B1). The os.WriteFile this
// replaced followed one; a rename does not, so moving to a rename silently
// changed the answer for every dotfiles-managed configuration — a
// ~/.codex/config.toml that stow or chezmoi links into a repository was
// replaced by a plain file, the repository copy stopped being what the client
// reads, and the next `stow -R` would put the link back over the entry
// `kelyfos connect` had just written.
//
// The resolution moved OUT of this function to writeTo in the review round, so
// that one destination is computed once and the mode rule, the scope rule and
// the write all agree about it. Two places resolving the same path separately
// is how they end up disagreeing, which is what the review found: the mode was
// decided on the name and the write landed on the target.
func writeConfigAtomic(path, dir string, body []byte, mode os.FileMode) error {
	if fi, err := os.Stat(path); err == nil {
		mode &= fi.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".kelyfos-connect-*")
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
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func removeFrom(c client, path, project, home string) error {
	// The same resolution and the same scope rule the write takes, because
	// --remove is a write: it rewrites the file without the kelyfos entry.
	dest, err := resolveLeafLink(path)
	if err != nil {
		return err
	}
	if err := checkConfigScope(path, dest, project, home); err != nil {
		return err
	}
	existing, err := os.ReadFile(dest)
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
	mode, _ := configModes(path, dest, home)
	if err := writeConfigAtomic(dest, filepath.Dir(dest), updated, mode); err != nil {
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

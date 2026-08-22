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
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	// ResLine records where each [resources] key was written, so a refusal can
	// name the line the ceiling came from instead of just the number.
	ResLine map[string]int

	// Path is where this was read from, for error messages that say which file
	// is wrong.
	Path string
}

// Find walks up from a directory looking for a policy file, so running kelyfos
// from a subdirectory of a project behaves the way git does.
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
// The parser is deliberately small: this is a flat table of scalars and string
// arrays, and a whole TOML library would be a dependency carried for a file
// format that a project is expected to read at a glance. Anything it does not
// understand is an error naming the line, not a silent skip — a policy file
// with a typo that quietly does nothing is worse than one that refuses.
func Load(path string) (*Config, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{Path: path, ResLine: map[string]int{}}
	section := ""

	for n, raw := range strings.Split(string(blob), "\n") {
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		where := fmt.Sprintf("%s:%d", path, n+1)

		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("%s: unterminated section header", where)
			}
			section = strings.Trim(line, "[]")
			if section != "sandbox" && section != "resources" {
				return nil, fmt.Errorf("%s: unknown section [%s]; only [sandbox] and [resources] are understood", where, section)
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s: expected key = value", where)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		// [resources] keys are kept separate from [sandbox] so a typo in one
		// section cannot silently satisfy the other.
		if section == "resources" {
			cfg.ResLine[key] = n + 1
			switch key {
			case "cpus":
				cfg.ResCPUs, err = parseInt(value, where)
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
			case "max_runtime", "idle_timeout":
				// Specified in docs/resources.md but not yet enforced. Refusing
				// beats accepting: a limit that silently does nothing is worse
				// than no limit, because you believe you have one.
				return nil, fmt.Errorf("%s: [resources] %s is specified but not enforced yet (%s) — "+
					"remove it rather than rely on a limit that would not hold; see docs/resources.md",
					where, key, landsIn[key])
			default:
				return nil, fmt.Errorf("%s: unknown key %q in [resources]", where, key)
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
		default:
			return nil, fmt.Errorf("%s: unknown key %q", where, key)
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
	for _, part := range strings.Split(inner, ",") {
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

// landsIn names the task each specified-but-unenforced key is waiting on, so
// the refusal tells you when to expect it rather than just saying no.
var landsIn = map[string]string{
	"max_runtime":  "E1-6, the time budgets",
	"idle_timeout": "E1-6, the time budgets",
}

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

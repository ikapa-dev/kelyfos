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
	cfg := &Config{Path: path}
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
			if section != "sandbox" {
				return nil, fmt.Errorf("%s: unknown section [%s]; only [sandbox] is understood", where, section)
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s: expected key = value", where)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

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

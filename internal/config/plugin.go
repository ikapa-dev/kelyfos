package config

import (
	"fmt"
	"regexp"
)

// Plugin is one [[plugin]] entry: an MCP server that runs inside the guest,
// launched by the supervisor from a read-only device (E4-6, F-D6).
//
// The declaration is deliberately thin. There is no `allow`, and asking for one
// is asking for a second door in a wall whose whole value is having one: a
// plugin has exactly the powers of a malicious agent, and the per-agent
// allowlist is the single network policy surface (docs/mcp-surface.md §3.1).
type Plugin struct {
	Name string
	// Path is the host directory packed into the plugins image, relative to
	// the policy file rather than to whatever directory a command was run from.
	Path    string
	Command string
	Args    []string
	Line    int
}

// pluginName is the constraint that makes <plugin>_<tool> unambiguous.
//
// Lowercase, no underscore and no dot, so the plugin half of a namespaced tool
// name cannot contain the separator and cannot collide with another plugin's
// after a client rewrites it. F-D36 has the whole argument; the short version
// is that a dot is legal in MCP and rejected downstream, and the rewriting that
// follows is silent and collides.
var pluginName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// pluginNameMax leaves room for the tool half. The strictest downstream limit
// on a whole tool name is 64 characters, and a prefix that used most of it
// would make perfectly reasonable tool names unadvertisable.
const pluginNameMax = 24

func (c *Config) pluginKey(key, value, where string) error {
	p := &c.Plugins[len(c.Plugins)-1]
	var err error
	switch key {
	case "name":
		p.Name, err = parseString(value, where)
		if err != nil {
			return err
		}
		if !pluginName.MatchString(p.Name) {
			return fmt.Errorf("%s: plugin name %q must be lowercase letters, digits and dashes, "+
				"starting with a letter.\n"+
				"    the name is the prefix of every tool this plugin advertises, as "+
				"<name>_<tool>, so it may not contain the separator itself", where, p.Name)
		}
		if len(p.Name) > pluginNameMax {
			return fmt.Errorf("%s: plugin name %q is %d characters, over the %d this allows — "+
				"the whole of <name>_<tool> has to fit in 64 for the strictest client",
				where, p.Name, len(p.Name), pluginNameMax)
		}
	case "path":
		p.Path, err = parseString(value, where)
	case "command":
		p.Command, err = parseString(value, where)
	case "args":
		p.Args, err = parseArray(value, where)
	default:
		return unknownKey(where, key, "plugin")
	}
	return err
}

// CheckPlugins is the whole-file check: what a single key cannot see.
//
// Called by whoever is about to build the plugins image, rather than by the
// parser, for the reason F-D16 gives — the parser stays small and the checks
// that need the finished document live where the document is finished.
func (c *Config) CheckPlugins() error {
	seen := map[string]int{}
	for i := range c.Plugins {
		p := &c.Plugins[i]
		switch {
		case p.Name == "":
			return fmt.Errorf("%s:%d: this [[plugin]] has no name, and the name is what its tools "+
				"are called", c.Path, p.Line)
		case p.Path == "":
			return fmt.Errorf("%s:%d: plugin %q has no path, and there is nothing to pack without "+
				"one", c.Path, p.Line, p.Name)
		case p.Command == "":
			return fmt.Errorf("%s:%d: plugin %q has no command, so nothing would be launched",
				c.Path, p.Line, p.Name)
		}
		if first, ok := seen[p.Name]; ok {
			return fmt.Errorf("%s:%d: a second plugin is also called %q, first declared at line %d. "+
				"Two plugins with one name would advertise the same tools and the agent could not "+
				"tell them apart", c.Path, p.Line, p.Name, first)
		}
		seen[p.Name] = p.Line
	}
	return nil
}

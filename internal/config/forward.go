package config

import "fmt"

// Forward is one [[forward]] entry: a host port carried to a guest-local port
// (E5-5, docs/qol.md §4).
//
// There is no `bind` key here, and its absence is the design rather than an
// omission. A forward binds the host's loopback; exposing one to the LAN is
// `--p-bind`, a thing somebody types in the session where it happens, because a
// line in a committed file is exactly how a machine ends up answering the
// network on behalf of someone who inherited the repository and never read it.
type Forward struct {
	Host  int
	Guest int
	Line  int
}

func (c *Config) forwardKey(key, value, where string) error {
	f := &c.Forwards[len(c.Forwards)-1]
	switch key {
	case "host":
		n, err := parsePort(value, where, key)
		if err != nil {
			return err
		}
		f.Host = n
	case "guest":
		n, err := parsePort(value, where, key)
		if err != nil {
			return err
		}
		f.Guest = n
	default:
		return unknownKey(where, key, "forward")
	}
	return nil
}

func parsePort(value, where, key string) (int, error) {
	n, err := parseRate(value, where, key)
	if err != nil {
		return 0, err
	}
	if n > 65535 {
		return 0, fmt.Errorf("%s: %s = %d is not a port number", where, key, n)
	}
	return n, nil
}

// CheckForwards is the whole-file check: what a single key cannot see.
//
// Called by whoever is about to bind the listeners rather than by the parser,
// which is where CheckPlugins is called and for the same reason (F-D16): the
// parser stays small, and a check that needs the finished document lives where
// the document is finished.
//
// An incomplete pair and a doubly-claimed host port are both refused rather
// than resolved. Two entries claiming host port 8080 have no correct
// interpretation — one of them was meant to be something else — and picking one
// would turn a typo into a forward that silently goes to the wrong place.
func (c *Config) CheckForwards() error {
	seen := map[int]int{}
	for _, f := range c.Forwards {
		switch {
		case f.Host == 0 && f.Guest == 0:
			return fmt.Errorf("%s:%d: a [[forward]] with neither host nor guest forwards nothing",
				c.Path, f.Line)
		case f.Host == 0:
			return fmt.Errorf("%s:%d: [[forward]] guest = %d has no host port to answer on",
				c.Path, f.Line, f.Guest)
		case f.Guest == 0:
			return fmt.Errorf("%s:%d: [[forward]] host = %d has no guest port to carry to",
				c.Path, f.Line, f.Host)
		}
		if prev, ok := seen[f.Host]; ok {
			return fmt.Errorf("%s:%d: host port %d is already forwarded at line %d; "+
				"one host port carries one guest port", c.Path, f.Line, f.Host, prev)
		}
		seen[f.Host] = f.Line
	}
	return nil
}

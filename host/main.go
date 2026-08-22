// Command kelyfos is the KelyfOS host CLI: it builds Firecracker
// configurations, boots and tears down microVMs, and talks to the supervisor
// inside them over the channels defined in docs/protocol.md.
package main

import (
	"errors"
	"fmt"
	"os"
)

// Version is stamped at build time; the zero value is honest about being a
// development build rather than claiming a release number.
var Version = "dev"

const usage = `kelyfos — a minimal, agent-native guest OS for microVM sandboxes

usage:
  kelyfos run [flags]              boot a sandbox and keep it running
  kelyfos exec [flags] <command>   run a command inside a running sandbox
  kelyfos mcp [flags]              bridge an MCP client's stdio to a sandbox
  kelyfos log [flags]              replay, follow or verify a session's record
  kelyfos bench [flags]            measure cold boot-to-ready over several runs
  kelyfos version

Run a subcommand with -h for its flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = runCmd(os.Args[2:])
	case "exec":
		err = execCmd(os.Args[2:])
	case "mcp":
		err = mcpCmd(os.Args[2:])
	case "log":
		err = logCmd(os.Args[2:])
	case "bench":
		err = benchCmd(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("kelyfos %s\n", Version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		// A command that ran and failed inside the guest is not a kelyfos
		// failure: pass its status through instead of flattening it to 1.
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		fmt.Fprintf(os.Stderr, "kelyfos: %v\n", err)
		os.Exit(1)
	}
}

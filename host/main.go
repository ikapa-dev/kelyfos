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
  kelyfos doctor                   check this machine can run KelyfOS
  kelyfos run [flags]              boot a sandbox and keep it running
  kelyfos exec [flags] <command>   run a command inside a running sandbox
  kelyfos mcp [flags]              bridge an MCP client's stdio to a sandbox
  kelyfos serve-mcp [flags]        serve KelyfOS itself as an MCP server
  kelyfos snapshot save|restore    save a sandbox's state, or bring it back
  kelyfos pause --as <name>        freeze a running sandbox under a name
  kelyfos resume <name>            bring a paused session back
  kelyfos sessions [rm <name>]     list paused sessions; rm, prune or erase one (-h on each for more)
  kelyfos diff [flags]             what a sandbox has done to its workspace
  kelyfos shell [flags]            an interactive terminal inside a sandbox
  kelyfos fork [flags]             restore one snapshot into several sandboxes
  kelyfos team up|ps|down|graph    run several agents with the paths between
                                   them written down and enforced, and inspect
                                   that topology with or without booting it
  kelyfos shim [flags]             serve an E2B-compatible REST subset
  kelyfos runs [flags]             what has run here, from the records themselves
  kelyfos rerun <id>               run a recorded session again, under its own policy
  kelyfos log [flags]              replay, follow (-f) or verify a session's record
                                   (kelyfos logs is the same command)
  kelyfos verify <file>            check the record an exported report carries,
                                   offline and with no key
  kelyfos connect <client>         write a client's own MCP configuration, and
                                   check it by starting the server it names
  kelyfos watch [flags]            live view of a sandbox (reads the record only)
  kelyfos bench [flags]            measure cold boot-to-ready over several runs
  kelyfos version                  print the version and exit
  kelyfos help                     print this list

Run a subcommand with -h for its flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	// A command that cannot work on this operating system says so here, once,
	// rather than in whatever it reaches for first (P6-12).
	if err := runsHere(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "doctor":
		err = doctorCmd(os.Args[2:])
	case "run":
		err = runCmd(os.Args[2:])
	case "exec":
		err = execCmd(os.Args[2:])
	case "mcp":
		err = mcpCmd(os.Args[2:])
	case "serve-mcp":
		err = serveMCPCmd(os.Args[2:])
	case "shell":
		err = shellCmd(os.Args[2:])
	case "diff":
		err = diffCmd(os.Args[2:])
	case "pause":
		err = pauseCmd(os.Args[2:])
	case "resume":
		err = resumeCmd(os.Args[2:])
	case "sessions":
		err = sessionsCmd(os.Args[2:])
	case "snapshot":
		err = snapshotCmd(os.Args[2:])
	case "fork":
		err = forkCmd(os.Args[2:])
	case "shim":
		err = shimCmd(os.Args[2:])
	case "runs":
		err = runsCmd(os.Args[2:])
	case "rerun":
		err = rerunCmd(os.Args[2:])
	// `logs` is `log`, because both names get typed and neither should be an
	// unknown command. One implementation, so the two cannot behave differently.
	case "log", "logs":
		err = logCmd(os.Args[2:])
	case "verify":
		err = verifyCmd(os.Args[2:])
	case "connect":
		err = connectCmd(os.Args[2:])
	case "team":
		err = teamCmd(os.Args[2:])
	case "watch":
		err = watchCmd(os.Args[2:])
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

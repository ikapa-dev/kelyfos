package main

import "flag"

// parseAround takes flags on either side of the positional arguments.
//
// Go's flag package stops at the first thing that is not a flag, so
// `kelyfos connect cursor --project .` puts `--project .` in the positionals and
// prints usage — and that is the order a person types, because the noun the
// command is about comes first. Parsing what is left after each positional
// accepts both orders without teaching the rest of the CLI a new convention.
//
// It lives here because two commands need it and a second copy of an argument
// parser is how two commands come to disagree about their own arguments — which
// this project has already found once, in the MCP argument summarisers.
func parseAround(fs *flag.FlagSet, argv []string) ([]string, error) {
	var positional []string
	rest := argv
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
}

package sandbox

import (
	"fmt"
	"os"
)

// warnf says something on the terminal that the caller did not ask about.
//
// This package does not otherwise print: the CLI owns what a person sees, and a
// library that writes to a terminal is a library that cannot be embedded. The
// exception is narrow and deliberate. A restored machine's confinement is a
// property of the snapshot, not of the command, and five commands restore
// snapshots — so the alternative is five call sites that each have to remember
// to check and to word it the same way, which is the shape P5-1 already got
// wrong once with session.start's jailed field.
//
// Everything here is a warning about a weaker posture than the default. It is
// never used for progress, and never for anything a caller could have asked
// for.
func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "kelyfos: "+format+"\n", args...)
}

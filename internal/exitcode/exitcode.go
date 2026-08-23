// Package exitcode is the CLI's exit statuses, in one place, with what each one
// means.
//
// It exists so the generated reference (E3-1) has a source that the CLI itself
// depends on. A table of exit codes maintained beside the code that returns them
// is a table that goes stale; this one is the code that returns them.
//
// The values are shell convention rather than a private numbering, so a script
// wrapping kelyfos can branch on them the way it already branches on timeout(1)
// and a missing binary.
package exitcode

const (
	// OK is success.
	OK = 0

	// Fail is any kelyfos-level error, printed as "kelyfos: <err>".
	Fail = 1

	// Usage is a missing or unknown subcommand, or a bad flag. Go's flag package
	// uses the same value, so the two cannot disagree.
	Usage = 2

	// TimedOut is timeout(1)'s status, for the same meaning: --max-runtime or
	// --idle-timeout fired, or a guest command exceeded its --timeout.
	TimedOut = 124

	// NotExecutable is the shell's status for a command that was found and could
	// not be run.
	NotExecutable = 126

	// NotFound is the shell's status for a command that does not exist.
	NotFound = 127

	// OOMKilled is 128 + SIGKILL: the guest's OOM killer ran during this
	// sandbox's life. It is returned even when the command itself exited 0,
	// because a run in which something was killed for memory is not a clean run.
	OOMKilled = 137
)

// Code is one exit status and what it tells the person reading it.
type Code struct {
	Code int
	Doc  string
}

// All is every status kelyfos returns on its own behalf, lowest first. A guest
// command's own status passes through unchanged and is therefore not listed:
// `kelyfos exec` exits with what ran inside, which is the point of it.
func All() []Code {
	return []Code{
		{OK, "success"},
		{Fail, "a kelyfos error, printed as `kelyfos: <message>`; also a failed `doctor` check and a broken chain from `log --verify`"},
		{Usage, "no subcommand, an unknown subcommand, or a bad flag"},
		{TimedOut, "a time budget expired — `--max-runtime`, `--idle-timeout`, or `exec --timeout`. Same as timeout(1)"},
		{NotExecutable, "the command was found in the guest and could not be executed"},
		{NotFound, "the command does not exist in the guest"},
		{OOMKilled, "the guest's OOM killer ran during this sandbox's life (128 + SIGKILL)"},
	}
}

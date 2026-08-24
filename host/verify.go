package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/report"
)

// verifyCmd checks a file somebody sent you.
//
// Every other command here works on this machine's own sessions, found by id
// under the cache directory. This one takes a path, because the reader it
// exists for is not the person who made the file: it is whoever received it.
// So it never looks at the cache, never asks which session, and needs nothing
// on this machine to have run — no sandbox, no daemon, no key, no network, no
// trust root of ours. Offline is not a feature of this command, it is the only
// mode it has.
func verifyCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos verify", flag.ExitOnError)
	var (
		replay = fs.Bool("replay", false, "print the session from the record it carries, rather than only checking it")
		asJSON = fs.Bool("json", false, "print the record's raw events instead of a readable replay (implies --replay)")
		toFile = fs.String("extract", "", "write the record it carries to this path (- for stdout)")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos verify <report.html|events.jsonl>

Re-runs the hash chain over the record a file carries, and reports the first
place it breaks. It reads only that file: no key, no network, no trust root —
what the chain proves, it proves on its own.

An exported report carries the record it was rendered from, so this works on a
report someone sent you as well as on a raw flight recorder. What it checks is
the record. It does not check that the page's timeline was drawn from that
record — for that, compare the page against --replay.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return &exitError{code: 2}
	}
	path := fs.Arg(0)

	blob, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", path, err)
	}
	chain, kind, err := recordIn(blob)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	// `--json` on its own would otherwise be a flag that does nothing, which is
	// the kind of silence this project treats as a defect elsewhere.
	if *asJSON {
		*replay = true
	}

	// Where the human half of this command goes. Whenever stdout is carrying the
	// record itself — `--extract -`, or `--json`, which prints the events as
	// they were written — the prose steps aside, because a reader's
	// `> events.jsonl` would otherwise capture a verdict in the middle of the
	// thing the verdict is about. A summary that corrupts the record it just
	// vouched for is its own kind of wrong answer.
	out := os.Stdout
	if *toFile == "-" || *asJSON {
		out = os.Stderr
	}

	if *toFile != "" {
		if *toFile == "-" {
			if _, err := os.Stdout.Write(chain); err != nil {
				return err
			}
		} else if err := os.WriteFile(*toFile, chain, 0o600); err != nil {
			return err
		} else {
			fmt.Fprintf(out, "wrote %s (%d bytes)\n", *toFile, len(chain))
		}
	}

	n, head, verifyErr := recorder.Verify(bytes.NewReader(chain))
	if verifyErr != nil {
		fmt.Fprintf(out, "%s: FAILED after %d events\n  %v\n", path, n, verifyErr)
		return &exitError{code: 1}
	}
	if n == 0 {
		// An empty chain verifies the way an empty file does, which is to say
		// it says nothing. Reporting "intact" here would let a file with the
		// evidence removed pass as a file that was checked.
		fmt.Fprintf(out, "%s: the record it carries is empty — nothing to verify\n", path)
		return &exitError{code: 1}
	}
	fmt.Fprintf(out, "%s: chain intact, %d events verified\n", path, n)
	fmt.Fprintf(out, "  chain head %s\n", head)
	fmt.Fprintf(out, "  %s\n", kind)
	fmt.Fprintf(out, "  this checks the record, not how any page rendered it — kelyfos verify --replay %s prints the record's own account\n", path)

	if *replay {
		if out == os.Stdout {
			fmt.Println()
		}
		return replayRecord(chain, *asJSON)
	}
	return nil
}

// recordIn finds the flight recorder in whatever the reader was sent.
//
// Two shapes, told apart by what they are rather than by their file extension:
// a flight recorder is newline-delimited JSON and begins with `{`, and an
// exported report carries one embedded. Anything else is refused by name — a
// reader who points this at the wrong file needs to be told that, not told
// their audit trail failed to verify.
func recordIn(blob []byte) (chain []byte, kind string, err error) {
	if bytes.HasPrefix(bytes.TrimLeft(blob, " \t\r\n"), []byte("{")) {
		return blob, "read from this file, which is a flight recorder itself", nil
	}
	chain, err = report.ExtractChain(blob)
	switch {
	case errors.Is(err, report.ErrNoChain):
		// Both directions, because a wrong guess here is what sends somebody
		// looking for a tampered record that does not exist. An export from
		// before v1.0 carried no record at all; one from a later KelyfOS may
		// carry it under a marker this build does not know, and the honest
		// answer to both is the same: this build cannot find a record in this
		// file, rather than this file is bad.
		return nil, "", errors.New("no KelyfOS record in this file: it is not a flight recorder, and not an" +
			" export carrying one. Exports written before v1.0 embed no record; one written by a newer" +
			" KelyfOS may embed it differently. `kelyfos log --verify` on the machine that ran the session" +
			" checks the record itself")
	case err != nil:
		return nil, "", err
	}
	return chain, "read out of the record this report carries", nil
}

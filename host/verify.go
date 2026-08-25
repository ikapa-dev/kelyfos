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
		anchor = fs.String("key", "", "check the signature against this ed25519 public key (a PEM file, or the key in hex)")
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

A signed report says who exported it, and that is worth exactly what knowing the
key is worth: --key checks the signature against one you already hold, rather
than against the one the file supplied itself.

`)
		fs.PrintDefaults()
	}
	// Flags on either side of the path — `kelyfos verify report.html --key k` is
	// the order a person types (flags.go).
	paths, err := parseAround(fs, argv)
	if err != nil {
		return err
	}
	if len(paths) != 1 {
		fs.Usage()
		return &exitError{code: 2}
	}
	path := paths[0]

	blob, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", path, err)
	}
	chain, kind, fromReport, err := recordIn(blob)
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

	n, head, verifyErr := verifiedChain(chain)
	if verifyErr != nil {
		fmt.Fprintf(out, "%s: FAILED after %d events\n  %v\n", path, n, verifyErr)
		return &exitError{code: 1}
	}
	fmt.Fprintf(out, "%s: chain intact, %d events verified\n", path, n)
	fmt.Fprintf(out, "  chain head %s\n", head)
	fmt.Fprintf(out, "  %s\n", kind)

	// Whether the record stops where a finished session stops. Stated as an
	// observation and never as a verdict: a record with no session.end is a
	// session that is still open just as often as it is one that was cut short,
	// and the chain cannot tell those apart. Saying which of the two it is would
	// be a policy, and a policy applied to files exported by older builds is an
	// accusation of forgery aimed at ordinary records.
	if !endsCleanly(chain) {
		fmt.Fprintf(out, "  the record has no session.end: either the session was still open, or it was cut short — the chain cannot tell those apart\n")
	}

	// Only a report states anything about the record it carries. A raw flight
	// recorder is the record, says nothing about itself, and is not asked to —
	// checking it against claims it never made would report three mismatches
	// for a file that is simply what it is.
	if !fromReport {
		fmt.Fprintf(out, "  this checks the record — kelyfos verify --replay %s prints its own account\n", path)
		if *replay {
			fmt.Println()
			return replayRecord(chain, *asJSON)
		}
		return nil
	}

	if bad := report.ClaimsIn(blob).Disagree(head, n, chain); len(bad) > 0 {
		for _, b := range bad {
			fmt.Fprintf(out, "  MISMATCH: %s\n", b)
		}
		fmt.Fprintf(out, "  the record in this file is intact; what the page says ABOUT it is not what the record says.\n")
		fmt.Fprintf(out, "  trust the values above, which came from the record, over anything printed on the page.\n")
		return &exitError{code: 1}
	}

	fmt.Fprintf(out, "  the values the page prints about this record agree with it\n")
	if err := reportSignature(out, blob, chain, head, *anchor); err != nil {
		return err
	}
	fmt.Fprintf(out, "  this checks the record and what the page claims about it, not how the page rendered its events — kelyfos verify --replay %s prints the record's own account\n", path)

	if *replay {
		if out == os.Stdout {
			fmt.Println()
		}
		return replayRecord(chain, *asJSON)
	}
	return nil
}

// endsCleanly reports whether the last event is a session.end.
//
// A cut-short chain verifies: nothing after the cut exists to break, so the
// truncated record is byte-for-byte what a shorter session would have written.
// This is the one observable difference between the common truncation and a
// finished session, and it is offered to a reader as an observation to weigh
// rather than as a check to pass.
func endsCleanly(chain []byte) bool {
	events, err := recorder.Read(bytes.NewReader(chain))
	if err != nil || len(events) == 0 {
		return false
	}
	return events[len(events)-1].Type == recorder.TypeSessionEnd
}

// verifiedChain is the walk plus the one rule the walk does not have: a chain
// with no events in it has not been checked, it has been read.
//
// recorder.Verify is right to accept it — nothing in an empty file contradicts
// anything — but "chain intact, 0 events verified" is the sentence a file with
// its evidence removed would like to be met with. Both `kelyfos verify` and
// `kelyfos log --verify` go through here, because the same file must not get
// two different answers depending on which command a person reached for.
func verifiedChain(blob []byte) (events int, head string, err error) {
	n, h, err := recorder.Verify(bytes.NewReader(blob))
	if err != nil {
		return n, "", err
	}
	if n == 0 {
		return 0, "", errors.New("the record is empty — there is nothing here to verify")
	}
	return n, h, nil
}

// reportSignature says who signed a report, in a vocabulary rather than a
// verdict (P6-7).
//
// Four things can be true and they are reported as four things: the chain is
// intact or broken, and the report is unsigned, signed by a key the reader named,
// or signed by a key only the file knows about. The last is the one that has to
// be said carefully. A signature whose key came out of the same file proves that
// whoever made the file had *a* key — which is nothing, unless the reader
// recognises it. Saying "signed" and stopping there is how a signature becomes
// the badge P6-6 removed.
func reportSignature(out *os.File, page, chain []byte, head, anchorArg string) error {
	sig := report.SignatureIn(page)
	if sig.Sig == "" {
		fmt.Fprintf(out, "  this report is not signed, which is not a fault: an unsigned report verifies,"+
			" and the chain proves what it proves either way\n")
		if anchorArg != "" {
			fmt.Fprintf(out, "  MISMATCH: you named a key, and there is no signature here to check against it\n")
			return &exitError{code: 1}
		}
		return nil
	}

	pub, err := sig.Check(chain, head)
	if err != nil {
		fmt.Fprintf(out, "  MISMATCH: %v\n", err)
		fmt.Fprintf(out, "  the record itself is intact; what fails is the claim about who exported it\n")
		return &exitError{code: 1}
	}

	if anchorArg == "" {
		fmt.Fprintf(out, "  signed by %s\n", report.PublicKeyHex(pub))
		fmt.Fprintf(out, "  that key came out of this same file, so it says only that whoever made this file"+
			" had a key. It is worth something once you recognise it: --key checks against one you already hold\n")
		return nil
	}

	want, err := report.LoadAnchorKey(anchorArg)
	if err != nil {
		return err
	}
	if report.PublicKeyHex(want) != report.PublicKeyHex(pub) {
		fmt.Fprintf(out, "  MISMATCH: signed by %s, and you named %s\n",
			report.PublicKeyHex(pub), report.PublicKeyHex(want))
		return &exitError{code: 1}
	}
	fmt.Fprintf(out, "  signed by the key you named (%s)\n", report.PublicKeyHex(pub))
	return nil
}

// recordIn finds the flight recorder in whatever the reader was sent.
//
// Two shapes, told apart by what they are rather than by their file extension:
// a flight recorder is newline-delimited JSON and begins with `{`, and an
// exported report carries one embedded. Anything else is refused by name — a
// reader who points this at the wrong file needs to be told that, not told
// their audit trail failed to verify.
func recordIn(blob []byte) (chain []byte, kind string, fromReport bool, err error) {
	trimmed := bytes.TrimLeft(blob, " \t\r\n")
	// An empty file is an empty flight recorder, which is what a process that
	// died before its first append leaves behind. recorder.Open creates one.
	// Telling its owner it is "not a flight recorder" sends them looking for
	// the wrong problem entirely.
	if len(trimmed) == 0 || bytes.HasPrefix(trimmed, []byte("{")) {
		return blob, "read from this file, which is a flight recorder itself", false, nil
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
		return nil, "", false, errors.New("no KelyfOS record in this file: it is not a flight recorder, and not an" +
			" export carrying one. Exports written before v1.0 embed no record; one written by a newer" +
			" KelyfOS may embed it differently. `kelyfos log --verify` on the machine that ran the session" +
			" checks the record itself")
	case err != nil:
		return nil, "", false, err
	}
	return chain, "read out of the record this report carries", true, nil
}

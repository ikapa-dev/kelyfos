package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/p4r4n0rm4l/KelyfOS/internal/notify"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// kelyfos diff, and run --review (E5-2, docs/qol.md §2).
//
// Both read the same comparison: what the sandbox did to the workspace, against
// the manifest recorded when it was packed. Not against the host directory as
// it is now — that is a different question, and SyncBack's fingerprint already
// answers it by diverting.

func diffCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos diff", flag.ExitOnError)
	id := fs.String("sandbox", "", "sandbox id (default: the only running one)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos diff [flags]

What a running sandbox has done to its workspace so far: added, modified and
deleted files, against the state the workspace was packed in.

This reads the workspace image, so it shows what has reached the disk. A file a
process inside the guest has written but not yet flushed is not on the disk yet
and is not here yet either.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	st, err := sandbox.Load(*id)
	if err != nil {
		return err
	}
	if st.Workspace == "" || st.WorkspaceHost == "" {
		return fmt.Errorf("sandbox %s has no workspace, so there is nothing to compare.\n"+
			"    give it one with:  kelyfos run --workspace ./dir", st.ID)
	}
	ws := sandbox.AdoptWorkspace(st.WorkspaceHost, st.Workspace)
	staged, err := ws.Stage()
	if err != nil {
		return err
	}
	defer staged.Discard()
	changes, err := staged.Changes()
	if err != nil {
		return fmt.Errorf("compare the workspace: %w", err)
	}
	added, modified, deleted := sandbox.Counts(changes)
	fmt.Printf("%s vs the workspace as packed\n\n", st.WorkspaceHost)
	fmt.Print(sandbox.FormatChanges(changes))
	fmt.Printf("\n%d added, %d modified, %d deleted\n", added, modified, deleted)
	return nil
}

// reviewOutcome is what a person decided about a sync-back.
type reviewOutcome struct {
	Sync    bool
	Reason  string
	Changes []sandbox.Change
}

// review shows what changed and asks. It is the one place this product asks a
// person to make a judgement, so the shape of the question matters: the summary
// first, the default explicit, and no answer taken on their behalf.
func review(staged *sandbox.Staged, hostDir string, n *notify.Notifier) reviewOutcome {
	changes, err := staged.Changes()
	if err != nil {
		// A workspace packed by an older kelyfos has no manifest. Saying so and
		// syncing is right — the alternative is refusing to write back work
		// somebody has already done because of a file this version invented.
		fmt.Fprintf(os.Stderr, "\nkelyfos: cannot compare this workspace (%v); syncing back "+
			"without a review\n", err)
		return reviewOutcome{Sync: true, Reason: "no_manifest"}
	}
	added, modified, deleted := sandbox.Counts(changes)
	fmt.Printf("\n%s — %d added, %d modified, %d deleted\n\n", hostDir, added, modified, deleted)
	fmt.Print(sandbox.FormatChanges(changes))

	if diverted, dest := staged.Diverted(); diverted {
		fmt.Printf("\nthe host directory changed while the sandbox was running, so a sync would "+
			"write to\n%s rather than over it.\n", dest)
	}

	// A flag whose whole purpose is asking a person becomes a trap the moment
	// it answers on their behalf. With nobody there, it declines and says so.
	if !onATerminal(os.Stdin) {
		fmt.Fprintf(os.Stderr, "\nkelyfos: --review has nobody to ask (stdin is not a terminal), "+
			"so nothing was written back.\n    the results are beside the directory; re-run "+
			"without --review to sync, or with a terminal to decide.\n")
		return reviewOutcome{Sync: false, Reason: "no_terminal", Changes: changes}
	}

	// The one place this product asks a person a question. If they walked away
	// — which is the whole reason --notify exists — this is the moment they
	// most need telling, because nothing else will happen until they answer.
	n.Send("kelyfos: waiting for you",
		fmt.Sprintf("%d added, %d modified, %d deleted in %s — write them back?",
			added, modified, deleted, filepath.Base(hostDir)))

	fmt.Printf("\nwrite these back to %s? [y/N] ", hostDir)
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return reviewOutcome{Sync: true, Reason: "accepted", Changes: changes}
	default:
		return reviewOutcome{Sync: false, Reason: "declined", Changes: changes}
	}
}

// recordReview writes the decision. A declined review is a fact worth keeping:
// a transcript that recorded only the accepted ones would be a record of
// agreement rather than of what happened.
// recordReview opens its own handle on the session, because by the time a
// review is answered the run's own recorder has been closed — the defers that
// end a session unwind before the one that writes the workspace back.
func recordReview(session string, out reviewOutcome, dest string) {
	rec, err := recorder.Open(sandbox.Root(), session)
	if err != nil {
		return
	}
	defer rec.Close()
	added, modified, deleted := sandbox.Counts(out.Changes)
	_ = rec.Append(recorder.Event{
		Type: recorder.TypeRunReview, Outcome: out.Reason, Path: dest,
		Added: added, Modified: modified, Deleted: deleted,
	})
}

// onATerminal reports whether this stream is a terminal, without a dependency
// for it: a character device is what a tty is, and the alternative is adding a
// module to ask a question the standard library already answers.
func onATerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// errReviewDeclined is what `run --review` exits with when nothing was written
// back. Not an error in the sense of something going wrong — but a run whose
// results did not land should not look identical to one whose results did.
var errReviewDeclined = errors.New("the workspace was not written back")

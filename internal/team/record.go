package team

import "github.com/p4r4n0rm4l/KelyfOS/internal/recorder"

// Record translates one broker event into a flight-recorder event.
//
// A translation rather than a decision: the broker decides what happened, the
// recorder decides how a session's chain is written, and this function is the
// seam between them so neither has to know the other's shape. It lives here
// because the fields it maps are the broker's, and a mapping is easiest to keep
// correct next to the thing that produces the values.
//
// From and To become Agent and Peer rather than reusing Host: an agent name and
// a hostname are different kinds of thing, and a reader of the log should not
// have to know which one a field means today.
func (e Event) Record() recorder.Event {
	return recorder.Event{
		Type:    e.Type,
		Source:  recorder.SourceHost,
		Agent:   e.From,
		Peer:    e.To,
		Kind:    e.Kind,
		Outcome: e.Outcome,
		Reason:  e.Reason,
		Bytes:   e.Bytes,
		SHA256:  e.SHA256,
		Data:    e.Body,
	}
}

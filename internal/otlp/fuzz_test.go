package otlp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// FuzzBuild drives Build with bounded-random chains assembled from raw fuzz
// bytes — internal/graph/fuzz_test.go's own fuzzInput pattern
// (FuzzLayoutNeverPanicsAndIsDeterministic), adapted to recorder.Event.
// Agent names and hosts come from small fixed pools so duplicate agents and
// repeated hosts occur often, the way a real team's chain does, rather than
// needing a corpus lucky enough to collide two arbitrary byte strings; argv,
// cwd, egress reasons and error messages are the raw fuzzed bytes, because
// those are exactly the guest-influenced fields safe() exists to defend and
// otlp_test.go's own fixed hostile corpus cannot cover every byte sequence.
//
// Two properties, not one:
//
//   - Build never panics on any chain shape, including an adversarial or
//     malformed one: a command.exit with no matching command.start, an
//     agent that appears only on an egress.attempt, a traceparent that is
//     garbage.
//   - The marshalled export carries no raw control byte outside \t\n\r
//     (the RENDER-checklist property this whole package exists to hold),
//     and the same chain, built twice, marshals byte-identically —
//     TestBuildIsDeterministic's own property, exercised here against
//     fuzzer-chosen input rather than only the fixed fixtures.
type otlpByteReader struct {
	data []byte
	pos  int
}

func (r *otlpByteReader) next() byte {
	if r.pos >= len(r.data) {
		return 0
	}
	b := r.data[r.pos]
	r.pos++
	return b
}

func (r *otlpByteReader) bytes(n int) []byte {
	if r.pos >= len(r.data) {
		return nil
	}
	end := r.pos + n
	if end > len(r.data) {
		end = len(r.data)
	}
	out := r.data[r.pos:end]
	r.pos = end
	return out
}

const (
	fuzzMaxEvents = 40
	fuzzMaxAgents = 4
	fuzzMaxHosts  = 4
)

func fuzzChain(data []byte) []recorder.Event {
	r := &otlpByteReader{data: data}

	agents := make([]string, fuzzMaxAgents)
	for i := range agents {
		agents[i] = fmt.Sprintf("agent-%d", i)
	}
	hosts := make([]string, fuzzMaxHosts)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host-%d.example", i)
	}

	n := int(r.next()) % (fuzzMaxEvents + 1)
	var events []recorder.Event
	for i := 0; i < n; i++ {
		agent := ""
		if r.next()%2 == 0 {
			agent = agents[int(r.next())%fuzzMaxAgents]
		}
		switch int(r.next()) % 5 {
		case 0:
			events = append(events, recorder.Event{
				Type:  recorder.TypeCommandStart,
				Agent: agent,
				Call:  fmt.Sprintf("c%d", int(r.next())%8),
				Cmd:   []string{string(r.bytes(16)), "arg"},
				Cwd:   string(r.bytes(8)),
				Via:   "exec",
			})
		case 1:
			code := int(r.next()) % 3
			var errPtr *recorder.EvError
			if r.next()%2 == 0 {
				errPtr = &recorder.EvError{Kind: "exit", Message: string(r.bytes(16))}
			}
			events = append(events, recorder.Event{
				Type:       recorder.TypeCommandExit,
				Agent:      agent,
				Call:       fmt.Sprintf("c%d", int(r.next())%8),
				Code:       &code,
				DurationMS: int64(r.next()),
				Error:      errPtr,
			})
		case 2:
			allowed := r.next()%2 == 0
			events = append(events, recorder.Event{
				Type:    recorder.TypeEgressAttempt,
				Agent:   agent,
				Host:    hosts[int(r.next())%fuzzMaxHosts],
				Port:    443,
				Allowed: &allowed,
				Reason:  string(r.bytes(16)),
				Mode:    "tunnelled",
			})
		case 3:
			events = append(events, recorder.Event{
				Type:        recorder.TypeSessionPolicy,
				Agent:       agent,
				Traceparent: string(r.bytes(55)),
			})
		default:
			events = append(events, recorder.Event{Type: recorder.TypeSessionReady, Agent: agent})
		}
	}
	return events
}

func FuzzBuild(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("hello"))
	f.Add([]byte{0x07, 0x1b, 0x00, 0xff, 0xfe})
	f.Add(bytes.Repeat([]byte{1, 2, 3}, 60))

	f.Fuzz(func(t *testing.T, data []byte) {
		events := fuzzChain(data)

		exp, err := Build("sess1", events)
		if err != nil {
			t.Fatalf("Build returned an error on a well-formed session id: %v", err)
		}
		blob, err := json.Marshal(exp)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		for i, b := range blob {
			if b < 0x20 && b != '\n' && b != '\t' && b != '\r' {
				t.Fatalf("raw control byte 0x%02x at offset %d in the marshalled export", b, i)
			}
		}

		exp2, err := Build("sess1", events)
		if err != nil {
			t.Fatalf("Build (second call): %v", err)
		}
		blob2, err := json.Marshal(exp2)
		if err != nil {
			t.Fatalf("marshal (second call): %v", err)
		}
		if !bytes.Equal(blob, blob2) {
			t.Fatal("Build is not deterministic on the same input")
		}
	})
}

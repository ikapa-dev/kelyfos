package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// observed puts one exchange past the observer — the client's lines, then the
// guest's — and hands back the chain it produced. The bridge is not in the way
// here on purpose: the observer sees exactly the lines a tee hands it, so a
// test can say what the record contains without a machine to run them against.
func observed(t *testing.T, client, guest []string) []recorder.Event {
	t.Helper()
	root := t.TempDir()
	rec, err := recorder.Open(root, "s1")
	if err != nil {
		t.Fatal(err)
	}
	obs := newObserver(rec, "")
	for _, line := range client {
		obs.fromClient([]byte(line))
	}
	for _, line := range guest {
		obs.fromGuest([]byte(line))
	}
	rec.Close()

	f, err := os.Open(recorder.Path(root, "s1"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := recorder.Read(f)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func writesIn(events []recorder.Event) []recorder.Event {
	var out []recorder.Event
	for _, e := range events {
		if e.Type == recorder.TypeFileWrite {
			out = append(out, e)
		}
	}
	return out
}

func writeFileCall(id int, path, content string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call",`+
		`"params":{"name":"write_file","arguments":{"path":%q,"content":%q}}}`, id, path, content)
}

func uploadCall(id int, path string, body []byte) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call",`+
		`"params":{"name":"upload","arguments":{"path":%q,"data":%q}}}`,
		id, path, base64.StdEncoding.EncodeToString(body))
}

// refusal is what the guest sends back when it will not do the write: a tool
// error, not a JSON-RPC one (internal/mcp says why that line is drawn there).
func refusal(id int, why string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"content":[{"type":"text","text":%q}],"isError":true}}`,
		id, why)
}

func wrote(id int, path string, n int) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"content":[{"type":"text","text":"wrote %d bytes"}],`+
		`"structuredContent":{"path":%q,"bytes":%d}}}`, id, n, path, n)
}

// A write the guest refused is not a write.
//
// The guest turns down a path outside the profile's writable trees and a body
// over the per-call limit, and its refusal is the whole of the answer: a
// file.write has no second event to correct it the way command.exit corrects a
// command.start. So recording the request as a completed write puts a line in
// the chain for a file that does not exist, with a size and a digest of content
// that was never stored — a record making a claim nobody can check is worse
// than no record of the attempt at all.
func TestAWriteTheGuestRefusedIsNotInTheChain(t *testing.T) {
	for _, tc := range []struct {
		name, call, why string
	}{
		{"outside the writable trees", writeFileCall(1, "/etc/passwd", "root::0:0:"),
			"/etc/passwd is not inside a writable tree"},
		{"over the per-call limit", uploadCall(1, "/work/big.bin", []byte("pretend this is huge")),
			"upload is 33554432 bytes, over the 16777216 byte per-call limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := observed(t, []string{tc.call}, []string{refusal(1, tc.why)})
			if got := writesIn(events); len(got) != 0 {
				t.Errorf("the guest refused this write and the chain says it happened: %+v", got[0])
			}
		})
	}
}

// A call the guest never answered has not written anything either. This is the
// case the bridge answers on its own behalf when the session ends with work
// outstanding (F-D33), and the record must agree with the answer the caller
// gets: nothing landed.
func TestAWriteWithNoAnswerAtAllIsNotInTheChain(t *testing.T) {
	events := observed(t, []string{writeFileCall(1, "/work/a.txt", "hello")}, nil)
	if got := writesIn(events); len(got) != 0 {
		t.Errorf("the guest never answered and the chain says the write happened: %+v", got[0])
	}
}

// Once the guest says it landed, the write is recorded — by path, size and
// digest, taken from the request because that is where the content is
// (docs/events.md §4).
func TestAWriteTheGuestAcceptedIsRecordedFromTheRequest(t *testing.T) {
	const content = "hello sandbox\n"
	sum := hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte(content)); return s[:] }())

	for _, tc := range []struct{ name, call, via string }{
		{"write_file", writeFileCall(1, "/work/a.txt", content), "write_file"},
		{"upload", uploadCall(1, "/work/a.txt", []byte(content)), "upload"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := observed(t, []string{tc.call}, []string{wrote(1, "/work/a.txt", len(content))})
			got := writesIn(events)
			if len(got) != 1 {
				t.Fatalf("want exactly one file.write, got %d", len(got))
			}
			w := got[0]
			if w.Path != "/work/a.txt" || w.Bytes != len(content) || w.SHA256 != sum || w.Via != tc.via {
				t.Errorf("the write was recorded as %+v, which is not what was asked for and accepted", w)
			}
		})
	}
}

// A command is still recorded the moment it is asked for, and holding writes
// back must not have moved it. A command that was started is a fact whatever it
// does next, and command.exit is there to say how it ended — including a
// non-zero exit, which is information for the agent rather than a refusal.
func TestACommandIsStillRecordedBeforeTheGuestAnswers(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "s1")
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	obs := newObserver(rec, "")
	obs.fromClient([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call",` +
		`"params":{"name":"exec","arguments":{"command":"false"}}}`))

	f, err := os.Open(recorder.Path(root, "s1"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := recorder.Read(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != recorder.TypeCommandStart {
		t.Fatalf("want a command.start before the answer, got %+v", events)
	}
}

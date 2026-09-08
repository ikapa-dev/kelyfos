package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// The security review of 2026-09-03: what one command's output can put on the
// host's disk through the flight recorder is bounded.

func TestReview_RecordedOutputIsCappedPerCommand(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "cap-test")
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	o := &outputRecorder{rec: rec, call: "c1"}
	chunk := bytes.Repeat([]byte("x"), 1<<20)
	for i := 0; i < 20; i++ { // 20 MiB, over the 16 MiB ceiling
		o.add("stdout", chunk)
	}
	o.flush()

	snap, err := recorder.ReadSnapshot(root, "cap-test")
	if err != nil {
		t.Fatal(err)
	}
	events, err := recorder.Read(bytes.NewReader(snap.Chain))
	if err != nil {
		t.Fatal(err)
	}
	var total int
	var notes int
	for _, e := range events {
		if e.Type != recorder.TypeCommandOutput {
			continue
		}
		total += e.Bytes
		if strings.Contains(decodeData(t, e), "the record keeps no more") {
			notes++
		}
	}
	if total > maxRecordedOutput+256 {
		t.Fatalf("recorded %d bytes for one command, over the %d ceiling", total, maxRecordedOutput)
	}
	if total < maxRecordedOutput {
		t.Fatalf("recorded only %d bytes; the ceiling itself should be reached", total)
	}
	if notes != 1 {
		t.Fatalf("want exactly one in-band note, got %d", notes)
	}
	// Nothing further is recorded, however much more arrives.
	before := len(events)
	o.add("stdout", chunk)
	o.add("stderr", chunk)
	o.flush()
	snap, _ = recorder.ReadSnapshot(root, "cap-test")
	after, _ := recorder.Read(bytes.NewReader(snap.Chain))
	if len(after) != before {
		t.Fatalf("output after the cap still reached the record: %d -> %d events", before, len(after))
	}
}

func TestReview_MCPObserverOutputIsCappedPerStream(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "cap-mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	o := newObserver(rec, "")
	o.appendCommandOutput("c1", "stdout", strings.Repeat("y", maxRecordedOutput+(4<<20)))
	snap, err := recorder.ReadSnapshot(root, "cap-mcp")
	if err != nil {
		t.Fatal(err)
	}
	events, err := recorder.Read(bytes.NewReader(snap.Chain))
	if err != nil {
		t.Fatal(err)
	}
	var total int
	for _, e := range events {
		total += e.Bytes
	}
	if total > maxRecordedOutput+256 || total < maxRecordedOutput {
		t.Fatalf("recorded %d bytes, want about %d", total, maxRecordedOutput)
	}
}

func decodeData(t *testing.T, e recorder.Event) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(e.Data)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

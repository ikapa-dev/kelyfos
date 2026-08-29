package proto

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// P7-17/F20, second review round.
//
// Two defects, one cause. ExecResponse.Sanitize and ControlResponse.Sanitize
// each cleaned some of their string fields and not ID, and proto.TeamRequest —
// which internal/sandbox/sandbox.go:427 decodes straight off the guest's team
// channel — had no Sanitize at all. The second is the one that mattered: it
// carries the identity-like fields F1 is about (a store key, an agent name),
// and internal/team/record.go puts req.To and req.Key into the hash chain
// verbatim.
//
// Both were invisible for the same reason. FuzzReaderRead listed every type but
// asserted only inside `if _, ok := v.(Sanitizer); ok` — so the one type whose
// MISSING interface was the defect was the one type the assertion skipped. A
// guard that excuses exactly what it exists to catch is not a guard, and this
// is the ninth test on this task found unable to fail.
//
// So the rule here is positive and enumerated: every frame the host decodes off
// a channel a guest writes to must implement Sanitizer, and feeding each one a
// frame with every string field hostile must leave nothing hostile behind.

// guestFrames is every type the HOST decodes from a channel the GUEST writes
// to, with the reader that does it. Adding a frame to the protocol without
// adding it here is caught by TestGuestFrameListIsComplete below.
func guestFrames() []struct {
	new   func() any
	where string
} {
	return []struct {
		new   func() any
		where string
	}{
		{func() any { return new(Ready) }, "internal/sandbox/sandbox.go:1697 serveReady"},
		{func() any { return new(Heartbeat) }, "internal/sandbox/sandbox.go:1697 serveReady"},
		{func() any { return new(GuestEvent) }, "internal/sandbox/sandbox.go:602 serveEvents"},
		{func() any { return new(ExecResponse) }, "host/exec.go:116 · internal/sandbox/exec.go:101"},
		{func() any { return new(ControlResponse) }, "internal/sandbox/sandbox.go:772/1054/1540/1600"},
		{func() any { return new(TeamRequest) }, "internal/sandbox/sandbox.go:427 serveTeam"},
		{func() any { return new(Error) }, "carried on every frame above that has one"},
		{func() any { return new(ShellExit) }, "host/shell.go:203 pumpShell"},
		{func() any { return new(ShellOp) }, "host/shell.go:192 pumpShell"},
		{func() any { return new(ForwardReply) }, "host/forward.go:181, via ReadForwardReply"},
	}
}

// shellFramed marks the guest->host frames that do NOT arrive through
// Reader.Read: the shell channel is length-prefixed and the forward channel
// does its own handshake, so each sanitises at its own decode site. They are
// still guest frames and still must implement Sanitizer; they are simply not
// FuzzReaderRead's business.
func (ShellExit) shellFramed()    {}
func (ShellOp) shellFramed()      {}
func (ForwardReply) shellFramed() {}

func TestEveryGuestFrameImplementsSanitizer(t *testing.T) {
	for _, f := range guestFrames() {
		v := f.new()
		if _, ok := v.(Sanitizer); !ok {
			t.Errorf("%T is decoded off a guest channel (%s) and does not implement Sanitizer.\n"+
				"  Every string on it reaches the host — and the flight recorder — exactly as the "+
				"guest chose to spell it.", v, f.where)
		}
	}
}

// hostileFrame builds a JSON object setting every string field of v to bad,
// skipping the base64 ones. Built by reflection rather than by hand so a field
// added to one of these structs is covered without anybody remembering.
func hostileFrame(v any, bad string) string {
	skip := map[string]bool{"data": true, "stdin": true, "entropy": true, "ca_pem": true, "body": true}
	rv := reflect.ValueOf(v).Elem()
	obj := map[string]any{}
	var walk func(reflect.Type)
	walk = func(rt reflect.Type) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if !f.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" || name == "-" || skip[name] {
				continue
			}
			switch f.Type.Kind() {
			case reflect.String:
				obj[name] = bad
			case reflect.Pointer:
				if f.Type.Elem() == reflect.TypeOf(Error{}) {
					obj[name] = map[string]any{"kind": bad, "message": bad}
				}
			}
		}
	}
	walk(rv.Type())
	blob, _ := json.Marshal(obj)
	return string(blob)
}

// The table that does not depend on a fuzzer finding the input. Every guest
// frame, every string field, one hostile value — read through the real reader.
func TestNoGuestFrameLetsAHostileStringThrough(t *testing.T) {
	for _, bad := range []string{"\x7f", "\x1b[2J", "‮elbatpecca", "\x00"} {
		for _, f := range guestFrames() {
			v := f.new()
			line := hostileFrame(v, bad)
			t.Run(fmt.Sprintf("%T/%q", v, bad), func(t *testing.T) {
				if err := NewReader(strings.NewReader(line + "\n")).Read(v); err != nil {
					t.Fatalf("Read(%s): %v", line, err)
				}
				if field, ok := unsafeStringField(v); ok {
					t.Errorf("%T.%s survived Read carrying %q (%s)", v, field, bad, f.where)
				}
			})
		}
	}
}

// And the list itself: a frame type added to this package without a row above
// is a frame nobody decided about. Every struct in this file with a `json` tag
// is either a guest frame (listed) or one the host WRITES and the guest reads
// (named here, with why).
func TestGuestFrameListIsComplete(t *testing.T) {
	hostWritten := map[string]string{
		"ExecRequest":    "host -> guest: the host writes it",
		"ControlRequest": "host -> guest: the host writes it",
		"TeamResponse":   "host -> guest: the broker writes it",
		"ForwardOpen":    "host -> guest: the host writes it",
		"ShellOpen":      "host -> guest: the host writes it",
		"ShellResize":    "host -> guest: the host writes it",
		"MalformedFrame": "not a frame: an error type",
		"Writer":         "not a frame",
		"Reader":         "not a frame",
	}
	listed := map[string]bool{}
	for _, f := range guestFrames() {
		listed[reflect.TypeOf(f.new()).Elem().Name()] = true
	}
	for _, name := range protoStructNames(t) {
		if listed[name] || hostWritten[name] != "" {
			continue
		}
		t.Errorf("type %s is declared in this package and is in neither list.\n"+
			"  Add it to guestFrames() if the host decodes it off a guest channel, "+
			"or to hostWritten with the reason it is not one.", name)
	}
}

package proto

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

// Fuzz targets for the host/guest wire (P6-3).
//
// This is the largest hostile surface in the product and the reason is
// structural rather than incidental: everything on these channels was written
// by a guest, and a guest runs whatever the agent decided to run. The host is
// the party with something to lose, so every function here is read from the
// host's side of a channel a compromised guest is writing to.
//
// What the harnesses assert is not only "does not panic". Where a function has
// an invariant the rest of the product relies on — a frame kind is one of two
// values, a payload is within the declared bound — the harness checks it,
// because a parser that returns nonsense without crashing is the failure that
// actually costs something.

// FuzzReadShellFrame drives the length-prefixed shell framing.
//
// This is the one place in the protocol where a byte count from the peer drives
// an allocation, which makes it the one place worth fuzzing hardest: five bytes
// of attacker input name a buffer up to MaxShellFrame.
func FuzzReadShellFrame(f *testing.F) {
	f.Add([]byte{ShellData, 0, 0, 0, 0})
	f.Add([]byte{ShellControl, 0, 0, 0, 2, '{', '}'})
	f.Add([]byte{ShellData, 0, 0, 0, 4, 'l', 's', '\n', 0})
	f.Add([]byte{ShellControl, 0, 0, 0, 25, '{', '"', 'o', 'p', '"', ':', '"', 'r', 'e', 's', 'i', 'z', 'e', '"', ',', '"', 'c', 'o', 'l', 's', '"', ':', '8', '0', '}'})
	// A length that is over the bound: must be refused, never allocated.
	f.Add([]byte{ShellData, 0xff, 0xff, 0xff, 0xff})
	// An unknown kind.
	f.Add([]byte{9, 0, 0, 0, 1, 'x'})
	// A truncated header, and a header whose payload never arrives.
	f.Add([]byte{ShellData, 0, 0})
	f.Add([]byte{ShellData, 0, 0, 0, 8, 'a', 'b'})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		// Bounded: a frame costs at least five bytes of input, so this cannot
		// spin on an input the fuzzer can construct — the cap is belt and
		// braces against a future reader that could return frames from nothing.
		for i := 0; i < 64; i++ {
			kind, payload, err := ReadShellFrame(r)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return
				}
				// A rejection is a correct outcome; only its shape matters.
				return
			}
			if kind != ShellData && kind != ShellControl {
				t.Fatalf("accepted frame kind %d, which is neither ShellData nor ShellControl", kind)
			}
			if len(payload) > MaxShellFrame {
				t.Fatalf("accepted a %d-byte payload over the %d limit", len(payload), MaxShellFrame)
			}
		}
	})
}

// FuzzReaderRead drives the newline-delimited JSON framing every other channel
// shares, decoding into the message types the HOST reads from a guest.
//
// Decoding into several types rather than one is deliberate: the framing is
// generic but the damage is type-specific, and a field that unmarshals into one
// shape and panics in another is exactly the bug a single-type harness misses.
func FuzzReaderRead(f *testing.F) {
	f.Add([]byte("{}\n"))
	f.Add([]byte(`{"v":1,"kernel":"6.12.105","supervisor":"dev","overlay":true}` + "\n"))
	f.Add([]byte(`{"v":1,"type":"oom","pid":42,"comm":"python3","rss_kib":1024}` + "\n"))
	f.Add([]byte(`{"v":1,"id":"x1","code":0,"stdout":"aGk="}` + "\n"))
	f.Add([]byte("\r\n\r\n{}\r\n"))
	f.Add([]byte("{\n{\n{\n"))
	f.Add([]byte(`{"v":99999999999999999999}` + "\n"))
	// The two shapes P7-17/F20 and F1 exist for, as raw bytes inside a string
	// field: an OSC title-set, and a right-to-left override.
	f.Add([]byte("{\"v\":1,\"kernel\":\"\x1b]0;pwned\x07\"}\n"))
	f.Add([]byte("{\"v\":1,\"type\":\"resource.oom\",\"comm\":\"‮elbatpecca\"}\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		decode := func(next func() any) {
			p := NewReader(bytes.NewReader(data))
			for i := 0; i < 256; i++ {
				v := next()
				if err := p.Read(v); err != nil {
					return
				}
				// P7-17/F20: Read is the edge, so a frame it accepted must
				// carry no string the host could not safely print. Asserted on
				// the decoded struct rather than at any one print site,
				// because the print sites are exactly what this defence exists
				// to stop having to enumerate.
				if _, ok := v.(Sanitizer); ok {
					if field, bad := unsafeStringField(v); bad {
						t.Fatalf("%T.%s survived Read carrying %q", v, field, data)
					}
				}
			}
		}
		decode(func() any { return new(Ready) })
		decode(func() any { return new(GuestEvent) })
		decode(func() any { return new(ExecResponse) })
		decode(func() any { return new(TeamRequest) })
		decode(func() any { return new(ControlResponse) })
		decode(func() any { return new(Heartbeat) })
		decode(func() any { return new(Error) })
	})
}

// unsafeStringField walks v — a pointer to one of the frame structs above —
// and names the first string field, at any depth, that still carries a
// character SafeText would have escaped.
//
// Reflection rather than a hand-written field list on purpose: a string field
// added to one of these structs later is covered without anybody remembering
// to add it here, and "somebody has to remember" is the failure mode F20 is.
//
// The base64 fields are skipped: they are bytes on the wire, decoded by the
// caller, and SafeBody's business rather than SafeText's.
func unsafeStringField(v any) (string, bool) {
	skip := map[string]bool{"Data": true, "Stdin": true, "Entropy": true, "CAPEM": true}
	var walk func(reflect.Value, string) (string, bool)
	walk = func(rv reflect.Value, path string) (string, bool) {
		switch rv.Kind() {
		case reflect.Pointer, reflect.Interface:
			if rv.IsNil() {
				return "", false
			}
			return walk(rv.Elem(), path)
		case reflect.Struct:
			for i := 0; i < rv.NumField(); i++ {
				f := rv.Type().Field(i)
				if !f.IsExported() || skip[f.Name] {
					continue
				}
				if where, bad := walk(rv.Field(i), path+"."+f.Name); bad {
					return where, true
				}
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < rv.Len(); i++ {
				if where, bad := walk(rv.Index(i), path); bad {
					return where, true
				}
			}
		case reflect.Map:
			for _, k := range rv.MapKeys() {
				if where, bad := walk(rv.MapIndex(k), path); bad {
					return where, true
				}
			}
		case reflect.String:
			if s := rv.String(); SafeText(s) != s {
				return path, true
			}
		}
		return "", false
	}
	where, bad := walk(reflect.ValueOf(v), "")
	return strings.TrimPrefix(where, "."), bad
}

// FuzzReadForwardOpen drives the first frame of an inbound port forward, which
// the guest sends and the host acts on by binding a listener.
func FuzzReadForwardOpen(f *testing.F) {
	f.Add([]byte(`{"v":1,"op":"open","port":8080}` + "\n"))
	f.Add([]byte(`{"v":1,"op":"open","port":0}` + "\n"))
	f.Add([]byte(`{"v":1,"op":"open","port":65536}` + "\n"))
	f.Add([]byte(`{"v":1,"op":"open","port":-1}` + "\n"))
	f.Add([]byte(`{"op":"close"}` + "\n"))
	f.Add([]byte("not json\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		open, err := ReadForwardOpen(bufio.NewReader(bytes.NewReader(data)))
		if err != nil {
			return
		}
		// The whole point of the port check is that nothing downstream has to
		// repeat it, so an accepted open must carry a bindable port.
		if open.Port < 1 || open.Port > 65535 {
			t.Fatalf("accepted a forward open naming port %d", open.Port)
		}
		if open.Op != "open" {
			t.Fatalf("accepted a forward open whose op is %q", open.Op)
		}
	})
}

// FuzzReadForwardReply drives the host's answer as the guest parses it. The
// weaker direction — the host is not the hostile party — but it is the same
// framing and costs one function to cover.
func FuzzReadForwardReply(f *testing.F) {
	f.Add([]byte(`{"v":1,"ok":true}` + "\n"))
	f.Add([]byte(`{"v":1,"ok":false,"error":"port in use"}` + "\n"))
	f.Add([]byte("\n\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadForwardReply(bufio.NewReader(bytes.NewReader(data)))
	})
}

package recorder

import (
	"strings"
	"testing"
)

// ST-4.2's second property: the chain digest is INJECTIVE over the value
// edges that could plausibly collide. hashOf hashes the canonical JSON of an
// event, so a collision needs two different field values whose marshalled
// bytes agree — the classic candidates being HTML-escape shapes ("<" versus a
// literal "\u003c" sequence), unicode normalisation (NFC versus NFD), and
// number-vs-string shapes. Any collision would let a fabricated event carry
// the digest of a genuine one, which is the property the whole chain rests
// on. This pins it, alongside FuzzAppendFieldValues, without touching D82's
// seeds.
func TestHashOf_InjectiveOverAdversarialValues(t *testing.T) {
	values := []string{
		"<script>",
		`\u003cscript\u003e`,                 // the literal escape sequence, not the characters
		`&lt;script&gt;`,                     // the HTML-entity form
		"café",                               // NFC
		"cafe\u0301",                         // NFD — a different byte sequence, same look
		"1",                                  // a number as a string
		"1.0",                                // the float spelling, as a string
		"1e3",                                // the exponent spelling, as a string
		"",                                   // empty
		"\x00",                               // a NUL byte
		"\xff\xfe",                           // invalid UTF-8 bytes
		strings.Repeat("a", 4096),            // long
		strings.Repeat("a", 4095) + "\u00e9", // long, one multi-byte suffix
	}
	for i, a := range values {
		for j, b := range values {
			if i == j {
				continue
			}
			if a == b {
				continue
			}
			ha, err := hashOf(Event{Type: TypeCommandOutput, Data: a, Host: "h"})
			if err != nil {
				t.Fatalf("hashOf(%q): %v", a, err)
			}
			hb, err := hashOf(Event{Type: TypeCommandOutput, Data: b, Host: "h"})
			if err != nil {
				t.Fatalf("hashOf(%q): %v", b, err)
			}
			if ha == hb {
				t.Fatalf("distinct values share a digest: %q and %q both hash to %s", a, b, ha)
			}
		}
	}
}

func TestHashOf_DeterministicForTheSameValue(t *testing.T) {
	e := Event{Type: TypeEgressAttempt, Host: "example.com", Data: "deterministic"}
	h1, err := hashOf(e)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := hashOf(e)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("the same event hashed to %s and %s", h1, h2)
	}
	// And the digest covers the value, not just the shape: change the data,
	// change the hash.
	e2 := e
	e2.Data = "different"
	h3, err := hashOf(e2)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h3 {
		t.Fatal("a changed value kept the same digest")
	}
}

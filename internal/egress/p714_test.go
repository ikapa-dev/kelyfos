package egress

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
)

// P7-14. covered trims one trailing slash off a bound prefix, so a scope
// written "/repos//" approved "/repos/", which an origin that strips matrix
// parameters resolves to "/repos" — not beneath the literal prefix. A scope
// is now refused where it enters unless it is already in the form requests
// are compared in, and covers withholds on any that is not.

func TestP714_AScopeThatIsNotInNormalFormIsRefusedWhereItEnters(t *testing.T) {
	for _, spec := range []string{
		"TOKEN@github.com/repos//",
		"TOKEN@github.com/repos/./x",
		"TOKEN@github.com/repos/../admin/",
		"TOKEN@github.com//repos/",
		"TOKEN@github.com//",
	} {
		if _, err := ParseSecretSpec(spec); err == nil {
			t.Errorf("ParseSecretSpec(%q) accepted a scope path that is not in normal form", spec)
		} else if !strings.Contains(err.Error(), "scope path") {
			t.Errorf("ParseSecretSpec(%q): the refusal does not say it is about the scope path: %v", spec, err)
		}
	}
	// The refusal names the form to write, which is the whole point of
	// refusing at the door rather than withholding later.
	_, err := ParseSecretSpec("TOKEN@github.com/repos//")
	if err == nil || !strings.Contains(err.Error(), `"/repos/"`) {
		t.Fatalf("the refusal for /repos// should say to write /repos/: %v", err)
	}
	for _, spec := range []string{
		"TOKEN@github.com/repos/",
		"TOKEN@github.com/repos",
		"TOKEN@github.com/",
		"TOKEN@github.com/my repo/",
		"TOKEN@github.com/a-b_c.d~e/",
		// D44: which characters a scope may carry is the grammar's business.
		"TOKEN@api.example.com/v1/models/x:generateContent",
		"TOKEN@api.example.com/search/A+B",
	} {
		if _, err := ParseSecretSpec(spec); err != nil {
			t.Errorf("ParseSecretSpec(%q) refused a scope path that is in normal form: %v", spec, err)
		}
	}
}

func TestP714_CoversWithholdsOnAScopeThatIsNotInNormalForm(t *testing.T) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET /repos/ HTTP/1.1\r\nHost: api.github.com\r\n\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	// Built by hand, past the parser: the second lock on the same door.
	for _, prefix := range []string{"/repos//", "/repos/.", "/repos/../repos/", "//repos/"} {
		ok, why := Scope{Path: prefix}.covers(req)
		if ok {
			t.Errorf("Scope{Path: %q}.covers(/repos/) approved the request; the prefix is not in normal form", prefix)
		}
		if why != WithheldPath {
			t.Errorf("Scope{Path: %q}: withheld for %q, want %q", prefix, why, WithheldPath)
		}
	}
	// And the canonical form still covers exactly what it says.
	if ok, _ := (Scope{Path: "/repos/"}).covers(req); !ok {
		t.Fatal("Scope{Path: /repos/} no longer covers /repos/")
	}
}

func TestP714_TheFoundInputHoldsUnderEveryOriginSimulation(t *testing.T) {
	// The input act's fuzzer minimised to, replayed as the property replays it.
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET /repo/ HTTP/1.1\r\nHost: api.github.com\r\n\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	prefix := "/repo//"
	if ok, _ := (Scope{Path: prefix}).covers(req); ok {
		t.Fatalf("covers(%q) approved /repo/, and under matrix-param strip it resolves to /repo", prefix)
	}
}

package denial

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The catalog's own invariants. They are the reason a refusal added later
// cannot be a dead end: an entry with no fix, or a fix naming a hole nothing
// fills, fails here rather than in front of a user.
func TestCatalogIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range All() {
		if d.ID == "" || d.Doc == "" || d.Msg == "" {
			t.Errorf("%+v: an entry needs an ID, a Doc and a Msg", d)
			continue
		}
		if d.Fix == "" {
			t.Errorf("%s: no fix line — a refusal without one is a dead end", d.ID)
		}
		if seen[d.ID] {
			t.Errorf("%s: two entries share this ID", d.ID)
		}
		seen[d.ID] = true
		if !strings.Contains(d.ID, ".") {
			t.Errorf("%s: an ID is <what-refuses>.<which>", d.ID)
		}
		if strings.HasSuffix(d.Fix, ".") {
			t.Errorf("%s: fix lines do not end in a full stop, for one look on the terminal", d.ID)
		}
		for _, p := range d.Placeholders() {
			if _, ok := d.Sample[p]; !ok {
				t.Errorf("%s: placeholder <%s> has no Sample value", d.ID, p)
			}
		}
	}
	if len(seen) < 10 {
		t.Errorf("the catalog has %d entries; it covered every refusal at E5-4", len(seen))
	}
}

// A refusal rendered with its own sample is what the reference prints, so it
// has to be a finished sentence rather than a template with holes in it.
func TestSampleLeavesNoHoles(t *testing.T) {
	for _, d := range All() {
		got := d.Render(d.Sample)
		if i := strings.Index(got, "<"); i >= 0 {
			t.Errorf("%s: unfilled placeholder in %q", d.ID, got[i:])
		}
		if !strings.Contains(got, "["+d.ID+"]") {
			t.Errorf("%s: the ID is not in the rendered refusal: %q", d.ID, got)
		}
		if !strings.Contains(got, "\n    ") {
			t.Errorf("%s: the fix is not on its own indented line: %q", d.ID, got)
		}
	}
}

// The headline example from the plan, exactly.
func TestEgressHostReadsAsPromised(t *testing.T) {
	err := EgressHost.Err(V{"host": "api.stripe.com"})
	want := "api.stripe.com is not in this sandbox's allowlist [egress.host]\n" +
		`    add allow = ["api.stripe.com"] to kelyfos.toml, or rerun with --allow api.stripe.com`
	if err.Error() != want {
		t.Errorf("got:\n%s\nwant:\n%s", err.Error(), want)
	}
}

// A refusal is recognisable as itself, which is the structured half of the
// promise: a caller branches on which refusal it was, not on its prose.
func TestARefusalKnowsWhichOneItIs(t *testing.T) {
	err := fmt.Errorf("starting the sandbox: %w", CeilingFlag.Err(V{"flag": "cpus"}))
	r, ok := Of(err)
	if !ok {
		t.Fatal("a wrapped refusal is not recognised")
	}
	if r.ID() != "ceiling.flag" {
		t.Errorf("ID = %q", r.ID())
	}
	if r.Values()["flag"] != "cpus" {
		t.Errorf("the values it named are lost: %v", r.Values())
	}
	if !Is(err, "ceiling.flag") || Is(err, "egress.host") {
		t.Error("Is does not agree with ID")
	}
	if _, ok := Of(errors.New("something else")); ok {
		t.Error("a plain error is not a refusal")
	}
}

// A hole nothing fills stays visible. Closing it up silently would produce a
// sentence that reads fine and says less, which is the worse failure.
func TestAnUnfilledHoleIsVisible(t *testing.T) {
	got := EgressHost.Err(V{}).Error()
	if !strings.Contains(got, "<host>") {
		t.Errorf("the hole was closed up quietly: %q", got)
	}
}

// Every entry is looked up by the ID it prints, because that is what a person
// reading a refusal has in their hand.
func TestLookupByPrintedID(t *testing.T) {
	for _, d := range All() {
		got, ok := Lookup(d.ID)
		if !ok || got.Msg != d.Msg {
			t.Errorf("%s: not found by its own ID", d.ID)
		}
	}
	if _, ok := Lookup("no.such.thing"); ok {
		t.Error("Lookup invented an entry")
	}
}

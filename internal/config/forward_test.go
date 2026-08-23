package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadForward(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kelyfos.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestForwardsParseInOrder(t *testing.T) {
	cfg, err := loadForward(t, `
[[forward]]
host  = 8080
guest = 80

[[forward]]
host  = 5433
guest = 5432
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Forwards) != 2 {
		t.Fatalf("got %d forwards", len(cfg.Forwards))
	}
	if cfg.Forwards[0].Host != 8080 || cfg.Forwards[0].Guest != 80 {
		t.Errorf("first = %+v", cfg.Forwards[0])
	}
	if cfg.Forwards[1].Host != 5433 || cfg.Forwards[1].Guest != 5432 {
		t.Errorf("second = %+v", cfg.Forwards[1])
	}
	if err := cfg.CheckForwards(); err != nil {
		t.Errorf("a complete pair was refused: %v", err)
	}
}

// Half a pair forwards nothing, and two entries claiming one host port have no
// correct interpretation. Both are refused where the finished document is, and
// both name the line.
func TestIncompleteAndCollidingForwardsAreRefused(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"no guest", "[[forward]]\nhost = 8080\n", "no guest port"},
		{"no host", "[[forward]]\nguest = 80\n", "no host port"},
		{"neither", "[[forward]]\n", "forwards nothing"},
		{"the same host port twice",
			"[[forward]]\nhost = 8080\nguest = 80\n\n[[forward]]\nhost = 8080\nguest = 81\n",
			"already forwarded"},
	} {
		cfg, err := loadForward(t, tc.body)
		if err != nil {
			t.Fatalf("%s: the parser refused what the check is meant to catch: %v", tc.name, err)
		}
		err = cfg.CheckForwards()
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// A port is a port. Anything that is not one is refused at the line that wrote
// it rather than at the moment something tries to bind it.
func TestForwardPortsAreChecked(t *testing.T) {
	for _, body := range []string{
		"[[forward]]\nhost = 0\nguest = 80\n",
		"[[forward]]\nhost = 70000\nguest = 80\n",
		"[[forward]]\nhost = -1\nguest = 80\n",
		"[[forward]]\nhost = \"eighty\"\nguest = 80\n",
		"[[forward]]\nhost = 8080\nbind = \"0.0.0.0\"\n",
	} {
		if _, err := loadForward(t, body); err == nil {
			t.Errorf("accepted:\n%s", body)
		}
	}
}

// There is no bind key, and the refusal for one is the ordinary unknown-key
// message — which names the keys that do exist, so the reader learns the shape
// rather than only that they were wrong.
func TestNoBindKeyInTheFile(t *testing.T) {
	_, err := loadForward(t, "[[forward]]\nhost = 8080\nguest = 80\nbind = \"0.0.0.0\"\n")
	if err == nil {
		t.Fatal("bind was accepted in the file; --p-bind is the only way to widen this")
	}
	for _, want := range []string{"bind", "host", "guest"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

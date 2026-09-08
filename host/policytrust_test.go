package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/config"
)

// D101: a discovered policy file that binds secrets is refused until the
// person approves it — at the terminal, or with `kelyfos trust`.

func d101Policy(t *testing.T, body string) (*config.Config, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), config.FileName)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, path
}

const d101Body = "[sandbox]\nallow = [\"api.github.com\"]\nsecrets = [\"GITHUB_TOKEN@api.github.com\"]\n"

func TestD101_ADiscoveredFileWithSecretsIsRefusedNonInteractively(t *testing.T) {
	cfg, path := d101Policy(t, d101Body)
	root := t.TempDir()
	var out strings.Builder
	err := approvePolicySecretsWith(cfg, path, root, strings.NewReader(""), &out, false)
	if err == nil {
		t.Fatal("an unapproved file's secrets were accepted with nobody to ask")
	}
	for _, want := range []string{"kelyfos trust " + path, "--policy " + path, "GITHUB_TOKEN", "api.github.com"} {
		if !strings.Contains(err.Error()+out.String(), want) {
			t.Errorf("the refusal does not say %q:\n%v\n%s", want, err, out.String())
		}
	}
	if strings.Contains(out.String(), "ghp_") {
		t.Error("a value reached the terminal")
	}
	if ok, _ := config.SecretsTrusted(root, path); ok {
		t.Error("a refusal recorded an approval")
	}
}

func TestD101_AnInteractiveYesRecordsTheApproval(t *testing.T) {
	cfg, path := d101Policy(t, d101Body)
	root := t.TempDir()
	var out strings.Builder
	// The reader carries more than one line, and only the first is consumed:
	// what follows belongs to whatever reads stdin next.
	in := strings.NewReader("y\nthe agent's own input\n")
	if err := approvePolicySecretsWith(cfg, path, root, in, &out, true); err != nil {
		t.Fatalf("a yes was refused: %v", err)
	}
	if rest, _ := d101Rest(in); rest != "the agent's own input\n" {
		t.Errorf("the prompt consumed past its line: %q left", rest)
	}
	if ok, err := config.SecretsTrusted(root, path); err != nil || !ok {
		t.Fatalf("the yes was not recorded: ok=%v err=%v", ok, err)
	}
	// Approved, the file is silent next time.
	out.Reset()
	if err := approvePolicySecretsWith(cfg, path, root, strings.NewReader(""), &out, false); err != nil {
		t.Fatalf("an approved file was refused: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("an approved file still prompted: %s", out.String())
	}
}

func TestD101_AnInteractiveNoRefuses(t *testing.T) {
	cfg, path := d101Policy(t, d101Body)
	root := t.TempDir()
	var out strings.Builder
	for _, answer := range []string{"n\n", "\n", "nope\n"} {
		if err := approvePolicySecretsWith(cfg, path, root, strings.NewReader(answer), &out, true); err == nil {
			t.Errorf("answer %q approved the file", answer)
		}
	}
}

func TestD101_AFileWithoutSecretsIsNotAskedAbout(t *testing.T) {
	cfg, path := d101Policy(t, "[sandbox]\nallow = [\"api.github.com\"]\nworkspace = \".\"\n")
	root := t.TempDir()
	var out strings.Builder
	if err := approvePolicySecretsWith(cfg, path, root, strings.NewReader(""), &out, false); err != nil {
		t.Fatalf("a file binding nothing was refused: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("a file binding nothing prompted: %s", out.String())
	}
}

func TestD101_ATeamAgentsSecretsCountToo(t *testing.T) {
	cfg, path := d101Policy(t, "[team]\nname = \"t\"\n\n[[team.agent]]\nname = \"a\"\nallow = [\"x.example\"]\n"+
		"secrets = [\"T@x.example\"]\n")
	var out strings.Builder
	err := approvePolicySecretsWith(cfg, path, t.TempDir(), strings.NewReader(""), &out, false)
	if err == nil || !strings.Contains(out.String(), "agent a") {
		t.Fatalf("a team agent's binding was not gated or not named: err=%v out=%s", err, out.String())
	}
}

func d101Rest(r *strings.Reader) (string, error) {
	b := make([]byte, r.Len())
	n, err := r.Read(b)
	return string(b[:n]), err
}

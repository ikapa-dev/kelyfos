//go:build darwin

package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The Linux layer, owned by kelyfos so a macOS user never types limactl (P6-12).
//
// Firecracker needs Linux and /dev/kvm, so on a Mac there is a VM underneath and
// somebody has to look after it. The owner's ruling is that the somebody is not
// the user: `kelyfos doctor` provisions it, starts it, stops it and reports on
// it, and prints the in-VM doctor's own output so one command answers the
// question a person actually has, which is "can I run this".
//
// The configuration is embedded rather than read from the source tree, because
// somebody who downloaded a binary has no source tree. dev/lima.yaml stays the
// file a developer edits and this is a copy of it, which is a second copy of the
// truth — so drift is detected rather than hoped against: Lima freezes the
// template into the instance at creation, and an instance made months ago is
// running whatever the file said then. This machine already carries one.

//go:embed lima.yaml
var limaConfig string

const instanceName = "kelyfos-dev"

// limaAvailable reports whether the tool this layer needs is installed.
func limaAvailable() (string, error) {
	path, err := exec.LookPath("limactl")
	if err != nil {
		return "", fmt.Errorf("limactl is not on your PATH.\n" +
			"    brew install lima\n" +
			"    then: kelyfos doctor --setup")
	}
	return path, nil
}

// limaState is what the layer is doing now, in one word.
func limaState() (string, error) {
	out, err := exec.Command("limactl", "list", "--format", "{{.Name}}\t{{.Status}}", instanceName).Output()
	if err != nil {
		return "absent", nil // limactl exits non-zero for an instance it does not have
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 2 {
		return "absent", nil
	}
	return strings.ToLower(fields[1]), nil
}

// limaDrifted reports whether the running instance was made from a different
// configuration than the one this binary carries.
//
// This is the check the owner asked for by name, and it is not hypothetical:
// Lima copies the template into the instance directory at creation and never
// looks at the original again, so an instance provisioned before a change is
// running the old shape with no sign that it is. A layer that silently differs
// from its description is the same defect as a document that does — which is
// what this whole phase is about.
func limaDrifted() (bool, string) {
	want := configDigest()
	got, err := os.ReadFile(markerPath())
	switch {
	case err != nil:
		// No marker at all: made by hand, or by a kelyfos from before this
		// command owned the layer. Reported as its own answer rather than as
		// drift, because "I do not know what this was made from" and "this was
		// made from something else" are different things to tell somebody.
		return true, "this instance was not created by `kelyfos doctor`, so what it was made from is unknown.\n" +
			"    It may be fine. To bring it under management, recreate it:\n" +
			"        kelyfos doctor --recreate    (stops it, deletes it, provisions it again)"
	case strings.TrimSpace(string(got)) != want:
		return true, fmt.Sprintf("made from a different configuration (%s, this binary carries %s).\n"+
			"    Lima freezes the template into the instance at creation and never looks at the\n"+
			"    original again, so this one keeps what it was made with until it is recreated:\n"+
			"        kelyfos doctor --recreate",
			short(strings.TrimSpace(string(got))), short(want))
	}
	return false, ""
}

// configDigest identifies the configuration this binary carries.
func configDigest() string {
	sum := sha256.Sum256([]byte(limaConfig))
	return hex.EncodeToString(sum[:])
}

// markerPath is where the digest of the configuration an instance was made from
// is recorded.
//
// Beside the instance rather than in it, and written by this command rather than
// read out of Lima's own frozen copy — because Lima normalises a template when
// it freezes it, filling in defaults and reordering, so the frozen file never
// matches the one it came from. Comparing those two digests would report drift
// for every instance including one created a second ago, which is a check that
// can only ever say yes.
func markerPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".lima", instanceName, "kelyfos-template.sha256")
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

// limaSetup provisions and starts the layer.
func limaSetup(recreate bool) error {
	if _, err := limaAvailable(); err != nil {
		return err
	}
	state, _ := limaState()

	if recreate && state != "absent" {
		fmt.Printf("stopping %s…\n", instanceName)
		_ = run("limactl", "stop", "-f", instanceName)
		fmt.Printf("deleting %s…\n", instanceName)
		if err := run("limactl", "delete", instanceName); err != nil {
			return err
		}
		state = "absent"
	}

	switch state {
	case "running":
		fmt.Printf("%s is already running\n", instanceName)
	case "absent":
		// Written to a temp file rather than piped, because `limactl create`
		// names the instance after the file it was given.
		dir, err := os.MkdirTemp("", "kelyfos-lima-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		path := filepath.Join(dir, instanceName+".yaml")
		if err := os.WriteFile(path, []byte(limaConfig), 0o644); err != nil {
			return err
		}
		fmt.Printf("provisioning %s — this takes a few minutes the first time\n", instanceName)
		if err := run("limactl", "start", "--tty=false", path); err != nil {
			return err
		}
		// What it was made from, recorded now, so a later run can tell whether
		// the binary has moved on.
		if m := markerPath(); m != "" {
			if err := os.WriteFile(m, []byte(configDigest()+"\n"), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "kelyfos: could not record the layer's configuration digest: %v\n", err)
			}
		}
	default:
		fmt.Printf("starting %s (was %s)…\n", instanceName, state)
		if err := run("limactl", "start", "--tty=false", instanceName); err != nil {
			return err
		}
	}
	return limaBootstrap()
}

// limaBootstrap installs what the layer needs to build and run KelyfOS.
//
// Inside the VM rather than on the Mac, because that is where the guest runs.
// Idempotent: every step is a package manager being asked for something it may
// already have.
func limaBootstrap() error {
	fmt.Println("checking the layer's own tools…")
	script := `set -e
missing=""
for t in firecracker mke2fs debugfs ip nft; do command -v $t >/dev/null || missing="$missing $t"; done
command -v go >/dev/null || missing="$missing go"
if [ -n "$missing" ]; then
  echo "the Linux layer is missing:$missing"
  echo "install them with the repository's own scripts, inside the layer:"
  echo "    limactl shell ` + instanceName + ` -- bash dev/install-build-deps.sh"
  echo "    limactl shell ` + instanceName + ` -- bash dev/install-firecracker.sh"
  exit 1
fi
echo "the layer has firecracker, e2fsprogs, ip, nft and go"`
	return run("limactl", "shell", instanceName, "--", "bash", "-c", script)
}

// limaStop stops the layer without destroying it.
func limaStop() error {
	if _, err := limaAvailable(); err != nil {
		return err
	}
	state, _ := limaState()
	if state == "absent" {
		return fmt.Errorf("there is no %s instance to stop", instanceName)
	}
	return run("limactl", "stop", instanceName)
}

// limaDoctor asks the in-VM kelyfos how the machine that matters is doing.
//
// The whole point of the layer is that the guest runs there, so the checks that
// mean anything run there too. Printing them here is what makes one command on
// a Mac answer the question a person actually has.
func limaDoctor(arch string) error {
	state, _ := limaState()
	if state != "running" {
		return fmt.Errorf("%s is %s; start it with: kelyfos doctor --setup", instanceName, state)
	}
	fmt.Println("\n--- the Linux layer's own doctor ---")
	cmd := exec.Command("limactl", "shell", instanceName, "--", "bash", "-lc",
		"cd /Users/*/dev/labs/KelyfOS 2>/dev/null || cd ~; "+
			"if command -v kelyfos >/dev/null; then kelyfos doctor --arch "+arch+"; "+
			"elif [ -x ./bin/kelyfos ]; then ./bin/kelyfos doctor --arch "+arch+"; "+
			"else echo 'kelyfos is not built inside the layer yet:'; "+
			"echo '    limactl shell "+instanceName+" -- make cli'; fi")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ikapa-dev/kelyfos/internal/config"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// trustCmd records, revokes or lists the discovered policy files whose secrets
// may be bound (D101).
func trustCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos trust", flag.ExitOnError)
	var (
		revoke = fs.Bool("revoke", false, "forget an approval")
		list   = fs.Bool("list", false, "print every approved file, with the digest each approval is bound to")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos trust <kelyfos.toml>
       kelyfos trust --revoke <kelyfos.toml>
       kelyfos trust --list

A kelyfos.toml that kelyfos finds by walking up from the working directory —
the one a cloned repository carries — may name your environment variables and
the domains they are sent to. Such a file is not believed about that on its own
say-so: its secrets are bound only once you have approved it, here or when
kelyfos run asks you at the terminal. The approval is bound to the file's path
and to the digest of its contents, so a file that changes has to be approved
again. Naming a file with --policy is the same decision made on the command
line and needs no entry here.

What is recorded is a path and a hash — never a value, never a variable's name.

`)
		fs.PrintDefaults()
	}
	paths, err := parseAround(fs, argv)
	if err != nil {
		return err
	}
	root := sandbox.Root()

	if *list {
		entries, err := config.TrustedSecretPolicies(root)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			fmt.Printf("no approved policy files (%s)\n", config.SecretTrustFile(root))
			return nil
		}
		for _, e := range entries {
			fmt.Printf("%s\n    sha256 %s · since %s\n", e.Path, e.SHA256, e.Since)
		}
		return nil
	}
	if len(paths) != 1 {
		fs.Usage()
		return &exitError{code: 2}
	}
	path, err := filepath.Abs(paths[0])
	if err != nil {
		return err
	}
	if *revoke {
		found, err := config.RevokeSecretTrust(root, path)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("%s was not approved, so there is nothing to revoke", path)
		}
		fmt.Printf("forgot %s\n", path)
		return nil
	}

	// Through the one gate every door reads a policy through (loadPolicyAt).
	// Named, so the writability half of config.Trust applies — naming a file
	// anybody can rewrite does not make it safe — and the ownership half and
	// the secrets gate do not, for the reason --policy skips them: naming the
	// file is the decision this command records.
	cfg, err := loadPolicyAt(path)
	if err != nil {
		return err
	}
	if cfg == nil {
		return fmt.Errorf("cannot approve %s: no such file", path)
	}
	if !cfg.DeclaresSecrets() {
		return errors.New(path + " binds no secrets, so there is nothing to approve: its workspace and " +
			"plugin paths are scoped to its own tree, and its allowlist is not a credential")
	}
	printPolicyReach(os.Stdout, cfg)
	entry, err := config.TrustSecrets(root, path)
	if err != nil {
		return err
	}
	fmt.Printf("approved: the secrets above may be bound from this file while its sha256 stays %s\n"+
		"    recorded in %s\n", entry.SHA256, config.SecretTrustFile(root))
	return nil
}

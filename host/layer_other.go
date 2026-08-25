//go:build !darwin

package main

import "fmt"

// There is no layer on a machine that runs the guest directly (P6-12).
//
// The flags exist here rather than being absent so that a person who learned
// them on a Mac gets a sentence rather than "flag provided but not defined" —
// a tool whose flags depend on the platform is a tool somebody has to remember
// two versions of.
func layerCommand(setup, recreate, stop bool, arch string) error {
	return fmt.Errorf("--setup, --recreate and --stop manage the Lima layer that macOS needs.\n" +
		"    This machine runs the guest directly, so there is no layer to manage:\n" +
		"    kelyfos doctor")
}

// layerReport is only reached on a platform with no layer and no KVM, which is
// neither Linux nor macOS. The platform check above has already said so.
func layerReport(arch string) error { return &exitError{code: 1} }

//go:build darwin

package main

import "fmt"

// layerCommand is `kelyfos doctor` acting on the Linux layer (P6-12).
func layerCommand(setup, recreate, stop bool, arch string) error {
	switch {
	case stop:
		return limaStop()
	case setup, recreate:
		if err := limaSetup(recreate); err != nil {
			return err
		}
		return limaDoctor(arch)
	}
	return nil
}

// layerReport is what `kelyfos doctor` says on a Mac.
//
// Not "this is macOS, go away". The layer is this command's to look after, so
// this reports its state, whether it has drifted from the configuration this
// binary carries, and then hands over to the in-VM doctor — because the checks
// that mean anything are the ones that run where the guest runs.
func layerReport(arch string) error {
	fmt.Println("  the guest runs in a Linux layer on this machine, and kelyfos looks after it")
	fmt.Println()
	if _, err := limaAvailable(); err != nil {
		fmt.Printf("  [FAIL] %-22s %v\n", "linux layer", err)
		return &exitError{code: 1}
	}
	state, _ := limaState()
	switch state {
	case "running":
		fmt.Printf("  [ok  ] %-22s %s is running\n", "linux layer", instanceName)
	case "absent":
		fmt.Printf("  [FAIL] %-22s no %s instance yet\n", "linux layer", instanceName)
		fmt.Printf("         kelyfos doctor --setup\n")
		return &exitError{code: 1}
	default:
		fmt.Printf("  [FAIL] %-22s %s is %s\n", "linux layer", instanceName, state)
		fmt.Printf("         kelyfos doctor --setup\n")
		return &exitError{code: 1}
	}

	if drifted, why := limaDrifted(); drifted {
		fmt.Printf("  [FAIL] %-22s %s\n", "layer configuration", why)
		return &exitError{code: 1}
	}
	fmt.Printf("  [ok  ] %-22s matches the configuration this binary carries\n", "layer configuration")

	return limaDoctor(arch)
}

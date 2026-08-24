package sandbox

// restoreWarning is what a restore has to say about the machine it brought
// back, or "" when there is nothing to say (P5-7, D32).
//
// A pure function of the two things the guest reported, so the wording and the
// condition can be tested without a machine — the case that matters most is
// also the one hardest to stage, because staging it needs a guest built before
// this version existed.
func restoreWarning(profile, profileError string) string {
	switch {
	case profileError != "":
		// The guest is current but its kernel could not give it a profile. Its
		// supervisor refuses every spawn, so this is a machine that will run
		// nothing rather than one that runs things unconfined.
		return "this machine cannot confine what it runs (" + profileError + ").\n" +
			"    Its supervisor came up without a profile, so commands inside it are refused " +
			"rather than run. Rebuild the image: the guest kernel needs CONFIG_SECURITY_LANDLOCK=y " +
			"and landlock named in CONFIG_LSM."
	case profile == "":
		// The guest predates confinement entirely. Restoring a snapshot does
		// not upgrade the guest inside it, and no amount of host-side work can
		// confine a supervisor with no such code in it.
		return "this snapshot predates guest confinement, so the machine restored from it " +
			"confines nothing it spawns.\n" +
			"    The host walls are unchanged — the jailer, the VMM's own syscall filter, the " +
			"egress policy and the cgroup all still apply. To gain the guest profile as well, " +
			"re-create the snapshot under this version: boot a fresh machine, prepare it, and " +
			"`kelyfos snapshot save` over the old name."
	}
	return ""
}

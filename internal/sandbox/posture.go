package sandbox

// postureSource is where an unconfined guest came from. The two cases need
// different words because they need different fixes: a snapshot is re-created,
// an image is fetched again.
type postureSource int

const (
	fromSnapshot postureSource = iota
	fromImage
)

// postureWarning is what a run has to say about a machine that confines nothing,
// or "" when there is nothing to say (P5-7, D32; the cold-boot case added at
// P5-4).
//
// A pure function of the two things the guest reported, so the wording and the
// condition can be tested without a machine — the cases that matter most are
// also the ones hardest to stage, because staging them needs a guest built
// before this version existed.
func postureWarning(src postureSource, profile, profileError string) string {
	switch {
	case profileError != "":
		// The guest is current but its kernel could not give it a profile. Its
		// supervisor refuses every spawn, so this is a machine that will run
		// nothing rather than one that runs things unconfined.
		return "this machine cannot confine what it runs (" + profileError + ").\n" +
			"    Its supervisor came up without a profile, so commands inside it are refused " +
			"rather than run. Rebuild the image: the guest kernel needs CONFIG_SECURITY_LANDLOCK=y " +
			"and landlock named in CONFIG_LSM."
	case profile == "" && src == fromSnapshot:
		// The guest predates confinement entirely. Restoring a snapshot does
		// not upgrade the guest inside it, and no amount of host-side work can
		// confine a supervisor with no such code in it.
		return "this snapshot predates guest confinement, so the machine restored from it " +
			"confines nothing it spawns.\n" +
			"    The host walls are unchanged — the jailer, the VMM's own syscall filter, the " +
			"egress policy still apply, and the cgroup where the policy set a quota. To gain the guest profile as well, " +
			"re-create the snapshot under this version: boot a fresh machine, prepare it, and " +
			"`kelyfos snapshot save` over the old name."
	case profile == "":
		// Same absence, different fix: this is a guest image older than the
		// CLI booting it, which is what a cached image or a pinned older
		// release gives you. Said out loud because the alternative is a run
		// that looks exactly like a confined one and is not.
		return "this guest image predates guest confinement, so nothing this machine spawns " +
			"is confined.\n" +
			"    The host walls are unchanged — the jailer, the VMM's own syscall filter, the " +
			"egress policy still apply, and the cgroup where the policy set a quota. For the guest profile as well, " +
			"update the image: `bash dev/fetch-image.sh`, or `make image` to build one."
	}
	return ""
}

package config

import (
	"os"
	"syscall"
)

// fileUID reads the owning uid out of an os.FileInfo, or reports that this
// platform did not say. Split into its own file because syscall.Stat_t is not
// portable and Trust's rule is (P7-17/F21).
func fileUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// fileGID is fileUID's counterpart, for the group half of the writability rule.
func fileGID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Gid), true
}

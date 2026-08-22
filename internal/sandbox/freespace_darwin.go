package sandbox

import "golang.org/x/sys/unix"

// freeBytes on macOS exists so `kelyfos doctor` can run there. Nothing else in
// KelyfOS does — Firecracker is Linux-only — but doctor is the first command a
// new user runs, and on a Mac they have no Linux layer yet, so refusing to
// start is precisely the wrong response.
func freeBytes(dir string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

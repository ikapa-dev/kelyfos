//go:build linux

package main

import "fmt"

// The seccomp return actions, from include/uapi/linux/seccomp.h. The low 16
// bits are data (an errno, a trap number); the action is the top half.
const (
	retKillProcess = 0x80000000
	retKillThread  = 0x00000000
	retTrap        = 0x00030000
	retErrno       = 0x00050000
	retUserNotif   = 0x7fc00000
	retTrace       = 0x7ff00000
	retLog         = 0x7ffc0000
	retAllow       = 0x7fff0000

	retActionMask = 0xffff0000
	retDataMask   = 0x0000ffff
)

// Two sentinels for things that are not actions at all. They sit in the
// 0xffff0000 action class, which the kernel defines no meaning for, so a real
// filter returning one would be rendered as the unknown action it is.
const (
	actionMalformed = 0xffff0001
	actionUnknown   = 0xffff0002
)

func actionName(v uint32) string {
	switch v {
	case actionMalformed:
		return "MALFORMED"
	case actionUnknown:
		return "UNRESOLVED"
	}
	switch v & retActionMask {
	case retKillProcess:
		return "KILL_PROCESS"
	case retKillThread:
		return "KILL_THREAD"
	case retTrap:
		return fmt.Sprintf("TRAP(%d)", v&retDataMask)
	case retErrno:
		return fmt.Sprintf("ERRNO(%d)", v&retDataMask)
	case retUserNotif:
		return "USER_NOTIF"
	case retTrace:
		return "TRACE"
	case retLog:
		return "LOG"
	case retAllow:
		return "ALLOW"
	}
	return fmt.Sprintf("UNKNOWN(0x%08x)", v)
}

func isAllow(v uint32) bool { return v&retActionMask == retAllow }

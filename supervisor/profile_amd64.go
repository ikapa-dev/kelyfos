//go:build linux && amd64

package main

// auditArch is AUDIT_ARCH_X86_64 (include/uapi/linux/audit.h). A seccomp filter that
// does not pin the architecture can be walked past on a machine that runs more
// than one ABI.
const auditArch = 0xc000003e

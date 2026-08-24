# KelyfOS — pinned toolchain versions (P0-6).
#
# This file is the single source of truth for every external component the build
# depends on. No target may reach for "latest": floating versions make a build
# that worked yesterday fail today and turn bisecting an upstream regression into
# archaeology. Every value uses ?= so a version can be overridden in the
# environment for a one-off experiment without editing this file.
#
# Bumping anything here is a deliberate act: change the version AND its checksum
# in the same commit, and record the reason in the PLAN.html progress log.

# --- Buildroot -------------------------------------------------------------
# The LTS line, and "LTS" here is buildroot.org's own word rather than an
# inference from the version number. Read on 2026-08-24, its download page lists
# exactly three: candidate 2026.08-rc1, stable 2026.05.1 (EOL September 2026),
# and long-term support 2025.02.17, EOL March 2028. The 2026.02.x line this
# project built on until now is on neither list. F-D35 caught the assumption;
# F-D40 ruled the move; D28 records what the move cost.
#
# buildroot.org publishes only a PGP-signed message, not a .sha256 file — the
# digest below is transcribed from buildroot-2025.02.17.tar.xz.sign, signed by
# the same key (fingerprint ending A500 D6EE 9CB0 E540) that signed the
# 2026.02.3 release this project was already trusting; that message's digest for
# 2026.02.3 matches the value pinned here before this change, which is how the
# transcription method was checked against a known-good value.
BUILDROOT_VERSION ?= 2025.02.17
BUILDROOT_SHA256 ?= 13618704563ad0b928a4564aaa73e2db97e12e8df0ed5ae874744a83964a023a

# --- Guest kernel ----------------------------------------------------------
# 6.12 is a longterm line on kernel.org with a projected EOL of December 2028 —
# the same projected EOL as 6.18, which this project ran until now. It is pinned
# here rather than 6.18 because the Buildroot LTS line above supports kernel
# header series only to 6.12, and a build system on a supported line matters
# more than six release cycles of a kernel whose support window ends on the same
# date. That trade is D28; it is a real cost, not a free move.
#
# Pinned to an exact patch release; digest from the kernel.org sha256sums.asc
# for v6.x, the same file the previous pin was read from.
LINUX_VERSION ?= 6.12.105
LINUX_SHA256 ?= eb36801e119529b13513c3459dc20e2a32f7053629f3aabb63ea501a4d88f63d

# --- Firecracker -----------------------------------------------------------
# The VMM the guest is built for. Plan floor is >= 1.7. Release tarballs ship
# their own .sha256.txt, which dev/install-firecracker.sh verifies.
FIRECRACKER_VERSION ?= v1.16.1

# --- Go --------------------------------------------------------------------
# Toolchain for the supervisor (guest PID 1) and the kelyfos CLI. Installed from
# the official tarball by dev/install-go.sh, not from the distribution package:
# Ubuntu 24.04 ships Go 1.22, which is too old to honour a go.mod toolchain line.
GO_VERSION ?= 1.27.0
GO_SHA256_aarch64 ?= 51798d2c42d0e1c6ed7fd9f48728b4193abac9e8aad6dbac2fe96a81f5909bda
GO_SHA256_x86_64 ?= 675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685

# --- govulncheck -----------------------------------------------------------
# The vulnerability scanner, run by `make vuln` and by .github/workflows/
# security.yml on a schedule (P6-2). It is a check rather than a build input, so
# it never enters go.mod — `go run <module>@<version>` keeps the pin here and the
# dependency graph unchanged.
#
# Pinned from the module proxy, not from GitHub releases, and the difference is
# not academic: golang/vuln's releases page stops at v1.1.4 (January 2025) while
# proxy.golang.org reports v1.7.0 (2026-08-13). Reading the familiar page would
# have pinned a scanner nineteen months stale and called it current.
GOVULNCHECK_VERSION ?= v1.7.0

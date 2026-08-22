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
# The 2026.02.x line is Buildroot's long-term-supported release (the yearly .02
# release), maintained with fixes for a year. Preferred over the newer 2026.05.x
# for a project whose selling point is reproducible images.
# buildroot.org publishes only a PGP-signed message, not a .sha256 file — the
# digest below is transcribed from buildroot-2026.02.3.tar.xz.sign.
BUILDROOT_VERSION ?= 2026.02.3
BUILDROOT_SHA256 ?= 5a59e7501b0b4ec52c41f4bfa79412320e0b37eae5f719605a258e8d0c6fc7fb

# --- Guest kernel ----------------------------------------------------------
# 6.18 is the newest longterm line on kernel.org. Pinned to an exact patch
# release; digest from the kernel.org sha256sums.asc for v6.x.
LINUX_VERSION ?= 6.18.45
LINUX_SHA256 ?= 30fa4a56579ca614ac125a12614f7f6466f87ab1278aef7b951dd74156deab33

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

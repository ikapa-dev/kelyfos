# KelyfOS — top-level build entry point.
#
# Everything here runs on Linux (the Lima VM on macOS, WSL2 on Windows, or a bare
# Linux/KVM box). See dev/lima.yaml and dev/wsl2.md.
#
# Targets are stubs until phase 1 (P1-1 onward); each prints what it will do.

# Pinned toolchain versions (P0-6). Hard include: a build with no version policy
# is not a build this project is willing to make.
include versions.mk

# Architecture. Defaults to the build host: aarch64 is primary (D9), x86_64 is
# cross-built and gated from P1-8 onward.
HOST_ARCH := $(shell uname -m | sed -e 's/^arm64$$/aarch64/' -e 's/^amd64$$/x86_64/')
ARCH      ?= $(HOST_ARCH)

# Image flavor: base, dev, (browser later).
FLAVOR ?= base

# Where artifacts land, and where the heavy Buildroot trees live. BUILD_DIR is
# deliberately overridable: on macOS the repo sits on a virtiofs mount, and
# Buildroot must not build there (device nodes, hardlinks, fakeroot, IO volume).
OUT_DIR   ?= $(CURDIR)/bin
BUILD_DIR ?= $(HOME)/.cache/kelyfos/build/$(ARCH)

# Kernel artifact differs per architecture and both must be uncompressed:
# Firecracker boots the ELF vmlinux on x86_64 and the raw Image on aarch64.
ifeq ($(ARCH),aarch64)
KERNEL_ARTIFACT := Image
else
KERNEL_ARTIFACT := vmlinux
endif

.DEFAULT_GOAL := help
.PHONY: help versions toolchain image run clean test

help: ## Show this target list
	@echo "KelyfOS — targets (ARCH=$(ARCH), FLAVOR=$(FLAVOR))"
	@echo
	@grep -hE '^[a-z][a-zA-Z0-9_-]*:.*?## ' $(MAKEFILE_LIST) \
	  | sort \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Variables: ARCH={aarch64|x86_64}  FLAVOR={base|dev}  BUILD_DIR=$(BUILD_DIR)"
	@echo "           OUT_DIR=$(OUT_DIR)"
	@echo
	@$(MAKE) --no-print-directory versions

versions: ## Print the pinned toolchain versions (versions.mk)
	@echo "Pinned (versions.mk):"
	@echo "  buildroot    $(BUILDROOT_VERSION)"
	@echo "  linux        $(LINUX_VERSION)"
	@echo "  firecracker  $(FIRECRACKER_VERSION)"
	@echo "  go           $(GO_VERSION)"

toolchain: ## Download and prepare the pinned Buildroot tree (long, once per arch)
	@echo "[stub] toolchain: fetch Buildroot $(BUILDROOT_VERSION), verify sha256,"
	@echo "                  unpack into $(BUILD_DIR), apply image/buildroot/ as an"
	@echo "                  external tree and configure for ARCH=$(ARCH). (P1-1)"

image: ## Build the guest kernel + rootfs.ext4 for ARCH/FLAVOR
	@echo "[stub] image: build linux $(LINUX_VERSION) as $(KERNEL_ARTIFACT) (uncompressed)"
	@echo "              and rootfs.ext4 for"
	@echo "              ARCH=$(ARCH) FLAVOR=$(FLAVOR), rootfs under 200 MB,"
	@echo "              output to $(OUT_DIR). (P1-2, P1-4)"

run: ## Boot a microVM from the built image under Firecracker
	@echo "[stub] run: build the kelyfos CLI, write the Firecracker machine config"
	@echo "            (vsock guest_cid=3 over a host-side UDS) and boot the guest,"
	@echo "            tearing down cleanly on Ctrl-C. (P1-5)"

test: ## Run the test suite
	@echo "[stub] test: Go unit tests for host/ and supervisor/, plus the boot smoke"
	@echo "             test (kelyfos exec \"uname -a\") for ARCH=$(ARCH). (P1-6, P3-6)"

clean: ## Remove build output (keeps the downloaded Buildroot toolchain)
	@echo "[stub] clean: remove $(OUT_DIR) and the built artifacts in $(BUILD_DIR),"
	@echo "              leaving the downloaded toolchain cache in place."

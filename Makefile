# KelyfOS — top-level build entry point.
#
# Everything here runs on Linux (the Lima VM on macOS, WSL2 on Windows, or a bare
# Linux/KVM box). See dev/lima.yaml and dev/wsl2.md.
#
# Targets are stubs until phase 1 (P1-1 onward); each prints what it will do.

# Version stamped into the CLI. A dev build says so rather than claiming a
# release number it does not have.
KELYFOS_VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)

# Pinned toolchain versions (P0-6). Hard include: a build with no version policy
# is not a build this project is willing to make.
include versions.mk

# Architecture. Defaults to the build host: aarch64 is primary (D9), x86_64 is
# cross-built and gated from P1-8 onward.
HOST_ARCH := $(shell uname -m | sed -e 's/^arm64$$/aarch64/' -e 's/^amd64$$/x86_64/')
ARCH      ?= $(HOST_ARCH)

# Image flavor: base, dev, (browser later).
FLAVOR ?= base

# Go's name for the same architectures.
ifeq ($(ARCH),aarch64)
GOARCH := arm64
else
GOARCH := amd64
endif

# Where artifacts land, and where the heavy Buildroot trees live. BUILD_DIR is
# deliberately overridable: on macOS the repo sits on a virtiofs mount, and
# Buildroot must not build there (device nodes, hardlinks, fakeroot, IO volume).
OUT_DIR       ?= $(CURDIR)/bin
KELYFOS_CACHE ?= $(HOME)/.cache/kelyfos
DL_DIR        ?= $(KELYFOS_CACHE)/dl
BR_SRC        ?= $(KELYFOS_CACHE)/buildroot-$(BUILDROOT_VERSION)
BUILD_DIR     ?= $(KELYFOS_CACHE)/build/$(ARCH)

# Buildroot invocation. BR2_EXTERNAL must be absolute: Buildroot resolves a
# relative one against its own source directory, not ours. BR2_DL_DIR is shared
# across architectures — the source tarballs are identical.
# Kernel series (6.18.45 -> 6.18 -> 6_18), used to pick Buildroot's kernel-header
# series symbol. Derived, never written by hand.
LINUX_SERIES    := $(word 1,$(subst ., ,$(LINUX_VERSION))).$(word 2,$(subst ., ,$(LINUX_VERSION)))
LINUX_SERIES_US := $(subst .,_,$(LINUX_SERIES))

# Guest image artifacts live on local disk, never on the macOS virtiofs mount:
# Firecracker reads the rootfs as a block device on every boot, and P1-7 measures
# that boot in milliseconds.
IMAGE_DIR      ?= $(KELYFOS_CACHE)/out/$(ARCH)
FLAVOR_OVERLAY := $(CURDIR)/image/flavors/$(FLAVOR)/overlay
GUEST_OVERLAY  := $(BUILD_DIR)/kelyfos-overlay
OVERLAY_DIRS   := $(FLAVOR_OVERLAY) $(GUEST_OVERLAY)

BR_EXTERNAL  := $(CURDIR)/image/buildroot
BR_FRAGMENTS := $(BR_EXTERNAL)/configs/kelyfos_common.fragment \
                $(BR_EXTERNAL)/configs/kelyfos_$(ARCH).fragment
BR_MAKE       = $(MAKE) -C $(BR_SRC) O=$(BUILD_DIR) \
                  BR2_EXTERNAL=$(BR_EXTERNAL) BR2_DL_DIR=$(DL_DIR)

# Kernel artifact differs per architecture and both must be uncompressed:
# Firecracker boots the ELF vmlinux on x86_64 and the raw Image on aarch64.
ifeq ($(ARCH),aarch64)
KERNEL_ARTIFACT := Image
else
KERNEL_ARTIFACT := vmlinux
endif

.DEFAULT_GOAL := help
.PHONY: help versions toolchain kernel supervisor cli image run bench clean test linux-only fetch-kernel

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

toolchain: linux-only fetch-kernel $(BUILD_DIR)/.config ## Download and prepare the pinned Buildroot tree (long, once per arch)
	@echo "==> building the $(ARCH) cross toolchain (long; once per architecture)"
	+$(BR_MAKE) toolchain
	@echo "==> toolchain ready: $$($(BUILD_DIR)/host/bin/*-linux-*-gcc --version 2>/dev/null | head -1)"

# Buildroot's own tree, fetched and checksum-verified against versions.mk.
$(BR_SRC)/Makefile:
	@$(CURDIR)/image/fetch-buildroot.sh \
	  "$(BUILDROOT_VERSION)" "$(BUILDROOT_SHA256)" "$(DL_DIR)" "$(dir $(BR_SRC))"

# The per-arch configuration, assembled from the shared fragment plus the arch
# fragment. Regenerated whenever either fragment changes, so an edit to the
# config cannot be silently ignored by a stale build directory.
$(BUILD_DIR)/.config: $(BR_SRC)/Makefile $(BR_FRAGMENTS)
	@mkdir -p $(BUILD_DIR)
	@echo "==> configuring buildroot for ARCH=$(ARCH)"
	@cat $(BR_FRAGMENTS) \
	  | sed -e 's/@LINUX_VERSION@/$(LINUX_VERSION)/g' \
	        -e 's/@LINUX_SERIES_US@/$(LINUX_SERIES_US)/g' \
	        -e 's|@OVERLAY_DIRS@|$(OVERLAY_DIRS)|g' \
	  > $(BUILD_DIR)/kelyfos_defconfig
	$(BR_MAKE) defconfig BR2_DEFCONFIG=$(BUILD_DIR)/kelyfos_defconfig
	@$(CURDIR)/image/check-config.sh $(BUILD_DIR)/kelyfos_defconfig $(BUILD_DIR)/.config

# The kernel tarball, verified against versions.mk before Buildroot sees it.
# Buildroot skips hash checks for custom versions, so this is the only integrity
# gate the guest kernel gets (decision D12).
fetch-kernel:
	@$(CURDIR)/image/fetch-kernel.sh "$(LINUX_VERSION)" "$(LINUX_SHA256)" "$(DL_DIR)"

kernel: linux-only fetch-kernel $(BUILD_DIR)/.config ## Build just the guest kernel and verify its config
	+$(BR_MAKE) linux
	@$(CURDIR)/image/check-kernel.sh "$(ARCH)" "$(BUILD_DIR)" "$(BR_EXTERNAL)"

linux-only:
	@if [ "$$(uname -s)" != "Linux" ]; then \
	  echo "This target builds a Linux guest image and must run on Linux."; \
	  echo "On macOS use the Lima layer:"; \
	  echo "    limactl shell kelyfos-dev -- make $(MAKECMDGOALS)"; \
	  exit 1; \
	fi

# The guest supervisor, cross-compiled into the generated rootfs overlay.
# CGO_ENABLED=0 makes it static: it must run as the first userspace process on a
# machine where nothing else is loaded yet, and it must not care that the rest of
# the image is musl.
supervisor: ## Cross-compile the guest supervisor into the rootfs overlay
	@mkdir -p $(GUEST_OVERLAY)/sbin $(GUEST_OVERLAY)/.oldroot
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) \
	  go build -trimpath -ldflags="-s -w" \
	    -o $(GUEST_OVERLAY)/sbin/kelyfos-supervisor ./supervisor
	@file $(GUEST_OVERLAY)/sbin/kelyfos-supervisor

image: linux-only supervisor fetch-kernel $(BUILD_DIR)/.config ## Build the guest kernel + rootfs.ext4 for ARCH/FLAVOR
	+$(BR_MAKE)
	@$(CURDIR)/image/check-kernel.sh "$(ARCH)" "$(BUILD_DIR)" "$(BR_EXTERNAL)"
	@mkdir -p $(IMAGE_DIR)
	@cp -f $(BUILD_DIR)/images/$(KERNEL_ARTIFACT) $(IMAGE_DIR)/
	@cp -f $(BUILD_DIR)/images/rootfs.ext4        $(IMAGE_DIR)/
	@$(CURDIR)/image/check-image.sh "$(ARCH)" "$(IMAGE_DIR)" "$(KERNEL_ARTIFACT)"

cli: linux-only ## Build the kelyfos host CLI into bin/
	@mkdir -p $(OUT_DIR)
	CGO_ENABLED=0 go build -trimpath \
	  -ldflags="-s -w -X main.Version=$(KELYFOS_VERSION)" \
	  -o $(OUT_DIR)/kelyfos ./host
	@$(OUT_DIR)/kelyfos version

# Reproducible boot-to-ready timing. The same code path `kelyfos run` uses, so a
# local number and a CI number are the same measurement (decision D15). The
# binding numbers come from the bare-KVM reference runner, not from a laptop.
BENCH_RUNS ?= 10

bench: cli ## Measure cold boot-to-ready (BENCH_RUNS cold boots)
	$(OUT_DIR)/kelyfos bench --runs $(BENCH_RUNS) --arch $(ARCH) --image $(FLAVOR)

run: cli ## Boot a microVM from the built image under Firecracker
	$(OUT_DIR)/kelyfos run --image $(FLAVOR) --arch $(ARCH)

test: ## Run the test suite
	go vet ./...
	go test ./...

clean: ## Remove build output (keeps the downloaded Buildroot toolchain)
	rm -rf $(OUT_DIR) $(IMAGE_DIR) $(GUEST_OVERLAY)
	@echo "removed CLI, images and the generated overlay for ARCH=$(ARCH)"
	@echo "kept the Buildroot tree and download cache under $(KELYFOS_CACHE)"

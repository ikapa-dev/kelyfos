# KelyfOS — top-level build entry point.
#
# Everything here runs on Linux (the Lima VM on macOS, WSL2 on Windows, or a bare
# Linux/KVM box). See dev/lima.yaml and dev/wsl2.md.
#
# The default goal is `help`. The build entry points are `toolchain` (once per
# architecture), `image` and `cli`.

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
BUILD_DIR     ?= $(KELYFOS_CACHE)/build/$(ARCH)-$(FLAVOR)

# Compiler cache, shared by both architectures and every flavor (ccache keys on
# the compiler binary, so the two toolchains simply never collide). Named
# BR_CCACHE_DIR rather than CCACHE_DIR because the latter is ccache's own
# environment variable and Buildroot deliberately renames it to BR_CACHE_DIR to
# keep the two apart. Templated into BR2_CCACHE_DIR by the .config rule below.
BR_CCACHE_DIR ?= $(KELYFOS_CACHE)/ccache

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
RELEASE_TAG    ?= latest
FLAVOR_OVERLAY := $(CURDIR)/image/flavors/$(FLAVOR)/overlay
GUEST_OVERLAY  := $(BUILD_DIR)/kelyfos-overlay
OVERLAY_DIRS   := $(FLAVOR_OVERLAY) $(GUEST_OVERLAY)

BR_EXTERNAL  := $(CURDIR)/image/buildroot
BR_FRAGMENTS := $(BR_EXTERNAL)/configs/kelyfos_common.fragment \
                $(BR_EXTERNAL)/configs/kelyfos_$(ARCH).fragment \
                $(CURDIR)/image/flavors/$(FLAVOR)/buildroot.fragment
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
.PHONY: help versions toolchain kernel supervisor cli image run bench docs cookbook prove-caps prove-team demo-team accept-e2 clean test test-integration linux-only fetch-kernel

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
#
# versions.mk is a prerequisite for the same reason and was missing: the kernel
# version is substituted into this config, so bumping LINUX_VERSION and
# rebuilding produced an image running the *old* kernel and said nothing. Found
# at the E4→E5 seam by bumping 6.18.45 to 6.18.46 and asking the guest what it
# was running.
$(BUILD_DIR)/.config: $(BR_SRC)/Makefile $(BR_FRAGMENTS) $(CURDIR)/versions.mk
	@mkdir -p $(BUILD_DIR)
	@echo "==> configuring buildroot for ARCH=$(ARCH)"
	@cat $(BR_FRAGMENTS) \
	  | sed -e 's/@LINUX_VERSION@/$(LINUX_VERSION)/g' \
	        -e 's/@LINUX_SERIES_US@/$(LINUX_SERIES_US)/g' \
	        -e 's|@OVERLAY_DIRS@|$(OVERLAY_DIRS)|g' \
	        -e 's|@CCACHE_DIR@|$(BR_CCACHE_DIR)|g' \
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
	  go build -trimpath -ldflags="-s -w -X main.Version=$(KELYFOS_VERSION)" \
	    -o $(GUEST_OVERLAY)/sbin/kelyfos-supervisor ./supervisor
	@file $(GUEST_OVERLAY)/sbin/kelyfos-supervisor

image: linux-only supervisor fetch-kernel $(BUILD_DIR)/.config ## Build the guest kernel + rootfs.ext4 for ARCH/FLAVOR
	+$(BR_MAKE)
	@$(CURDIR)/image/check-kernel.sh "$(ARCH)" "$(BUILD_DIR)" "$(BR_EXTERNAL)"
	@mkdir -p $(IMAGE_DIR)
	@cp -f $(BUILD_DIR)/images/$(KERNEL_ARTIFACT) $(IMAGE_DIR)/
	@cp -f $(BUILD_DIR)/images/rootfs.ext4        $(IMAGE_DIR)/
	@$(CURDIR)/image/check-image.sh "$(ARCH)" "$(IMAGE_DIR)" "$(KERNEL_ARTIFACT)"
	@$(CURDIR)/image/write-manifest.sh "$(ARCH)" "$(FLAVOR)" "$(IMAGE_DIR)" "$(KERNEL_ARTIFACT)" "$(BUILDROOT_VERSION)" "$(LINUX_VERSION)"

# Prebuilt guest images from the GitHub release (D20), built from this tree,
# without the 35-minute build. Checksum-verified for integrity, not provenance:
# they are not bit-for-bit what `image` makes here, because the build is not
# reproducible yet (P6-9), and they are not signed (P6-11).
fetch-image: ## Download a prebuilt guest image for ARCH instead of building it
	@$(CURDIR)/dev/fetch-image.sh "$(ARCH)" "$(RELEASE_TAG)"

# Package the built artifacts for a release, arch-tagged so one release can carry
# both, with the sums file fetch-image.sh verifies against.
release-artifacts: ## Stage $(IMAGE_DIR) artifacts + SHA256SUMS into dist/
	@mkdir -p $(CURDIR)/dist
	@gzip -9 -c $(IMAGE_DIR)/$(KERNEL_ARTIFACT) > $(CURDIR)/dist/$(KERNEL_ARTIFACT)-$(ARCH).gz
	@gzip -9 -c $(IMAGE_DIR)/rootfs.ext4        > $(CURDIR)/dist/rootfs-$(ARCH).ext4.gz
	@cp -f $(IMAGE_DIR)/image.json $(CURDIR)/dist/image-$(ARCH).json
	@cd $(CURDIR)/dist && sha256sum $(KERNEL_ARTIFACT)-$(ARCH).gz rootfs-$(ARCH).ext4.gz image-$(ARCH).json >> SHA256SUMS
	@cd $(CURDIR)/dist && ls -la $(KERNEL_ARTIFACT)-$(ARCH).gz rootfs-$(ARCH).ext4.gz

# Static CLI binaries for the release (D20). CGO is already off, so these run
# on any Linux of the right architecture with no runtime dependencies at all —
# which is what lets the quickstart skip installing a Go toolchain.
release-cli: ## Cross-build static kelyfos binaries for both arches into dist/
	@mkdir -p $(CURDIR)/dist
	@for a in amd64:x86_64 arm64:aarch64; do \
	  goarch=$${a%%:*}; uarch=$${a##*:}; \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$goarch go build -trimpath \
	    -ldflags="-s -w -X main.Version=$(KELYFOS_VERSION) \
	                -X main.FirecrackerVersion=$(FIRECRACKER_VERSION)" \
	    -o $(CURDIR)/dist/kelyfos-linux-$$uarch ./host || exit 1; \
	  ( cd $(CURDIR)/dist && sha256sum kelyfos-linux-$$uarch >> SHA256SUMS ); \
	  echo "built dist/kelyfos-linux-$$uarch"; \
	done

cli: linux-only ## Build the kelyfos host CLI into bin/
	@mkdir -p $(OUT_DIR)
	CGO_ENABLED=0 go build -trimpath \
	  -ldflags="-s -w -X main.Version=$(KELYFOS_VERSION) \
	              -X main.FirecrackerVersion=$(FIRECRACKER_VERSION)" \
	  -o $(OUT_DIR)/kelyfos ./host
	@$(OUT_DIR)/kelyfos version

# Reproducible boot-to-ready timing. The same code path `kelyfos run` uses, so a
# local number and a CI number are the same measurement (decision D15). The
# binding numbers come from the bare-KVM reference runner, not from a laptop.
BENCH_RUNS ?= 10

bench: cli ## Measure cold boot-to-ready (BENCH_RUNS cold boots)
	$(OUT_DIR)/kelyfos bench --runs $(BENCH_RUNS) --arch $(ARCH) --image $(FLAVOR)

# The caps are a claim until something tries to exceed each one and the host
# watches it fail (E1-8). Needs the dev flavor, which carries stress-ng.
prove-caps: linux-only cli ## Drive every resource cap past its limit and check it held
	@echo "note: binding numbers come from the bare-KVM CI runner (D15); this run is informational"
	ARCH=$(ARCH) bash $(CURDIR)/dev/prove-caps.sh

# A team's collective cap needs five guests' worth of demand to be exceedable,
# so this one strains the machine harder than prove-caps does (E2-6).
prove-team: linux-only cli ## Drive a five-agent team past its collective CPU cap and check it held
	@echo "note: binding numbers come from the bare-KVM CI runner (D15); this run is informational"
	ARCH=$(ARCH) bash $(CURDIR)/dev/prove-team.sh

# Epic E2's proof: a real five-agent team doing real work, driven through the
# real MCP tools on five real microVMs (E2-9).
demo-team: linux-only cli ## Run the agent-teams proof demo end to end
	@echo "note: binding numbers come from the bare-KVM CI runner (D15); this run is informational"
	ARCH=$(ARCH) bash $(CURDIR)/dev/demo-team.sh

# Epic E2's acceptance list, run in its own order and with its own numbers.
accept-e2: linux-only cli ## Run Epic E2's acceptance test end to end
	@echo "note: binding numbers come from the bare-KVM CI runner (D15); this run is informational"
	ARCH=$(ARCH) bash $(CURDIR)/dev/accept-e2.sh

# The generated half of the documentation (E3-1). Nothing here is written by
# hand: the commands and flags come from the CLI's own -h, the MCP tools from
# the supervisor's own tools/list, and the toml keys, event types and exit codes
# from tables the product itself depends on. CI runs this and fails on a diff,
# so the reference is physically unable to describe a KelyfOS that does not
# exist (F-D4).
#
# The supervisor is built for the host here rather than for the guest: it is
# being asked what tools it would advertise, which needs no guest at all.
docs: linux-only cli ## Regenerate docs/reference from the source
	CGO_ENABLED=0 go build -trimpath -o $(OUT_DIR)/kelyfos-supervisor-host ./supervisor
	go run ./tools/gendocs \
	  -bin $(OUT_DIR)/kelyfos \
	  -supervisor $(OUT_DIR)/kelyfos-supervisor-host \
	  -out $(CURDIR)/docs/reference \
	  -repo $(CURDIR)

# Every recipe in docs/cookbook.md, run as written (E3-3). The recipes are the
# documentation, so this is how a recipe that stopped working gets found by us
# rather than by a stranger.
cookbook: linux-only cli ## Run every cookbook recipe on this machine
	bash $(CURDIR)/dev/cookbook.sh

run: cli ## Boot a microVM from the built image under Firecracker
	$(OUT_DIR)/kelyfos run --image $(FLAVOR) --arch $(ARCH)

test: ## Run the test suite (unit tests; integration tests skip without an image)
	go vet ./...
	go test ./...

test-integration: linux-only cli ## Boot a real microVM and exercise the guest
	go test -count=1 -v -timeout 15m -run 'TestConcurrent|TestOrphans|TestExec|TestMCP' ./internal/sandbox/

clean: ## Remove build output (keeps the downloaded Buildroot toolchain)
	rm -rf $(OUT_DIR) $(IMAGE_DIR) $(GUEST_OVERLAY)
	@echo "removed CLI, images and the generated overlay for ARCH=$(ARCH)"
	@echo "kept the Buildroot tree, the download cache and the compiler cache"
	@echo "under $(KELYFOS_CACHE)"

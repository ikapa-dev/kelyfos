# KelyfOS — top-level build entry point.
#
# Everything here runs on Linux (the Lima VM on macOS, WSL2 on Windows, or a bare
# Linux/KVM box). See dev/lima.yaml and dev/wsl2.md.
#
# The default goal is `help`. The build entry points are `toolchain` (once per
# architecture), `image` and `cli`.

# Version stamped into the CLI. A dev build says so rather than claiming a
# release number it does not have.
#
# --abbrev=12 is not cosmetic. `git describe` with core.abbrev unset picks its
# abbreviation length from the repository's object count, so a commit followed
# by an automatic repack moved it from eight hex digits to seven between two
# invocations seconds apart: v1.1.1-4-ge74699a0 and then v1.1.1-4-ge74699a, one
# commit, two version strings. That string is stamped into every CLI through
# -X main.Version, into the guest's generated /etc/os-release and into the SBOM,
# so two builds of one commit could differ for no reason but how many objects
# were in .git at the time -- which is exactly the property P6-9 measures and
# repro-check reports on. Fixing the length makes it depend on the commit alone.
# It cannot happen at a tag, where `git describe` returns the tag and no
# abbreviation at all, so no release ever carried this; it is dev builds and
# anything measured from one. Found by D81's SBOM work and left to the owner
# there because it changes every dev artifact's version string.
KELYFOS_VERSION ?= $(shell git describe --tags --dirty --always --abbrev=12 2>/dev/null || echo dev)

# The timestamp everything that records one uses (P6-9, D38).
#
# Taken from the commit rather than from the clock, so two builds of one commit
# agree about what time it is. A tree with no git history falls back to zero,
# which is the epoch every reproducible-build tool treats as "no date" rather
# than a date somebody chose.
export SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null || echo 0)

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
.PHONY: help versions toolchain kernel supervisor cli image run bench docs cookbook vuln fuzz release-sums release-sbom tokens prove-caps prove-team prove-two-teams demo-team accept-e2 clean test test-integration linux-only fetch-kernel

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
	@echo "==> toolchain ready: $$($(BUILD_DIR)/host/bin/*-linux-*-gcc --version 2>/dev/null | sed -n '1,1p')"

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
	@mkdir -p $(GUEST_OVERLAY)/sbin $(GUEST_OVERLAY)/.oldroot $(GUEST_OVERLAY)/etc
	@# The guest's own os-release, generated (P6-1 routed this here, P6-9).
	@# It was a static file in each flavor's overlay saying 0.1.0-dev, which was
	@# false from v0.1 onwards: a machine that reports a version nobody shipped
	@# is a machine whose transcript names the wrong thing. Generated from the
	@# same KELYFOS_VERSION the binaries carry, so the two cannot disagree.
	@printf 'NAME="KelyfOS"\nID=kelyfos\nPRETTY_NAME="KelyfOS (%s)"\nVERSION="%s"\nVERSION_ID=%s\nHOME_URL="https://github.com/ikapa-dev/kelyfos"\n' \
	  "$(FLAVOR)" "$(KELYFOS_VERSION)" "$(KELYFOS_VERSION)" > $(GUEST_OVERLAY)/etc/os-release
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
# without the 35-minute build. This checks SHA256SUMS and nothing else, which is
# integrity. Whether they are bit-for-bit what `image` makes here is measured
# rather than claimed — the repro-check workflow builds one commit twice and
# diffs the result per artifact (P6-9). Provenance is a separate statement, and
# on a release the release workflow builds there is one: it attests the checksums
# file, so `gh attestation verify <file> --repo ikapa-dev/kelyfos` names the
# workflow and the commit that built those bytes (P6-11). No published release
# carries one from v1.0-rc2 onward, which is the first release that workflow
# built. Older tags were assembled by hand and have none, so on what this target
# downloads for those, that command finds nothing.
fetch-image: ## Download a prebuilt guest image for ARCH instead of building it
	@$(CURDIR)/dev/fetch-image.sh "$(ARCH)" "$(RELEASE_TAG)"

# Package the built artifacts for a release, arch-tagged so one release can carry
# both, with the sums file fetch-image.sh verifies against.
release-artifacts: ## Stage $(IMAGE_DIR) artifacts + SHA256SUMS into dist/
	@mkdir -p $(CURDIR)/dist
	@# -n: no original name and no timestamp in the gzip header. Without it two
	@# identical images compress to two different files, and the difference is
	@# the clock rather than anything in them (P6-9).
	@gzip -9 -n -c $(IMAGE_DIR)/$(KERNEL_ARTIFACT) > $(CURDIR)/dist/$(KERNEL_ARTIFACT)-$(ARCH).gz
	@gzip -9 -n -c $(IMAGE_DIR)/rootfs.ext4        > $(CURDIR)/dist/rootfs-$(ARCH).ext4.gz
	@cp -f $(IMAGE_DIR)/image.json $(CURDIR)/dist/image-$(ARCH).json
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
	  echo "built dist/kelyfos-linux-$$uarch"; \
	done
	@# macOS, since P6-12 (D35's scoping of P4-7). A smaller program than the
	@# Linux one and it says so: doctor owns the Lima layer, verify checks a
	@# report somebody sent you, and everything that needs a guest refuses with
	@# the way in. Shipping it is what makes `kelyfos doctor --setup` reachable
	@# by somebody who has not cloned anything.
	@for a in amd64:x86_64 arm64:aarch64; do \
	  goarch=$${a%%:*}; uarch=$${a##*:}; \
	  CGO_ENABLED=0 GOOS=darwin GOARCH=$$goarch go build -trimpath \
	    -ldflags="-s -w -X main.Version=$(KELYFOS_VERSION) \
	                -X main.FirecrackerVersion=$(FIRECRACKER_VERSION)" \
	    -o $(CURDIR)/dist/kelyfos-darwin-$$uarch ./host || exit 1; \
	  echo "built dist/kelyfos-darwin-$$uarch"; \
	done

# One SBOM per architecture, covering every artifact the release ships for it
# (P6-10): Buildroot's packages, the guest supervisor, and both host CLIs.
#
# Buildroot knows about its own packages and nothing else. The guest supervisor
# is cross-compiled by this project's toolchain and arrives through the rootfs
# overlay, so a Buildroot-only inventory omits the one component KelyfOS
# actually wrote — and an SBOM that is confidently incomplete is the
# supply-chain form of an audit record that is confidently wrong.
#
# The macOS CLI is read for a different reason, and it is not a formality. The
# release attests this document against `dist/*$(ARCH)*`, and that glob matches
# `kelyfos-darwin-$(ARCH)` as surely as it matches the Linux one. While this
# target read only the Linux binary, the release said an SBOM described a
# shipped artifact it had never opened — a claim about bytes a stranger
# downloads that nothing here had checked. Today it adds no components, because
# the macOS build of ./host resolves the same modules the Linux build does; what
# it adds is the checking. A dependency that arrives on darwin only now lands in
# the document, instead of quietly turning the attestation into a false
# statement that no one would be told about.
#
# `make show-info` is filtered from the first `{` because make prefixes its own
# chatter and the generator parses the whole stream as JSON. Found by running
# it.
release-sbom: ## Merge Buildroot + every released Go binary into dist/sbom-$(ARCH).cdx.json
	@mkdir -p $(CURDIR)/dist
	@$(MAKE) -s --no-print-directory -C $(BR_SRC) O=$(BUILD_DIR) \
	  BR2_EXTERNAL=$(BR_EXTERNAL) show-info 2>/dev/null \
	  | sed -n '/^{/,$$p' > $(BUILD_DIR)/show-info.json
	@python3 $(BR_SRC)/utils/generate-cyclonedx \
	  < $(BUILD_DIR)/show-info.json > $(BUILD_DIR)/sbom-buildroot.json
	@go run $(CURDIR)/tools/sbom -arch $(ARCH) -version $(KELYFOS_VERSION) \
	  -buildroot $(BUILD_DIR)/sbom-buildroot.json \
	  -binary $(GUEST_OVERLAY)/sbin/kelyfos-supervisor \
	  -binary $(CURDIR)/dist/kelyfos-linux-$(ARCH) \
	  -binary $(CURDIR)/dist/kelyfos-darwin-$(ARCH) \
	  -out $(CURDIR)/dist/sbom-$(ARCH).cdx.json

# The sums file, written from scratch over whatever is in dist/ (P6-8).
#
# It used to be appended to by both targets above and truncated by nothing, so a
# second run of either doubled its entries and a release cut twice carried a file
# that listed every artifact more than once. Nothing verified it against the
# directory it described, so a stale line — an artifact renamed, an architecture
# dropped — survived every release after the one that produced it.
#
# Computed here instead, once, at the end, over exactly what is there. `sort`
# because a sums file whose order depends on the order two targets happened to
# run in is a file that differs between two identical releases.
release-sums: ## Write dist/SHA256SUMS from scratch over everything staged
	@cd $(CURDIR)/dist && rm -f SHA256SUMS && \
	  find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\n' | sort | \
	  xargs sha256sum > SHA256SUMS
	@echo "dist/SHA256SUMS covers $$(wc -l < $(CURDIR)/dist/SHA256SUMS) artifacts:"
	@cat $(CURDIR)/dist/SHA256SUMS

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

# Two teams at once, which is a behaviour rather than a number, so unlike the
# two above it means the same on a nested host as on bare KVM (P7-16).
prove-two-teams: linux-only cli ## Boot two teams at once and stop one; the other must not notice
	ARCH=$(ARCH) bash $(CURDIR)/dev/prove-two-teams.sh

# Epic E2's proof: a real five-agent team doing real work, driven through the
# real MCP tools on five real microVMs (E2-9).
demo-team: linux-only cli ## Run the agent-teams proof demo end to end
	@echo "note: binding numbers come from the bare-KVM CI runner (D15); this run is informational"
	ARCH=$(ARCH) bash $(CURDIR)/dev/demo-team.sh

# Epic E2's acceptance list, run in its own order and with its own numbers.
accept-e2: linux-only cli ## Run Epic E2's acceptance test end to end
	@echo "note: binding numbers come from the bare-KVM CI runner (D15); this run is informational"
	ARCH=$(ARCH) bash $(CURDIR)/dev/accept-e2.sh

# The security lab suites (ST-1.2..1.9): the independent audit's scenarios,
# committed as machine-checked suites. Each sources dev/security-lab.sh, which
# sources scope.sh (D83), and tears down only the machines it started. The
# egress suite's online battery skips itself, loudly, when the network is down
# (D87); the rest of it and the other suites never need the internet.
accept-security: linux-only cli ## Run the security lab suites (egress, secrets, record, caps, surfaces, workspace)
	ARCH=$(ARCH) bash $(CURDIR)/dev/accept-security-egress.sh
	ARCH=$(ARCH) bash $(CURDIR)/dev/accept-security-secrets.sh
	ARCH=$(ARCH) bash $(CURDIR)/dev/accept-security-record.sh
	ARCH=$(ARCH) bash $(CURDIR)/dev/accept-security-caps.sh
	ARCH=$(ARCH) bash $(CURDIR)/dev/accept-security-surfaces.sh
	ARCH=$(ARCH) bash $(CURDIR)/dev/accept-security-workspace.sh

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

# The size of the generated set, by a command rather than by a sentence (P6-17).
#
# The figure quoted in llms.txt and in progress rows used to come from an
# invocation recorded only in prose, which is exactly the unrecorded provenance
# this project refuses everywhere else. This is that invocation, committed.
tokens: ## Measure llms-full.txt: bytes and characters exactly, tokens estimated
	@go run $(CURDIR)/tools/tokens $(CURDIR)/llms-full.txt

# Every recipe in docs/cookbook.md, run as written (E3-3). The recipes are the
# documentation, so this is how a recipe that stopped working gets found by us
# rather than by a stranger.
cookbook: linux-only cli ## Run every cookbook recipe on this machine
	bash $(CURDIR)/dev/cookbook.sh

# The vulnerability scanner (P6-2). Reachability-based rather than a manifest
# diff: it reports a vulnerable symbol only when this code can actually reach
# it. One target so a developer and .github/workflows/security.yml run the same
# scanner at the same pinned version, rather than two invocations that drift.
vuln: ## Scan for known vulnerabilities in dependencies and the stdlib
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

# Every fuzz target in the repository, discovered rather than listed (P6-3).
# FUZZTIME is per target: 10s is the per-push pass, minutes are the scheduled
# one. A target added anywhere is picked up with nothing to remember.
FUZZTIME ?= 10s
fuzz: ## Run every fuzz target for FUZZTIME each (default 10s)
	bash $(CURDIR)/dev/fuzz.sh $(FUZZTIME)

run: cli ## Boot a microVM from the built image under Firecracker
	$(OUT_DIR)/kelyfos run --image $(FLAVOR) --arch $(ARCH)

test: ## Run the test suite (unit tests; integration tests skip without an image)
	go vet ./...
	go test ./...

# The committed ci.yml, run here. A clean clone of $(REF) (default HEAD) is
# made, act executes the job in Docker, the clone is removed. Uncommitted
# edits are never part of the evidence. See dev/ci-act.sh.
ci-act: ## Run ci.yml's checks job in Docker via act, on a clean clone of REF (default HEAD)
	@dev/ci-act.sh $(REF)

test-integration: linux-only cli ## Boot a real microVM and exercise the guest
	go test -count=1 -v -timeout 15m -run 'TestConcurrent|TestOrphans|TestExec|TestMCP' ./internal/sandbox/

clean: ## Remove build output (keeps the downloaded Buildroot toolchain)
	rm -rf $(OUT_DIR) $(IMAGE_DIR) $(GUEST_OVERLAY)
	@echo "removed CLI, images and the generated overlay for ARCH=$(ARCH)"
	@echo "kept the Buildroot tree, the download cache and the compiler cache"
	@echo "under $(KELYFOS_CACHE)"

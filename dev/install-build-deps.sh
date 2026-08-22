#!/usr/bin/env bash
# KelyfOS — build dependencies for the Linux layer (quickstart section 7, step 3).
#
# Run INSIDE the Lima VM / WSL2 / bare Linux box:
#   limactl shell kelyfos-dev -- bash dev/install-build-deps.sh
#
# Debian/Ubuntu package names. Everything here is what Buildroot and the kernel
# need to build, plus Go for the supervisor and CLI.
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This script targets Debian/Ubuntu. Install the Buildroot prerequisites" >&2
  echo "for your distribution manually: https://buildroot.org/downloads/manual/" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
sudo -E apt-get update
# cmake is here for ccache alone (BR2_CCACHE in the shared Buildroot fragment):
# ccache builds with cmake, and without a host cmake >= 3.18 Buildroot quietly
# builds its own — ten minutes to save a few, on every fresh machine.
sudo -E apt-get install -y --no-install-recommends \
  build-essential git bc flex bison cmake \
  libssl-dev libelf-dev libncurses-dev \
  unzip rsync file cpio wget curl \
  ca-certificates e2fsprogs

# Go comes from the pinned official tarball, not from apt: Ubuntu 24.04 ships
# Go 1.22, too old to honour a go.mod toolchain directive. See versions.mk.
bash "$(dirname "${BASH_SOURCE[0]}")/install-go.sh"

make --version | head -1
gcc --version | head -1
cmake --version | head -1
go version

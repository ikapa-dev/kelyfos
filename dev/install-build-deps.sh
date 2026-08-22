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
sudo -E apt-get install -y --no-install-recommends \
  build-essential git bc flex bison \
  libssl-dev libelf-dev libncurses-dev \
  unzip rsync file cpio wget curl golang \
  ca-certificates e2fsprogs

make --version | head -1
gcc --version | head -1
go version

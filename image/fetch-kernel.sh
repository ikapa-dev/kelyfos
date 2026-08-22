#!/usr/bin/env bash
# KelyfOS — pre-seed Buildroot's download cache with a verified kernel tarball (P1-2).
#
#   image/fetch-kernel.sh <version> <sha256> <br2_dl_dir>
#
# Why this exists: Buildroot's manual says it "checks hashes of all packages
# downloaded, except those for which a custom version is used." KelyfOS pins an
# exact kernel patch release, which is by definition a custom version to
# Buildroot, so Buildroot would fetch it with no integrity check at all and the
# LINUX_SHA256 in versions.mk would be a checksum nothing ever checks.
#
# So we fetch it ourselves, verify it against versions.mk, and place it where
# Buildroot looks. Buildroot then finds it cached and never downloads anything.
set -euo pipefail

version="${1:?version}"; want="${2:?sha256}"; dl="${3:?BR2_DL_DIR}"
tarball="linux-${version}.tar.xz"
dest="$dl/linux"
series="v${version%%.*}.x"

verify() { [ "$(sha256sum "$1" | awk '{print $1}')" = "$want" ]; }

if [ -f "$dest/$tarball" ] && verify "$dest/$tarball"; then
  echo "==> linux $version already cached and verified"
  exit 0
fi

mkdir -p "$dest"
echo "==> downloading linux $version"
curl -fsSL --retry 3 -o "$dest/$tarball.part" \
  "https://cdn.kernel.org/pub/linux/kernel/$series/$tarball"

if ! verify "$dest/$tarball.part"; then
  echo "checksum mismatch for linux $version" >&2
  echo "  expected $want (versions.mk)" >&2
  echo "  got      $(sha256sum "$dest/$tarball.part" | awk '{print $1}')" >&2
  rm -f "$dest/$tarball.part"
  exit 1
fi
mv "$dest/$tarball.part" "$dest/$tarball"
echo "==> sha256 ok: $want"

#!/usr/bin/env bash
# KelyfOS — fetch and unpack the pinned Buildroot release (P1-1).
#
# Idempotent: does nothing if the tree is already present. Called by the
# Makefile; safe to run by hand.
#
#   image/fetch-buildroot.sh <version> <sha256> <dl_dir> <dest_parent>
set -euo pipefail

version="${1:?version}"; want="${2:?sha256}"; dl="${3:?dl dir}"; dest_parent="${4:?dest parent}"
tree="$dest_parent/buildroot-$version"
tarball="$dl/buildroot-$version.tar.xz"

if [ -f "$tree/Makefile" ]; then
  echo "==> buildroot $version already unpacked at $tree"
  exit 0
fi

mkdir -p "$dl" "$dest_parent"

if [ ! -f "$tarball" ]; then
  echo "==> downloading buildroot $version"
  curl -fsSL --retry 3 -o "$tarball.part" \
    "https://buildroot.org/downloads/buildroot-$version.tar.xz"
  mv "$tarball.part" "$tarball"
fi

have="$(sha256sum "$tarball" | awk '{print $1}')"
if [ "$want" != "$have" ]; then
  echo "checksum mismatch for buildroot $version" >&2
  echo "  expected $want (versions.mk)" >&2
  echo "  got      $have ($tarball)" >&2
  echo "Delete the file and retry, or fix the pin — do not build from this." >&2
  exit 1
fi
echo "==> sha256 ok: $have"

# Unpack into a temporary sibling and rename, so an interrupted extraction never
# leaves a half tree that the "already unpacked" check above would accept.
rm -rf "$tree.tmp"
mkdir -p "$tree.tmp"
tar -xJf "$tarball" -C "$tree.tmp" --strip-components=1
mv "$tree.tmp" "$tree"
echo "==> unpacked to $tree"

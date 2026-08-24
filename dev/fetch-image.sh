#!/usr/bin/env bash
# Download a prebuilt KelyfOS guest image from a GitHub release (D20).
#
# The artifacts are built from this source at the release tag, and save you the
# ~35 minutes of compiling a toolchain, a kernel and a userland. They are not
# bit-for-bit what `make image` produces on your machine: the build is not
# reproducible yet (P6-9). SHA256SUMS gives you integrity, not provenance —
# nothing here is signed yet, that is P6-11. If you need to know who built the
# bytes, build them yourself.
#
# Usage: dev/fetch-image.sh [ARCH] [TAG]
set -euo pipefail

REPO="${KELYFOS_REPO:-p4r4n0rm4l/KelyfOS}"
ARCH="${1:-$(uname -m)}"
TAG="${2:-latest}"

case "$ARCH" in
  x86_64|amd64)  ARCH=x86_64; KERNEL=vmlinux ;;
  aarch64|arm64) ARCH=aarch64; KERNEL=Image  ;;
  *) echo "unsupported arch: $ARCH (want x86_64 or aarch64)" >&2; exit 1 ;;
esac

CACHE="${KELYFOS_CACHE:-$HOME/.cache/kelyfos}"
DEST="$CACHE/out/$ARCH"
mkdir -p "$DEST"

# KELYFOS_RELEASE_BASE overrides the source entirely — used by the test that
# exercises this script's verify path without a network round trip.
if [ -n "${KELYFOS_RELEASE_BASE:-}" ]; then
  base="$KELYFOS_RELEASE_BASE"
elif [ "$TAG" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$TAG"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() {
  local name="$1"
  echo "  $name"
  if ! curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/$name" "$base/$name"; then
    cat >&2 <<MSG

Could not download $base/$name

If this is a 404, the release may not publish this arch yet, or the tag is
wrong. Check https://github.com/$REPO/releases — or build it yourself:

    make image ARCH=$ARCH FLAVOR=dev

MSG
    exit 1
  fi
}

echo "Fetching KelyfOS $TAG image for $ARCH from $REPO"
fetch "SHA256SUMS"
fetch "$KERNEL-$ARCH.gz"
fetch "rootfs-$ARCH.ext4.gz"
fetch "image-$ARCH.json"

# Verify against the published sums before anything lands in the cache. grep the
# two lines we care about so a release carrying other arches still verifies.
echo "Verifying checksums"
( cd "$tmp" && grep -E "  ($KERNEL-$ARCH\.gz|rootfs-$ARCH\.ext4\.gz|image-$ARCH\.json)\$" SHA256SUMS > want.txt \
  && test -s want.txt \
  && sha256sum -c want.txt ) || {
    echo "CHECKSUM MISMATCH — refusing to install. Nothing was written to $DEST." >&2
    exit 1
  }

# Decompress only after the sums check passes, and into the cache last, so a
# failure anywhere above leaves the existing image untouched.
echo "Decompressing"
gunzip -c "$tmp/$KERNEL-$ARCH.gz"      > "$tmp/$KERNEL"
gunzip -c "$tmp/rootfs-$ARCH.ext4.gz"  > "$tmp/rootfs.ext4"

mv -f "$tmp/$KERNEL"          "$DEST/$KERNEL"
mv -f "$tmp/rootfs.ext4"      "$DEST/rootfs.ext4"
mv -f "$tmp/image-$ARCH.json" "$DEST/image.json"

flavor=$(sed -n 's/.*"flavor"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$DEST/image.json")
echo
echo "Installed the '$flavor' image for $ARCH into $DEST"
echo "Run it with:  kelyfos run --image $flavor"

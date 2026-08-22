#!/usr/bin/env bash
# Write image.json next to a built image (D21).
#
# The sandbox reads this to check that the flavor you asked for is the flavor
# you are actually booting, so the flight recorder never records a guess.
set -euo pipefail

ARCH="$1"; FLAVOR="$2"; DIR="$3"; KERNEL="$4"
BUILDROOT="${5:-}"; LINUX="${6:-}"

cd "$DIR"
[ -f "$KERNEL" ]     || { echo "no kernel at $DIR/$KERNEL" >&2; exit 1; }
[ -f rootfs.ext4 ]   || { echo "no rootfs at $DIR/rootfs.ext4" >&2; exit 1; }

k_sha=$(sha256sum "$KERNEL"   | cut -d' ' -f1)
r_sha=$(sha256sum rootfs.ext4 | cut -d' ' -f1)

# SOURCE_DATE_EPOCH keeps this field meaningful under reproducible builds (P4-3).
built=$(date -u -d "@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y-%m-%dT%H:%M:%SZ)

cat > image.json <<JSON
{
  "schema": 1,
  "arch": "$ARCH",
  "flavor": "$FLAVOR",
  "kernel": "$KERNEL",
  "kernel_sha256": "$k_sha",
  "rootfs": "rootfs.ext4",
  "rootfs_sha256": "$r_sha",
  "buildroot": "$BUILDROOT",
  "linux": "$LINUX",
  "built": "$built"
}
JSON
echo "manifest: $DIR/image.json ($ARCH/$FLAVOR)"

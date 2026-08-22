#!/usr/bin/env bash
# KelyfOS — assert the built image is what the plan promises (P1-4).
#
#   image/check-image.sh <arch> <image_dir> <kernel_artifact>
set -euo pipefail

arch="${1:?arch}"; dir="${2:?image dir}"; kernel="${3:?kernel artifact}"
rootfs="$dir/rootfs.ext4"
limit=$((200 * 1024 * 1024))   # the plan's ceiling for the rootfs

for f in "$dir/$kernel" "$rootfs"; do
  [ -f "$f" ] || { echo "missing artifact: $f" >&2; exit 1; }
done

size="$(stat -c %s "$rootfs")"
if [ "$size" -ge "$limit" ]; then
  echo "rootfs.ext4 is ${size} bytes, over the 200 MB budget" >&2
  exit 1
fi

printf '==> %-14s %10s bytes  %s\n' "$kernel" "$(stat -c %s "$dir/$kernel")" "$(file -b "$dir/$kernel" | cut -c1-60)"
printf '==> %-14s %10s bytes  (%s on disk, sparse) — under the 200 MB budget\n' \
  "rootfs.ext4" "$size" "$(du -h "$rootfs" | cut -f1)"

# The image is useless without an init and an interface; catch that here rather
# than as a kernel panic three minutes into a boot test.
for path in /init /sbin/kelyfos-supervisor; do
  if ! debugfs -R "stat $path" "$rootfs" >/dev/null 2>&1; then
    echo "rootfs is missing $path" >&2
    exit 1
  fi
done
echo "==> rootfs contains /init and /sbin/kelyfos-supervisor"

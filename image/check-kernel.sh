#!/usr/bin/env bash
# KelyfOS — verify the built guest kernel is the kernel we specified (P1-2).
#
#   image/check-kernel.sh <arch> <build_dir> <br2_external>
#
# Two things are checked, because two things can silently go wrong:
#   1. the resulting .config honours every line of our fragments — olddefconfig
#      absorbing a 6.1 → 6.18 gap must not quietly drop a guarantee;
#   2. the artifact is the uncompressed form Firecracker actually boots. A
#      gzipped Image or a bzImage fails at boot with an unhelpful error, so it is
#      cheaper to fail here.
set -euo pipefail

arch="${1:?arch}"; build_dir="${2:?build dir}"; ext="${3:?br2 external}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

kconfig="$(ls -d "$build_dir"/build/linux-*/.config 2>/dev/null | head -1)"
[ -n "$kconfig" ] || { echo "no built kernel .config under $build_dir/build/linux-*" >&2; exit 1; }
echo "==> checking $kconfig"

cat "$ext/kernel/kelyfos.fragment" "$ext/kernel/kelyfos-$arch.fragment" > "$build_dir/.kelyfos-kernel-want"
"$here/check-config.sh" "$build_dir/.kelyfos-kernel-want" "$kconfig"

case "$arch" in
  aarch64) artifact="$build_dir/images/Image";   expect="Linux kernel ARM64 boot executable" ;;
  x86_64)  artifact="$build_dir/images/vmlinux"; expect="ELF 64-bit LSB executable" ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

[ -f "$artifact" ] || { echo "expected kernel artifact missing: $artifact" >&2; exit 1; }

kind="$(file -b "$artifact")"
case "$kind" in
  *gzip*|*"bzImage"*)
    echo "artifact is compressed, Firecracker will not boot it: $kind" >&2; exit 1 ;;
esac
case "$kind" in
  *"$expect"*) : ;;
  *) echo "unexpected artifact format for $arch:" >&2
     echo "  $artifact: $kind" >&2
     echo "  expected something matching: $expect" >&2
     exit 1 ;;
esac

printf '==> %s: %s (%s bytes)\n' "$(basename "$artifact")" "$kind" "$(stat -c %s "$artifact")"

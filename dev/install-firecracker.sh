#!/usr/bin/env bash
# KelyfOS — install Firecracker + jailer inside the Linux layer (P0-2).
#
# Run this INSIDE the Lima VM / WSL2 / bare Linux box, not on macOS:
#   limactl shell kelyfos-dev -- bash dev/install-firecracker.sh
#
# The version comes from versions.mk (P0-6) so there is exactly one place that
# says which Firecracker this project is built against. FIRECRACKER_VERSION in
# the environment overrides it, for bisecting upstream regressions only.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${FIRECRACKER_VERSION:-}"
if [ -z "$version" ] && [ -f "$here/versions.mk" ]; then
  version="$(sed -n 's/^[[:space:]]*FIRECRACKER_VERSION[[:space:]]*[:?]\{0,1\}=[[:space:]]*//p' "$here/versions.mk" | tail -1)"
fi
# No fallback default. There used to be one, which quietly made this script a
# second place that says which Firecracker to install — the exact thing the
# header above promises it is not. dev/install-go.sh has always failed here.
if [ -z "$version" ]; then
  echo "cannot read FIRECRACKER_VERSION from $here/versions.mk" >&2
  echo "  set FIRECRACKER_VERSION in the environment to override, or fix versions.mk" >&2
  exit 1
fi

arch="$(uname -m)"
case "$arch" in
  aarch64|x86_64) ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

prefix="${PREFIX:-/usr/local/bin}"
tarball="firecracker-${version}-${arch}.tgz"
base="https://github.com/firecracker-microvm/firecracker/releases/download/${version}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "==> firecracker ${version} (${arch}) -> ${prefix}"
curl -fsSL --retry 3 -o "$tmp/$tarball"        "$base/$tarball"
curl -fsSL --retry 3 -o "$tmp/$tarball.sha256" "$base/$tarball.sha256.txt"

# Upstream publishes "<sha>  <path/to/tarball>"; compare the digest itself so a
# differing path prefix does not turn a good download into a failure.
want="$(awk '{print $1}' "$tmp/$tarball.sha256")"
have="$(sha256sum "$tmp/$tarball" | awk '{print $1}')"
if [ "$want" != "$have" ]; then
  echo "checksum mismatch: expected $want, got $have" >&2
  exit 1
fi
echo "==> sha256 ok: $have"

tar -xzf "$tmp/$tarball" -C "$tmp"
release_dir="$tmp/release-${version}-${arch}"

sudo install -m 0755 "$release_dir/firecracker-${version}-${arch}" "$prefix/firecracker"
sudo install -m 0755 "$release_dir/jailer-${version}-${arch}"      "$prefix/jailer"

"$prefix/firecracker" --version
"$prefix/jailer" --version | sed -n '1,1p'

#!/usr/bin/env bash
# KelyfOS — install the pinned Go toolchain into the Linux layer (P0-6).
#
#   limactl shell kelyfos-dev -- bash dev/install-go.sh
#
# Ubuntu 24.04 ships Go 1.22, too old to honour a go.mod toolchain directive, so
# the version in versions.mk is installed from the official tarball instead of
# the distribution package. GO_VERSION in the environment overrides it.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mk_get() { sed -n "s/^[[:space:]]*$1[[:space:]]*[:?]\{0,1\}=[[:space:]]*//p" "$here/versions.mk" | tail -1; }

version="${GO_VERSION:-$(mk_get GO_VERSION)}"
[ -n "$version" ] || { echo "GO_VERSION not found in versions.mk" >&2; exit 1; }

arch="$(uname -m)"
case "$arch" in
  aarch64) goarch=arm64 ;;
  x86_64)  goarch=amd64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
want="$(mk_get "GO_SHA256_${arch}")"
[ -n "$want" ] || { echo "GO_SHA256_${arch} not found in versions.mk" >&2; exit 1; }

if command -v go >/dev/null 2>&1 && [ "$(go version | awk '{print $3}')" = "go${version}" ]; then
  echo "==> go${version} already installed: $(command -v go)"
  go version
  exit 0
fi

tarball="go${version}.linux-${goarch}.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "==> go ${version} (${goarch})"
curl -fsSL --retry 3 -o "$tmp/$tarball" "https://go.dev/dl/$tarball"
have="$(sha256sum "$tmp/$tarball" | awk '{print $1}')"
if [ "$want" != "$have" ]; then
  echo "checksum mismatch: expected $want, got $have" >&2
  exit 1
fi
echo "==> sha256 ok: $have"

# The distro package, if present, would otherwise shadow this on PATH.
if dpkg -s golang-go >/dev/null 2>&1; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y golang golang-go golang-1.22 >/dev/null 2>&1 || true
fi

sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "$tmp/$tarball"
printf 'export PATH=$PATH:/usr/local/go/bin\n' | sudo tee /etc/profile.d/kelyfos-go.sh >/dev/null
sudo chmod 0644 /etc/profile.d/kelyfos-go.sh
sudo ln -sf /usr/local/go/bin/go     /usr/local/bin/go
sudo ln -sf /usr/local/go/bin/gofmt  /usr/local/bin/gofmt

/usr/local/go/bin/go version

#!/usr/bin/env bash
# Install the prebuilt kelyfos CLI from a GitHub release (D20).
#
# The CLI is a static CGO-free binary, so this needs nothing but bash, curl and
# sha256sum — no Go toolchain, no build-essential. Building it yourself is
# `make cli`, which needs dev/install-build-deps.sh first.
set -euo pipefail

REPO="${KELYFOS_REPO:-p4r4n0rm4l/KelyfOS}"
TAG="${1:-latest}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${KELYFOS_BIN_DIR:-$here/bin}"

case "$(uname -m)" in
  x86_64|amd64)  ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

if [ -n "${KELYFOS_RELEASE_BASE:-}" ]; then
  base="$KELYFOS_RELEASE_BASE"
elif [ "$TAG" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$TAG"
fi

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
echo "Fetching kelyfos $TAG for $ARCH"
for f in SHA256SUMS "kelyfos-linux-$ARCH"; do
  curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/$f" "$base/$f" \
    || { echo "could not download $base/$f — build it instead with: make cli" >&2; exit 1; }
done

echo "Verifying checksum"
( cd "$tmp" && grep -E "  kelyfos-linux-$ARCH\$" SHA256SUMS > want.txt \
  && test -s want.txt && sha256sum -c want.txt ) \
  || { echo "CHECKSUM MISMATCH — refusing to install." >&2; exit 1; }

mkdir -p "$DEST"
install -m 0755 "$tmp/kelyfos-linux-$ARCH" "$DEST/kelyfos"
echo
"$DEST/kelyfos" version
echo "Installed $DEST/kelyfos"

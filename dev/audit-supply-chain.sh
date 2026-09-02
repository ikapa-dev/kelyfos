#!/usr/bin/env bash
# KelyfOS — supply-chain scanning of the guest image, against the Buildroot
# layer SECURITY.md and docs/hardening.md §5 admit is "taken on trust" (ST-4.4).
#
#   bash dev/audit-supply-chain.sh                       scan the built image
#   bash dev/audit-supply-chain.sh old.cdx.json new.cdx.json   diff two SBOMs
#
# Two halves:
#
# 1. IMAGE SCAN — trivy or grype (whichever is installed) against the built
#    rootfs.ext4, the layer no Go scanner sees: it is Buildroot's packages,
#    the kernel, and the CA bundle. Findings here are the guest's own
#    attack surface, the part the supervisor's confinement does not fence.
# 2. SBOM DIFF — the release SBOM (dist/sbom-<arch>.cdx.json, built by
#    `make release-sbom`, rebuilt in v1.1.2 with per-arch serials) compared
#    between two builds, so a component that appears, disappears or changes
#    version between builds is a named thing rather than a surprise.
#
# Every tool is skipped loudly, by name, when absent — the script fabricates
# no clean result for a tool that did not run.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
IMAGE="${REPO}/.cache/kelyfos/out/${ARCH}/rootfs.ext4"
[ -f "$IMAGE" ] || IMAGE="${HOME}/.cache/kelyfos/out/${ARCH}/rootfs.ext4"

if [ $# -ge 2 ]; then
  echo "SBOM diff: $1 vs $2"
  diff <(python3 -c 'import json,sys
b=json.load(open(sys.argv[1]))
for c in b.get("components",[]):
    print(c.get("type",""), c.get("name",""), c.get("version",""))' "$1" | sort) \
    <(python3 -c 'import json,sys
b=json.load(open(sys.argv[2]))
for c in b.get("components",[]):
    print(c.get("type",""), c.get("name",""), c.get("version",""))' "$2" | sort) \
    && echo "no component differences" || echo "^ components differ"
  exit 0
fi

if [ ! -f "$IMAGE" ]; then
  echo "no guest image at $IMAGE — build one with make image, or point at it directly" >&2
  exit 1
fi
echo "scanning $IMAGE ($ARCH)"

if command -v trivy >/dev/null 2>&1; then
  trivy rootfs --scanners vuln "$IMAGE"
elif command -v grype >/dev/null 2>&1; then
  grype "$IMAGE"
else
  echo "SKIP image scan: neither trivy nor grype is installed." >&2
  echo "  trivy rootfs --scanners vuln <rootfs.ext4> is the invocation; install one to measure." >&2
  echo "  The gap this leaves is real: the Buildroot layer is otherwise taken on trust." >&2
fi

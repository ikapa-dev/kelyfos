#!/usr/bin/env bash
# KelyfOS — a disposable Lima VM for the security suites' destructive half
# (ST-6.1).
#
#   bash dev/provision-sec-lab-vm.sh provision [name]   build one (default: kelyfos-seclab)
#   bash dev/provision-sec-lab-vm.sh destroy  [name]    remove it entirely
#
# Why this exists. The lifecycle suite creates orphans on purpose and the
# reaper test reaps them; the dev VM is SHARED, and a machine where several
# worktrees are working at once is the exact reason D83 exists. A disposable
# instance — one provisioning script, one destroy — gives the destructive
# suites a machine whose only occupant is themselves, which is much smaller
# than a two-architecture lab and answers the audit's x86_64 note where it
# can be answered cheaply (the x86_64 lane is ci.yml's boot job; D89).
#
# The provisioning reuses the README's own install path — dev/lima.yaml,
# dev/install-build-deps.sh, dev/install-firecracker.sh, then make image —
# so a suite's disposable VM is configured like a user's machine, not like
# a fork of it. The first image build takes about thirty-five minutes on a
# cold toolchain; after that the instance is recreated in minutes.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="${2:-kelyfos-seclab}"

case "${1:-help}" in
provision)
  limactl list --json 2>/dev/null | grep -q "\"name\":\"$NAME\"" && {
    echo "instance $NAME already exists — destroy it first, or pick another name" >&2
    exit 1
  }
  echo "provisioning $NAME (aarch64, from dev/lima.yaml)"
  limactl start --name "$NAME" "$REPO/dev/lima.yaml"
  limactl shell "$NAME" -- bash dev/install-build-deps.sh
  limactl shell "$NAME" -- bash dev/install-firecracker.sh
  echo "building the guest image (this is the long step; ~35 min cold)"
  limactl shell "$NAME" -- bash -lc "cd /Users/\$(whoami | sed 's/\\.guest$//')/dev/labs/KelyfOS 2>/dev/null || cd \$HOME/KelyfOS; make image FLAVOR=dev"
  echo "$NAME is ready — run the destructive suites inside it:"
  echo "  limactl shell $NAME -- bash dev/accept-security-lifecycle.sh"
  ;;
destroy)
  echo "destroying $NAME"
  limactl delete --force "$NAME"
  echo "$NAME removed, with every machine it ever hosted"
  ;;
*)
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  ;;
esac

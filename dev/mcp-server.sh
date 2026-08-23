#!/usr/bin/env bash
# KelyfOS as an MCP server, from wherever you happen to be developing it.
#
# This is what `.mcp.json` launches, and it exists because the answer differs by
# platform. KelyfOS runs on Linux with /dev/kvm; on macOS the CLI lives inside
# the Lima VM and there is nothing on the host PATH to run. A committed
# configuration file has to work for both, so the branch lives here rather than
# in a file every contributor would have to edit.
#
# Two rules it follows, both from things that went wrong:
#
#   - The policy is named, never discovered. A serve-mcp that searches upward
#     from a working directory the client chose can find no policy and run with
#     no ceiling at all (F-D44). The path is passed explicitly.
#   - The binary is named absolutely. A non-interactive `limactl shell` gets a
#     minimal PATH, so a bare `kelyfos` is not found there even when it exists.
#
# The Lima home path is the same on both sides of the mount, which is why one
# absolute path works for the host and for the VM.
#
#   KELYFOS_LIMA   the VM to use on macOS (default: kelyfos-dev)
#   KELYFOS_BIN    the binary to run (default: <repo>/bin/kelyfos)
#   KELYFOS_POLICY the policy to hold it to (default: <repo>/kelyfos.toml)
#
# Everything this prints on stdout is the protocol. Diagnostics go to stderr,
# which the MCP specification reserves for exactly that.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="${KELYFOS_BIN:-$repo/bin/kelyfos}"
policy="${KELYFOS_POLICY:-$repo/kelyfos.toml}"

if [ ! -f "$policy" ]; then
  echo "kelyfos: no policy at $policy — a server with no ceiling is not worth starting" >&2
  exit 1
fi

case "$(uname -s)" in
  Linux)
    if [ ! -x "$bin" ]; then
      echo "kelyfos: $bin is not built — run 'make cli'" >&2
      exit 1
    fi
    exec "$bin" serve-mcp --policy "$policy"
    ;;
  Darwin)
    vm="${KELYFOS_LIMA:-kelyfos-dev}"
    if ! command -v limactl >/dev/null; then
      echo "kelyfos: limactl is not installed, and KelyfOS needs a Linux machine with /dev/kvm." >&2
      echo "         see dev/lima.yaml, or set KELYFOS_BIN to a kelyfos on a machine that has one." >&2
      exit 1
    fi
    if ! limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | grep -q "^$vm Running$"; then
      echo "kelyfos: the Lima VM '$vm' is not running — 'limactl start $vm'" >&2
      exit 1
    fi
    # The absolute path is deliberate: a non-interactive shell inside the VM has
    # a minimal PATH and would not find a bare `kelyfos`.
    exec limactl shell "$vm" -- "$bin" serve-mcp --policy "$policy"
    ;;
  *)
    echo "kelyfos: $(uname -s) is not a platform KelyfOS runs on; it needs Linux with /dev/kvm" >&2
    exit 1
    ;;
esac

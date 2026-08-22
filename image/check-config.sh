#!/usr/bin/env bash
# KelyfOS — assert that the configuration we asked for is the configuration we got.
#
#   image/check-config.sh <requested_defconfig> <resulting_.config>
#
# Kconfig silently drops a symbol whose name is misspelled or whose dependencies
# are unmet. For an image whose whole point is a controlled attack surface, a
# silently ignored "no modules" or "no getty" is the worst possible failure mode:
# the build succeeds and the guarantee is gone. So every request is verified.
set -euo pipefail

want_file="${1:?requested defconfig}"
got_file="${2:?resulting .config}"
fail=0

while IFS= read -r line; do
  # Kconfig writes a disabled bool as "# CONFIG_X is not set", and fragments are
  # written the same way. Treat that as a request for n rather than a comment.
  case "$line" in
    '# '*' is not set')
      sym="${line#\# }"; sym="${sym% is not set}"; val=n ;;
    ''|'#'*) continue ;;
    *)
      sym="${line%%=*}"
      val="${line#*=}" ;;
  esac

  case "$val" in
    n)
      if grep -qx -- "$sym=y" "$got_file" || grep -qx -- "$sym=m" "$got_file"; then
        echo "  MISMATCH $sym: asked for n, got $(grep -m1 -x -- "$sym=." "$got_file")" >&2
        fail=1
      fi
      ;;
    *)
      if ! grep -qx -- "$sym=$val" "$got_file"; then
        got="$(grep -m1 "^$sym=" "$got_file" || true)"
        echo "  MISMATCH $sym: asked for $val, got ${got:-<absent — misspelled symbol, or dependencies unmet>}" >&2
        fail=1
      fi
      ;;
  esac
done < "$want_file"

# A renamed symbol is accepted into .config and then makes Buildroot refuse to
# build, with an error that names no symbol at all. Catching it here says which.
if grep -q '^BR2_LEGACY=y' "$got_file" 2>/dev/null; then
  echo "  LEGACY: the configuration selects renamed symbols; Buildroot will refuse to build" >&2
  grep -E '^BR2_PACKAGE_[A-Z0-9_]+=y' "$want_file" | while IFS='=' read -r sym _; do
    if grep -q "^# ${sym} is not set" "$got_file"; then
      echo "    $sym looks renamed — check Config.in.legacy for its replacement" >&2
    fi
  done
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "config verification failed: $got_file does not honour $want_file" >&2
  exit 1
fi
echo "==> config verified: every requested symbol is present in $(basename "$got_file")"

#!/usr/bin/env sh
# Fail unless each given binary is statically linked.
set -eu

for bin in "$@"; do
  info=$(file -L "$bin")
  echo "$info"
  case "$info" in
    *"statically linked"* | *"static-pie linked"*) ;;
    *) echo "error: $bin is not statically linked" >&2; exit 1 ;;
  esac
  # glibc ldd prints "not a dynamic executable" (static) or "statically
  # linked" (static-pie); any "=>" line is a shared library dependency.
  deps=$(ldd "$bin" 2>&1 || true)
  if printf '%s\n' "$deps" | grep -q '=>'; then
    echo "error: $bin has shared library dependencies:" >&2
    printf '%s\n' "$deps" >&2
    exit 1
  fi
done

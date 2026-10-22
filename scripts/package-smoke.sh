#!/bin/sh
# Install a .deb or .rpm inside the current (container) system and check
# layout, permissions, default-path startup and clean removal.
# No systemd is required; see scripts/package-e2e.sh for the service test.
# Usage: package-smoke.sh /path/to/rusty-sock.{deb,rpm}
set -eu

pkg=$1
fail() { echo "FAIL: $*" >&2; exit 1; }

case "$pkg" in
  *.deb) dpkg -i "$pkg" >/dev/null ;;
  *.rpm) rpm -i "$pkg" ;;
  *) fail "unknown package type: $pkg" ;;
esac

check_mode() {
  got=$(stat -c '%a %U:%G' "$2")
  [ "$got" = "$1" ] || fail "$2: expected $1, got $got"
  echo "ok: $2 $got"
}
check_mode "755 root:root" /usr/bin/rusty-sock
check_mode "644 root:root" /etc/rusty-sock/config.toml
check_mode "600 root:root" /etc/rusty-sock/users
check_mode "644 root:root" /usr/lib/systemd/system/rusty-sock.service

rusty-sock --version

# Must start from the default config path with no flags and log a warning
# about the empty users file, then keep running until the timeout.
log=$(timeout 2 rusty-sock serve 2>&1 || true)
echo "$log"
echo "$log" | grep -q "listening" || fail "server did not start with default paths"
echo "$log" | grep -q "no users configured" || fail "missing empty-users warning"
printf '%s' "$log" | grep -q "$(printf '\033')" && fail "ANSI codes in non-tty output"

# Manage a user against the packaged root-only file.
printf 'smoke-pw\n' | rusty-sock user create smoke --password-stdin >/dev/null || fail "user create"
[ "$(rusty-sock user list)" = "smoke" ] || fail "user list"
check_mode "600 root:root" /etc/rusty-sock/users
rusty-sock user delete smoke >/dev/null || fail "user delete"
[ -z "$(rusty-sock user list)" ] || fail "user not deleted"
echo "ok: user create/list/delete on the packaged users file"

case "$pkg" in
  *.deb)
    dpkg -s rusty-sock | grep -q '^Conffiles:' || fail "no conffiles registered"
    dpkg -r rusty-sock >/dev/null
    [ ! -e /usr/bin/rusty-sock ] || fail "binary left after remove"
    [ -e /etc/rusty-sock/config.toml ] || fail "conffile removed before purge"
    dpkg -P rusty-sock >/dev/null
    [ ! -e /etc/rusty-sock/config.toml ] || fail "conffile left after purge"
    ;;
  *.rpm)
    rpm -qc rusty-sock | grep -q /etc/rusty-sock/users || fail "users not %config"
    rpm -e rusty-sock
    [ ! -e /usr/bin/rusty-sock ] || fail "binary left after erase"
    ;;
esac
echo "PASS: $pkg"

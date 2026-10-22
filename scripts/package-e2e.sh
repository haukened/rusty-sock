#!/bin/sh
# End-to-end test of the .deb under real systemd: install, configure a user,
# start the hardened service, proxy a request, and verify the sandbox.
# Requires root, systemd as PID 1, curl and python3. Modifies the system
# (installs and purges the package). Usage: sudo package-e2e.sh rusty-sock.deb
set -eu

deb=$1
unit=rusty-sock.service
port=18999
fail() { echo "FAIL: $*" >&2; journalctl -u "$unit" --no-pager -n 50 >&2 || true; exit 1; }
ok() { echo "ok: $*"; }

[ "$(id -u)" -eq 0 ] || fail "must run as root"
[ -d /run/systemd/system ] || fail "systemd is not running"

webroot=$(mktemp -d)
cleanup() {
  systemctl stop "$unit" >/dev/null 2>&1 || true
  dpkg -P rusty-sock >/dev/null 2>&1 || true
  [ -n "${web_pid:-}" ] && kill "$web_pid" 2>/dev/null || true
  rm -rf "$webroot"
}
trap cleanup EXIT

dpkg -i "$deb" >/dev/null
ok "installed"

# Installed but not enabled or started.
[ "$(systemctl is-enabled "$unit" 2>/dev/null || true)" = "disabled" ] || fail "unit should be disabled after install"
systemctl is-active --quiet "$unit" && fail "unit should not be running after install"
ok "unit disabled and inactive after install"

systemd-analyze verify "/usr/lib/systemd/system/$unit" || fail "systemd-analyze verify"
# Threshold is on a 0-100 scale: 20 = exposure 2.0.
systemd-analyze security --threshold=20 "$unit" >/dev/null || fail "exposure above 2.0"
ok "unit verified; $(systemd-analyze security "$unit" 2>/dev/null | tail -1 | sed 's/^→ //')"

# Configure: one user, and allow loopback so we can test against a local server.
printf 'e2e-password\n' | rusty-sock user create e2e --password-stdin >/dev/null || fail "user create"
[ "$(rusty-sock user list)" = "e2e" ] || fail "user list should show only e2e"
[ "$(stat -c '%a %U:%G' /etc/rusty-sock/users)" = "600 root:root" ] || fail "users file mode changed"
ok "user created with rusty-sock user create; file still 0600 root:root"
sed -i 's/^allow_private = false/allow_private = true/' /etc/rusty-sock/config.toml

echo "proxied-ok" > "$webroot/index.html"
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$webroot" >/dev/null 2>&1 &
web_pid=$!

systemctl start "$unit"
for _ in $(seq 1 50); do
  systemctl is-active --quiet "$unit" && journalctl -u "$unit" --no-pager | grep -q listening && break
  sleep 0.2
done
systemctl is-active --quiet "$unit" || fail "service did not start"
ok "service started"

body=$(curl -fsS --max-time 5 -x "socks5h://e2e:e2e-password@127.0.0.1:1080" "http://127.0.0.1:$port/") || fail "proxied request"
[ "$body" = "proxied-ok" ] || fail "unexpected body: $body"
ok "HTTP through the proxy"

if curl -fsS --max-time 5 -x "socks5h://e2e:wrong@127.0.0.1:1080" "http://127.0.0.1:$port/" >/dev/null 2>&1; then
  fail "wrong password accepted"
fi
ok "wrong password rejected"

# --restart applies a password change to the running service.
old_pid=$(systemctl show -p MainPID --value "$unit")
out=$(printf 'rotated-password\n' | rusty-sock user update e2e --password-stdin --restart) || fail "user update --restart"
echo "$out" | grep -q "restarted rusty-sock" || fail "unexpected output: $out"
new_pid=$(systemctl show -p MainPID --value "$unit")
[ "$new_pid" != "$old_pid" ] || fail "service was not restarted"
# Wait for the new process to accept connections.
for _ in $(seq 1 50); do
  curl -fsS --max-time 2 -x "socks5h://e2e:rotated-password@127.0.0.1:1080" "http://127.0.0.1:$port/" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -fsS --max-time 5 -x "socks5h://e2e:rotated-password@127.0.0.1:1080" "http://127.0.0.1:$port/" >/dev/null || fail "new password rejected after --restart"
if curl -fsS --max-time 5 -x "socks5h://e2e:e2e-password@127.0.0.1:1080" "http://127.0.0.1:$port/" >/dev/null 2>&1; then
  fail "old password still accepted after --restart"
fi
ok "user update --restart rotated the password on the running service"

# Sandbox checks on the running process.
pid=$(systemctl show -p MainPID --value "$unit")
[ "$pid" -gt 0 ] || fail "no main pid"
[ "$(systemctl show -p DynamicUser --value "$unit")" = "yes" ] || fail "DynamicUser not set"
[ -z "$(systemctl show -p CapabilityBoundingSet --value "$unit")" ] || fail "bounding set not empty"
for cap in CapInh CapPrm CapEff CapBnd CapAmb; do
  val=$(awk -v k="$cap:" '$1 == k { print $2 }' "/proc/$pid/status")
  [ "$val" = "0000000000000000" ] || fail "$cap=$val, expected none"
done
[ "$(awk '$1 == "NoNewPrivs:" { print $2 }' "/proc/$pid/status")" = "1" ] || fail "NoNewPrivs not set"
uid=$(awk '$1 == "Uid:" { print $2 }' "/proc/$pid/status")
[ "$uid" -ne 0 ] || fail "running as root"
ok "pid $pid: uid $uid, no capabilities, no_new_privs"

# Users must come from the systemd credential, and logs must be plain text.
journalctl -u "$unit" --no-pager | grep -q "path=/run/credentials/$unit/users users=1" || fail "users not read from credentials"
journalctl -u "$unit" --no-pager -o cat | grep -q "$(printf '\033')" && fail "ANSI codes in journal"
ok "users loaded via LoadCredential; journal output is plain"

systemctl stop "$unit"
dpkg -P rusty-sock >/dev/null
[ ! -e "/usr/lib/systemd/system/$unit" ] || fail "unit left after purge"
ok "purged"
echo "PASS"

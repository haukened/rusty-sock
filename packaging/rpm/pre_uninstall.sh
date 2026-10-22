# $1: 0 on erase, >0 on upgrade.
if [ "$1" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --no-reload disable --now rusty-sock.service >/dev/null 2>&1 || :
fi

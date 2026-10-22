# $1: 0 on erase, >0 on upgrade.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    if [ "$1" -ge 1 ]; then
        systemctl try-restart rusty-sock.service >/dev/null 2>&1 || :
    fi
fi

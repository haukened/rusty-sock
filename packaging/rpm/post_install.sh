#!/bin/sh
# $1: 1 on first install, >1 on upgrade.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || :
    if [ "$1" -eq 1 ]; then
        # Distribution presets decide; the default for unknown units is
        # "disable", so the proxy is not started until the admin enables it.
        systemctl --no-reload preset rusty-sock.service >/dev/null 2>&1 || :
    fi
fi

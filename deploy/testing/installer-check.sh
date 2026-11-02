#!/bin/sh
# Installs the agent with the real install.sh from a running installer-stub,
# checks it runs and reports, uninstalls it and checks nothing is left.
# CI runs this on FreeBSD, OpenBSD and NetBSD VMs, and on Linux.
#
#   sh deploy/testing/installer-check.sh http://127.0.0.1:8099
set -eu
STUB=${1:?usage: installer-check.sh <stub url>}
os=$(uname -s | tr '[:upper:]' '[:lower:]')
RC_SERVICE=sentinel_agent

get() {
    if command -v curl >/dev/null 2>&1; then curl -fsS "$1"
    elif [ "$os" = freebsd ]; then fetch -qo - "$1"
    else ftp -V -o - "$1"
    fi
}

running() {
    case "$os" in
        freebsd) service "$RC_SERVICE" status >/dev/null 2>&1 ;;
        openbsd) rcctl check "$RC_SERVICE" >/dev/null 2>&1 ;;
        netbsd) /etc/rc.d/$RC_SERVICE status >/dev/null 2>&1 ;;
        *) systemctl is-active --quiet sentinel-agent ;;
    esac
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

echo "== install"
get "$STUB/install.sh" >/tmp/install.sh
sh /tmp/install.sh --key pg_ci_install_key --tags ci,"$os"

echo "== checks"
/usr/local/bin/sentinel-agent version
ls /var/lib/sentinel
running || fail "service is not running"
i=0
while [ "$(get "$STUB/pushes")" = 0 ]; do
    i=$((i + 1))
    [ $i -lt 60 ] || fail "the agent sent no metrics in 60 s"
    sleep 1
done
echo "agent reported (pushes: $(get "$STUB/pushes"))"
crontab -l 2>/dev/null | grep -q sentinel-agent || [ -d /run/systemd/system ] ||
    fail "no hourly update in root's crontab"

echo "== uninstall"
sh /tmp/install.sh --uninstall
sleep 2
running && fail "service still running after uninstall"
for p in /usr/local/bin/sentinel-agent /var/lib/sentinel /etc/sentinel "/etc/rc.d/$RC_SERVICE" \
    "/usr/local/etc/rc.d/$RC_SERVICE"; do
    [ ! -e "$p" ] || fail "$p left behind"
done
if crontab -l 2>/dev/null | grep -q sentinel-agent; then fail "cron entry left behind"; fi
if pgrep -f 'sentinel-agent run' >/dev/null 2>&1; then fail "agent process left behind"; fi
echo "PASS on $os"

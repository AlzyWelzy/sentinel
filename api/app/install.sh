#!/bin/sh
# Pulsegrid agent installer for Linux, FreeBSD, OpenBSD and NetBSD.
#   curl -fsSL __DOWNLOAD_URL__/install.sh | sudo sh -s -- --key <install key> [--tags web,production]
#   (FreeBSD without curl: fetch -qo - ... | sh -s -- ...; OpenBSD: ftp -o - ... | doas sh -s -- ...)
#
# Served by the Pulsegrid API with the URLs below filled in from its config.
# Windows uses install.ps1 instead.
set -eu
# Non-interactive root shells (ssh, some sudo setups, NetBSD) often leave the
# sbin directories out of PATH, where useradd, service and friends live.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
export PATH

DOWNLOAD_URL="__DOWNLOAD_URL__"
INGEST_URL="__INGEST_URL__"
VERSION="__AGENT_VERSION__"

BIN=/usr/local/bin/pulsegrid-agent
STATE_DIR=/var/lib/pulsegrid
# Plugin and action files: written by root only, read by the agent.
CONFIG_DIR=/etc/pulsegrid
SERVICE=pulsegrid-agent
RC_SERVICE=pulsegrid_agent # rc.subr names can't contain dashes

die() { echo "pulsegrid: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

KEY=""
TAGS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --key) [ $# -ge 2 ] || die "--key needs a value"; KEY="$2"; shift 2 ;;
        --key=*) KEY="${1#*=}"; shift ;;
        --tags) [ $# -ge 2 ] || die "--tags needs a value"; TAGS="$2"; shift 2 ;;
        --tags=*) TAGS="${1#*=}"; shift ;;
        *) die "unknown option: $1" ;;
    esac
done
[ -n "$KEY" ] || die "usage: install.sh --key <install key> [--tags a,b]"
[ "$(id -u)" -eq 0 ] || die "run as root (sudo or doas)"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
    linux | freebsd | openbsd | netbsd) ;;
    *) die "this agent doesn't support $os yet" ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) die "unsupported CPU architecture: $(uname -m)" ;;
esac
# OpenBSD convention: daemon accounts start with an underscore.
SERVICE_USER=pulsegrid
[ "$os" = openbsd ] && SERVICE_USER=_pulsegrid

fetch_url() {
    if have curl; then
        curl -fsSL -o "$2" "$1"
    elif have wget; then
        wget -qO "$2" "$1"
    elif [ "$os" = freebsd ] && have fetch; then
        fetch -qo "$2" "$1"
    elif [ "$os" = openbsd ] || [ "$os" = netbsd ]; then
        ftp -V -o "$2" "$1"
    else
        die "curl or wget is required"
    fi
}

sha256_of() {
    if have sha256sum; then
        sha256sum "$1" | cut -d' ' -f1
    elif have sha256; then
        sha256 -q "$1"
    else
        openssl dgst -sha256 -r "$1" | cut -d' ' -f1
    fi
}

create_user() {
    id "$SERVICE_USER" >/dev/null 2>&1 && return 0
    case "$os" in
        freebsd) pw useradd "$SERVICE_USER" -d /nonexistent -s /usr/sbin/nologin -c "Pulsegrid agent" ;;
        openbsd) useradd -d /var/empty -s /sbin/nologin -c "Pulsegrid agent" "$SERVICE_USER" ;;
        netbsd) useradd -d /nonexistent -s /sbin/nologin -c "Pulsegrid agent" "$SERVICE_USER" ;;
        *)
            if have useradd; then
                useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
            else
                adduser -S -D -H -s /sbin/nologin "$SERVICE_USER" # Alpine
            fi
            ;;
    esac
}

# Updates run as root on a schedule, separately from the unprivileged agent,
# which can't replace its own binary. $1, if given, is a watchdog command run
# every 5 minutes, for init systems that don't restart a crashed service.
schedule_updates_with_cron() {
    minute=$(awk 'BEGIN { srand(); print int(rand() * 60) }')
    # Hourly: the updater only downloads when a new version is advertised.
    { crontab -l 2>/dev/null | grep -v "pulsegrid" || true
      echo "$minute * * * * $BIN update --state-dir $STATE_DIR --restart $SERVICE >/dev/null 2>&1 # pulsegrid"
      if [ $# -gt 0 ]; then
          echo "* * * * * ($1) >/dev/null 2>&1 # pulsegrid watchdog"
      fi
    } | crontab -
}

# The config directory holds plugin files (database passwords) and the list
# of actions the dashboard may run, so the agent can read but never write it.
setup_config_dir() {
    mkdir -p "$CONFIG_DIR/plugins.d" "$CONFIG_DIR/scripts"
    chown root "$CONFIG_DIR" "$CONFIG_DIR/plugins.d" "$CONFIG_DIR/scripts"
    chmod 0755 "$CONFIG_DIR" "$CONFIG_DIR/plugins.d" "$CONFIG_DIR/scripts"
    # Ours, so rewritten on every install to describe this version.
    cat >"$CONFIG_DIR/README" <<'PULSEGRID_README'
Pulsegrid agent configuration (root-owned; the agent only reads it).

plugins.d/<name>.conf   one plugin per file, "key = value" lines:
    type = mysql        dsn = monitor:secret@tcp(127.0.0.1:3306)/
    type = postgres     dsn = postgres://monitor:secret@127.0.0.1:5432/postgres
    type = redis        address = 127.0.0.1:6379   (password = ...)
    type = nginx        url = http://127.0.0.1/nginx_status
    type = apache       url = http://127.0.0.1/server-status?auto
    type = docker       socket = /var/run/docker.sock  (add the agent's user to the docker group)
    type = prometheus   url = http://127.0.0.1:9100/metrics   (include = regexp)
    type = script       command = /etc/pulsegrid/scripts/my-metrics.sh  (prints "name value" lines)
    type = snmp         address = 10.0.0.2   community = public   (or version = 3, user, auth_*, priv_*)
                        interfaces = true    oids = ups_load=1.3.6.1.2.1.33.1.4.4.1.5.1
  Disk health (SMART) and board sensors (IPMI): sudo pulsegrid-agent enable-hardware
  Files holding passwords: chmod 0640 and chgrp them to the agent's group.
  Test them with: pulsegrid-agent plugins

actions.conf            actions the dashboard may run on this server. Manage with:
    sudo pulsegrid-agent allow-action restart-nginx -- /usr/bin/systemctl restart nginx
    sudo pulsegrid-agent allow-action --remove restart-nginx

logs.conf               log files to ship for log search (nothing is shipped without it):
    file = /var/log/nginx/*.log
    file = /var/log/myapp/app.log
    journal = true      (systemd journal; the agent's user is in systemd-journal)
  New lines only, from when a file is first seen. The agent's user must be able
  to read the files (it's in the adm group, which covers most of /var/log).

apm.conf                receive OpenTelemetry traces from apps on this server:
    listen = 127.0.0.1:4318
  Then run your apps with OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
  (and OTEL_SERVICE_NAME=<name>); traces appear under APM in the dashboard.
PULSEGRID_README
    chmod 0644 "$CONFIG_DIR/README"
}

install_systemd() {
    cat >/etc/systemd/system/$SERVICE.service <<EOF
[Unit]
Description=Pulsegrid monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
User=$SERVICE_USER
ExecStart=$BIN run --state-dir $STATE_DIR
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$STATE_DIR

[Install]
WantedBy=multi-user.target
EOF
    cat >/etc/systemd/system/$SERVICE-update.service <<EOF
[Unit]
Description=Update the Pulsegrid agent
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN update --state-dir $STATE_DIR --restart $SERVICE
EOF
    cat >/etc/systemd/system/$SERVICE-update.timer <<EOF
[Unit]
Description=Check for Pulsegrid agent updates hourly

[Timer]
OnBootSec=10min
OnUnitActiveSec=1h
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE" >/dev/null 2>&1
    systemctl restart "$SERVICE"
    systemctl enable --now "$SERVICE-update.timer" >/dev/null 2>&1
    # Watchdog: Restart=always covers crashes, not `systemctl stop`; this
    # starts the agent again within a minute (a no-op while it runs). To
    # stop it for good: systemctl disable --now $SERVICE-watchdog.timer
    cat >/etc/systemd/system/$SERVICE-watchdog.service <<EOF
[Unit]
Description=Keep the Pulsegrid agent running

[Service]
Type=oneshot
ExecStart=/bin/systemctl start $SERVICE.service
EOF
    cat >/etc/systemd/system/$SERVICE-watchdog.timer <<EOF
[Unit]
Description=Start the Pulsegrid agent if it was stopped

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$SERVICE-watchdog.timer" >/dev/null 2>&1
}

install_openrc() {
    cat >/etc/init.d/$SERVICE <<EOF
#!/sbin/openrc-run
description="Pulsegrid monitoring agent"
command="$BIN"
command_args="run --state-dir $STATE_DIR"
command_user="$SERVICE_USER"
command_background=true
pidfile="/run/$SERVICE.pid"
depend() { need net; }
EOF
    chmod 0755 /etc/init.d/$SERVICE
    rc-update add "$SERVICE" default >/dev/null
    rc-service "$SERVICE" restart
    schedule_updates_with_cron "rc-service $SERVICE status || rc-service $SERVICE start"
}

install_freebsd() {
    # daemon(8) supervises the agent: restarts it if it dies (-r), drops to
    # the service user (-u) and sends its output to syslog (-S).
    cat >/usr/local/etc/rc.d/$RC_SERVICE <<EOF
#!/bin/sh
# PROVIDE: $RC_SERVICE
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name=$RC_SERVICE
rcvar=${RC_SERVICE}_enable
load_rc_config \$name
: \${${RC_SERVICE}_enable:=NO}

pidfile=/var/run/${RC_SERVICE}.pid
command=/usr/sbin/daemon
command_args="-P \${pidfile} -r -S -T $SERVICE -u $SERVICE_USER $BIN run --state-dir $STATE_DIR"

run_rc_command "\$1"
EOF
    chmod 0555 /usr/local/etc/rc.d/$RC_SERVICE
    sysrc -q ${RC_SERVICE}_enable=YES >/dev/null
    service "$RC_SERVICE" restart >/dev/null 2>&1 || service "$RC_SERVICE" start
    schedule_updates_with_cron "/usr/sbin/service $RC_SERVICE status || /usr/sbin/service $RC_SERVICE start"
}

install_openbsd() {
    cat >/etc/rc.d/$RC_SERVICE <<EOF
#!/bin/ksh

daemon="$BIN"
daemon_flags="run --state-dir $STATE_DIR"
daemon_user="$SERVICE_USER"

. /etc/rc.d/rc.subr

rc_bg=YES
rc_reload=NO

rc_cmd \$1
EOF
    chmod 0555 /etc/rc.d/$RC_SERVICE
    rcctl enable "$RC_SERVICE"
    rcctl restart "$RC_SERVICE" >/dev/null
    schedule_updates_with_cron "/usr/sbin/rcctl check $RC_SERVICE || /usr/sbin/rcctl start $RC_SERVICE"
}

install_netbsd() {
    # NetBSD's rc.subr finds a service by executable name unless given a
    # pidfile, which would also match (and kill) `pulsegrid-agent update`
    # while it restarts the agent. The agent writes its own pidfile.
    cat >/etc/rc.d/$RC_SERVICE <<EOF
#!/bin/sh
# PROVIDE: $RC_SERVICE
# REQUIRE: NETWORKING DAEMON

\$_rc_subr_loaded . /etc/rc.subr

name="$RC_SERVICE"
rcvar=\$name
command="$BIN"
pidfile="$STATE_DIR/agent.pid"
start_cmd="${RC_SERVICE}_start"

${RC_SERVICE}_start()
{
    echo "Starting \${name}."
    su -m $SERVICE_USER -c "$BIN run --state-dir $STATE_DIR --pidfile \$pidfile >/dev/null 2>&1 &"
}

load_rc_config \$name
run_rc_command "\$1"
EOF
    chmod 0555 /etc/rc.d/$RC_SERVICE
    grep -q "^${RC_SERVICE}=" /etc/rc.conf 2>/dev/null || echo "${RC_SERVICE}=YES" >>/etc/rc.conf
    # An agent started by an older script has no pidfile; stop it by user.
    pkill -u "$SERVICE_USER" -f "$BIN run" 2>/dev/null || true
    service "$RC_SERVICE" start
    schedule_updates_with_cron "/usr/sbin/service $RC_SERVICE status || /usr/sbin/service $RC_SERVICE start"
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
asset="pulsegrid-agent-$os-$arch"
echo "Downloading $asset ($VERSION)..."
fetch_url "$DOWNLOAD_URL/agent/$VERSION/$asset" "$tmp/$asset"
fetch_url "$DOWNLOAD_URL/agent/$VERSION/$asset.sha256" "$tmp/$asset.sha256"
expected=$(cut -d' ' -f1 <"$tmp/$asset.sha256")
[ "$expected" = "$(sha256_of "$tmp/$asset")" ] || die "checksum mismatch for $asset"

mkdir -p "$(dirname "$BIN")"
install -m 0755 "$tmp/$asset" "$BIN"
create_user
mkdir -p "$STATE_DIR"
setup_config_dir
# Read-only access to system logs, for log checks: on Debian/Ubuntu they
# belong to the adm group, the journal to systemd-journal.
for g in adm systemd-journal; do
    if getent group "$g" >/dev/null 2>&1; then
        if have usermod; then usermod -aG "$g" "$SERVICE_USER" 2>/dev/null || true
        elif have adduser; then adduser "$SERVICE_USER" "$g" 2>/dev/null || true
        fi
    fi
done

"$BIN" register --url "$INGEST_URL" --key "$KEY" --tags "$TAGS" --state-dir "$STATE_DIR"
chown -R "$SERVICE_USER" "$STATE_DIR"
chmod 0700 "$STATE_DIR"

case "$os" in
    freebsd) install_freebsd ;;
    openbsd) install_openbsd ;;
    netbsd) install_netbsd ;;
    *)
        if have systemctl && [ -d /run/systemd/system ]; then
            install_systemd
        elif have rc-service; then
            install_openrc
        else
            die "no systemd or OpenRC found; start '$BIN run --state-dir $STATE_DIR' with your init system"
        fi
        ;;
esac

echo "Pulsegrid agent installed and running."

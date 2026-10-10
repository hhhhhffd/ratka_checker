#!/usr/bin/env bash
set -euo pipefail

DEPLOY_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$DEPLOY_DIR/app"
BACKUP_DIR="/opt/ratscan/update-backup-$(date +%Y%m%d%H%M%S)"
ROLLBACK_NEEDED=0

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo bash scripts/update_ubuntu.sh" >&2
    exit 1
fi

if [ ! -x "$APP_DIR/ratscan" ]; then
    echo "Missing executable: $APP_DIR/ratscan" >&2
    echo "Build it first from the repository root: sh scripts/package_release.sh deploy/app" >&2
    exit 1
fi

if [ ! -f "$APP_DIR/config/rules.yaml" ]; then
    echo "Missing scanner rules: $APP_DIR/config/rules.yaml" >&2
    exit 1
fi

if [ ! -f /etc/ratscan/ratscan.env ]; then
    echo "Missing /etc/ratscan/ratscan.env; run scripts/install_ubuntu.sh for first install." >&2
    exit 1
fi

rollback() {
    if [ "$ROLLBACK_NEEDED" -ne 1 ]; then
        return
    fi

    echo "Update failed; restoring previous RatScan files from $BACKUP_DIR" >&2
    if [ -f "$BACKUP_DIR/ratscan" ]; then
        install -m 0755 "$BACKUP_DIR/ratscan" /opt/ratscan/bin/ratscan
    fi
    if [ -d "$BACKUP_DIR/config" ]; then
        rm -rf /opt/ratscan/config
        cp -a "$BACKUP_DIR/config" /opt/ratscan/config
    fi
    chown -R root:root /opt/ratscan/bin /opt/ratscan/config
    systemctl daemon-reload
    systemctl restart ratscan || true
}

trap rollback ERR

install -d -m 0755 "$BACKUP_DIR"
if [ -f /opt/ratscan/bin/ratscan ]; then
    cp -a /opt/ratscan/bin/ratscan "$BACKUP_DIR/ratscan"
fi
if [ -d /opt/ratscan/config ]; then
    cp -a /opt/ratscan/config "$BACKUP_DIR/config"
fi
ROLLBACK_NEEDED=1

systemctl disable --now ratscan-telegram-bot >/dev/null 2>&1 || true
systemctl stop ratscan

install -d -m 0755 /opt/ratscan/bin /opt/ratscan/config /opt/ratscan/storage
install -m 0755 "$APP_DIR/ratscan" /opt/ratscan/bin/ratscan
rm -rf /opt/ratscan/config
mkdir -p /opt/ratscan/config
cp -R "$APP_DIR/config/." /opt/ratscan/config/
chown -R root:root /opt/ratscan/bin /opt/ratscan/config
chown -R ratscan:ratscan /opt/ratscan/storage

install -m 0644 "$DEPLOY_DIR/systemd/ratscan.service" /etc/systemd/system/ratscan.service
rm -f /etc/systemd/system/ratscan-telegram-bot.service

systemctl daemon-reload
systemctl restart ratscan

for attempt in 1 2 3 4 5; do
    if curl --fail --silent --show-error http://127.0.0.1:8080/health >/dev/null; then
        break
    fi
    if [ "$attempt" -eq 5 ]; then
        exit 1
    fi
    sleep 1
done

ROLLBACK_NEEDED=0
echo "RatScan updated successfully."
echo "Backup kept at: $BACKUP_DIR"

#!/usr/bin/env bash
set -euo pipefail

DEPLOY_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$DEPLOY_DIR/app"
DB_NAME="${RATSCAN_DB_NAME:-ratscan}"
DB_USER="${RATSCAN_DB_USER:-ratscan}"
DB_PASSWORD="${RATSCAN_DB_PASSWORD:-}"
SWAP_SIZE="${RATSCAN_SWAP_SIZE:-4G}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo bash deploy/scripts/install_ubuntu.sh" >&2
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

if [[ ! "$DB_NAME" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "RATSCAN_DB_NAME must be a PostgreSQL identifier: letters, numbers, and underscore." >&2
    exit 1
fi

if [[ ! "$DB_USER" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "RATSCAN_DB_USER must be a PostgreSQL identifier: letters, numbers, and underscore." >&2
    exit 1
fi

case "$DB_PASSWORD" in
    *[!A-Za-z0-9._-]*)
        echo "RATSCAN_DB_PASSWORD may contain only letters, numbers, dot, underscore, or dash." >&2
        exit 1
        ;;
esac

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl nginx openssl postgresql postgresql-client

if [ -z "$DB_PASSWORD" ]; then
    DB_PASSWORD="$(openssl rand -hex 24)"
fi

if ! getent group ratscan >/dev/null; then
    groupadd --system ratscan
fi

if ! getent passwd ratscan >/dev/null; then
    useradd --system --gid ratscan --home-dir /opt/ratscan --shell /usr/sbin/nologin ratscan
else
    usermod --gid ratscan ratscan
fi

install -d -m 0755 /opt/ratscan /opt/ratscan/bin /opt/ratscan/config /opt/ratscan/storage
install -d -m 0755 /var/www/ratscan
install -d -m 0750 /etc/ratscan

install -m 0755 "$APP_DIR/ratscan" /opt/ratscan/bin/ratscan
cp -R "$APP_DIR/config/." /opt/ratscan/config/
cp -R "$DEPLOY_DIR/frontend/." /var/www/ratscan/

chown -R root:root /opt/ratscan/bin /opt/ratscan/config /var/www/ratscan
chown -R ratscan:ratscan /opt/ratscan/storage

systemctl enable --now postgresql

if ! runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname = '$DB_USER'" | grep -q 1; then
    runuser -u postgres -- psql -c "CREATE ROLE $DB_USER LOGIN PASSWORD '$DB_PASSWORD';"
else
    runuser -u postgres -- psql -c "ALTER ROLE $DB_USER WITH LOGIN PASSWORD '$DB_PASSWORD';"
fi

if ! runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1; then
    runuser -u postgres -- createdb --owner="$DB_USER" "$DB_NAME"
fi

runuser -u postgres -- psql -d "$DB_NAME" -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"

cat >/etc/ratscan/ratscan.env <<EOF
RUST_LOG=info
DATABASE_URL=postgres://$DB_USER:$DB_PASSWORD@localhost:5432/$DB_NAME
RATSCAN_BIND_ADDR=127.0.0.1:8080
RATSCAN_RULES_PATH=config/rules.yaml
RATSCAN_STORAGE_DIR=storage
MAX_TOTAL_UNCOMPRESSED_MB=80
MAX_FILES_IN_ARCHIVE=3000
MAX_NESTING_DEPTH=3
MAX_SINGLE_FILE_MB=25
FILE_RETENTION_DAYS=3
FILE_CLEANUP_INTERVAL_MINUTES=60
VIRUSTOTAL_ENABLED=false
VIRUSTOTAL_API_KEY=
VIRUSTOTAL_TIMEOUT_SECONDS=20
VIRUSTOTAL_CACHE_TTL_HOURS=24
VIRUSTOTAL_POLL_ATTEMPTS=6
VIRUSTOTAL_POLL_INTERVAL_SECONDS=10
EOF
chown root:ratscan /etc/ratscan
chmod 0750 /etc/ratscan
chown root:ratscan /etc/ratscan/ratscan.env
chmod 0640 /etc/ratscan/ratscan.env

install -m 0644 "$DEPLOY_DIR/systemd/ratscan.service" /etc/systemd/system/ratscan.service
install -m 0644 "$DEPLOY_DIR/nginx/ratscan.conf" /etc/nginx/sites-available/ratscan.conf
ln -sf /etc/nginx/sites-available/ratscan.conf /etc/nginx/sites-enabled/ratscan.conf
rm -f /etc/nginx/sites-enabled/default

if ! swapon --show=NAME | grep -qx "/swapfile"; then
    if [ ! -f /swapfile ]; then
        fallocate -l "$SWAP_SIZE" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=4096
        chmod 0600 /swapfile
        mkswap /swapfile
    fi
    swapon /swapfile
fi

if ! grep -q '^/swapfile ' /etc/fstab; then
    echo "/swapfile none swap sw 0 0" >>/etc/fstab
fi

systemctl daemon-reload
systemctl enable --now ratscan
nginx -t
systemctl enable --now nginx
systemctl reload nginx

echo "RatScan is installed."
echo "Local URL: http://127.0.0.1/"

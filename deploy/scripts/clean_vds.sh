#!/usr/bin/env bash
set -euo pipefail

APPLY=false

if [ "${1:-}" = "--apply" ]; then
    APPLY=true
elif [ "$#" -ne 0 ]; then
    echo "Usage: sudo bash scripts/clean_vds.sh [--apply]" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo bash scripts/clean_vds.sh [--apply]" >&2
    exit 1
fi

targets=(
    "/etc/systemd/system/ratscan.service"
    "/etc/systemd/system/ratscan-telegram-bot.service"
    "/etc/ratscan"
    "/opt/ratscan"
    "/var/www/ratscan"
)
services=(ratscan ratscan-telegram-bot)
databases=(ratscan ratka)
roles=(ratscan ratka_bot)

echo "The following legacy RatScan targets will be removed:"
printf '  %s\n' "${targets[@]}"
echo "PostgreSQL databases to drop: ${databases[*]}"
echo "PostgreSQL roles to drop: ${roles[*]}"
echo "PostgreSQL packages are retained because the new deployment requires them."

if [ "$APPLY" != true ]; then
    echo "Dry run only. Re-run with --apply to remove the listed targets."
    exit 0
fi

for service in "${services[@]}"; do
    systemctl disable --now "$service" >/dev/null 2>&1 || true
done

rm -f /etc/systemd/system/ratscan.service
rm -f /etc/systemd/system/ratscan-telegram-bot.service
systemctl daemon-reload
systemctl reset-failed "${services[@]}" || true

for database in "${databases[@]}"; do
    if runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname = '$database'" | grep -q 1; then
        runuser -u postgres -- dropdb --force "$database"
    fi
done

for role in "${roles[@]}"; do
    if runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname = '$role'" | grep -q 1; then
        runuser -u postgres -- psql -c "DROP ROLE $role;"
    fi
done

rm -rf /etc/ratscan /opt/ratscan /var/www/ratscan

echo "Legacy RatScan installation removed. PostgreSQL is still installed."

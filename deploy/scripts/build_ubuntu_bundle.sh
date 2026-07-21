#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_DIR="$REPO_DIR/deploy"
APP_DIR="$DEPLOY_DIR/app"

cd "$REPO_DIR"

cargo build --release --bins

rm -rf "$APP_DIR/config" "$APP_DIR/telegram_bot"
install -d -m 0755 "$APP_DIR"
install -m 0755 target/release/ratscan "$APP_DIR/ratscan"
install -m 0755 target/release/ratscan-discord "$APP_DIR/ratscan-discord"
cp -R config "$APP_DIR/config"
cp -R telegram_bot "$APP_DIR/telegram_bot"
rm -f "$APP_DIR/telegram_bot/Dockerfile"
find "$APP_DIR/telegram_bot" -type d -name __pycache__ -prune -exec rm -rf {} +
cp .env.example "$APP_DIR/.env.example"

if [ -f .env ]; then
    install -m 0600 .env "$APP_DIR/.env"
    echo "Copied local .env to deploy/app/.env"
else
    echo "Local .env was not found; deploy/app/.env was not created." >&2
fi

cat > "$APP_DIR/RUN.md" <<'RUN_DOC'
# RatScan Ubuntu Deploy Bundle

Copy the whole `deploy/` directory to an Ubuntu host and run:

```sh
sudo bash scripts/install_ubuntu.sh
```

The installer uses this directory:

- `ratscan` - release API binary;
- `config/rules.yaml` - scanner rules;
- `telegram_bot/` - independent aiogram Telegram client;
- `.env` - optional local secrets copied by `build_ubuntu_bundle.sh`.

The installer creates PostgreSQL locally and writes the final runtime environment
to `/etc/ratscan/ratscan.env`.
RUN_DOC

echo "Ubuntu deploy bundle written to $APP_DIR"

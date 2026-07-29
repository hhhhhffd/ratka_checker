#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_DIR="$REPO_DIR/deploy"
RELEASES_DIR="$DEPLOY_DIR/releases"
GIT_REVISION="$(git -C "$REPO_DIR" rev-parse --short HEAD)"
RELEASE_NAME="ratscan-$(date -u +%Y%m%dT%H%M%SZ)-$GIT_REVISION"
RELEASE_DIR="${1:-$RELEASES_DIR/$RELEASE_NAME}"
APP_DIR="$RELEASE_DIR/app"

cd "$REPO_DIR"

cargo build --release --package ratscan-api

if [ -e "$RELEASE_DIR" ]; then
    echo "Release directory already exists: $RELEASE_DIR" >&2
    exit 1
fi

install -d -m 0755 "$APP_DIR"
install -d -m 0755 "$RELEASE_DIR/scripts" "$RELEASE_DIR/systemd" "$RELEASE_DIR/env"
install -m 0755 target/release/ratscan "$APP_DIR/ratscan"
cp -R config "$APP_DIR/config"
cp -R telegram_bot "$APP_DIR/telegram_bot"
find "$APP_DIR/telegram_bot" -type d -name __pycache__ -prune -exec rm -rf {} +
cp .env.example "$APP_DIR/.env.example"
install -m 0755 "$DEPLOY_DIR/scripts/install_ubuntu.sh" "$RELEASE_DIR/scripts/install_ubuntu.sh"
install -m 0755 "$DEPLOY_DIR/scripts/update_ubuntu.sh" "$RELEASE_DIR/scripts/update_ubuntu.sh"
install -m 0755 "$DEPLOY_DIR/scripts/clean_vds.sh" "$RELEASE_DIR/scripts/clean_vds.sh"
install -m 0644 "$DEPLOY_DIR/systemd/ratscan.service" "$RELEASE_DIR/systemd/ratscan.service"
install -m 0644 "$DEPLOY_DIR/env/ratscan.env.example" "$RELEASE_DIR/env/ratscan.env.example"

if [ -f .env ]; then
    install -m 0600 .env "$APP_DIR/.env"
    echo "Copied local .env to $APP_DIR/.env"
else
    echo "Local .env was not found; $APP_DIR/.env was not created." >&2
fi

cat > "$APP_DIR/RUN.md" <<'RUN_DOC'
# RatScan Ubuntu Deploy Bundle

Copy this whole release directory to an Ubuntu host. For a fresh installation,
first inspect cleanup and then run:

```sh
sudo bash scripts/clean_vds.sh
sudo bash scripts/clean_vds.sh --apply
```

Install the release with:

```sh
sudo bash scripts/install_ubuntu.sh
```

The installer uses `app/`:

- `ratscan` - release API binary;
- `config/rules.yaml` - scanner rules;
- `telegram_bot/` - Telegram worker launched by the RatScan API process;
- `.env` - optional local secrets copied by `build_ubuntu_bundle.sh`.

The installer creates PostgreSQL locally and writes the final runtime environment
to `/etc/ratscan/ratscan.env`.
RUN_DOC

echo "Ubuntu deploy bundle written to $RELEASE_DIR"

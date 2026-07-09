# RatScan Deploy

This directory is the Ubuntu deployment kit for a small test VPS.

It runs:

- Rust API through systemd on `127.0.0.1:8080`;
- optional aiogram Telegram bot through systemd;
- PostgreSQL on the same host.

## 1. Build the package locally

Run this from the repository root on your dev machine:

```sh
bash deploy/scripts/build_ubuntu_bundle.sh
```

The bundle script builds the Rust binary locally, copies `telegram_bot/`, and
copies local `.env` to `deploy/app/.env` when it exists. `deploy/app/` is ignored
by git because it can contain secrets.

After that, copy the whole `deploy/` directory to the VPS:

```sh
scp -r deploy ubuntu@YOUR_SERVER_IP:/home/ubuntu/ratka-deploy
```

## 2. Install on Ubuntu

SSH into the VPS:

```sh
ssh ubuntu@YOUR_SERVER_IP
cd /home/ubuntu/ratka-deploy
sudo bash scripts/install_ubuntu.sh
```

The installer will:

- install `postgresql`, `curl`, `ca-certificates`, and `openssl`;
- install `python3-venv` and Telegram bot dependencies into
  `/opt/ratscan/telegram-venv`;
- create a 4 GB `/swapfile` if it is not active;
- copy the API to `/opt/ratscan`;
- copy the Telegram bot to `/opt/ratscan/telegram_bot`;
- create `/etc/ratscan/ratscan.env`, preserving supported values from
  `deploy/app/.env`;
- create the PostgreSQL database and user;
- enable `ratscan.service` and `ratscan-telegram-bot.service` when
  `TG_BOT_TOKEN` and `ALLOWED_TG_ID` are set.

## 3. Check service state

```sh
systemctl status ratscan --no-pager
systemctl status ratscan-telegram-bot --no-pager
curl -s http://127.0.0.1:8080/health
```

Logs:

```sh
journalctl -u ratscan -f
journalctl -u ratscan-telegram-bot -f
```

## 4. Runtime paths

- API binary: `/opt/ratscan/bin/ratscan`
- scanner config: `/opt/ratscan/config/rules.yaml`
- uploaded files: `/opt/ratscan/storage`
- Telegram bot: `/opt/ratscan/telegram_bot`
- Telegram bot venv: `/opt/ratscan/telegram-venv`
- environment: `/etc/ratscan/ratscan.env`

## 5. Update an existing VPS

For an already installed VPS, do not rerun the full installer unless you want to
recreate deployment defaults. Use the update script; it preserves:

- `/etc/ratscan/ratscan.env`;
- PostgreSQL database/user/password;
- `/opt/ratscan/storage`.

Build the Linux release package locally again:

```sh
bash deploy/scripts/build_ubuntu_bundle.sh
scp -r deploy ubuntu@YOUR_SERVER_IP:/home/ubuntu/ratka-deploy
```

Then on the VPS:

```sh
cd /home/ubuntu/ratka-deploy
sudo bash scripts/update_ubuntu.sh
```

The updater:

- does not run `apt-get`;
- does not touch PostgreSQL;
- backs up the old binary/config/Telegram bot under `/opt/ratscan/update-backup-*`;
- installs the new binary, `rules.yaml`, Telegram bot, and systemd units;
- restarts `ratscan` and `ratscan-telegram-bot` when bot env is configured;
- checks `http://127.0.0.1:8080/health`;
- rolls files back if the update fails before the health check.

Useful checks after update:

```sh
systemctl status ratscan --no-pager
journalctl -u ratscan -n 100 --no-pager
curl -s http://127.0.0.1:8080/health
```

Use `scripts/install_ubuntu.sh` only for first install or when rebuilding the
host from scratch.

# RatScan Deploy

Ubuntu deployment kit for one RatScan systemd unit and PostgreSQL.

`ratscan.service` runs the HTTP API and, when `TG_BOT_TOKEN` plus
`ALLOWED_TG_ID` are configured, starts the Telegram worker as an internal,
supervised child process. There is no `ratscan-telegram-bot.service`.

The Discord bot is deployed independently from the `modhub.bot` repository.

## Build and install

```sh
# development machine
bash deploy/scripts/build_ubuntu_bundle.sh
scp -r deploy/releases/ratscan-<release> ubuntu@YOUR_SERVER_IP:/home/ubuntu/ratka-deploy

# VPS
cd /home/ubuntu/ratka-deploy
sudo bash scripts/clean_vds.sh --apply
sudo bash scripts/install_ubuntu.sh
```

The installer creates the API database. The internal Telegram worker is compiled
into the Rust binary. Check the combined service with:

```sh
systemctl status ratscan --no-pager
journalctl -u ratscan -f
curl -s http://127.0.0.1:8080/health
```

To update, copy a new bundle and run `sudo bash scripts/update_ubuntu.sh`.

# RatScan Deploy

This directory is the Ubuntu deployment kit for a small test VPS.

It runs:

- static frontend through nginx;
- Rust API through systemd on `127.0.0.1:8080`;
- PostgreSQL on the same host;
- optional Cloudflare Tunnel in front of nginx.

## 1. Build the package locally

Run this from the repository root on your dev machine:

```sh
sh scripts/package_release.sh deploy/app
```

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

- install `postgresql`, `nginx`, `curl`, `ca-certificates`, and `openssl`;
- create a 4 GB `/swapfile` if it is not active;
- copy the API to `/opt/ratscan`;
- copy the frontend to `/var/www/ratscan`;
- create `/etc/ratscan/ratscan.env`;
- create the PostgreSQL database and user;
- enable `ratscan.service` and nginx.

## 3. Check service state

```sh
systemctl status ratscan --no-pager
systemctl status nginx --no-pager
curl -s http://127.0.0.1/health
```

Logs:

```sh
journalctl -u ratscan -f
```

## 4. Cloudflare Tunnel

In Cloudflare Zero Trust, create a tunnel and set its public hostname to:

```text
http://localhost:80
```

For Oracle `VM.Standard.E2.1.Micro` use the `linux-amd64` package:

```sh
curl -L -o cloudflared.deb \
  https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared.deb
```

Then paste and run the service install command from the Cloudflare dashboard. It looks like this:

```sh
sudo cloudflared service install YOUR_TUNNEL_TOKEN
```

Check it:

```sh
systemctl status cloudflared --no-pager
```

## 5. Runtime paths

- API binary: `/opt/ratscan/bin/ratscan`
- scanner config: `/opt/ratscan/config/rules.yaml`
- uploaded files: `/opt/ratscan/storage`
- environment: `/etc/ratscan/ratscan.env`
- frontend: `/var/www/ratscan`
- nginx config: `/etc/nginx/sites-available/ratscan.conf`

## 6. Update an existing VPS

For an already installed VPS, do not rerun the full installer unless you want to
recreate deployment defaults. Use the update script; it preserves:

- `/etc/ratscan/ratscan.env`;
- PostgreSQL database/user/password;
- `/opt/ratscan/storage`.

Build the Linux release package locally again:

```sh
sh scripts/package_release.sh deploy/app
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
- backs up the old binary/config/frontend under `/opt/ratscan/update-backup-*`;
- installs the new binary, `rules.yaml`, frontend, systemd unit, and nginx config;
- restarts `ratscan`;
- reloads nginx;
- checks `http://127.0.0.1/health`;
- rolls files back if the update fails before the health check.

Useful checks after update:

```sh
systemctl status ratscan --no-pager
journalctl -u ratscan -n 100 --no-pager
curl -s http://127.0.0.1/health
```

Use `scripts/install_ubuntu.sh` only for first install or when rebuilding the
host from scratch.

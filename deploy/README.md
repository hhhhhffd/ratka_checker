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
- enable `ratscan.service` and nginx;
- write the one-time web API key to `/root/ratscan-api-key.txt`.

Open the API key:

```sh
sudo cat /root/ratscan-api-key.txt
```

Use that key in the frontend field.

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

## 6. Update deploy

Build locally again:

```sh
sh scripts/package_release.sh deploy/app
scp -r deploy ubuntu@YOUR_SERVER_IP:/home/ubuntu/ratka-deploy
```

Then on the VPS:

```sh
cd /home/ubuntu/ratka-deploy
sudo bash scripts/install_ubuntu.sh
```

The installer keeps the existing API key file if it already exists.

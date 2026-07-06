# RatScan API

Rust API service for static scanning Minecraft `.jar` mods.

## Build Binary Package In Docker

Docker is only used as a build environment:

```sh
sh scripts/package_release.sh
```

Output:

```text
dist/ratscan/
  ratscan
  config/rules.yaml
  .env.example
  RUN.md
```

Copy `dist/ratscan/` to the host that will run the service. The service itself does not need Docker.

## Run On Host

PostgreSQL must be available through `DATABASE_URL`. Migrations are embedded in the binary and run on startup.

```sh
cd dist/ratscan
cp .env.example .env
mkdir -p storage
set -a
. ./.env
set +a

./ratscan
```

The API is open by default. Put nginx, a tunnel, or firewall rules in front of it if public access needs to be restricted.

## Upload

```sh
curl -F "file=@mod.jar" \
  http://127.0.0.1:8080/v1/scans
```

## VirusTotal

VirusTotal is optional and disabled by default. Set `VIRUSTOTAL_ENABLED=true`
and provide `VIRUSTOTAL_API_KEY` to add the `virustotal` field to scan
responses. Reports are cached by sha256 in PostgreSQL using
`VIRUSTOTAL_CACHE_TTL_HOURS` to avoid repeated quota usage for the same jar.
The `virustotal.behavior` field contains condensed VirusTotal sandbox artifacts
when the behaviours relationship is available for the file.

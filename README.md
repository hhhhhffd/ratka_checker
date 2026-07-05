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

./ratscan seed-api-key --label discord-bot-prod
./ratscan serve
```

Save the printed API key. It is shown once; only its sha256 hash is stored in PostgreSQL.

## Upload

```sh
curl -H "X-API-Key: $RATSCAN_KEY" \
  -F "file=@mod.jar" \
  http://127.0.0.1:8080/v1/scans
```

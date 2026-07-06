#!/usr/bin/env sh
set -eu

RUST_IMAGE="${RUST_IMAGE:-rust:1.88-bookworm}"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
OUT_DIR="${1:-dist/ratscan}"
CARGO_CACHE_DIR="${CARGO_CACHE_DIR:-.cargo-cache}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-.docker-target}"

case "$OUT_DIR" in
    "" | "/" | ".")
        echo "Refusing unsafe output directory: $OUT_DIR" >&2
        exit 1
        ;;
esac

mkdir -p "$OUT_DIR" "$CARGO_CACHE_DIR" "$CARGO_TARGET_DIR"

# Cargo runs in Docker, but cache/target/output are mounted into the repo and owned by the host user.
docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    --user "$(id -u):$(id -g)" \
    -v "$PWD":/app \
    -w /app \
    -e CARGO_HOME=/app/"$CARGO_CACHE_DIR" \
    -e CARGO_TARGET_DIR=/app/"$CARGO_TARGET_DIR" \
    "$RUST_IMAGE" \
    cargo build --release

rm -rf "$OUT_DIR/config"
mkdir -p "$OUT_DIR"
cp "$CARGO_TARGET_DIR/release/ratscan" "$OUT_DIR/ratscan"
cp -R config "$OUT_DIR/config"
cp .env.example "$OUT_DIR/.env.example"
chmod +x "$OUT_DIR/ratscan"

cat > "$OUT_DIR/RUN.md" <<'RUN_DOC'
# RatScan Runtime Package

This directory is enough to run the API on a Linux host:

- `ratscan` — release binary
- `config/rules.yaml` — scan rules loaded at startup
- `.env.example` — environment template

Runtime still needs PostgreSQL reachable through `DATABASE_URL`.

```sh
cp .env.example .env
mkdir -p storage
set -a
. ./.env
set +a

./ratscan
```

The API is open by default. Put nginx, a tunnel, or firewall rules in front of it if public access needs to be restricted.
RUN_DOC

echo "Release package written to $OUT_DIR"

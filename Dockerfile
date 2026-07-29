FROM rust:1.88-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY src ./src
COPY migrations ./migrations
COPY config ./config
RUN cargo build --release --workspace

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 ratscan
WORKDIR /app
COPY --from=builder /app/target/release/ratscan /usr/local/bin/ratscan
COPY config ./config
COPY telegram_bot ./telegram_bot
RUN python3 -m venv telegram-venv \
    && telegram-venv/bin/pip install --no-cache-dir -r telegram_bot/requirements.txt \
    && mkdir -p storage \
    && chown -R ratscan:ratscan /app
USER ratscan

EXPOSE 8080
CMD ["ratscan"]

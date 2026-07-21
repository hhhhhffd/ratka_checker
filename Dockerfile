FROM rust:1.88-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY src ./src
COPY migrations ./migrations
COPY config ./config
RUN cargo build --release --workspace

FROM debian:bookworm-slim

RUN useradd --create-home --uid 10001 ratscan
WORKDIR /app
COPY --from=builder /app/target/release/ratscan /usr/local/bin/ratscan
COPY --from=builder /app/target/release/ratscan-discord /usr/local/bin/ratscan-discord
COPY config ./config
RUN mkdir -p /app/storage && chown -R ratscan:ratscan /app
USER ratscan

EXPOSE 8080
CMD ["ratscan"]

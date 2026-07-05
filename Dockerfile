FROM rust:1.88-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY migrations ./migrations
COPY config ./config
RUN cargo build --release

FROM debian:bookworm-slim

RUN useradd --create-home --uid 10001 ratscan
WORKDIR /app
COPY --from=builder /app/target/release/ratscan /usr/local/bin/ratscan
COPY config ./config
RUN mkdir -p /app/storage && chown -R ratscan:ratscan /app
USER ratscan

EXPOSE 8080
CMD ["ratscan", "serve"]

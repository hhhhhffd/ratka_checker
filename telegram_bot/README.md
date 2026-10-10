# RatScan Telegram worker

This is an internal component of the RatScan service, not a standalone service.
The Rust `ratscan` process starts and supervises it whenever both credentials
are present:

```sh
TG_BOT_TOKEN=
ALLOWED_TG_ID=
RATSCAN_API_BASE_URL=http://127.0.0.1:8080
```

A Telegram crash is retried without stopping the HTTP API. Stopping RatScan
stops the worker too; no `ratscan-telegram-bot.service` exists.

The worker is implemented in `src/telegram/bot.rs` and compiled into the same
Rust executable. The API launches it with `--telegram-worker`; it continues to
access RatScan through HTTP. For local development, export the settings above
and run:

```sh
cargo run
```

Python and a virtual environment are not required in Docker or Ubuntu installs.

Optional settings remain `TG_BOT_REQUEST_TIMEOUT_SECONDS` (30),
`TG_BOT_POLL_ATTEMPTS` (24), and `TG_BOT_POLL_INTERVAL_SECONDS` (5).

## Usage

- Send a `.jar` document to start a scan.
- Use `/id <scan_id>` to fetch the full report.
- Use `/sha256 <hash>` (or `/hash <hash>`) to fetch the latest report by SHA-256.
- Messages from Telegram users other than `ALLOWED_TG_ID` are ignored.

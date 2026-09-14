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

For local `cargo run`, prepare the relative virtual environment expected by the
API process:

```sh
python3 -m venv telegram-venv
telegram-venv/bin/pip install -r telegram_bot/requirements.txt
cargo run
```

The Docker image and Ubuntu installer create this environment automatically.

## Usage

- Send a `.jar` document to start a scan.
- Use `/id <scan_id>` to fetch the full report.
- Use `/sha256 <hash>` (or `/hash <hash>`) to fetch the latest report by SHA-256.
- Messages from Telegram users other than `ALLOWED_TG_ID` are ignored.

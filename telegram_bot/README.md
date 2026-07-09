# RatScan Telegram Bot

Independent Telegram client for the RatScan HTTP API. The Rust API does not import
or depend on this bot; run it only when Telegram access is needed.

## Configuration

Add these values to `.env` or export them before starting the bot. The bot
loads `.env` automatically from the current working directory.

```sh
TG_BOT_TOKEN=
ALLOWED_TG_ID=
RATSCAN_API_BASE_URL=http://127.0.0.1:8080
```

Optional settings:

```sh
TG_BOT_REQUEST_TIMEOUT_SECONDS=30
TG_BOT_POLL_ATTEMPTS=24
TG_BOT_POLL_INTERVAL_SECONDS=5
```

## Run

```sh
python -m venv .venv-tg
. .venv-tg/bin/activate
python -m telegram_bot.bot
```

## Usage

- Send a `.jar` document to start a scan.
- Use `/id <scan_id>` to fetch the full public API report.
- Messages from Telegram users other than `ALLOWED_TG_ID` are ignored.

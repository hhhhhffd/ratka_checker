import asyncio
import html
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiohttp
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import BufferedInputFile, Message
from dotenv import load_dotenv

LOGGER = logging.getLogger(__name__)

DEFAULT_API_BASE_URL = "http://127.0.0.1:8080"
DEFAULT_REQUEST_TIMEOUT_SECONDS = 30
DEFAULT_POLL_ATTEMPTS = 24
DEFAULT_POLL_INTERVAL_SECONDS = 5
MAX_MESSAGE_LENGTH = 3900


@dataclass(frozen=True)
class BotConfig:
    token: str
    allowed_tg_id: int
    api_base_url: str
    request_timeout_seconds: float
    poll_attempts: int
    poll_interval_seconds: float


class ConfigError(ValueError):
    pass


class ApiError(RuntimeError):
    pass


def load_config() -> BotConfig:
    token = required_env("TG_BOT_TOKEN")
    allowed_tg_id = parse_int_env("ALLOWED_TG_ID")

    return BotConfig(
        token=token,
        allowed_tg_id=allowed_tg_id,
        api_base_url=os.getenv("RATSCAN_API_BASE_URL", DEFAULT_API_BASE_URL).rstrip("/"),
        request_timeout_seconds=parse_float_env(
            "TG_BOT_REQUEST_TIMEOUT_SECONDS",
            DEFAULT_REQUEST_TIMEOUT_SECONDS,
        ),
        poll_attempts=parse_int_env("TG_BOT_POLL_ATTEMPTS", DEFAULT_POLL_ATTEMPTS),
        poll_interval_seconds=parse_float_env(
            "TG_BOT_POLL_INTERVAL_SECONDS",
            DEFAULT_POLL_INTERVAL_SECONDS,
        ),
    )


def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ConfigError(f"{name} is required")
    return value


def parse_int_env(name: str, default: int | None = None) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        if default is None:
            raise ConfigError(f"{name} is required")
        return default

    try:
        return int(raw_value)
    except ValueError as error:
        raise ConfigError(f"{name} must be an integer") from error


def parse_float_env(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        return float(raw_value)
    except ValueError as error:
        raise ConfigError(f"{name} must be a number") from error


class RatScanClient:
    def __init__(self, config: BotConfig) -> None:
        timeout = aiohttp.ClientTimeout(total=config.request_timeout_seconds)
        self._session = aiohttp.ClientSession(timeout=timeout)
        self._base_url = config.api_base_url

    async def close(self) -> None:
        await self._session.close()

    async def create_scan(self, file_path: Path, filename: str) -> dict[str, Any]:
        form = aiohttp.FormData()
        with file_path.open("rb") as file:
            form.add_field(
                "file",
                file,
                filename=filename,
                content_type="application/java-archive",
            )
            async with self._session.post(f"{self._base_url}/v1/scans", data=form) as response:
                return await self._read_json_response(response)

    async def get_scan(self, scan_id: str) -> dict[str, Any]:
        async with self._session.get(f"{self._base_url}/v1/scans/{scan_id}") as response:
            return await self._read_json_response(response)

    async def _read_json_response(self, response: aiohttp.ClientResponse) -> dict[str, Any]:
        text = await response.text()
        if response.status >= 400:
            raise ApiError(f"RatScan API returned HTTP {response.status}: {text[:500]}")

        try:
            payload = json.loads(text)
        except json.JSONDecodeError as error:
            raise ApiError("RatScan API returned invalid JSON") from error

        if not isinstance(payload, dict):
            raise ApiError("RatScan API returned unexpected JSON shape")
        return payload


def is_allowed(message: Message, allowed_tg_id: int) -> bool:
    return message.from_user is not None and message.from_user.id == allowed_tg_id


def build_router(config: BotConfig, client: RatScanClient) -> Router:
    router = Router()

    @router.message(CommandStart())
    async def handle_start(message: Message) -> None:
        if not is_allowed(message, config.allowed_tg_id):
            return

        await message.answer(
            "Скинь .jar файлом для проверки или используй /id <scan_id> для полного отчета."
        )

    @router.message(Command("id"))
    async def handle_scan_id(message: Message) -> None:
        if not is_allowed(message, config.allowed_tg_id):
            return

        scan_id = command_argument(message)
        if not scan_id:
            await message.answer("Формат: /id <scan_id>")
            return

        try:
            report = await client.get_scan(scan_id)
        except ApiError as error:
            LOGGER.warning("failed to fetch scan report: %s", error)
            await message.answer(f"Не удалось получить отчет: {html.escape(str(error))}")
            return

        await send_report(message, report, title="Полный отчет")

    @router.message(F.document)
    async def handle_document(message: Message, bot: Bot) -> None:
        if not is_allowed(message, config.allowed_tg_id):
            return

        document = message.document
        if document is None:
            return

        filename = Path(document.file_name or "upload.jar").name
        if not filename.lower().endswith(".jar"):
            await message.answer("API принимает только .jar файлы.")
            return

        status_message = await message.answer("Файл получен, запускаю проверку.")
        try:
            with tempfile.TemporaryDirectory(prefix="ratscan_tg_") as tmp_dir:
                file_path = Path(tmp_dir) / filename
                await bot.download(document, destination=file_path)
                report = await client.create_scan(file_path, filename)
        except (ApiError, OSError, aiohttp.ClientError, asyncio.TimeoutError) as error:
            LOGGER.exception("failed to submit document")
            escaped_error = html.escape(str(error))
            await status_message.edit_text(f"Не удалось запустить проверку: {escaped_error}")
            return

        scan_id = report.get("scan_id")
        if not isinstance(scan_id, str):
            await status_message.edit_text("API не вернул scan_id.")
            return

        await status_message.edit_text(f"Проверка запущена: <code>{html.escape(scan_id)}</code>")
        final_report = await wait_for_final_report(client, scan_id, config)
        await send_report(message, final_report, title="Отчет по файлу")

    @router.message()
    async def handle_unknown(message: Message) -> None:
        if not is_allowed(message, config.allowed_tg_id):
            return

        await message.answer("Скинь .jar файлом или используй /id <scan_id>.")

    return router


def command_argument(message: Message) -> str:
    text = message.text or ""
    parts = text.split(maxsplit=1)
    return parts[1].strip() if len(parts) == 2 else ""


async def wait_for_final_report(
    client: RatScanClient,
    scan_id: str,
    config: BotConfig,
) -> dict[str, Any]:
    last_report: dict[str, Any] | None = None
    for _ in range(config.poll_attempts):
        last_report = await client.get_scan(scan_id)
        if last_report.get("status") in {"done", "failed"}:
            return last_report
        await asyncio.sleep(config.poll_interval_seconds)

    if last_report is None:
        return await client.get_scan(scan_id)
    return last_report


async def send_report(message: Message, report: dict[str, Any], title: str) -> None:
    summary = format_summary(report, title)
    raw_json = json.dumps(report, ensure_ascii=False, indent=2)

    if len(summary) <= MAX_MESSAGE_LENGTH:
        await message.answer(summary)
    else:
        await message.answer(format_summary(report, title, include_findings=False))

    await message.answer_document(
        BufferedInputFile(
            raw_json.encode("utf-8"),
            filename=f"ratscan-{report.get('scan_id', 'report')}.json",
        ),
        caption="Полный JSON отчет.",
    )


def format_summary(
    report: dict[str, Any],
    title: str,
    include_findings: bool = True,
) -> str:
    lines = [
        f"<b>{html.escape(title)}</b>",
        f"ID: <code>{html.escape(str(report.get('scan_id', 'unknown')))}</code>",
        f"Статус: <b>{html.escape(str(report.get('status', 'unknown')))}</b>",
        f"SHA-256: <code>{html.escape(str(report.get('sha256', 'unknown')))}</code>",
        f"Вердикт: <b>{html.escape(str(report.get('verdict', 'unknown')))}</b>",
        f"Риск: <b>{html.escape(str(report.get('risk_score', 'unknown')))}</b>",
    ]

    findings = report.get("findings")
    if isinstance(findings, list):
        lines.append(f"Findings: <b>{len(findings)}</b>")
        if include_findings:
            lines.extend(format_findings(findings))

    virustotal = report.get("virustotal")
    if isinstance(virustotal, dict):
        lines.extend(format_virustotal(virustotal))

    return "\n".join(lines)


def format_findings(findings: list[Any]) -> list[str]:
    if not findings:
        return []

    lines = ["", "<b>Findings</b>"]
    for index, item in enumerate(findings[:20], start=1):
        if not isinstance(item, dict):
            continue
        rule_id = html.escape(str(item.get("rule_id", "unknown")))
        severity = html.escape(str(item.get("severity", "unknown")))
        message = html.escape(str(item.get("message", "")))
        lines.append(f"{index}. <b>{severity}</b> <code>{rule_id}</code> - {message}")

    if len(findings) > 20:
        lines.append(f"...и еще {len(findings) - 20}; полный список в JSON.")
    return lines


def format_virustotal(virustotal: dict[str, Any]) -> list[str]:
    lines = ["", "<b>VirusTotal</b>"]
    status = virustotal.get("status")
    if status is not None:
        lines.append(f"Статус: <b>{html.escape(str(status))}</b>")

    stats = virustotal.get("stats")
    if isinstance(stats, dict):
        lines.append(
            "Stats: "
            + ", ".join(
                f"{html.escape(str(key))}={html.escape(str(value))}"
                for key, value in stats.items()
            )
        )

    flagged = virustotal.get("flagged_engines")
    if isinstance(flagged, list):
        lines.append(f"Flagged engines: <b>{len(flagged)}</b>")

    error = virustotal.get("error")
    if error:
        lines.append(f"Ошибка: {html.escape(str(error))}")

    return lines


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    load_dotenv()
    config = load_config()
    bot = Bot(
        token=config.token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    client = RatScanClient(config)
    dispatcher = Dispatcher()
    dispatcher.include_router(build_router(config, client))

    try:
        await dispatcher.start_polling(bot)
    finally:
        await client.close()
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())

# Repository Guidelines

## Project Structure & Module Organization

RatScan is a Cargo workspace. The root `src/` hosts the primary API binary and
shared API concerns. Workspace crates live in `crates/`: `ratscan-core` contains
the static JAR scanner and rules engine, `ratscan-models` defines shared response
types, root `src/storage` owns PostgreSQL access, and `ratscan-api` provides the API service binary. SQLx migrations are in `migrations/`;
scanner configuration is in `config/rules.yaml`. Keep Rust unit tests beside the
code they cover and use `tests/fixtures/` or `tests/compiled-fixtures/` for scan
regressions. The optional Python Telegram client is in `telegram_bot/`.

## Build, Test, and Development Commands

- `cargo check --workspace` checks all Rust crates quickly.
- `cargo test --workspace` runs Rust unit and integration tests.
- `cargo fmt --check` verifies Rust formatting; run `cargo fmt` to apply it.
- `cargo clippy --workspace --all-targets -- -D warnings` catches lint issues.
- `docker compose up --build` starts PostgreSQL, the API with its optional Telegram worker, and local UI;
  create a local `.env` first. Do not commit it.
- `python3 -m venv telegram-venv && telegram-venv/bin/pip install -r telegram_bot/requirements.txt`
  prepares the optional Telegram worker for `cargo run`.

## Coding Style & Naming Conventions

Use Rust 2021 and `rustfmt` defaults (four-space indentation). Name modules,
functions, and variables in `snake_case`; types and traits use `PascalCase`;
constants use `SCREAMING_SNAKE_CASE`. Keep scanner findings, evidence, and
serialized models in `ratscan-models` when multiple services consume them.
Handle errors explicitly with contextual messages and use `tracing` rather than
`println!`. Add ordered, timestamp-prefixed SQL files such as
`migrations/20260723000100_description.sql`; never alter an applied migration.

## Testing Guidelines

Add a focused `#[test]` near the affected Rust behavior. Scanner changes should
exercise a representative fixture and assert the expected JSON report. Run the
narrowest relevant crate during iteration, then `cargo test --workspace` before
opening a pull request. There is no configured coverage threshold; preserve or
extend regression coverage for changed detection logic.

## Commits & Pull Requests

Use Conventional Commits, as in `fix(scanner): detect staged memory loaders` or
`feat(discord): simplify scan reporting`. Keep commits scoped to one concern.
Pull requests should explain the behavioral change, link the issue when one
exists, list commands run, and include request/response examples or UI
screenshots for API or frontend changes. Call out migration, configuration, and
deployment impacts explicitly.

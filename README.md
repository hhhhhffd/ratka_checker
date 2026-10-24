<div align="center">

<h1>RatScan</h1>
<hr>

**Static analysis of Minecraft `.jar` mods in one place: evidence-backed verdicts, optional VirusTotal enrichment, and a browser build that never uploads the file**

![Rust](https://img.shields.io/badge/RUST-1.99-DEA584?style=flat-square&logo=rust&logoColor=white)
![Axum](https://img.shields.io/badge/AXUM-0.8-000000?style=flat-square&logo=rust&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/POSTGRESQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![WebAssembly](https://img.shields.io/badge/WEBASSEMBLY-wasm32-654FF0?style=flat-square&logo=webassembly&logoColor=white)
![Docker](https://img.shields.io/badge/DOCKER-compose-2496ED?style=flat-square&logo=docker&logoColor=white)

[![Rust CI](https://img.shields.io/github/actions/workflow/status/hhhhhffd/ratka_checker/rust-ci.yml?style=flat-square&label=RUST%20CI&logo=githubactions&logoColor=white)](https://github.com/hhhhhffd/ratka_checker/actions/workflows/rust-ci.yml)
[![Pages](https://img.shields.io/github/actions/workflow/status/hhhhhffd/ratka_checker/pages.yml?style=flat-square&label=PAGES&logo=github&logoColor=white)](https://github.com/hhhhhffd/ratka_checker/actions/workflows/pages.yml)

<!-- No release or license badges: the repo has no releases and no LICENSE file. -->

[Live Demo (pending deployment)](https://hhhhhffd.github.io/ratka_checker/) · [Architecture](#architecture-deep-dive) · [Setup](#setup--deployment)

</div>

## Executive Summary

RatScan statically scans Minecraft `.jar` mods for stealers and remote access
trojans. It never executes the archive: it parses bytecode and resources, tracks
data flow, and reports risk only when evidence links an API to a dangerous chain.

The scanner is one Rust library (`ratscan-core`) shared by two front doors: an
`axum` API with PostgreSQL storage and an integrated Telegram worker, and a
WebAssembly build that runs entirely in the browser.

## Technical Stack

| Group | Technology                             | Version                                 | Role                                       |
| ----- | -------------------------------------- | --------------------------------------- | ------------------------------------------ |
| Core  | Rust (edition 2021)                    | 1.99.0, pinned in `rust-toolchain.toml` | Scanner, API, Telegram worker              |
| Core  | axum                                   | 0.8                                     | HTTP API with multipart upload             |
| Core  | YAML rules (`config/rules.yaml`)       | n/a                                     | Non-scoring heuristic observations         |
| Data  | PostgreSQL                             | 16 (`postgres:16-alpine`)               | Scan results, hashes, VirusTotal cache     |
| Data  | sqlx                                   | 0.8                                     | Queries; migrations embedded in the binary |
| Infra | Docker Compose                         | n/a                                     | `postgres`, `api`, `dev-ui`                |
| Infra | nginx                                  | 1.27-alpine                             | `dev-ui` static frontend                   |
| Infra | WebAssembly (`wasm32-unknown-unknown`) | n/a                                     | Client-side scanner in `web/`              |
| Infra | GitHub Actions                         | n/a                                     | `rust-ci.yml`, `pages.yml`                 |

## Architecture Deep Dive

### System diagram

```mermaid
flowchart LR
    User([User]) -->|POST /v1/scans| API[api: ratscan axum]
    TG([Telegram user]) --> Worker[Telegram worker]
    Worker -->|HTTP| API
    API --> Core[ratscan-core<br/>scanner + rules engine]
    Rules[(config/rules.yaml)] --> Core
    Core --> Models[ratscan-models<br/>report types]
    API <--> PG[(postgres)]
    API -.->|optional| VT[VirusTotal]
    Files[(storage dir)] <--> API
    Browser([Browser]) --> Web[web/ static page]
    Web --> Wasm[ratscan-wasm]
    Wasm --> Core
```

The Telegram worker runs inside the same `ratscan` process but is supervised
independently: a Telegram failure is retried without stopping the API.

### Scan sequence

```mermaid
sequenceDiagram
    participant C as Client
    participant A as ratscan API
    participant S as ratscan-core
    participant D as postgres
    participant V as VirusTotal
    C->>A: POST /v1/scans (multipart jar)
    A->>S: scan archive (bounded parsing)
    S-->>A: capabilities, findings, chains
    opt VIRUSTOTAL_ENABLED=true
        A->>D: lookup cached report by sha256
        A->>V: query on cache miss
    end
    A->>D: store result
    A-->>C: scan_id, status, sha256, verdict, risk_score
    C->>A: GET /v1/scans/{id}
```

### Architecture decisions

| Decision                                | Rationale                                                                                                                                   |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Scanner in a standalone crate           | `ratscan-core` has no server dependencies, so the same logic builds for `wasm32` and the API. It uses pure-Rust zip codecs for that target. |
| Evidence-gated verdicts                 | `malicious` requires a confirmed dangerous chain or a trusted VirusTotal detection; weak API matches cannot reach it by accumulation.       |
| Shared report types in `ratscan-models` | The API, the Telegram worker, and the WASM build serialize one contract.                                                                    |
| Embedded migrations                     | The binary runs SQLx migrations at startup, so a host needs only `DATABASE_URL`.                                                            |

### Scan result model

Completed responses separate neutral `capabilities` from risk-bearing
`findings` and evidence-backed `confirmed_chains`. Each finding carries its
scope, confidence, score contribution, and archive/class/method/offset
evidence when available. `obfuscation` is reported independently and lowers
analysis confidence; it is not a malicious verdict by itself. `limitations`
describe bounded parsing or attribution gaps.

`analysis_coverage` is a separate 0–100 completeness measure with class and
resource counters. It is never a risk score. Standalone APIs, embedded native
binaries, large assets, and build metadata are reported as `capabilities`; they
become risk-bearing only when evidence links them into a dangerous chain.

Text resources are decoded only through a bounded detector (UTF-8, UTF-8 BOM,
UTF-16 LE/BE, Windows-1251, ISO-8859-1). A resource whose text encoding cannot
be established becomes a `limitation`, never a string-based finding. Responses
also retain `text_resources` (encoding and confidence) and `decoded_strings`
(original value, decoder, result, and bytecode provenance). File paths used by
data-flow are compared symbolically, so equivalent `%APPDATA%`, Windows, and
Java-home forms do not break a confirmed chain.

YAML rule matches are non-scoring `heuristic` observations, including
anti-analysis markers (VMware, Sandboxie, or antivirus-process discovery).
They can guide manual review but do not affect `risk_score` or `verdict` on
their own. Contextual findings with source-level evidence, confirmed data-flow
chains, or trusted VirusTotal evidence can affect `risk_score` and `verdict`.

The flow adapter follows bounded calls inside an archive layer, including JVM
parameter slots, instance-method `this`, return values, and concrete
`ProcessBuilder` command state. Generic file reads are neutral; credential
exfiltration requires a recognized credential target and a proven network send.
`analysis_coverage` separately reports class parsing, method-flow, supported
instruction, call-resolution, target-resolution, scope, and overall coverage.

`malicious` requires a confirmed dangerous chain (for example credential
exfiltration, remote download → write → execute, or decoded dynamic loading)
or a trusted VirusTotal detection; weak API matches cannot produce it by
accumulation alone.

### API endpoints

| Method | Path                  | Purpose                               |
| ------ | --------------------- | ------------------------------------- |
| `POST` | `/v1/scans`           | Upload a jar (multipart field `file`) |
| `GET`  | `/v1/scans/{id}`      | Fetch a scan result                   |
| `GET`  | `/v1/hashes/{sha256}` | Look up a report by sha256            |
| `GET`  | `/health`             | Liveness check                        |

### VirusTotal

VirusTotal is optional and disabled by default. Set `VIRUSTOTAL_ENABLED=true`
and provide `VIRUSTOTAL_API_KEY` to add the `virustotal` field to scan
responses. Reports are cached by sha256 in PostgreSQL using
`VIRUSTOTAL_CACHE_TTL_HOURS` to avoid repeated quota usage for the same jar.
The `virustotal.behavior` field contains condensed VirusTotal sandbox artifacts
when the behaviours relationship is available for the file.

### Web demo (WebAssembly)

`web/` is a static page that runs the same scanner compiled to WebAssembly, so
the jar never leaves the browser. VirusTotal and storage are server-only and are
not part of it. `.github/workflows/pages.yml` deploys it to GitHub Pages on
pushes to `main` (enable Settings → Pages → Source: GitHub Actions).

Local build, with a `wasm-bindgen-cli` matching the version in `Cargo.lock`:

```sh
rustup target add wasm32-unknown-unknown
sh scripts/build_web.sh
python3 -m http.server -d web 8000
```

### Service boundaries

RatScan API and the Rust Telegram worker are one deployable service. The API owns scan
results, uploaded files, rules, the Telegram worker lifecycle, and the RatScan
PostgreSQL schema.

The Discord client is a separate project at `../modhub.bot`.
Its Compose stack has a separate PostgreSQL database for Discord settings and
uses RatScan solely through the published HTTP port `8080` (`MODHUB_API_BASE_URL`), never through RatScan PostgreSQL. The JSON
response provides its complete scan contract: `scan_id`, `status`, `sha256`,
`verdict`, and `risk_score`.

## Project Structure

```text
.
├── src/                    # ratscan binary: axum routes, config, storage, VirusTotal, Telegram worker
├── crates/
│   ├── ratscan-core/       # static JAR scanner and rules engine
│   ├── ratscan-models/     # shared report and response types
│   ├── ratscan-api/        # API service crate
│   └── ratscan-wasm/       # WebAssembly build of the scanner
├── web/                    # static client-side demo (GitHub Pages)
├── config/rules.yaml       # scanner rules
├── migrations/             # SQLx migrations
├── tests/                  # fixtures, compiled fixtures, Telegram worker test
├── scripts/                # package_release.sh, build_web.sh
├── deploy/                 # frontend, systemd units, env and release helpers
├── telegram_bot/           # legacy Telegram client notes
├── Dockerfile
├── docker-compose.yml      # postgres, api, dev-ui
└── .github/workflows/      # rust-ci.yml, pages.yml
```

## Setup & Deployment

### Docker Compose

```sh
cp .env.example .env
docker compose up --build
```

| Service    | Image or build       | Port   | Purpose                                                       |
| ---------- | -------------------- | ------ | ------------------------------------------------------------- |
| `postgres` | `postgres:16-alpine` | `5432` | Database `ratscan`, user `ratscan`, password `ratscan`        |
| `api`      | `Dockerfile`         | `8080` | `ratscan` API and optional Telegram worker                    |
| `dev-ui`   | `nginx:1.27-alpine`  | `8081` | Local UI from `deploy/frontend`, proxied per `dev/nginx.conf` |

Compose overrides `DATABASE_URL` for `api` with
`postgres://ratscan:ratscan@postgres:5432/ratscan`, so the `localhost` default in
`.env.example` applies only to runs outside Compose. Uploaded files persist in
the `ratscan-storage` volume.

> [!WARNING]
> Never commit `.env`. `TG_BOT_TOKEN` and `VIRUSTOTAL_API_KEY` are secrets.

### Environment variables

<details>
<summary>Full reference (defaults from <code>.env.example</code>)</summary>

| Variable                           | Default                                             | Purpose                                                     |
| ---------------------------------- | --------------------------------------------------- | ----------------------------------------------------------- |
| `RUST_LOG`                         | `info`                                              | Log filter                                                  |
| `DATABASE_URL`                     | `postgres://ratscan:ratscan@localhost:5432/ratscan` | PostgreSQL connection                                       |
| `RATSCAN_BIND_ADDR`                | `0.0.0.0:8080`                                      | API listen address                                          |
| `RATSCAN_RULES_PATH`               | `config/rules.yaml`                                 | Scanner rules file                                          |
| `RATSCAN_STORAGE_DIR`              | `storage`                                           | Uploaded file storage                                       |
| `MAX_TOTAL_UNCOMPRESSED_MB`        | `200`                                               | Archive size limit after inflation                          |
| `MAX_FILES_IN_ARCHIVE`             | `5000`                                              | Entry count limit                                           |
| `MAX_NESTING_DEPTH`                | `3`                                                 | Nested archive depth limit                                  |
| `MAX_SINGLE_FILE_MB`               | `50`                                                | Single entry size limit                                     |
| `FILE_RETENTION_DAYS`              | `1`                                                 | Stored file retention                                       |
| `FILE_CLEANUP_INTERVAL_MINUTES`    | `60`                                                | Cleanup job interval                                        |
| `VIRUSTOTAL_ENABLED`               | `false`                                             | Enable VirusTotal enrichment                                |
| `VIRUSTOTAL_API_KEY`               | _empty_                                             | VirusTotal API key                                          |
| `VIRUSTOTAL_TIMEOUT_SECONDS`       | `20`                                                | VirusTotal request timeout                                  |
| `VIRUSTOTAL_CACHE_TTL_HOURS`       | `24`                                                | Report cache lifetime                                       |
| `VIRUSTOTAL_POLL_ATTEMPTS`         | `6`                                                 | Analysis poll attempts                                      |
| `VIRUSTOTAL_POLL_INTERVAL_SECONDS` | `10`                                                | Delay between polls                                         |
| `TG_BOT_TOKEN`                     | _empty_                                             | Telegram bot token; worker starts only with `ALLOWED_TG_ID` |
| `ALLOWED_TG_ID`                    | _empty_                                             | Telegram user allowed to use the bot                        |
| `RATSCAN_API_BASE_URL`             | `http://127.0.0.1:8080`                             | API URL used by the worker                                  |
| `TG_BOT_REQUEST_TIMEOUT_SECONDS`   | `30`                                                | Telegram request timeout                                    |
| `TG_BOT_POLL_ATTEMPTS`             | `24`                                                | Scan result poll attempts                                   |
| `TG_BOT_POLL_INTERVAL_SECONDS`     | `5`                                                 | Delay between polls                                         |

</details>

### Integrated Telegram worker

The same `ratscan` process starts the Telegram worker when both `TG_BOT_TOKEN`
and `ALLOWED_TG_ID` are set. It is supervised independently: a Telegram failure
is retried without stopping the API. There is no `ratscan-telegram-bot.service`.
The worker is compiled into the Rust binary; Python and a virtual environment
are no longer required.

### Build binary package in Docker

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

### Run on host

PostgreSQL must be available through `DATABASE_URL`. Migrations are embedded in the binary and run on startup.

```sh
cd dist/ratscan
cp .env.example .env
mkdir -p storage
set -a
. ./.env
set +a

./ratscan
```

> [!WARNING]
> The API is open by default. Put nginx, a tunnel, or firewall rules in front of it if public access needs to be restricted.

### Upload

```sh
curl -F "file=@mod.jar" \
  http://127.0.0.1:8080/v1/scans
```

### Development checks

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

GitHub Actions runs these on Rust 1.99.0 and stable for pushes and pull
requests, plus Telegram worker startup, scanner regression fixtures, and release
builds. CI uses mock Telegram endpoints and needs neither production credentials
nor PostgreSQL.

## Deliverables & Links

| Item      | Link                                                                                                           |
| --------- | -------------------------------------------------------------------------------------------------------------- |
| Live Demo | [hhhhhffd.github.io/ratka_checker](https://hhhhhffd.github.io/ratka_checker/) (pending first Pages deployment) |

## License

<!-- TODO: add a LICENSE file and state the license here -->

_TBD_: the repository has no LICENSE file yet.

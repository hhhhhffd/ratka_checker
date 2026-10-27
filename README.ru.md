<div align="center">

<h1>RatScan — Malware Analysis for Minecraft Mods</h1>
<hr>

**Статический анализ `.jar`-модов Minecraft в одном месте: собственный парсер JVM-байткода, вердикты только по доказанной цепочке, опциональное обогащение через VirusTotal и браузерная сборка, которая не загружает файл на сервер**

![Rust](https://img.shields.io/badge/RUST-1.99-DEA584?style=flat-square&logo=rust&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/POSTGRESQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![WebAssembly](https://img.shields.io/badge/WEBASSEMBLY-wasm32-654FF0?style=flat-square&logo=webassembly&logoColor=white)

[![Rust CI](https://img.shields.io/github/actions/workflow/status/hhhhhffd/ratka_checker/rust-ci.yml?style=flat-square&label=RUST%20CI&logo=githubactions&logoColor=white)](https://github.com/hhhhhffd/ratka_checker/actions/workflows/rust-ci.yml)
[![Release](https://img.shields.io/github/v/release/hhhhhffd/ratka_checker?style=flat-square&label=RELEASE)](https://github.com/hhhhhffd/ratka_checker/releases)
[![License](https://img.shields.io/badge/LICENSE-AGPL--3.0-blue?style=flat-square)](LICENSE)

[Live Demo](https://hhhhhffd.github.io/ratka_checker/) · [Архитектура](#архитектура) · [Установка](#установка-и-запуск) · [Releases](https://github.com/hhhhhffd/ratka_checker/releases) · [English](README.md) · Русский

</div>

## Что это

Моды Minecraft — это `.jar`-архивы, которые выполняются с правами пользователя, и
под видом модов распространяются стилеры и трояны удалённого доступа. RatScan
сканирует jar, не выполняя его: разбирает байткод и ресурсы, отслеживает потоки
данных и называет мод `malicious` только тогда, когда доказательства связывают API
с опасной цепочкой.

Сканер — одна Rust-библиотека (`ratscan-core`) с тремя точками входа: `axum` API с
хранилищем в PostgreSQL, Telegram-воркер и сборка в WebAssembly, которая целиком
работает в браузере и как плагин лаунчера
[`_k0t1k`](https://github.com/hhhhhffd/_k0t1k).

## Основное

- Собственный парсер JVM-байткода (`class_file.rs`): для каждого метода строит базовые блоки и рёбра графа потока управления.
- Taint-анализ между методами: вердикт `malicious` требует доказанной цепочки, например чтение учётных данных, затем отправка в сеть. Слабые совпадения API не складываются в него накоплением.
- 81 YAML-правило в `config/rules.yaml` дают не влияющие на оценку эвристические наблюдения для ручной проверки.
- Опциональное обогащение через VirusTotal, Telegram-бот и сборка WebAssembly, используемая внутри лаунчера `_k0t1k`.
- Регрессионный корпус fixture-jar в `tests/` (исходные и скомпилированные fixtures с контрактами `expected.json`), запускается в CI.

## Технологии

| Группа | Технология                             | Версия                                  | Роль                                              |
| ------ | -------------------------------------- | --------------------------------------- | ------------------------------------------------- |
| Core   | Rust (edition 2021)                    | 1.99.0, закреплена в `rust-toolchain.toml` | Сканер, API, Telegram-воркер                   |
| Core   | Парсер байткода, CFG, data-flow        | n/a                                     | Собственный код в `ratscan-core`, без crate для class-файлов |
| Core   | axum                                   | 0.8                                     | HTTP API с multipart-загрузкой                    |
| Core   | YAML-правила (`config/rules.yaml`)     | n/a                                     | Эвристические наблюдения без влияния на оценку    |
| Data   | PostgreSQL                             | 16 (`postgres:16-alpine`)               | Результаты сканов, хеши, кеш VirusTotal           |
| Data   | sqlx                                   | 0.8                                     | Запросы; миграции встроены в бинарник             |
| Infra  | Docker Compose                         | n/a                                     | `postgres`, `api`, `dev-ui`                       |
| Infra  | nginx                                  | 1.27-alpine                             | Статический фронтенд `dev-ui`                     |
| Infra  | WebAssembly (`wasm32-unknown-unknown`) | n/a                                     | Клиентский сканер в `web/`                        |
| Infra  | GitHub Actions                         | n/a                                     | `rust-ci.yml`, `pages.yml`                        |

## Архитектура

### Схема системы

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

Telegram-воркер работает внутри того же процесса `ratscan`, но супервизируется
независимо: сбой Telegram перезапускается без остановки API.

### Последовательность скана

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

### Архитектурные решения

| Решение                                  | Обоснование                                                                                                                                  |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Сканер в отдельном crate                 | `ratscan-core` не зависит от серверных библиотек, поэтому одна и та же логика собирается и для `wasm32`, и для API. Для wasm используются чисто Rust-кодеки zip. |
| Вердикты на основе доказательств         | `malicious` требует подтверждённой опасной цепочки или доверенного срабатывания VirusTotal; слабые совпадения API не дают его накоплением.   |
| Общие типы отчёта в `ratscan-models`     | API, Telegram-воркер и сборка WASM сериализуют один и тот же контракт.                                                                       |
| Встроенные миграции                      | Бинарник сам применяет миграции SQLx при старте, хосту нужен только `DATABASE_URL`.                                                          |

### Модель результата скана

Завершённые ответы разделяют нейтральные `capabilities`, влияющие на риск
`findings` и подкреплённые доказательствами `confirmed_chains`. Каждый finding
содержит область, уверенность, вклад в оценку и доказательства (архив, класс,
метод, смещение), если они есть. `obfuscation` сообщается отдельно и снижает
уверенность анализа; сама по себе она не даёт вредоносного вердикта.
`limitations` описывают ограничения разбора и атрибуции.

`analysis_coverage` — отдельная мера полноты анализа от 0 до 100 со счётчиками
классов и ресурсов. Это не оценка риска. Автономные API, встроенные нативные
бинарники, крупные ресурсы и метаданные сборки попадают в `capabilities` и
становятся значимыми для риска, только если доказательства связывают их с опасной
цепочкой.

Текстовые ресурсы декодируются только через ограниченный детектор (UTF-8, UTF-8
BOM, UTF-16 LE/BE, Windows-1251, ISO-8859-1). Ресурс с неустановленной
кодировкой становится `limitation`, а не строковым finding. В ответах также
сохраняются `text_resources` (кодировка и уверенность) и `decoded_strings`
(исходное значение, декодер, результат и происхождение в байткоде). Пути к файлам
в data-flow сравниваются символически, поэтому эквивалентные формы `%APPDATA%`,
Windows и Java-home не ломают подтверждённую цепочку.

Совпадения YAML-правил — это не влияющие на оценку `heuristic`-наблюдения, в том
числе маркеры анти-анализа (VMware, Sandboxie, поиск антивирусных процессов). Они
помогают ручной проверке, но сами не меняют `risk_score` и `verdict`. На
`risk_score` и `verdict` влияют контекстные findings с доказательствами на уровне
исходного кода, подтверждённые цепочки data-flow или доверенные данные
VirusTotal.

Адаптер потока следует за ограниченными вызовами внутри слоя архива, включая
слоты параметров JVM, `this` в методах экземпляра, возвращаемые значения и
конкретное состояние команды `ProcessBuilder`. Общее чтение файлов нейтрально;
кража учётных данных требует распознанной цели с учётными данными и доказанной
отправки в сеть. `analysis_coverage` отдельно сообщает о покрытии разбора
классов, потока методов, поддерживаемых инструкций, разрешения вызовов и целей,
области и общем покрытии.

`malicious` требует подтверждённой опасной цепочки (например, кража учётных
данных, либо загрузка из сети → запись → запуск, либо декодированная динамическая
загрузка) или доверенного срабатывания VirusTotal; слабые совпадения API не могут
дать его одним накоплением.

### API

| Метод  | Путь                  | Назначение                              |
| ------ | --------------------- | --------------------------------------- |
| `POST` | `/v1/scans`           | Загрузить jar (multipart-поле `file`)   |
| `GET`  | `/v1/scans/{id}`      | Получить результат скана                |
| `GET`  | `/v1/hashes/{sha256}` | Найти отчёт по sha256                   |
| `GET`  | `/health`             | Проверка живости                        |

### VirusTotal

VirusTotal опционален и по умолчанию выключен. Задайте `VIRUSTOTAL_ENABLED=true`
и `VIRUSTOTAL_API_KEY`, чтобы в ответах появилось поле `virustotal`. Отчёты
кешируются в PostgreSQL по sha256 на время `VIRUSTOTAL_CACHE_TTL_HOURS`, чтобы не
тратить квоту на один и тот же jar. Поле `virustotal.behavior` содержит
сжатые артефакты песочницы VirusTotal, если для файла доступна связь behaviours.

### Веб-демо (WebAssembly)

`web/` — статическая страница, которая запускает тот же сканер, собранный в
WebAssembly, поэтому jar не покидает браузер. VirusTotal и хранилище работают
только на сервере и в демо не входят. `.github/workflows/pages.yml` публикует его
на GitHub Pages при пуше в `main` (включите Settings → Pages → Source: GitHub
Actions).

Локальная сборка, нужен `wasm-bindgen-cli` той же версии, что в `Cargo.lock`:

```sh
rustup target add wasm32-unknown-unknown
sh scripts/build_web.sh
python3 -m http.server -d web 8000
```

### Релизы плагина лаунчера

RatScan также поставляется как плагин лаунчера
[`_k0t1k`](https://github.com/hhhhhffd/_k0t1k): GitHub Release с `plugin.json`,
`plugin.json.sig` и файлами `wasm-bindgen --target web` `ratscan_wasm.js` и
`ratscan_wasm_bg.wasm`. Тег релиза `v<version>` берёт версию crate `ratscan-wasm`,
поэтому перед релизом поднимите её в `crates/ratscan-wasm/Cargo.toml` и
запушьте. Plugin API v1 экспортирует `default` (init) и `scan(bytes) -> string`
(JSON `{summary, report}`, при ошибке бросает исключение).

```sh
bash scripts/release-plugin.sh   # нужны gh, openssl, jq, wasm-bindgen-cli
```

Скрипт отказывается работать при грязном дереве, непушенном `HEAD`, существующем
теге или релизе, а также если подпись не проверяется открытым ключом лаунчера.
Он подписывает ключом `$K0T1K_PLUGIN_KEY` (по умолчанию
`~/.config/k0t1k/plugin-signing-key.pem`); ключ нельзя хранить в репозитории.

### Границы сервисов

RatScan API и Rust-воркер Telegram — один разворачиваемый сервис. API владеет
результатами сканов, загруженными файлами, правилами, жизненным циклом
Telegram-воркера и схемой PostgreSQL RatScan.

Клиент Discord — отдельный проект в `../modhub.bot`. Его Compose-стек имеет
отдельную базу PostgreSQL для настроек Discord и обращается к RatScan только через
опубликованный HTTP-порт `8080` (`MODHUB_API_BASE_URL`), но не через PostgreSQL
RatScan. JSON-ответ задаёт весь контракт скана: `scan_id`, `status`, `sha256`,
`verdict`, `risk_score`.

## Структура проекта

```text
.
├── src/                    # бинарник ratscan: маршруты axum, config, storage, VirusTotal, Telegram-воркер
├── crates/
│   ├── ratscan-core/       # статический сканер JAR и движок правил
│   ├── ratscan-models/     # общие типы отчёта и ответа
│   ├── ratscan-api/        # crate API-сервиса
│   └── ratscan-wasm/       # сборка сканера в WebAssembly
├── web/                    # статическое клиентское демо (GitHub Pages)
├── config/rules.yaml       # правила сканера
├── migrations/             # миграции SQLx
├── tests/                  # fixtures, скомпилированные fixtures, тест Telegram-воркера
├── scripts/                # package_release.sh, build_web.sh, release-plugin.sh
├── deploy/                 # frontend, systemd-юниты, env и вспомогательные скрипты
├── telegram_bot/           # заметки об устаревшем Telegram-клиенте
├── Dockerfile
├── docker-compose.yml      # postgres, api, dev-ui
└── .github/workflows/      # rust-ci.yml, pages.yml
```

## Установка и запуск

### Docker Compose

```sh
cp .env.example .env
docker compose up --build
```

| Сервис     | Образ или сборка     | Порт   | Назначение                                                    |
| ---------- | -------------------- | ------ | ------------------------------------------------------------- |
| `postgres` | `postgres:16-alpine` | `5432` | База `ratscan`, пользователь `ratscan`, пароль `ratscan`      |
| `api`      | `Dockerfile`         | `8080` | API `ratscan` и опциональный Telegram-воркер                  |
| `dev-ui`   | `nginx:1.27-alpine`  | `8081` | Локальный UI из `deploy/frontend`, прокси по `dev/nginx.conf` |

Compose переопределяет `DATABASE_URL` для `api` на
`postgres://ratscan:ratscan@postgres:5432/ratscan`, поэтому значение с `localhost`
из `.env.example` действует только при запуске вне Compose. Загруженные файлы
сохраняются в томе `ratscan-storage`.

> [!WARNING]
> Никогда не коммитьте `.env`. `TG_BOT_TOKEN` и `VIRUSTOTAL_API_KEY` — секреты.

### Переменные окружения

<details>
<summary>Полный справочник (значения по умолчанию из <code>.env.example</code>)</summary>

| Переменная                         | По умолчанию                                        | Назначение                                                  |
| ---------------------------------- | --------------------------------------------------- | ----------------------------------------------------------- |
| `RUST_LOG`                         | `info`                                              | Фильтр логов                                                |
| `DATABASE_URL`                     | `postgres://ratscan:ratscan@localhost:5432/ratscan` | Подключение к PostgreSQL                                    |
| `RATSCAN_BIND_ADDR`                | `0.0.0.0:8080`                                      | Адрес прослушивания API                                     |
| `RATSCAN_RULES_PATH`               | `config/rules.yaml`                                 | Файл правил сканера                                         |
| `RATSCAN_STORAGE_DIR`              | `storage`                                           | Хранилище загруженных файлов                                |
| `MAX_TOTAL_UNCOMPRESSED_MB`        | `200`                                               | Лимит размера архива после распаковки                       |
| `MAX_FILES_IN_ARCHIVE`             | `5000`                                              | Лимит числа записей                                         |
| `MAX_NESTING_DEPTH`                | `3`                                                 | Лимит глубины вложенных архивов                             |
| `MAX_SINGLE_FILE_MB`               | `50`                                                | Лимит размера одной записи                                  |
| `FILE_RETENTION_DAYS`              | `1`                                                 | Срок хранения файлов                                        |
| `FILE_CLEANUP_INTERVAL_MINUTES`    | `60`                                                | Интервал задачи очистки                                     |
| `VIRUSTOTAL_ENABLED`               | `false`                                             | Включить обогащение через VirusTotal                        |
| `VIRUSTOTAL_API_KEY`               | _пусто_                                             | Ключ API VirusTotal                                         |
| `VIRUSTOTAL_TIMEOUT_SECONDS`       | `20`                                                | Таймаут запроса к VirusTotal                                |
| `VIRUSTOTAL_CACHE_TTL_HOURS`       | `24`                                                | Время жизни кеша отчёта                                     |
| `VIRUSTOTAL_POLL_ATTEMPTS`         | `6`                                                 | Число попыток опроса анализа                                |
| `VIRUSTOTAL_POLL_INTERVAL_SECONDS` | `10`                                                | Пауза между опросами                                        |
| `TG_BOT_TOKEN`                     | _пусто_                                             | Токен Telegram-бота; воркер стартует только вместе с `ALLOWED_TG_ID` |
| `ALLOWED_TG_ID`                    | _пусто_                                             | Пользователь Telegram, которому разрешён бот                |
| `RATSCAN_API_BASE_URL`             | `http://127.0.0.1:8080`                             | URL API, который использует воркер                          |
| `TG_BOT_REQUEST_TIMEOUT_SECONDS`   | `30`                                                | Таймаут запроса к Telegram                                  |
| `TG_BOT_POLL_ATTEMPTS`             | `24`                                                | Число попыток опроса результата скана                       |
| `TG_BOT_POLL_INTERVAL_SECONDS`     | `5`                                                 | Пауза между опросами                                        |

</details>

### Встроенный Telegram-воркер

Тот же процесс `ratscan` запускает Telegram-воркер, когда заданы и `TG_BOT_TOKEN`,
и `ALLOWED_TG_ID`. Он супервизируется независимо: сбой Telegram перезапускается без
остановки API. Отдельного `ratscan-telegram-bot.service` нет. Воркер скомпилирован
в Rust-бинарник; Python и виртуальное окружение больше не нужны.

### Сборка бинарного пакета в Docker

Docker используется только как среда сборки:

```sh
sh scripts/package_release.sh
```

Результат:

```text
dist/ratscan/
  ratscan
  config/rules.yaml
  .env.example
  RUN.md
```

Скопируйте `dist/ratscan/` на хост, где будет работать сервис. Самому сервису
Docker не нужен.

### Запуск на хосте

PostgreSQL должен быть доступен через `DATABASE_URL`. Миграции встроены в
бинарник и применяются при старте.

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
> По умолчанию API открыт. Если публичный доступ нужно ограничить, поставьте перед ним nginx, туннель или правила файрвола.

### Загрузка файла

```sh
curl -F "file=@mod.jar" \
  http://127.0.0.1:8080/v1/scans
```

### Проверки при разработке

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

GitHub Actions запускает их на Rust 1.99.0 и stable при пушах и pull request, а
также проверяет запуск Telegram-воркера, регрессионные fixtures сканера и
релизные сборки. CI использует mock-эндпоинты Telegram и не требует ни
продакшн-секретов, ни PostgreSQL.

## Лицензия

AGPL-3.0-only. © 2026 hhhhhffd. См. [LICENSE](LICENSE).

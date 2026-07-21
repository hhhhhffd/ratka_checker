# RatScan API

Rust API service for static scanning Minecraft `.jar` mods.

## Build Binary Package In Docker

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

## Run On Host

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

The API is open by default. Put nginx, a tunnel, or firewall rules in front of it if public access needs to be restricted.

## Upload

```sh
curl -F "file=@mod.jar" \
  http://127.0.0.1:8080/v1/scans
```

## Scan result model

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

YAML rule matches are non-scoring `heuristic` observations. Only contextual
findings with source-level evidence, confirmed data-flow chains, or trusted
VirusTotal evidence can affect `risk_score` and `verdict`.

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

## VirusTotal

VirusTotal is optional and disabled by default. Set `VIRUSTOTAL_ENABLED=true`
and provide `VIRUSTOTAL_API_KEY` to add the `virustotal` field to scan
responses. Reports are cached by sha256 in PostgreSQL using
`VIRUSTOTAL_CACHE_TTL_HOURS` to avoid repeated quota usage for the same jar.
The `virustotal.behavior` field contains condensed VirusTotal sandbox artifacts
when the behaviours relationship is available for the file.
# RatScan

RatScan is a single Cargo workspace with separate service binaries:

```text
crates/
├── ratscan-models   # shared serializable scanner/API models
├── ratscan-core     # rules and static scanner
├── ratscan-storage  # PostgreSQL access shared by service clients
├── ratscan-api      # dedicated API binary
└── ratscan-discord  # Discord Gateway binary
```

`ratscan-discord` uses the same PostgreSQL database and SQLx migration history
as the API. It does not create tables at startup and never stores duplicated
verdict, SHA-256, or risk-score values; `discord_scan_context.scan_id` references
the API-owned `scans` row.

## Discord configuration

Set the following in `.env` (keep this file out of version control):

```text
DISCORD_TOKEN=
OWNER_USER_IDS=123,456
DATABASE_URL=postgres://ratscan:ratscan@postgres:5432/ratscan
RATSCAN_API_BASE_URL=http://api:8080
DISCORD_MAX_JAR_BYTES=52428800
DISCORD_MAX_CONCURRENT_SCANS=2
DISCORD_MAX_QUEUED_SCANS=20
DISCORD_PER_USER_SCANS_PER_MINUTE=10
DISCORD_PER_GUILD_SCANS_PER_MINUTE=30
```

Start all local services with `docker compose up --build`. The Discord service
uses `/health` and requires `{"status":"ok"}` before reporting API health.

To import settings from a previous `ds-bot` installation after the SQL
migrations have run, use `DATABASE_URL=... scripts/migrate_discord_settings.sh`.
The script imports only guild settings and never imports legacy scan history,
because those rows cannot be safely mapped to UUID scans.

See [the Discord parity checklist](docs/discord-parity-checklist.md) for the
automated and staging verification matrix.

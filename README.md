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

## Integrated Telegram worker

The same `ratscan` process starts the Telegram worker when both `TG_BOT_TOKEN`
and `ALLOWED_TG_ID` are set. It is supervised independently: a Telegram failure
is retried without stopping the API. There is no `ratscan-telegram-bot.service`.
The worker is compiled into the Rust binary; Python and a virtual environment
are no longer required.

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

## VirusTotal

VirusTotal is optional and disabled by default. Set `VIRUSTOTAL_ENABLED=true`
and provide `VIRUSTOTAL_API_KEY` to add the `virustotal` field to scan
responses. Reports are cached by sha256 in PostgreSQL using
`VIRUSTOTAL_CACHE_TTL_HOURS` to avoid repeated quota usage for the same jar.
The `virustotal.behavior` field contains condensed VirusTotal sandbox artifacts
when the behaviours relationship is available for the file.
# Service boundaries

RatScan API and the Rust Telegram worker are one deployable service. The API owns scan
results, uploaded files, rules, the Telegram worker lifecycle, and the RatScan
PostgreSQL schema.

The Discord client is a separate project at [`../modhub.bot`](../modhub.bot).
Its Compose stack has a separate PostgreSQL database for Discord settings and
uses RatScan solely through the published HTTP port `8080` (`MODHUB_API_BASE_URL`), never through RatScan PostgreSQL. The JSON
response provides its complete scan contract: `scan_id`, `status`, `sha256`,
`verdict`, and `risk_score`.

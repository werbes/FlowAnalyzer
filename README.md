### FlowAnalyzer

A lightweight NetFlow/IPFIX collector and web UI for quickly exploring network flows in real time. It listens for flows over UDP, keeps a rolling in‑memory view, persists compact flow logs to a Windows‑friendly filesystem time‑series store, and serves a web UI plus JSON/WebSocket APIs for analysis.

- NetFlow v1/v5/v9 and IPFIX (v10) parsers
- Live session feed and searchable flow logs per IP
- Top talkers, throughput charts, per‑IP peers and protocol breakdowns
- Simple HTTP ingestion endpoint for custom producers
- Optional on‑disk TSDB for flow logs (enabled by default)
- Windows Service support out of the box, plus cross‑platform console mode
- INI or environment‑based configuration

---

### Screens and endpoints at a glance

UI pages:
- `/` IP table dashboard: sortable summary view, peer drill‑downs, integrated log search panel
- `/logs` dedicated log search page (filter by IP, ports, protocol, time window)
- `/live` live sessions page (WebSocket powered)
- `/bad-ips` page listing IPs with repeated no‑response attempts

APIs (HTTP JSON):
- `GET /healthz` health probe
- `POST /ingest` ingest custom `FlowSession` records
- `GET /api/sessions` filter recent sessions (by router/src/dst/protocol/ports/time/limit)
- `GET /api/metrics/throughput` time‑bucketed throughput
- `GET /api/metrics/top` top protocols/peers
- `GET /api/metrics/throughput_by_protocol_precomputed` precomputed per‑protocol throughput
- `GET /api/top_ips` top talkers
- `GET /api/ip` per‑IP summary (series + counters)
- `GET /api/ips` list IPs seen
- `GET /api/ip/protocols` protocol mix for an IP
- `GET /api/ip/peers` peers for an IP
- `GET /api/ip_table` data for the IP table dashboard
- `GET /api/bad-ips` suspicious/no‑response sources

WebSockets:
- `GET /ws/logs` live flow logs feed
- `GET /ws/sessions` live sessions feed

---

### Quick start

1) Build or download the binary
- Requires Go 1.21+ (recommended). Build:
```
go build -o FlowAnalyzer.exe .
```
- On Linux/macOS:
```
go build -o flowanalyzer .
```

2) Run
- Console mode with defaults (HTTP on `0.0.0.0:8080`, NetFlow on `0.0.0.0:2055`, IPFIX on `0.0.0.0:4739`):
```
./FlowAnalyzer.exe
```
- Open the UI at `http://localhost:8080/`.

3) Point your routers/exporters
- Send NetFlow v5/v9 to `udp://<host>:2055`
- Send IPFIX (v10) to `udp://<host>:4739`

That’s it. Data should appear in the dashboard within seconds.

---

### Configuration

You can configure via environment variables or a simple INI placed next to the executable. On startup, if no INI is present, `FlowAnalyzer.ini` is auto‑generated with the effective settings. Environment variables override INI values.

Key settings (env var or INI key):
- `ADDR` (default `0.0.0.0`): HTTP listen address
- `PORT` (default `8080`): HTTP port
- `PPROF_ENABLE` (`0`/`1`, default `0`): expose `/debug/pprof/*`
- `LOG_REQUESTS` (`0`/`1`, default `0`): log each HTTP request
- `SERVICE_DISABLE` (`0`/`1`, default `0`): when running as service on Windows, force console mode

Memory/aggregation knobs:
- `RETENTION_MINUTES` (default internal): in‑memory session retention window
- `FLOW_TIMEOUT_MINUTES` (default internal): per‑flow idle timeout
- `COMPACT_EVERY_SECONDS` (default internal): background compaction interval
- `MAX_SESSIONS_TRIGGER` (default internal): opportunistic compaction threshold
- `METRICS_RETENTION_HOURS` (default internal): retention of precomputed series

Collectors:
- `NETFLOW_ADDR` (default `0.0.0.0:2055`): UDP listener for NetFlow v1/v5/v9
- `IPFIX_ADDR` (default `0.0.0.0:4739`): UDP listener for IPFIX (v10)
- `COLLECTOR_WORKERS` (default `GOMAXPROCS`): number of UDP packet workers
- `COLLECTOR_QUEUE` (default `65536`): UDP packet queue depth

Deduplication across routers:
- `DEDUP_ENABLE` (`0`/`1`, default `1`): enable cross‑router de‑dup of identical 5‑tuples
- `DEDUP_TTL_MIN` (default `1`): ownership TTL per 5‑tuple

Filesystem TSDB (flow log persistence):
- `TSDB_ENABLE` (`0`/`1`, default `1`): toggle persistence
- `TSDB_ROOT` (default `E:\DB`, falls back to `.\DB` if not available): root directory for logs
- `TSDB_SHARDS` (default `GOMAXPROCS`): number of writer shards
- `TSDB_QUEUE_SIZE` (default `65536`): writer queue depth
- `TSDB_FLUSH_MS` (default `1000`): flush interval
- `TSDB_IDLE_CLOSE_SEC` (default `60`): close idle files after N seconds
- `TSDB_LOG_DROPS` (`0`/`1`, default `0`): log when queue overflows
- `TSDB_LOG_ERRORS` (`0`/`1`, default `1`): log I/O errors
- `TSDB_FILTER_CIDRS` (e.g., `10.0.0.0/8,192.168.0.0/16`): if set, only flows whose src/dst matches any CIDR are written to disk; also used to filter the UI

WebSockets:
- `WS_MAX_CONNS` (default internal): cap on live connections

Example using environment variables (PowerShell):
```
$env:PORT = "9000"
$env:NETFLOW_ADDR = "0.0.0.0:9995"
$env:IPFIX_ADDR = "0.0.0.0:9996"
$env:TSDB_ROOT = "D:\\FlowDB"
./FlowAnalyzer.exe
```

INI example (`FlowAnalyzer.ini`):
```
ADDR=0.0.0.0
PORT=8080
PPROF_ENABLE=0
LOG_REQUESTS=0
RETENTION_MINUTES=1440
FLOW_TIMEOUT_MINUTES=5
COMPACT_EVERY_SECONDS=30
MAX_SESSIONS_TRIGGER=500000
METRICS_RETENTION_HOURS=48
COLLECTOR_WORKERS=4
COLLECTOR_QUEUE=65536
WS_MAX_CONNS=200
DEDUP_ENABLE=1
DEDUP_TTL_MIN=1
TSDB_ENABLE=1
TSDB_ROOT=E:\\DB
TSDB_SHARDS=4
TSDB_QUEUE_SIZE=65536
TSDB_FLUSH_MS=1000
TSDB_IDLE_CLOSE_SEC=60
TSDB_LOG_DROPS=0
TSDB_LOG_ERRORS=1
TSDB_FILTER_CIDRS=10.0.0.0/8,192.168.0.0/16
NETFLOW_ADDR=0.0.0.0:2055
IPFIX_ADDR=0.0.0.0:4739
```

---

### Data model: FlowSession

`POST /ingest` accepts either a single object or an array of objects with the following schema:
```
{
  "timestamp": "2025-09-22T06:58:00Z",    // optional, defaults to now
  "start": "2025-09-22T06:57:00Z",       // optional
  "end": "2025-09-22T06:58:00Z",         // optional
  "router": "router-1",                  // required (or provide Routers)
  "routers": "r1,r2",                    // optional; historical multi-router path
  "src_ip": "10.1.2.3",                  // required
  "src_port": 54321,
  "dst_ip": "93.184.216.34",
  "dst_port": 443,
  "protocol": "TCP",                     // case-insensitive; normalized to upper
  "bytes": 12345,
  "packets": 12,
  "post_packets": 0,                       // optional
  "dropped_packets": 0,                    // optional
  "in_if": 1,                              // optional
  "out_if": 2,                             // optional
  "src_country": "US",                    // filled automatically when possible
  "dst_country": "DE",                    // filled automatically when possible
  "cum_bytes": 0,                          // optional cumulative counter from exporter
  "cum_packets": 0,                        // optional cumulative counter from exporter
  "end_reason": 0,                         // exporter end reason (if any)
  "notes": ""                              // optional freeform
}
```

Notes:
- Minimal required fields: `router`, `src_ip`, `dst_ip` (flow is skipped if missing)
- `protocol` is normalized to upper case
- Country codes are populated using the built‑in IP‑to‑country dataset

Example curl ingestion:
```
curl -X POST http://localhost:8080/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "router":"custom-agent",
    "src_ip":"10.0.0.10", "src_port":55000,
    "dst_ip":"1.1.1.1",   "dst_port":53,
    "protocol":"udp",
    "bytes": 2500, "packets": 5
  }'
```

Array payload:
```
[
  { "router":"r1", "src_ip":"10.0.0.1", "dst_ip":"8.8.8.8", "protocol":"udp", "bytes":1200, "packets":3 },
  { "router":"r1", "src_ip":"10.0.0.1", "dst_ip":"8.8.4.4", "protocol":"udp", "bytes":800, "packets":2 }
]
```

---

### API reference (selected)

- `GET /api/sessions`
  - Query: `router`, `src`, `dst`, `protocol`, `src_port`, `dst_port`, `since`, `until`, `limit`
  - Times accept RFC3339 or common formats handled by the server.

- `GET /api/metrics/throughput`
  - Query: `router`, `since`, `until`, `step` (seconds; default 60)

- `GET /api/ip?ip=<addr>` returns per‑IP series and counters

- `GET /api/ip/peers?ip=<addr>&since=<t>&until=<t>` peers for an IP

- `GET /api/top_ips?window=<15m|1h|8h>` top talkers with bytes/packets

- `GET /api/bad-ips` suspicious/no‑response sources

- WebSockets `GET /ws/sessions` and `GET /ws/logs` push events as JSON frames

---

### Filesystem TSDB layout

When enabled, flows are written to a simple tree under `TSDB_ROOT` (default `E:\DB`, fallback `.\DB`). The store is append‑only, sharded, and flushes periodically. You can safely back it up or index it with external tools. A CIDR filter can limit what gets written.

The UI’s log search reads from this TSDB and supports:
- Time range filters (since/until)
- Protocol/port filters
- Side filters (src/dst for a given IP)
- Pagination and live tail via WebSocket

---

### Windows Service

FlowAnalyzer can run as a Windows Service without any external wrappers.

- Create a service (PowerShell, running as Administrator):
```
New-Service -Name "FlowAnalyzer" -BinaryPathName "C:\\Path\\To\\FlowAnalyzer.exe" -DisplayName "FlowAnalyzer" -StartupType Automatic
Start-Service FlowAnalyzer
```
- Or using `sc.exe`:
```
sc.exe create FlowAnalyzer binPath= "C:\\Path\\To\\FlowAnalyzer.exe" start= auto
sc.exe start FlowAnalyzer
```
- Place `FlowAnalyzer.ini` alongside the EXE to configure it. Set `SERVICE_DISABLE=1` to force console mode while debugging.

To remove:
```
Stop-Service FlowAnalyzer
sc.exe delete FlowAnalyzer
```

---

### Building from source

Prerequisites:
- Go 1.21 or newer

Steps:
- Clone and build:
```
git clone <your-fork-or-origin>/FlowAnalyzer.git
cd FlowAnalyzer
go build -o FlowAnalyzer.exe .
```
- Optional: build for Linux/macOS:
```
GOOS=linux GOARCH=amd64 go build -o flowanalyzer .
GOOS=darwin GOARCH=arm64 go build -o flowanalyzer .
```

---

### Security and performance notes

- UDP packet processing uses a bounded worker pool (`COLLECTOR_WORKERS`, `COLLECTOR_QUEUE`) to cap memory.
- Cross‑router dedup prevents double‑counting when the same flow is exported by multiple routers.
- Gzip middleware is enabled for HTTP responses.
- Enable `PPROF_ENABLE=1` for profiling endpoints under `/debug/pprof/`.

---

### Troubleshooting

- No data in UI?
  - Verify exporters point to the correct host/ports (`NETFLOW_ADDR`, `IPFIX_ADDR`).
  - Check server logs for parse errors.
  - Ensure `TSDB_FILTER_CIDRS` isn’t filtering out your subnets.

- Cannot write `E:\DB`?
  - The app will fall back to `.\DB`. Override with `TSDB_ROOT`.

- Service starts then stops?
  - Check Windows Event Viewer and run the EXE in a console to inspect logs.

---

### License

Specify your chosen license here (e.g., MIT). Add a `LICENSE` file in the repository.

---

### Acknowledgements

- `gorilla/websocket` for WebSocket support
- `orcaman/concurrent-map` for efficient concurrent maps

---

### Roadmap ideas

- Export to Prometheus / OpenTelemetry
- Enriched metadata from external sources
- User authentication / RBAC for the UI

---

### Contact

Issues and feature requests: open a GitHub issue in this repository.

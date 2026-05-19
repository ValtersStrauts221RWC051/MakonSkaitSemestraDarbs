# DNS Security Analysis

A self-contained DNS tunneling / exfiltration detector. Every DNS query the host makes is intercepted by CoreDNS, streamed into a FastAPI service, scored by a trained MLP classifier exported to ONNX, persisted to Postgres, and surfaced on a React dashboard. When the malicious probability crosses the threshold, the bundled Mattermost bot fires an alert.

Trained against nine DNS-tunneling tools (cobaltstrike, dns2tcp, dnscat2, dnsexfiltrator, dnspot, iodine, ozymandns, tcp-over-dns) plus benign traffic; ten linguistic features per query name; StandardScaler + softmax baked into the ONNX graph so the runtime ships pure floats in and a probability out.

---

## Contents

1. [Components](#components)
2. [Quick start](#quick-start)
3. [How it works](#how-it-works)
4. [The ML model](#the-ml-model)
5. [Feature extraction](#feature-extraction)
6. [Domain enrichment](#domain-enrichment)
7. [Persistence](#persistence)
8. [Mattermost alerts](#mattermost-alerts)
9. [Frontend](#frontend)
10. [API endpoints](#api-endpoints)
11. [Configuration](#configuration)
12. [Verifying the flow](#verifying-the-flow)
13. [Tests](#tests)
14. [Retraining the model](#retraining-the-model)
15. [Run the API only (no Docker)](#run-the-api-only-no-docker)
16. [Stop / reset](#stop--reset)
17. [Known limitations](#known-limitations)

---

## Components

| Service | Container | Port | Role |
|---|---|---|---|
| **coredns** | `dns-security-coredns` | 127.0.0.1:53 (udp/tcp) | Catches every DNS query, forwards to `8.8.8.8` / `1.1.1.1`, emits one JSON log line per query |
| **log-forwarder** | `dns-security-log-forwarder` | — | Attaches to CoreDNS via the Docker SDK, parses each JSON line, POSTs it to `/analyze` |
| **api** | `dns-security-api` | 127.0.0.1:8000 | FastAPI: feature extraction, ONNX scoring, persistence, enrichment, legacy HTML dashboard |
| **frontend** | `dns-security-frontend` | 127.0.0.1:3000 | React + Vite SPA served by nginx; nginx also proxies the API endpoints |
| **postgres** | `dns-security-postgres` | 127.0.0.1:5432 | Persistent storage (`analyses` + `domain_info` tables) |
| **mattermost** | `dns-security-mattermost` | 8065 | Notification destination |
| **mattermost-bootstrap** | `dns-security-mattermost-bootstrap` | — | One-shot job: creates admin/user/team/channel/bot, writes `.runtime/mattermost.env` for the API to source |

---

## Quick start

```bash
docker compose up --build -d
```

The `api` service waits for `mattermost-bootstrap` to finish (so the bot token exists) and for Postgres to pass its healthcheck before starting.

### Point the host's DNS at CoreDNS (one-time)

```bash
sudo chattr -i /etc/resolv.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
sudo chattr +i /etc/resolv.conf
```

> Without this, CoreDNS is just another container. With it, every `dig`, `ping`, browser request, package install — all of it flows through `/analyze`.

### URLs

- **React dashboard** — `http://127.0.0.1:3000` (charts, country map, searchable table, detail modal)
- API — `http://127.0.0.1:8000` (also proxied through the SPA on port 3000)
- Legacy server-rendered dashboard — `http://127.0.0.1:8000/dashboard`
- Mattermost — `http://localhost:8065` (login `user@example.com` / `Password123!`, channel `dns-security-alerts`)

Default `MODEL_THRESHOLD=0.5` (set in `docker-compose.yml`). Lower it for noisier testing.

---

## How it works

```
any process → 127.0.0.1:53 (CoreDNS)
                    │
                    ├──→ resolves via 8.8.8.8 / 1.1.1.1, returns answer
                    │
                    └──→ JSON log line on stdout
                              │
                       log-forwarder  (Docker SDK, streams logs)
                              │
                              ▼  POST /analyze  {client_ip, query_type, query_name, ...}
                       FastAPI
                              │
                              ├──→ compute 10 linguistic features from query_name
                              ├──→ ONNX model → P(malicious)
                              ├──→ INSERT into analyses (raw fields + features + score)
                              └──→ if score >= threshold: post Mattermost alert
```

Out-of-band, the dashboard's "Enrich next 10 domains" button calls `POST /admin/enrich`, which resolves the IP, runs WHOIS, and hits `ip-api.com` for GeoIP, then writes everything to the `domain_info` table. The country map and per-country stats use that data.

---

## The ML model

**A real, trained MLP ships with the repo as `model.onnx` + `model.onnx.data`.** It is **not** a placeholder — the API loads it via `onnxruntime` at startup and uses it for every request. `random_score` exists only as a fallback if `MODEL_PATH` is unreadable.

### Architecture (`ml-stuff/train.py`)

PyTorch MLP, binary classifier (benign vs. malicious):

```
Linear(10 → 128) + BatchNorm1d + ReLU + Dropout(0.3)
Linear(128 → 64) + BatchNorm1d + ReLU + Dropout(0.2)
Linear(64 → 32)  + ReLU
Linear(32 → 2)   + Softmax
```

Trained with class-balancing undersampling on a per-CSV 70/15/15 split and evaluated with accuracy, precision, recall, F1, and ROC-AUC.

### Export (`ml-stuff/export_onnx.py`)

The exported graph wraps the raw MLP with two extra ops so the runtime needs zero preprocessing:

- `(x - mean) / scale` — the `StandardScaler` mean/scale vectors are baked in as ONNX constants.
- `softmax(...)[:, 1]` — the malicious-class probability becomes the single output.

Constant folding + `FuseBatchNormIntoGemm` shrink the graph: BatchNorm layers are merged into the preceding `Gemm` ops, and the final artifact has `Gemm` → `Relu` → `Gemm` → `Relu` → `Gemm` → `Softmax`. Opset 18, dynamic batch dimension.

Tensors:

| Name | Shape | Type | Meaning |
|---|---|---|---|
| `features` (input) | `[N, 10]` | float32 | raw, unscaled feature vector |
| `prob_malicious` (output) | `[N]` | float32 | probability of the malicious class |

After export the script does a parity check: PyTorch vs `onnxruntime` outputs on 16 random samples must agree to within `1e-5` or the export aborts.

### File layout

Two files live side by side at the repo root and **must stay together**:

- `model.onnx` — graph (~3 KB)
- `model.onnx.data` — weights as ONNX external data (~46 KB)

Both are copied into the Docker image (`Dockerfile`'s `COPY . .`; not excluded by `.dockerignore`).

### Standalone batch inference

`inference_onnx.py` (also at `ml-stuff/inference_onnx.py`) is a CLI that reads CoreDNS log lines from a file or stdin and prints one row per query:

```
$ python inference_onnx.py < coredns.log
   malicious  p=0.8234  TXT    aGVsbG8.tunnel.example.
      benign  p=0.3421  A      google.com.
```

Args: `--model` (path), `--threshold` (default `0.5`), `--batch` (default `256`). Inference is batched — features and metadata accumulate until the batch fills, then a single `sess.run` call processes the whole chunk.

---

## Feature extraction

`app/features.py` computes ten numeric features per query name:

| Feature | What it measures |
|---|---|
| `dns_domain_name_length` | total length of the canonical name (incl. trailing dot) |
| `dns_subdomain_name_length` | length of the subdomain portion (left of the registrable 2LD.TLD) |
| `numerical_percentage` | fraction of characters that are decimal digits |
| `character_entropy` | Shannon entropy (base 2) over the character distribution |
| `max_continuous_numeric_len` | longest contiguous run of digits |
| `max_continuous_alphabet_len` | longest contiguous run of letters |
| `max_continuous_consonants_len` | longest contiguous run of consonants |
| `max_continuous_same_alphabet_len` | longest run of the same character repeated |
| `vowels_consonant_ratio` | vowel count ÷ consonant count |
| `conv_freq_vowels_consonants` | vowel↔consonant transition frequency over the alpha-only sequence |

The same module exposes `parent_domain(name)` (last two labels) and `subdomain_depth(name)` (total label count); both are stored next to the features on every row.

---

## Domain enrichment

`app/enrichment.py` performs three lookups per parent domain and stores the union in the `domain_info` table:

| Source | Library / endpoint | Timeout | Fields produced |
|---|---|---|---|
| DNS A record | `socket.gethostbyname` | 3 s | `ip` |
| GeoIP | `http://ip-api.com/json/{ip}` (free, no key) | 5 s | `country`, `country_code`, `city`, `isp` |
| WHOIS | `python-whois` | 10 s | `registrar`, `creation_date`, `whois_country` |

Failures land in a comma-separated `error` column (e.g. `resolve,whois`) so partial enrichments are still useful. Upsert on `parent_domain` conflict — re-enriching the same domain just refreshes the row.

Trigger from the dashboard ("Enrich next 10 domains" button) or directly:

```bash
curl -X POST 'http://127.0.0.1:8000/admin/enrich?limit=10'
```

---

## Persistence

SQLAlchemy 2.x against Postgres 16. Two tables:

- **`analyses`** — one row per DNS query. Columns: timestamps, `client_ip`/`client_port`/`proto`, full DNS metadata (`query_type`/`query_name`/`query_class`/`rcode`/`response_size`/`duration_ms`/`dns_id`/`opcode`/`bufsize`/`do_flag`), derived `parent_domain` + `subdomain_depth`, the ten ML features, the `score` / `threshold` / `alerted` verdict, and the raw CoreDNS log as JSONB.
- **`domain_info`** — one row per parent domain with the enrichment fields above plus `looked_up_at`.

Without `DATABASE_URL`, the API silently swaps to an in-memory `Store` with the same surface (data is lost on restart). All endpoints work against both backends.

---

## Mattermost alerts

When `score >= threshold` **and** `mattermost_enabled` is true, the API posts to `MATTERMOST_CHANNEL_ID` via `POST /api/v4/posts` with the bot token. The message looks like:

```
### DNS security alert
- Query: `TXT aGVsbG8.tunnel.example.`
- Client IP: `10.0.0.1`
- Risk score: `0.9123` (threshold `0.5000`)
- Response: `rcode=NOERROR size=150 duration=4.20ms`
```

Token, channel ID, base URL and the enabled flag come from env vars (which override `config.toml`). The `mattermost-bootstrap` service writes these into `.runtime/mattermost.env`, and `scripts/run_api.sh` sources that file before starting uvicorn.

---

## Frontend

React 18 + Vite + TypeScript, served via nginx. Charts use **Recharts**; the world map uses **react-simple-maps**.

| Component | What it shows |
|---|---|
| `StatsCards` | total, safe, alerts, average score, max score, threshold |
| `HourlyChart` | bar chart of queries vs alerts per hour for the last 24 h |
| `TopSuspiciousChart` | horizontal bars: top alerted query names by hit count |
| `TopDomainsChart` | horizontal bars: most-queried parent domains |
| `QueryTypeChart` | pie chart of DNS record types (`TXT`/`NULL`/`MX` highlighted red — tunneling-prone) |
| `CountryMap` | choropleth coloured by alert ratio per country, plus top-5 countries panel and an "Enrich next 10 domains" trigger |
| `AnalysesTable` | paginated table with debounced search (`query_name` or `client_ip`), filters (query type, alerted/safe), sortable columns, CSV export |
| `DetailModal` | per-row detail: timestamp, client, query, response, DNS metadata (id/opcode/bufsize/DO flag), the ten features, score vs threshold, full raw CoreDNS log JSON |

Auto-refresh runs every 5 s via the `useAutoRefresh` hook (togglable in the header). Human-readable labels for DNS types, rcodes, opcodes and the DO flag live in `frontend/src/labels.ts` (e.g. `TXT → "Text record"`, `NXDOMAIN → "Not found"`). The nginx config (`frontend/nginx.conf`) proxies `/analyses`, `/analyze`, `/stats`, `/health`, `/docs`, `/openapi.json` to `api:8000` and falls back to `index.html` for SPA routing.

---

## API endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness |
| `POST` | `/analyze` | Score one DNS query, persist result. Accepts structured fields **or** a raw CoreDNS `request`/`response` pair |
| `GET` | `/analyses` | Paginated query history; supports `limit`, `offset`, `query_type`, `alerted`, `q` (substring match on name or client IP) |
| `GET` | `/analyses/{id}` | Single row by id |
| `GET` | `/stats` | Total / alerts / safe / average / max score / threshold |
| `GET` | `/stats/top?limit=10` | Top alerted domains grouped by `query_name` (count + max score) |
| `GET` | `/stats/hourly?hours=24` | Per-hour query + alert counts (PG `date_trunc`) |
| `GET` | `/stats/clients?limit=10` | Top client IPs by query volume |
| `GET` | `/stats/parents?limit=10` | Top parent domains by query volume |
| `GET` | `/stats/types` | Counts grouped by DNS record type |
| `GET` | `/stats/countries` | Per-country totals + alerts (joins `domain_info` on `parent_domain`) |
| `GET` | `/domain-info` | Full `domain_info` table |
| `POST` | `/admin/enrich?limit=5` | Resolve / WHOIS / GeoIP the next N un-enriched parent domains |
| `GET` | `/dashboard` | Legacy server-rendered HTML dashboard |

CORS is wide open (`*` origins/methods/headers) so the SPA can hit the API directly on a different port during dev.

### Flexible `/analyze` body

`AnalysisRequest.to_analysis()` normalizes two input shapes:

```json
// Structured (what the log-forwarder posts)
{ "client_ip": "10.0.0.1", "query_type": "A", "query_name": "example.com.",
  "rcode": "NOERROR", "response_size": 43, "duration_ms": 12.5 }

// Raw CoreDNS log lines
{ "request":  "{...json line from CoreDNS...}",
  "response": "{...json line from CoreDNS...}" }
```

Defaults are filled in (`query_type=A`, `rcode=NOERROR`, `proto=udp`). `client_ip` and `query_name` are required.

---

## Configuration

### Environment variables

| Var | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | — (in-memory) | SQLAlchemy URL, e.g. `postgresql://dns_user:dns_pass@postgres:5432/dns_security` |
| `MODEL_PATH` | `model.onnx` | ONNX classifier to load at startup |
| `MODEL_THRESHOLD` | `0.75` (`0.5` in compose) | Alert decision threshold (must be in `[0, 1]`) |
| `MATTERMOST_BASE_URL` | — | Mattermost server URL |
| `MATTERMOST_TOKEN` | — | Bot token |
| `MATTERMOST_CHANNEL_ID` | — | Target channel |
| `MATTERMOST_ENABLED` | `false` | Set to `1`/`true`/`yes`/`on` to actually post |
| `COREDNS_CONTAINER` | `dns-security-coredns` | Log-forwarder: which container's logs to stream |
| `API_URL` | `http://api:8000/analyze` | Log-forwarder: where to POST parsed lines |

Env vars override `config.toml`. Example `config.toml`:

```toml
[model]
threshold = 0.75

[mattermost]
base_url  = "https://mattermost.example.com"
token     = "YOUR_BOT_TOKEN"
channel_id = "YOUR_CHANNEL_ID"
enabled   = true
```

### CoreDNS

`coredns/Corefile` forwards everything to Google + Cloudflare, caches for 30 s, hot-reloads on file changes, and emits a JSON log line per query containing `remote`, `port`, `proto`, `type`, `name`, `class`, `rcode`, `size`, `duration`, `id`, `opcode`, `bufsize`, `do`. The log-forwarder turns each of those into an `/analyze` POST.

---

## Verifying the flow

### 1. Service health

```bash
docker compose ps
```
All services should be `Up`; `postgres` should be `healthy`; `mattermost-bootstrap` should be `Exited (0)`.

### 2. End-to-end DNS → DB

```bash
dig +short example.com @127.0.0.1
sleep 2
docker exec dns-security-postgres psql -U dns_user -d dns_security \
  -c "SELECT query_name, character_entropy, score, alerted
      FROM analyses ORDER BY id DESC LIMIT 3;"
```
You should see `example.com.` with computed features and a model score.

### 3. Mattermost alert

Open `http://localhost:8065`, log in as `user@example.com` / `Password123!`, look in the `dns-security-alerts` channel.

### 4. Force-score a query directly

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"client_ip":"10.0.0.1","query_type":"TXT",
       "query_name":"aGVsbG93b3JsZA.tunnel.example.",
       "rcode":"NOERROR","response_size":150,"duration_ms":4.2}'
```

The long base64-ish subdomain should push the model toward a high `score`.

---

## Tests

```bash
pip install pytest
pytest
```

`tests/test_app.py` covers the `Store` + `/analyze` contract:

- safe query (`score < threshold`) is recorded with `alerted=false` and does not notify
- query at the threshold (`score >= threshold`) flips to `alerted=true` and triggers the notify callback
- `/stats`, `/analyses` and `/dashboard` reflect new fields and render
- `/stats/top` groups by `query_name`
- `/stats/clients` groups by `client_ip`

The fixture builds the app with an in-memory `Store`, a deterministic mock scorer, and a mock notify callback — the tests don't need Postgres, ONNX, or Mattermost.

---

## Retraining the model

`ml-stuff/train.sh` is the full retraining loop:

1. Create / activate a venv, install `ml-stuff/requirements.txt`.
2. `download_dataset.py` pulls [`daumel/dns-tunneling-dataset`](https://www.kaggle.com/datasets/daumel/dns-tunneling-dataset) from Kaggle via `kagglehub` and writes the CSV paths to `csv_files.txt`.
3. Appends the bundled synthetic CSVs in `ml-stuff/synthetic_data/` (benign, cobaltstrike, dns2tcp, dnscat2, dnsexfiltrator, dnspot, iodine, ozymandns, tcp-over-dns) to the same list.
4. `train.py` per-CSV 70/15/15 split, undersample to balance classes, train, report accuracy / precision / recall / F1 / ROC-AUC, save `model.pt`.
5. `export_onnx.py` converts the `.pt` to ONNX (with the `StandardScaler` + softmax baked in) and runs the parity check.
6. Both `.pt` and `.onnx` artifacts are time-stamped (`model_YYYYMMDD-HHMMSS.{pt,onnx}`).

Drop the resulting `model.onnx` (and `model.onnx.data` if the export produces one) at the repo root, rebuild the API image, and the new weights are live.

---

## Run the API only (no Docker)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Without `DATABASE_URL`, the API uses an in-memory `Store`. With `model.onnx` (and its `.data` sibling) in the working directory, it scores against the real model — otherwise it falls back to random. Configure Mattermost in `config.toml` or via env vars.

---

## Stop / reset

```bash
docker compose down            # stop containers (data persists)
docker compose down -v         # also wipe postgres + mattermost volumes
rm -rf .runtime                # wipe Mattermost bootstrap tokens

# Restore system DNS if you flipped /etc/resolv.conf:
sudo chattr -i /etc/resolv.conf
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
sudo chattr +i /etc/resolv.conf
```

**Warning**: if you stop CoreDNS without restoring `/etc/resolv.conf` first, the host has no DNS until you do.

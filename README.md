# DNS Security Analysis

System that intercepts every DNS query from the host, computes ML features over the queried domain, runs a (currently dummy) risk model, stores the result in PostgreSQL, and posts a Mattermost alert when the score crosses a threshold.

## Components

| Service | Container | Port | Role |
|---|---|---|---|
| **coredns** | `dns-security-coredns` | 127.0.0.1:53 | Catches every DNS query the host makes |
| **log-forwarder** | `dns-security-log-forwarder` | — | Streams CoreDNS logs → `POST /analyze` |
| **api** | `dns-security-api` | 127.0.0.1:8000 | FastAPI, feature extraction, model, legacy HTML dashboard |
| **frontend** | `dns-security-frontend` | 127.0.0.1:3000 | React + Vite SPA with charts, filters, blocklist UI |
| **postgres** | `dns-security-postgres` | 127.0.0.1:5432 | Persistent storage for analyses + blocklist |
| **mattermost** | `dns-security-mattermost` | 8065 | Notification destination |

## Quick start

```bash
docker compose up --build -d
```

### Point the host's DNS at CoreDNS (one-time)

```bash
sudo chattr -i /etc/resolv.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
sudo chattr +i /etc/resolv.conf
```

> Without this, CoreDNS is just another container. With this, every `dig`, `ping`, browser request, package install — all of it flows through `/analyze`.

### URLs

- **React dashboard: `http://127.0.0.1:3000`** ← main UI (charts, filters, blocklist)
- API: `http://127.0.0.1:8000` (also proxied through frontend on port 3000)
- Legacy HTML dashboard: `http://127.0.0.1:8000/dashboard`
- Mattermost: `http://localhost:8065` (login `user@example.com` / `Password123!`)

For local testing, `MODEL_THRESHOLD=0.0`, so every request triggers an alert.

---

## How it works

```
any process → 127.0.0.1:53 (CoreDNS)
                    │
                    ├──→ resolves via 8.8.8.8 / 1.1.1.1, returns answer
                    │
                    └──→ JSON log on stdout
                              │
                       log-forwarder (Docker SDK)
                              │
                              ▼  POST /analyze {client_ip, query_type, query_name, ...}
                       FastAPI
                              │
                              ├──→ compute 10 ML features from query_name
                              ├──→ if query_name in blocklist:   score = 1.0
                              │    else:                         score = random_score()  (dummy)
                              ├──→ INSERT into analyses (features + score)
                              └──→ if score >= threshold: Mattermost alert
```

---

## API endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness |
| `POST` | `/analyze` | Score a single DNS query, store result |
| `GET` | `/analyses?limit=50` | Recent rows |
| `GET` | `/stats` | Total / alerts / safe / avg / max score |
| `GET` | `/stats/top?limit=10` | Top suspicious domains (grouped by `query_name`) |
| `GET` | `/stats/hourly?hours=24` | Per-hour query and alert counts |
| `GET` | `/stats/clients?limit=10` | Distribution of queries per client IP |
| `GET` | `/blocklist` | List manually flagged domains |
| `POST` | `/blocklist` | Add a domain (body: `{query_name, reason?}`) |
| `DELETE` | `/blocklist/{id}` | Remove a blocked domain |
| `GET` | `/dashboard` | HTML dashboard with recent table |

---

## Verifying the flow

### 1. Service health

```bash
docker compose ps
```
All 5 services should be `Up` and `postgres` should be `healthy`.

### 2. End-to-end DNS → DB

```bash
dig +short example.com @127.0.0.1
sleep 2
docker exec dns-security-postgres psql -U dns_user -d dns_security \
  -c "SELECT query_name, character_entropy, score, alerted
      FROM analyses ORDER BY id DESC LIMIT 3;"
```
You should see `example.com.` with computed features and a score.

### 3. Blocklist forces an alert

```bash
curl -X POST http://127.0.0.1:8000/blocklist \
  -H "Content-Type: application/json" \
  -d '{"query_name":"evil.example.","reason":"test"}'

curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"client_ip":"10.0.0.1","query_type":"A","query_name":"evil.example.","rcode":"NOERROR","response_size":50,"duration_ms":1.0}'
```
The response should have `"score": 1.0`.

### 4. Mattermost alert

Open `http://localhost:8065`, login as `user@example.com` / `Password123!`, check the `dns-security-alerts` channel.

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

---

## Run API only (no Docker)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Without `DATABASE_URL` env var, the API falls back to an in-memory `Store` (data lost on restart). Configure Mattermost in `config.toml`:

```toml
[model]
threshold = 0.75

[mattermost]
base_url = "https://mattermost.example.com"
token = "YOUR_BOT_TOKEN"
channel_id = "YOUR_CHANNEL_ID"
enabled = true
```

---

## Tests

```bash
pip install pytest
pytest
```

20 tests cover:
- `Store` and `/analyze` flow (score, threshold, notify)
- Stats endpoints (`top`, `clients`, `hourly`)
- All 10 feature functions
- Blocklist CRUD + integration with `/analyze`

---

## Further reading

- **`docs/SCHEMA.md`** — full database schema with column rationale and example queries
- **`docs/BLOCKLIST.md`** — blocklist API, behavior, and SQL audit queries
- **`inference_onnx.py`** — standalone CLI that runs the ONNX model on CoreDNS log lines (not yet wired into the API; `app/main.py` still uses `random_score`)

---

## Known limitations

- **Model is dummy** — `random_score()` returns a random number. To produce real verdicts, wire up `inference_onnx.py` (load `model.onnx` once at startup, run features through `ort.InferenceSession.run`).
- **`client_ip` is always Docker bridge** (`172.20.0.1`) — every query coming through `coredns` container appears to originate from the Docker gateway. To see real per-process source IPs, run CoreDNS on the host network or use `dnstap`.
- **No alert rate-limiting** — with `threshold=0.0` and a busy host, Mattermost gets one alert per DNS query (could be hundreds per minute).
- **No authentication** — API and dashboard are open on localhost. Lock down with a reverse proxy + auth if exposing beyond loopback.

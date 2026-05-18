# DNS Security Analysis

Small prototype that:

- accepts DNS data at `POST /analyze`
- generates a dummy risk score from `0.0` to `1.0`
- keeps recent analyses in memory while the API is running
- sends a Mattermost alert when `score >= threshold`
- shows recent stats at `/dashboard`

## Start Everything

```bash
docker compose up --build -d
```

URLs:

- API: http://localhost:8000
- Dashboard: http://localhost:8000/dashboard
- Mattermost: http://localhost:8065

Docker Compose automatically creates:

```text
Team: dns-security
Channel: dns-security-alerts
Bot: dns-security-bot
Admin: admin@example.com / Password123!
Recipient: user@example.com / Password123!
```

For local testing, Compose sets `MODEL_THRESHOLD=0.0`, so every request sends a Mattermost alert.

## Trigger Alert

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"dns_address":"10.50.0.102","request":"SRV _kerberos._tcp.google.com.","response":"rcode=- size=43 duration=0.000058525s"}'
```

Then open Mattermost, log in as `user@example.com`, and check `dns-security-alerts`.

## Stop Or Reset

```bash
docker compose down
```

Reset generated Mattermost data and tokens:

```bash
docker compose down -v
rm -rf .runtime
```

## How DNS Security Is Validated

This project currently uses a dummy model. It does not inspect real system DNS traffic automatically and it does not perform real machine-learning classification yet.

Validation flow:

1. A client sends DNS information to `POST /analyze`.
2. The dummy model returns a risk score between `0.0` and `1.0`.
3. The service compares the score with the configured threshold.
4. If `score >= threshold`, the DNS request is treated as suspicious.
5. Suspicious requests are shown as alerts on `/dashboard`.
6. If Mattermost is enabled, the service posts an alert into `dns-security-alerts`.

For local Docker testing, the threshold is `0.0`, so every request is suspicious and always triggers a Mattermost message.

To validate the alert path:

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"dns_address":"10.50.0.102","request":"SRV _kerberos._tcp.google.com.","response":"rcode=- size=43 duration=0.000058525s"}'
```

Expected response fields:

```json
{
  "safe": false,
  "notification_sent": true
}
```

Then check:

- Dashboard: http://localhost:8000/dashboard
- Mattermost channel: `dns-security-alerts`

When replacing the dummy model with a real model, calculate the risk score from DNS features such as query rate, domain length, query type diversity, entropy, response size, and request timing.

## Run API Only

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Configure non-Docker Mattermost in `config.toml`:

```toml
[model]
threshold = 0.75

[mattermost]
base_url = "https://mattermost.example.com"
token = "YOUR_BOT_TOKEN"
channel_id = "YOUR_CHANNEL_ID"
enabled = true
```

Environment variables override `config.toml`: `MODEL_THRESHOLD`, `MATTERMOST_BASE_URL`, `MATTERMOST_TOKEN`, `MATTERMOST_CHANNEL_ID`, `MATTERMOST_ENABLED`.

## Test

```bash
pip install -r requirements.txt pytest
pytest
```

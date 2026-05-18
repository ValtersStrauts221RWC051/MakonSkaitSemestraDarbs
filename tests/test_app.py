from fastapi.testclient import TestClient

from app.main import Config, Store, create_app


SAMPLE = {
    "client_ip": "10.50.0.102",
    "query_type": "A",
    "query_name": "example.com.",
    "rcode": "NOERROR",
    "response_size": 43,
    "duration_ms": 12.5,
}


def make_client(score=0.9, threshold=0.7, notify=lambda *_: True):
    app = create_app(
        config=Config(threshold=threshold),
        store=Store(),
        model=lambda _: score,
        notify=notify,
    )
    return TestClient(app)


def test_below_threshold_is_safe_and_does_not_notify():
    calls = []
    client = make_client(score=0.2, threshold=0.7, notify=lambda *args: calls.append(args) or True)

    response = client.post("/analyze", json=SAMPLE)

    body = response.json()
    assert body["safe"] is True
    assert body["notification_sent"] is False
    assert calls == []


def test_score_at_threshold_notifies():
    response = make_client(score=0.7, threshold=0.7).post("/analyze", json=SAMPLE)
    body = response.json()
    assert body["safe"] is False
    assert body["notification_sent"] is True


def test_stats_and_recent_use_new_fields():
    client = make_client(score=0.9, threshold=0.7)
    client.post("/analyze", json=SAMPLE)

    assert client.get("/stats").json()["alerts"] == 1
    recent = client.get("/analyses").json()
    assert recent[0]["query_name"] == "example.com."
    assert recent[0]["client_ip"] == "10.50.0.102"
    assert recent[0]["query_type"] == "A"
    assert "DNS Security Dashboard" in client.get("/dashboard").text


def test_top_suspicious_groups_by_query_name():
    client = make_client(score=0.9, threshold=0.7)
    client.post("/analyze", json={**SAMPLE, "query_name": "evil.com."})
    client.post("/analyze", json={**SAMPLE, "query_name": "evil.com."})
    client.post("/analyze", json={**SAMPLE, "query_name": "safe.com."})

    top = client.get("/stats/top").json()
    names = {entry["query_name"]: entry["count"] for entry in top}
    assert names["evil.com."] == 2
    assert names["safe.com."] == 1


def test_client_distribution_groups_by_ip():
    client = make_client(score=0.9, threshold=0.7)
    client.post("/analyze", json={**SAMPLE, "client_ip": "10.0.0.1"})
    client.post("/analyze", json={**SAMPLE, "client_ip": "10.0.0.1"})
    client.post("/analyze", json={**SAMPLE, "client_ip": "10.0.0.2"})

    dist = client.get("/stats/clients").json()
    counts = {row["client_ip"]: row["count"] for row in dist}
    assert counts["10.0.0.1"] == 2
    assert counts["10.0.0.2"] == 1

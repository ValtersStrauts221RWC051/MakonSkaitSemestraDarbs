from fastapi.testclient import TestClient

from app.main import Config, Store, create_app


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

    response = client.post(
        "/analyze",
        json={"dns_address": "10.50.0.101", "request": "A faceboox.com.", "response": "size=30"},
    )

    assert response.json()["safe"] is True
    assert response.json()["notification_sent"] is False
    assert calls == []


def test_score_at_threshold_notifies():
    response = make_client(score=0.7, threshold=0.7).post(
        "/analyze",
        json={"dns_address": "10.50.0.102", "request": "SRV _kerberos._tcp.google.com.", "response": "size=43"},
    )

    assert response.json()["safe"] is False
    assert response.json()["notification_sent"] is True


def test_stats_dashboard_and_recent_analyses_use_memory_store():
    client = make_client(score=0.9, threshold=0.7)
    client.post(
        "/analyze",
        json={"dns_address": "10.50.0.102", "request": "TXT _dmarc.google.com.", "response": "size=35"},
    )

    assert client.get("/stats").json()["alerts"] == 1
    assert client.get("/analyses").json()[0]["dns_address"] == "10.50.0.102"
    assert "DNS Security Dashboard" in client.get("/dashboard").text


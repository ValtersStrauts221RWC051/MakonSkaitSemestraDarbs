from __future__ import annotations

import html
import os
import random
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

import requests
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field


@dataclass(frozen=True)
class Config:
    threshold: float = 0.75
    mattermost_url: str = ""
    mattermost_token: str = ""
    mattermost_channel_id: str = ""
    mattermost_enabled: bool = False


class AnalysisIn(BaseModel):
    dns_address: str = Field(..., examples=["10.50.0.102"])
    request: str = Field(..., examples=["SRV _kerberos._tcp.google.com."])
    response: str = Field(..., examples=["rcode=- size=43 duration=0.000058525s"])


class AnalysisOut(BaseModel):
    id: int
    score: float
    threshold: float
    safe: bool
    notification_sent: bool


def load_config(path: str = "config.toml") -> Config:
    raw = {}
    if Path(path).exists():
        with open(path, "rb") as file:
            raw = tomllib.load(file)

    model = raw.get("model", {})
    mattermost = raw.get("mattermost", {})
    threshold = float(os.getenv("MODEL_THRESHOLD", model.get("threshold", 0.75)))
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be between 0 and 1")

    return Config(
        threshold=threshold,
        mattermost_url=os.getenv("MATTERMOST_BASE_URL", mattermost.get("base_url", "")).rstrip("/"),
        mattermost_token=os.getenv("MATTERMOST_TOKEN", mattermost.get("token", "")),
        mattermost_channel_id=os.getenv("MATTERMOST_CHANNEL_ID", mattermost.get("channel_id", "")),
        mattermost_enabled=str(os.getenv("MATTERMOST_ENABLED", mattermost.get("enabled", False))).lower()
        in {"1", "true", "yes", "on"},
    )


class Store:
    def __init__(self) -> None:
        self.records: list[dict] = []

    def add(self, data: AnalysisIn, score: float, threshold: float, alerted: bool) -> dict:
        created_at = datetime.now(UTC).isoformat(timespec="seconds")
        record = {
            "id": len(self.records) + 1,
            "created_at": created_at,
            "dns_address": data.dns_address,
            "request": data.request,
            "response": data.response,
            "score": score,
            "threshold": threshold,
            "alerted": alerted,
        }
        self.records.append(record)
        return record

    def recent(self, limit: int = 50) -> list[dict]:
        return list(reversed(self.records[-limit:]))

    def stats(self) -> dict:
        total = len(self.records)
        alerts = sum(1 for record in self.records if record["alerted"])
        scores = [record["score"] for record in self.records]
        return {
            "total": total,
            "alerts": alerts,
            "safe": total - alerts,
            "average_score": round(sum(scores) / total, 4) if total else 0.0,
            "max_score": round(max(scores), 4) if scores else 0.0,
        }


def random_score(_: AnalysisIn) -> float:
    return round(random.random(), 4)


def _extract_query_name(request: str) -> str:
    parts = request.split(" ", 1)
    return parts[1].strip() if len(parts) > 1 else parts[0].strip()


def make_onnx_scorer(model_path: str) -> Callable[[AnalysisIn], float]:
    import numpy as np
    import onnxruntime as ort

    from inference_onnx import extract_features

    sess = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])
    in_name = sess.get_inputs()[0].name
    out_name = sess.get_outputs()[0].name

    def score(data: AnalysisIn) -> float:
        name = _extract_query_name(data.request)
        if not name:
            return 0.0
        features = extract_features(name)
        batch = np.expand_dims(features, axis=0)
        probs = sess.run([out_name], {in_name: batch})[0]
        return float(probs.flatten()[0])

    return score


def send_mattermost(config: Config, data: AnalysisIn, score: float) -> bool:
    if not config.mattermost_enabled:
        return False
    if not all([config.mattermost_url, config.mattermost_token, config.mattermost_channel_id]):
        return False

    message = (
        "### DNS security alert\n"
        f"- DNS address: `{data.dns_address}`\n"
        f"- Risk score: `{score:.4f}`\n"
        f"- Threshold: `{config.threshold:.4f}`\n"
        f"- Request: `{data.request}`\n"
        f"- Response: `{data.response}`"
    )
    try:
        response = requests.post(
            f"{config.mattermost_url}/api/v4/posts",
            headers={"Authorization": f"Bearer {config.mattermost_token}"},
            json={"channel_id": config.mattermost_channel_id, "message": message},
            timeout=10,
        )
        response.raise_for_status()
        return True
    except requests.RequestException:
        return False


def create_app(
    config: Config | None = None,
    store: Store | None = None,
    model: Callable[[AnalysisIn], float] | None = None,
    notify: Callable[[Config, AnalysisIn, float], bool] = send_mattermost,
) -> FastAPI:
    config = config or load_config()
    store = store or Store()
    if model is None:
        model_path = os.getenv("MODEL_PATH", "model.onnx")
        if Path(model_path).exists():
            try:
                model = make_onnx_scorer(model_path)
            except Exception as exc:
                import logging
                logging.getLogger(__name__).warning(
                    "ONNX model %s could not be loaded, falling back to random_score: %s",
                    model_path, exc,
                )
                model = random_score
        else:
            model = random_score
    app = FastAPI(title="DNS Security Analysis")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/analyze", response_model=AnalysisOut)
    def analyze(data: AnalysisIn) -> AnalysisOut:
        score = min(1.0, max(0.0, float(model(data))))
        alerted = score >= config.threshold
        notification_sent = notify(config, data, score) if alerted else False
        record = store.add(data, score, config.threshold, alerted)
        return AnalysisOut(
            id=record["id"],
            score=score,
            threshold=config.threshold,
            safe=not alerted,
            notification_sent=notification_sent,
        )

    @app.get("/analyses")
    def analyses(limit: int = 50) -> list[dict]:
        return store.recent(limit)

    @app.get("/stats")
    def stats() -> dict:
        return store.stats()

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard() -> str:
        return render_dashboard(store.stats(), store.recent(25), config.threshold)

    return app


def render_dashboard(stats: dict, records: list[dict], threshold: float) -> str:
    rows = "".join(
        f"<tr><td>{r['created_at']}</td><td>{html.escape(r['dns_address'])}</td>"
        f"<td>{html.escape(r['request'])}</td><td>{r['score']:.4f}</td>"
        f"<td class=\"{'bad' if r['alerted'] else 'good'}\">{'Alert' if r['alerted'] else 'Safe'}</td></tr>"
        for r in records
    ) or "<tr><td colspan='5'>No analyses yet</td></tr>"

    return f"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>DNS Security Dashboard</title>
      <style>
        body {{ margin: 0; font-family: Arial, sans-serif; background: #f4f6f8; color: #17202a; }}
        header {{ background: #16324f; color: white; padding: 24px 32px; }}
        main {{ max-width: 1100px; margin: 0 auto; padding: 24px 32px; }}
        h1 {{ margin: 0 0 6px; font-size: 28px; }}
        .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }}
        .card, table {{ background: white; border: 1px solid #d8dee6; border-radius: 8px; }}
        .card {{ padding: 16px; }}
        .label {{ color: #53606f; font-size: 13px; }}
        .value {{ font-size: 28px; font-weight: 700; margin-top: 8px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; overflow: hidden; }}
        th, td {{ border-bottom: 1px solid #e8edf2; padding: 12px; text-align: left; font-size: 14px; }}
        th {{ background: #e9eef5; }}
        .good {{ color: #2f8f5b; font-weight: 700; }}
        .bad {{ color: #c43d3d; font-weight: 700; }}
        @media (max-width: 720px) {{ header, main {{ padding-left: 16px; padding-right: 16px; }} table {{ display: block; overflow-x: auto; }} }}
      </style>
    </head>
    <body>
      <header><h1>DNS Security Dashboard</h1><div>Alert threshold: {threshold:.2f}</div></header>
      <main>
        <section class="cards">
          <div class="card"><div class="label">Total</div><div class="value">{stats['total']}</div></div>
          <div class="card"><div class="label">Safe</div><div class="value">{stats['safe']}</div></div>
          <div class="card"><div class="label">Alerts</div><div class="value">{stats['alerts']}</div></div>
          <div class="card"><div class="label">Average score</div><div class="value">{stats['average_score']:.2f}</div></div>
          <div class="card"><div class="label">Max score</div><div class="value">{stats['max_score']:.2f}</div></div>
        </section>
        <table>
          <thead><tr><th>Time</th><th>DNS address</th><th>Request</th><th>Score</th><th>Status</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </main>
    </body>
    </html>
    """


app = create_app()

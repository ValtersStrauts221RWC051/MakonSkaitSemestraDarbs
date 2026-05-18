from __future__ import annotations

import html
import os
import random
import re
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import case, func

from app.database import Base, make_engine, make_session_factory
from app.features import FEATURE_NAMES, compute_features, parent_domain, subdomain_depth
from app.models import Analysis


@dataclass(frozen=True)
class Config:
    threshold: float = 0.75
    mattermost_url: str = ""
    mattermost_token: str = ""
    mattermost_channel_id: str = ""
    mattermost_enabled: bool = False


logger = logging.getLogger(__name__)


_REQUEST_RE = re.compile(r"^(?P<qtype>\S+)\s+(?P<qname>\S+)$")
_RESPONSE_RE = re.compile(
    r"rcode=(?P<rcode>\S+)|size=(?P<size>\d+)|duration=(?P<duration>\d+(?:\.\d+)?)s?"
)


def _safe_int(value: str | int | None) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _parse_duration(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        return float(value) * 1000.0
    except ValueError:
        return 0.0


def _parse_response(text: str) -> tuple[str, int, float]:
    rcode = ""
    size = 0
    duration_ms = 0.0
    for match in _RESPONSE_RE.finditer(text):
        if match.group("rcode"):
            rcode = match.group("rcode")
        elif match.group("size"):
            size = int(match.group("size"))
        elif match.group("duration"):
            duration_ms = float(match.group("duration")) * 1000.0
    return rcode, size, duration_ms


class AnalysisIn(BaseModel):
    client_ip: str = Field(..., examples=["10.50.0.102"])
    client_port: int = Field(default=0, examples=[58954])
    proto: str = Field(default="udp", examples=["udp"])
    query_type: str = Field(..., examples=["A"])
    query_name: str = Field(..., examples=["wikipedia.org."])
    query_class: str = Field(default="IN", examples=["IN"])
    rcode: str = Field(default="NOERROR", examples=["NOERROR"])
    response_size: int = Field(default=0, examples=[54])
    duration_ms: float = Field(default=0.0, examples=[38.5])
    dns_id: str = Field(default="", examples=["12345"])
    opcode: str = Field(default="", examples=["QUERY"])
    bufsize: str = Field(default="", examples=["1232"])
    do_flag: str = Field(default="", examples=["false"])
    raw_log: dict = Field(default_factory=dict)


class AnalysisOut(BaseModel):
    id: int
    score: float
    threshold: float
    safe: bool
    notification_sent: bool


class AnalysisRequest(BaseModel):
    client_ip: str | None = None
    query_type: str | None = None
    query_name: str | None = None
    rcode: str | None = None
    response_size: int | None = None
    duration_ms: float | None = None
    dns_address: str | None = None
    request: str | None = None
    response: str | None = None

    def to_analysis(self) -> AnalysisIn:
        client_ip = self.client_ip or self.dns_address or ""
        query_type = self.query_type or ""
        query_name = self.query_name or ""
        rcode = self.rcode
        response_size = self.response_size
        duration_ms = self.duration_ms

        if self.request:
            entry = parse_log_line(self.request)
            if entry is not None:
                query_type = query_type or get_type(entry)
                query_name = query_name or get_name(entry)
                client_ip = client_ip or entry.get("src_ip") or entry.get("remote")
            else:
                request_match = _REQUEST_RE.match(self.request.strip())
                if request_match:
                    query_type = query_type or request_match.group("qtype")
                    query_name = query_name or request_match.group("qname")

        if self.response:
            entry = parse_log_line(self.response)
            if entry is not None:
                rcode = rcode or entry.get("rcode") or entry.get("response_code")
                response_size = response_size if response_size is not None else _safe_int(entry.get("size"))
                duration_ms = duration_ms if duration_ms is not None else _parse_duration(entry.get("duration"))
            else:
                parsed = _parse_response(self.response)
                rcode = rcode or parsed[0]
                response_size = response_size if response_size is not None else parsed[1]
                duration_ms = duration_ms if duration_ms is not None else parsed[2]

        if not client_ip:
            raise ValueError("client_ip or dns_address is required")
        if not query_name:
            raise ValueError("query_name is required")

        return AnalysisIn(
            client_ip=client_ip,
            query_type=query_type or "A",
            query_name=query_name,
            rcode=rcode or "NOERROR",
            response_size=response_size or 0,
            duration_ms=duration_ms or 0.0,
        )


class BlocklistIn(BaseModel):
    query_name: str = Field(..., examples=["evil.example."])
    reason: str = Field(default="", examples=["Confirmed C2 endpoint"])


class BlocklistOut(BaseModel):
    id: int
    query_name: str
    added_at: str
    reason: str


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


def _record_dict(record: Analysis | dict) -> dict:
    if isinstance(record, dict):
        return record
    base = {
        "id": record.id,
        "created_at": record.created_at.isoformat(timespec="seconds"),
        "client_ip": record.client_ip,
        "client_port": record.client_port,
        "proto": record.proto,
        "query_type": record.query_type,
        "query_name": record.query_name,
        "query_class": record.query_class,
        "parent_domain": record.parent_domain,
        "subdomain_depth": record.subdomain_depth,
        "rcode": record.rcode,
        "response_size": record.response_size,
        "duration_ms": record.duration_ms,
        "dns_id": record.dns_id,
        "opcode": record.opcode,
        "bufsize": record.bufsize,
        "do_flag": record.do_flag,
        "raw_log": record.raw_log or {},
        "score": record.score,
        "threshold": record.threshold,
        "alerted": record.alerted,
    }
    for name in FEATURE_NAMES:
        base[name] = getattr(record, name, 0.0)
    return base


class Store:
    def __init__(self) -> None:
        self.records: list[dict] = []

    def add(
        self,
        data: AnalysisIn,
        score: float,
        threshold: float,
        alerted: bool,
        features: dict[str, float] | None = None,
    ) -> dict:
        record = {
            "id": len(self.records) + 1,
            "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "client_ip": data.client_ip,
            "client_port": data.client_port,
            "proto": data.proto,
            "query_type": data.query_type,
            "query_name": data.query_name,
            "query_class": data.query_class,
            "parent_domain": parent_domain(data.query_name),
            "subdomain_depth": subdomain_depth(data.query_name),
            "rcode": data.rcode,
            "response_size": data.response_size,
            "duration_ms": data.duration_ms,
            "dns_id": data.dns_id,
            "opcode": data.opcode,
            "bufsize": data.bufsize,
            "do_flag": data.do_flag,
            "raw_log": data.raw_log,
            "score": score,
            "threshold": threshold,
            "alerted": alerted,
        }
        features = features or {}
        for name in FEATURE_NAMES:
            record[name] = float(features.get(name, 0.0))
        self.records.append(record)
        return record

    def recent(self, limit: int = 50) -> list[dict]:
        return list(reversed(self.records[-limit:]))

    def query(
        self,
        limit: int = 50,
        offset: int = 0,
        query_type: str | None = None,
        alerted: bool | None = None,
        q: str | None = None,
    ) -> dict:
        rows = list(reversed(self.records))
        if query_type:
            rows = [r for r in rows if r["query_type"] == query_type]
        if alerted is not None:
            rows = [r for r in rows if r["alerted"] == alerted]
        if q:
            ql = q.lower()
            rows = [
                r for r in rows
                if ql in r["query_name"].lower() or ql in r["client_ip"].lower()
            ]
        total = len(rows)
        return {"total": total, "items": rows[offset:offset + limit]}

    def get(self, record_id: int) -> dict | None:
        for r in self.records:
            if r["id"] == record_id:
                return r
        return None

    def stats(self) -> dict:
        total = len(self.records)
        alerts = sum(1 for r in self.records if r["alerted"])
        scores = [r["score"] for r in self.records]
        return {
            "total": total,
            "alerts": alerts,
            "safe": total - alerts,
            "average_score": round(sum(scores) / total, 4) if total else 0.0,
            "max_score": round(max(scores), 4) if scores else 0.0,
        }

    def query_type_counts(self) -> list[dict]:
        counts: dict[str, int] = {}
        for r in self.records:
            counts[r["query_type"]] = counts.get(r["query_type"], 0) + 1
        return [
            {"query_type": qt, "count": cnt}
            for qt, cnt in sorted(counts.items(), key=lambda x: x[1], reverse=True)
        ]

    def top_suspicious(self, limit: int = 10) -> list[dict]:
        agg: dict[str, dict] = {}
        for r in self.records:
            if not r["alerted"]:
                continue
            name = r["query_name"]
            slot = agg.setdefault(name, {"query_name": name, "count": 0, "max_score": 0.0})
            slot["count"] += 1
            slot["max_score"] = max(slot["max_score"], r["score"])
        return sorted(agg.values(), key=lambda x: x["max_score"], reverse=True)[:limit]

    def hourly_counts(self, hours: int = 24) -> list[dict]:
        buckets: dict[str, dict] = {}
        for r in self.records:
            hour = r["created_at"][:13] + ":00:00"
            slot = buckets.setdefault(hour, {"hour": hour, "total": 0, "alerts": 0})
            slot["total"] += 1
            slot["alerts"] += 1 if r["alerted"] else 0
        return sorted(buckets.values(), key=lambda x: x["hour"])[-hours:]

    def client_distribution(self, limit: int = 10) -> list[dict]:
        counts: dict[str, int] = {}
        for r in self.records:
            counts[r["client_ip"]] = counts.get(r["client_ip"], 0) + 1
        return [
            {"client_ip": ip, "count": cnt}
            for ip, cnt in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        ]

    def parent_distribution(self, limit: int = 10) -> list[dict]:
        counts: dict[str, int] = {}
        for r in self.records:
            pd = r.get("parent_domain") or ""
            if not pd:
                continue
            counts[pd] = counts.get(pd, 0) + 1
        return [
            {"parent_domain": pd, "count": cnt}
            for pd, cnt in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        ]



class DbStore:
    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    def add(
        self,
        data: AnalysisIn,
        score: float,
        threshold: float,
        alerted: bool,
        features: dict[str, float] | None = None,
    ) -> dict:
        with self._session_factory() as db:
            features = features or {}
            kwargs = {name: float(features.get(name, 0.0)) for name in FEATURE_NAMES}
            kwargs.update(
                client_port=data.client_port,
                proto=data.proto,
                query_class=data.query_class,
                parent_domain=parent_domain(data.query_name),
                subdomain_depth=subdomain_depth(data.query_name),
                dns_id=data.dns_id,
                opcode=data.opcode,
                bufsize=data.bufsize,
                do_flag=data.do_flag,
                raw_log=data.raw_log,
            )
            record = Analysis(
                client_ip=data.client_ip,
                query_type=data.query_type,
                query_name=data.query_name,
                rcode=data.rcode,
                response_size=data.response_size,
                duration_ms=data.duration_ms,
                score=score,
                threshold=threshold,
                alerted=alerted,
                **kwargs,
            )
            db.add(record)
            db.commit()
            db.refresh(record)
            return _record_dict(record)

    def recent(self, limit: int = 50) -> list[dict]:
        with self._session_factory() as db:
            records = (
                db.query(Analysis)
                .order_by(Analysis.created_at.desc())
                .limit(limit)
                .all()
            )
            return [_record_dict(r) for r in records]

    def query(
        self,
        limit: int = 50,
        offset: int = 0,
        query_type: str | None = None,
        alerted: bool | None = None,
        q: str | None = None,
    ) -> dict:
        with self._session_factory() as db:
            base = db.query(Analysis)
            if query_type:
                base = base.filter(Analysis.query_type == query_type)
            if alerted is not None:
                base = base.filter(Analysis.alerted.is_(alerted))
            if q:
                like = f"%{q.lower()}%"
                base = base.filter(
                    (func.lower(Analysis.query_name).like(like))
                    | (func.lower(Analysis.client_ip).like(like))
                )
            total = base.with_entities(func.count(Analysis.id)).scalar() or 0
            rows = (
                base.order_by(Analysis.created_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            return {"total": int(total), "items": [_record_dict(r) for r in rows]}

    def get(self, record_id: int) -> dict | None:
        with self._session_factory() as db:
            r = db.query(Analysis).filter(Analysis.id == record_id).first()
            return _record_dict(r) if r else None

    def stats(self) -> dict:
        with self._session_factory() as db:
            total = db.query(func.count(Analysis.id)).scalar() or 0
            alerts = (
                db.query(func.count(Analysis.id))
                .filter(Analysis.alerted.is_(True))
                .scalar() or 0
            )
            avg_score = db.query(func.avg(Analysis.score)).scalar() or 0.0
            max_score = db.query(func.max(Analysis.score)).scalar() or 0.0
            return {
                "total": total,
                "alerts": alerts,
                "safe": total - alerts,
                "average_score": round(float(avg_score), 4),
                "max_score": round(float(max_score), 4),
            }

    def top_suspicious(self, limit: int = 10) -> list[dict]:
        with self._session_factory() as db:
            rows = (
                db.query(
                    Analysis.query_name,
                    func.count(Analysis.id).label("count"),
                    func.max(Analysis.score).label("max_score"),
                )
                .filter(Analysis.alerted.is_(True))
                .group_by(Analysis.query_name)
                .order_by(func.max(Analysis.score).desc())
                .limit(limit)
                .all()
            )
            return [
                {"query_name": r.query_name, "count": int(r.count), "max_score": round(float(r.max_score), 4)}
                for r in rows
            ]

    def hourly_counts(self, hours: int = 24) -> list[dict]:
        with self._session_factory() as db:
            bucket = func.date_trunc("hour", Analysis.created_at)
            rows = (
                db.query(
                    bucket.label("hour"),
                    func.count(Analysis.id).label("total"),
                    func.sum(case((Analysis.alerted.is_(True), 1), else_=0)).label("alerts"),
                )
                .group_by(bucket)
                .order_by(bucket.desc())
                .limit(hours)
                .all()
            )
            return [
                {
                    "hour": r.hour.isoformat(timespec="seconds") if r.hour else None,
                    "total": int(r.total),
                    "alerts": int(r.alerts or 0),
                }
                for r in reversed(rows)
            ]

    def client_distribution(self, limit: int = 10) -> list[dict]:
        with self._session_factory() as db:
            rows = (
                db.query(Analysis.client_ip, func.count(Analysis.id).label("count"))
                .group_by(Analysis.client_ip)
                .order_by(func.count(Analysis.id).desc())
                .limit(limit)
                .all()
            )
            return [{"client_ip": r.client_ip, "count": int(r.count)} for r in rows]

    def parent_distribution(self, limit: int = 10) -> list[dict]:
        with self._session_factory() as db:
            rows = (
                db.query(Analysis.parent_domain, func.count(Analysis.id).label("count"))
                .filter(Analysis.parent_domain != "")
                .group_by(Analysis.parent_domain)
                .order_by(func.count(Analysis.id).desc())
                .limit(limit)
                .all()
            )
            return [{"parent_domain": r.parent_domain, "count": int(r.count)} for r in rows]

    def query_type_counts(self) -> list[dict]:
        with self._session_factory() as db:
            rows = (
                db.query(Analysis.query_type, func.count(Analysis.id).label("count"))
                .group_by(Analysis.query_type)
                .order_by(func.count(Analysis.id).desc())
                .all()
            )
            return [{"query_type": r.query_type, "count": int(r.count)} for r in rows]

def random_score(_: AnalysisIn) -> float:
    return round(random.random(), 4)


random_score.__onnx__ = False


def make_onnx_scorer(model_path: str) -> Callable[[AnalysisIn], float]:
    import numpy as np
    import onnxruntime as ort

    from app.features import extract_features

    sess = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])
    in_name = sess.get_inputs()[0].name
    out_name = sess.get_outputs()[0].name

    def score(data: AnalysisIn) -> float:
        if not data.query_name:
            return 0.0
        features = extract_features(data.query_name)
        batch = np.array([features], dtype=np.float32)
        probs = sess.run([out_name], {in_name: batch})[0]
        return float(probs.flatten()[0])

    score.__onnx__ = True

    return score


def send_mattermost(config: Config, data: AnalysisIn, score: float) -> bool:
    if not config.mattermost_enabled:
        return False
    if not all([config.mattermost_url, config.mattermost_token, config.mattermost_channel_id]):
        return False

    message = (
        "### DNS security alert\n"
        f"- Query: `{data.query_type} {data.query_name}`\n"
        f"- Client IP: `{data.client_ip}`\n"
        f"- Risk score: `{score:.4f}` (threshold `{config.threshold:.4f}`)\n"
        f"- Response: `rcode={data.rcode} size={data.response_size} duration={data.duration_ms:.2f}ms`"
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
    store: Store | DbStore | None = None,
    model: Callable[[AnalysisIn], float] | None = None,
    notify: Callable[[Config, AnalysisIn, float], bool] = send_mattermost,
) -> FastAPI:
    config = config or load_config()
    app = FastAPI(title="DNS Security Analysis")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    db_url = os.getenv("DATABASE_URL", "")
    if store is None:
        if db_url:
            engine = make_engine(db_url)
            Base.metadata.create_all(bind=engine)
            store = DbStore(make_session_factory(engine))
        else:
            store = Store()

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

    # Log which model was selected
    try:
        is_onnx = getattr(model, "__onnx__", False)
        if is_onnx:
            logger.info("Using ONNX model from %s", os.getenv("MODEL_PATH", "model.onnx"))
        else:
            logger.info("Using fallback/random model (ONNX not used)")
    except Exception:
        logger.debug("Unable to determine model type for logging")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/analyze", response_model=AnalysisOut)
    def analyze(data: AnalysisRequest) -> AnalysisOut:
        logger.info("Received /analyze request: %s", data.dict())
        try:
            analysis = data.to_analysis()
        except ValueError as exc:
            logger.warning("Invalid analyze request: %s", exc)
            raise HTTPException(status_code=422, detail=str(exc))

        logger.debug("Normalized analysis input: %s", analysis.dict())
        features = compute_features(analysis.query_name)
        logger.debug("Computed features for %s: %s", analysis.query_name, features)

        model_is_onnx = getattr(model, "__onnx__", False)
        if store.is_blocked(analysis.query_name):
            logger.info("Query %s is blocklisted, forcing score=1.0", analysis.query_name)
            score = 1.0
        else:
            logger.debug("Scoring with model (onnx=%s) for %s", model_is_onnx, analysis.query_name)
            score = min(1.0, max(0.0, float(model(analysis))))

        alerted = score >= config.threshold
        notification_sent = notify(config, analysis, score) if alerted else False
        record = store.add(analysis, score, config.threshold, alerted, features)

        logger.info(
            "Analysis result: id=%s score=%.4f threshold=%.4f safe=%s onnx=%s notified=%s",
            record.get("id"),
            score,
            config.threshold,
            not alerted,
            model_is_onnx,
            notification_sent,
        )

        return AnalysisOut(
            id=record["id"],
            score=score,
            threshold=config.threshold,
            safe=not alerted,
            notification_sent=notification_sent,
        )

    @app.get("/analyses")
    def analyses(
        limit: int = 50,
        offset: int = 0,
        query_type: str | None = None,
        alerted: bool | None = None,
        q: str | None = None,
    ) -> dict:
        return store.query(limit=limit, offset=offset, query_type=query_type, alerted=alerted, q=q)

    @app.get("/analyses/{record_id}")
    def analysis_detail(record_id: int) -> dict:
        record = store.get(record_id)
        if record is None:
            raise HTTPException(status_code=404, detail="not found")
        return record

    @app.get("/stats")
    def stats() -> dict:
        s = store.stats()
        s["threshold"] = config.threshold
        return s

    @app.get("/stats/top")
    def stats_top(limit: int = 10) -> list[dict]:
        return store.top_suspicious(limit)

    @app.get("/stats/hourly")
    def stats_hourly(hours: int = 24) -> list[dict]:
        return store.hourly_counts(hours)

    @app.get("/stats/clients")
    def stats_clients(limit: int = 10) -> list[dict]:
        return store.client_distribution(limit)

    @app.get("/stats/parents")
    def stats_parents(limit: int = 10) -> list[dict]:
        return store.parent_distribution(limit)

    @app.get("/stats/types")
    def stats_types() -> list[dict]:
        return store.query_type_counts()

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard() -> str:
        return render_dashboard(store.stats(), store.recent(25), config.threshold)

    return app


def render_dashboard(stats: dict, records: list[dict], threshold: float) -> str:
    rows = "".join(
        f"<tr><td>{r['created_at']}</td>"
        f"<td>{html.escape(r['client_ip'])}</td>"
        f"<td>{html.escape(r['query_type'])} {html.escape(r['query_name'])}</td>"
        f"<td>{r['score']:.4f}</td>"
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
          <thead><tr><th>Time</th><th>Client</th><th>Query</th><th>Score</th><th>Status</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </main>
    </body>
    </html>
    """


app = create_app()

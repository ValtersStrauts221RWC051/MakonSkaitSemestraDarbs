import json
import logging
import os
import time

import docker
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [forwarder] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

CONTAINER = os.getenv("COREDNS_CONTAINER", "dns-security-coredns")
API_URL = os.getenv("API_URL", "http://api:8000/analyze")
RETRY_SLEEP = 2.0
POST_TIMEOUT = 2.0


def parse_duration_ms(raw) -> float:
    if not raw:
        return 0.0
    s = str(raw).strip().lower()
    try:
        if s.endswith("ms"):
            return float(s[:-2])
        if s.endswith("s"):
            return float(s[:-1]) * 1000.0
        return float(s) * 1000.0
    except ValueError:
        return 0.0


def to_payload(entry: dict) -> dict:
    try:
        size = int(entry.get("size", 0) or 0)
    except (TypeError, ValueError):
        size = 0
    try:
        port = int(entry.get("port", 0) or 0)
    except (TypeError, ValueError):
        port = 0
    return {
        "client_ip": entry.get("remote", ""),
        "client_port": port,
        "proto": entry.get("proto", "udp"),
        "query_type": entry.get("type", ""),
        "query_name": entry.get("name", ""),
        "query_class": entry.get("class", "IN"),
        "rcode": entry.get("rcode", "-"),
        "response_size": size,
        "duration_ms": parse_duration_ms(entry.get("duration", 0)),
        "dns_id": str(entry.get("id", "")),
        "opcode": str(entry.get("opcode", "")),
        "bufsize": str(entry.get("bufsize", "")),
        "do_flag": str(entry.get("do", "")),
        "raw_log": entry,
    }


def stream_once(client: docker.DockerClient) -> None:
    container = client.containers.get(CONTAINER)
    log.info("attached to container %s", CONTAINER)
    for raw in container.logs(stream=True, follow=True, tail=0):
        line = raw.decode("utf-8", errors="replace").strip()
        start = line.find("{")
        if start == -1:
            continue
        try:
            entry = json.loads(line[start:])
        except json.JSONDecodeError:
            continue

        payload = to_payload(entry)
        try:
            requests.post(API_URL, json=payload, timeout=POST_TIMEOUT)
        except requests.RequestException as exc:
            log.warning("POST %s failed: %s", API_URL, exc)


def main() -> None:
    client = docker.from_env()
    while True:
        try:
            stream_once(client)
        except docker.errors.NotFound:
            log.warning("container %s not found, retrying", CONTAINER)
        except Exception as exc:
            log.warning("stream error: %s", exc)
        time.sleep(RETRY_SLEEP)


if __name__ == "__main__":
    main()

from __future__ import annotations

import logging
import socket
from datetime import UTC, datetime

import requests

log = logging.getLogger(__name__)

GEOIP_URL = "http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp,query,status,message"
RESOLVE_TIMEOUT = 3.0
GEOIP_TIMEOUT = 5.0
WHOIS_TIMEOUT = 10.0


def resolve_ip(domain: str) -> str:
    bare = domain.rstrip(".")
    if not bare:
        return ""
    try:
        socket.setdefaulttimeout(RESOLVE_TIMEOUT)
        return socket.gethostbyname(bare)
    except (OSError, socket.gaierror) as exc:
        log.debug("resolve %s failed: %s", bare, exc)
        return ""
    finally:
        socket.setdefaulttimeout(None)


def geoip_lookup(ip: str) -> dict:
    if not ip:
        return {}
    try:
        r = requests.get(GEOIP_URL.format(ip=ip), timeout=GEOIP_TIMEOUT)
        data = r.json()
        if data.get("status") != "success":
            return {}
        return {
            "country": data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "city": data.get("city", ""),
            "isp": data.get("isp", ""),
        }
    except (requests.RequestException, ValueError) as exc:
        log.debug("geoip %s failed: %s", ip, exc)
        return {}


def whois_lookup(domain: str) -> dict:
    bare = domain.rstrip(".")
    if not bare:
        return {}
    try:
        import whois
        w = whois.whois(bare)
        country = (w.country or "") if isinstance(w.country, str) else ""
        registrar = (w.registrar or "") if isinstance(w.registrar, str) else ""
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0] if creation else None
        creation_str = creation.isoformat() if isinstance(creation, datetime) else ""
        return {
            "whois_country": country.upper() if country else "",
            "registrar": registrar,
            "creation_date": creation_str,
        }
    except Exception as exc:
        log.debug("whois %s failed: %s", bare, exc)
        return {}


def enrich(parent_domain: str) -> dict:
    bare = parent_domain.rstrip(".")
    if not bare:
        return {"error": "empty domain"}

    result: dict = {"parent_domain": parent_domain, "looked_up_at": datetime.now(UTC)}
    errors: list[str] = []

    ip = resolve_ip(bare)
    result["ip"] = ip
    if not ip:
        errors.append("resolve")

    if ip:
        geo = geoip_lookup(ip)
        result.update(geo)
        if not geo:
            errors.append("geoip")

    who = whois_lookup(bare)
    result.update(who)
    if not who:
        errors.append("whois")

    if errors:
        result["error"] = ",".join(errors)
    return result

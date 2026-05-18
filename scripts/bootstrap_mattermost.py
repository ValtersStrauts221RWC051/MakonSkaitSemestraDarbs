from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import requests


BASE = os.getenv("MATTERMOST_BOOTSTRAP_URL", "http://mattermost:8065").rstrip("/")
PUBLIC = os.getenv("MATTERMOST_PUBLIC_URL", "http://localhost:8065").rstrip("/")
ADMIN_EMAIL = os.getenv("MATTERMOST_ADMIN_EMAIL", "admin@example.com")
ADMIN_USER = os.getenv("MATTERMOST_ADMIN_USERNAME", "admin")
ADMIN_PASS = os.getenv("MATTERMOST_ADMIN_PASSWORD", "Password123!")
USER_EMAIL = os.getenv("MATTERMOST_TEST_USER_EMAIL", "user@example.com")
USER_NAME = os.getenv("MATTERMOST_TEST_USER_USERNAME", "test-user")
USER_PASS = os.getenv("MATTERMOST_TEST_USER_PASSWORD", "Password123!")
TEAM = os.getenv("MATTERMOST_TEAM_NAME", "dns-security")
CHANNEL = os.getenv("MATTERMOST_CHANNEL_NAME", "dns-security-alerts")
BOT = os.getenv("MATTERMOST_BOT_USERNAME", "dns-security-bot")
RUNTIME_ENV = Path(os.getenv("MATTERMOST_RUNTIME_ENV", "/runtime/mattermost.env"))


def main() -> None:
    wait_ready()
    create_user(ADMIN_EMAIL, ADMIN_USER, ADMIN_PASS)
    create_user(USER_EMAIL, USER_NAME, USER_PASS)
    admin_token = login()
    team = get_or_create_team(admin_token)
    channel = get_or_create_channel(admin_token, team["id"])
    bot_id, bot_token = get_or_create_bot_token(admin_token)
    user_id = get_user(admin_token, USER_NAME)["id"]
    add_member(admin_token, f"/api/v4/teams/{team['id']}/members", {"team_id": team["id"], "user_id": bot_id})
    add_member(admin_token, f"/api/v4/channels/{channel['id']}/members", {"user_id": bot_id})
    add_member(admin_token, f"/api/v4/teams/{team['id']}/members", {"team_id": team["id"], "user_id": user_id})
    add_member(admin_token, f"/api/v4/channels/{channel['id']}/members", {"user_id": user_id})
    write_env(bot_token, channel["id"])
    print("Mattermost bootstrap complete")
    print(f"Mattermost URL: {PUBLIC}")
    print(f"Admin login: {ADMIN_EMAIL} / {ADMIN_PASS}")
    print(f"Recipient login: {USER_EMAIL} / {USER_PASS}")
    print(f"Alert channel: {CHANNEL}")


def wait_ready() -> None:
    for _ in range(180):
        try:
            if requests.get(f"{BASE}/api/v4/system/ping", timeout=5).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    raise RuntimeError("Mattermost did not become ready")


def api(method: str, path: str, token: str | None = None, ok: tuple[int, ...] = (200,), **kwargs):
    headers = kwargs.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.request(method, f"{BASE}{path}", headers=headers, timeout=10, **kwargs)
    if response.status_code not in ok:
        raise RuntimeError(f"{method} {path} failed: {response.status_code} {response.text}")
    return response


def create_user(email: str, username: str, password: str) -> None:
    response = requests.post(
        f"{BASE}/api/v4/users",
        json={"email": email, "username": username, "password": password},
        timeout=10,
    )
    if response.status_code not in {200, 201, 400, 403}:
        response.raise_for_status()


def login() -> str:
    response = api(
        "POST",
        "/api/v4/users/login",
        ok=(200,),
        json={"login_id": ADMIN_EMAIL, "password": ADMIN_PASS},
    )
    token = response.headers.get("Token")
    if not token:
        raise RuntimeError("Mattermost login did not return a token")
    return token


def get_user(token: str, username: str) -> dict | None:
    response = requests.get(f"{BASE}/api/v4/users/username/{username}", headers=auth(token), timeout=10)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


def get_or_create_team(token: str) -> dict:
    response = requests.get(f"{BASE}/api/v4/teams/name/{TEAM}", headers=auth(token), timeout=10)
    if response.status_code == 200:
        return response.json()
    return api(
        "POST",
        "/api/v4/teams",
        token,
        ok=(201,),
        json={"name": TEAM, "display_name": "DNS Security", "type": "O"},
    ).json()


def get_or_create_channel(token: str, team_id: str) -> dict:
    response = requests.get(f"{BASE}/api/v4/teams/{team_id}/channels/name/{CHANNEL}", headers=auth(token), timeout=10)
    if response.status_code == 200:
        return response.json()
    return api(
        "POST",
        "/api/v4/channels",
        token,
        ok=(201,),
        json={"team_id": team_id, "name": CHANNEL, "display_name": "DNS Security Alerts", "type": "O"},
    ).json()


def get_or_create_bot_token(token: str) -> tuple[str, str]:
    bot = get_user(token, BOT)
    if not bot:
        bot = api(
            "POST",
            "/api/v4/bots",
            token,
            ok=(201,),
            json={"username": BOT, "display_name": "DNS Security Bot"},
        ).json()
    bot_id = bot.get("user_id") or bot["id"]
    access_token = api(
        "POST",
        f"/api/v4/users/{bot_id}/tokens",
        token,
        ok=(200, 201),
        json={"description": "DNS security local test token"},
    ).json()["token"]
    return bot_id, access_token


def add_member(token: str, path: str, body: dict) -> None:
    response = requests.post(f"{BASE}{path}", headers=auth(token), json=body, timeout=10)
    if response.status_code not in {200, 201, 400}:
        response.raise_for_status()


def write_env(bot_token: str, channel_id: str) -> None:
    RUNTIME_ENV.parent.mkdir(parents=True, exist_ok=True)
    RUNTIME_ENV.write_text(
        f"MATTERMOST_ENABLED=true\n"
        f"MATTERMOST_BASE_URL={BASE}\n"
        f"MATTERMOST_PUBLIC_URL={PUBLIC}\n"
        f"MATTERMOST_TOKEN={bot_token}\n"
        f"MATTERMOST_CHANNEL_ID={channel_id}\n"
    )
    RUNTIME_ENV.chmod(0o600)


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Mattermost bootstrap failed: {exc}", file=sys.stderr)
        sys.exit(1)

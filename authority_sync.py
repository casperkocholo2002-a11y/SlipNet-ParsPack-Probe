#!/usr/bin/env python3
import json
import os
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

XRAY = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
XRAY_API = os.environ.get("XRAY_API", "127.0.0.1:19182")
INBOUND_TAG = os.environ.get("XRAY_INBOUND_TAG", "shadow-vless")
INGRESS_CONFIG = Path(os.environ.get("XRAY_INGRESS_CONFIG", "/tmp/slipnet-shadow/ingress.json"))
AUTHORITY_URL = os.environ.get("AUTHORITY_URL", "").strip()
AUTHORITY_TOKEN = os.environ.get("AUTHORITY_TOKEN", "").strip()
POLL_S = max(2, int(os.environ.get("AUTHORITY_POLL_S", "5")))
ROOT = Path("/tmp/slipnet-shadow")
CACHE = ROOT / "authority-applied.json"
PREFERENCE = Path("/var/lib/slipnet-smart-egress/preference.json")

def bootstrap_users():
    try:
        data = json.loads(os.environ.get("SHADOW_USERS_JSON", "[]"))
    except Exception:
        return {}
    out = {}
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        uid = str(item.get("id") or "").strip().lower()
        email = str(item.get("email") or "").strip()
        if uid and email:
            name = email[6:] if email.startswith("v2ray-") else email
            out[name] = {"uuid": uid, "email": email}
    return out

def load_applied():
    try:
        data = json.loads(CACHE.read_text())
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return bootstrap_users()

def save_applied(data):
    ROOT.mkdir(parents=True, exist_ok=True)
    tmp = CACHE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n")
    os.replace(tmp, CACHE)

def request_snapshot():
    if not AUTHORITY_URL:
        return None
    req = urllib.request.Request(AUTHORITY_URL, headers={
        "accept": "application/json",
        "authorization": "Bearer " + AUTHORITY_TOKEN,
        "user-agent": "slipnet-no95-authority-sync/1",
    })
    with urllib.request.urlopen(req, timeout=4) as res:
        if res.status != 200:
            raise RuntimeError(f"authority status {res.status}")
        data = json.loads(res.read(2 * 1024 * 1024))
    if not isinstance(data, dict) or not isinstance(data.get("users"), list):
        raise RuntimeError("invalid authority snapshot")
    return data

def user_allowed(user, now):
    if not bool(user.get("enabled", True)):
        return False
    state = str(user.get("access_state") or "active").strip().lower()
    if state not in ("", "active"):
        return False
    expires = int(user.get("expires_at", 0) or 0)
    if expires and now >= expires:
        return False
    quota = int(user.get("quota_bytes", 0) or 0)
    used = int(user.get("used_bytes", 0) or 0)
    if quota and used >= quota:
        return False
    return True

def desired(snapshot):
    now = int(time.time())
    out = {}
    for user in snapshot.get("users") or []:
        if not isinstance(user, dict) or not user_allowed(user, now):
            continue
        name = str(user.get("name") or "").strip()
        uid = str(user.get("uuid") or "").strip().lower()
        if not name or not uid:
            continue
        out[name] = {"uuid": uid, "email": "v2ray-" + name}
    return out

def run(args, timeout=12):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    text = (p.stdout or "") + "\n" + (p.stderr or "")
    return p.returncode, text

def runtime_add(name, item):
    source = json.loads(INGRESS_CONFIG.read_text())
    inbound = None
    for candidate in source.get("inbounds") or []:
        if isinstance(candidate, dict) and candidate.get("tag") == INBOUND_TAG:
            inbound = json.loads(json.dumps(candidate))
            break
    if inbound is None:
        raise RuntimeError("runtime add source inbound not found: " + INBOUND_TAG)

    settings = inbound.setdefault("settings", {})
    settings["clients"] = [{"id": item["uuid"], "email": item["email"]}]

    fd, path = tempfile.mkstemp(prefix="no95-user-", suffix=".json", dir="/tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"inbounds": [inbound]}, f)
        rc, text = run([XRAY, "api", "adu", "--server=" + XRAY_API, path])
        if rc != 0 or "Added 1 user(s)" not in text:
            raise RuntimeError("runtime add failed: " + text[-1000:])
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

def runtime_remove(item):
    rc, text = run([
        XRAY, "api", "rmu",
        "--server=" + XRAY_API,
        "-tag=" + INBOUND_TAG,
        item["email"],
    ])
    if rc != 0:
        raise RuntimeError("runtime remove failed: " + text[-500:])

def apply_preference(snapshot):
    pref = snapshot.get("route_preference") or {}
    mode = str(pref.get("mode") or "auto").strip().lower()
    route = str(pref.get("preferred") or "").strip().lower()
    if mode != "manual" or route not in ("worker", "arvan", "parspack"):
        payload = {"mode": "auto", "preferred": None, "updated_at": int(time.time())}
    else:
        payload = {"mode": "manual", "preferred": route, "updated_at": int(time.time())}
    PREFERENCE.parent.mkdir(parents=True, exist_ok=True)
    tmp = PREFERENCE.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, separators=(",", ":")) + "\n")
    os.replace(tmp, PREFERENCE)

def reconcile(snapshot):
    current = load_applied()
    target = desired(snapshot)

    for name in sorted(set(current) - set(target)):
        runtime_remove(current[name])
        current.pop(name, None)
        save_applied(current)

    for name, item in target.items():
        old = current.get(name)
        if old == item:
            continue
        if old:
            runtime_remove(old)
        runtime_add(name, item)
        current[name] = item
        save_applied(current)

    apply_preference(snapshot)
    return len(current)

def main():
    if not AUTHORITY_URL:
        print("AUTHORITY_SYNC_DISABLED", flush=True)
        while True:
            time.sleep(3600)

    if not AUTHORITY_TOKEN:
        raise RuntimeError("AUTHORITY_TOKEN is required when AUTHORITY_URL is set")

    while True:
        try:
            snapshot = request_snapshot()
            count = reconcile(snapshot)
            print(f"AUTHORITY_SYNC_OK users={count}", flush=True)
        except Exception as exc:
            print(f"AUTHORITY_SYNC_WARN {type(exc).__name__}: {exc}", flush=True)
        time.sleep(POLL_S)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.request
import uuid
from collections import Counter
from pathlib import Path

XRAY = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
XRAY_API = os.environ.get("XRAY_API", "127.0.0.1:19182")
TELEMETRY_URL = os.environ.get("TELEMETRY_URL", "").strip()
TELEMETRY_TOKEN = os.environ.get("TELEMETRY_TOKEN", "").strip()
INGRESS_NAME = os.environ.get("INGRESS_NAME", "shadow").strip().lower()
REPORT_INTERVAL = max(2, int(os.environ.get("TELEMETRY_INTERVAL_S", "5")))
INSTANCE_ID = os.environ.get("TELEMETRY_INSTANCE_ID", "").strip() or (
    INGRESS_NAME + "-" + uuid.uuid4().hex
)
SELECTOR_STATE = Path("/run/slipnet-smart-egress/state.json")
ACCESS_LOG = Path("/tmp/slipnet-shadow/vless-access.log")

ACCESS_RE = re.compile(r"accepted\s+(?:tcp|udp):([^\s]+).*email:\s*(\S+)", re.I)
TS_RE = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
EMAIL_PREFIX = "v2ray-"
STAT_RE = re.compile(r"^user>>>v2ray-(.+)>>>traffic>>>(uplink|downlink)$", re.I)

def split_dest(dest):
    raw = str(dest or "").strip().lower()
    if raw.startswith("["):
        end = raw.find("]")
        host = raw[1:end] if end > 0 else raw
        port = raw[end + 2:] if end > 0 and len(raw) > end + 2 else ""
        return host, port
    if ":" in raw:
        return raw.rsplit(":", 1)
    return raw, ""

def classify(dest):
    host, port = split_dest(dest)
    if host in ("mqtt-gw.pushnotifs.com", "edge-mqtt.facebook.com", "mqtt-mini.facebook.com", "z-m-gateway.facebook.com"):
        return "Meta", True
    if (host.startswith("149.154.") or host.startswith("91.108.")) and port == "5222":
        return "Telegram", True
    background = (
        port in ("53", "853", "123")
        or "pool.ntp.org" in host
        or host in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1")
        or any(x in host for x in (
            "mqtt-gw.pushnotifs.com", "mtalk.google.com", "cloudflare-dns.com",
            "firebaseremoteconfig.googleapis.com", "androidwearcloudsync-pa.googleapis.com",
            "app-measurement.com", "sentry.io", "appsflyer", "datadome",
            "moengage", "statsig", "doubleclick.net", "googlesyndication.com",
            "crashlytics", "telemetry.", "metrics.", "edge-mqtt.facebook.com",
            "mqtt-mini.facebook.com", "monitor.cspf.shop", "monitor.reoos.ir",
            "www.google.com", "android.apis.google.com", "z-m-gateway.facebook.com",
            "supercell.zendesk.com", "cloud.aditude.io", "mobile-data.onetrust.io",
            "i1.sndcdn.com", "play.googleapis.com", "instantmessaging-pa.googleapis.com",
            "fitness.googleapis.com", "reminders-pa.googleapis.com", "connectivitycheck.gstatic.com",
            "android-context-data.googleapis.com", "findnms.samsungiotcloud.com",
            "sdk.pushmessage.samsung.com", "dc.dqa.samsung.com", "split.io",
        ))
    )
    if background:
        return "Background", True
    if "instagram" in host or "cdninstagram" in host:
        return "Instagram", False
    if "telegram" in host or host.startswith("149.154.") or host.startswith("91.108."):
        return "Telegram", False
    if "whatsapp" in host:
        return "WhatsApp", False
    if "youtube" in host or "googlevideo" in host or "ytimg" in host or "yt3.ggpht.com" in host:
        return "YouTube", False
    if "facebook.com" in host or "fbcdn" in host or host.startswith(("57.144.", "57.145.", "179.60.")):
        return "Meta", False
    if "soundcloud" in host or "sndcdn" in host:
        return "SoundCloud", False
    if "openai" in host or "chatgpt" in host:
        return "OpenAI", False
    if host == "x.com" or host.endswith(".x.com") or "twitter" in host or "twimg" in host:
        return "X", False
    if "duolingo" in host:
        return "Duolingo", False
    if "tiktok" in host:
        return "TikTok", False
    if "tradingview" in host:
        return "TradingView", False
    if "forexfactory" in host or "faireconomy.media" in host:
        return "ForexFactory", False
    if "speedtest" in host or "ooklaserver" in host:
        return "Speedtest", False
    if "weather.com" in host:
        return "Weather", False
    if "ipify.org" in host:
        return "Network", False
    if "iranlms" in host:
        return "IranLMS", False
    if "termius.com" in host:
        return "Termius", False
    if "playstation.net" in host:
        return "PlayStation", False
    if "microsoft" in host or "skype.com" in host or "appcenter.ms" in host or "aria.microsoft.com" in host:
        return "Microsoft", False
    if "adobe" in host or "adobedtm.com" in host:
        return "Adobe", False
    if "amazonaws.com" in host:
        return "AWS", False
    if "bixby" in host or "samsung" in host:
        return "Samsung", False
    if "google" in host or "gstatic" in host or "googleapis" in host or "gvt3.com" in host:
        return "Google", False
    if "cloudflare" in host:
        return "Cloudflare", False
    if any(x in host for x in ("ttdcdn.org", "ziffstatic.com", "cdnst.net")):
        return "Web/CDN", False
    if re.fullmatch(r"[0-9a-f:.]+", host):
        return "Unknown-IP", False
    if "." in host and port in ("80", "443", "8080", "8443"):
        return "Web/CDN", False
    return "Other", False

def run(args, timeout=10):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or "command failed")[-600:])
    return p.stdout or ""

def raw_stats():
    out = run([XRAY, "api", "statsquery", "--server=" + XRAY_API], timeout=8)
    data = json.loads(out or "{}")
    result = {}
    for item in data.get("stat", []):
        result[str(item.get("name") or "")] = int(item.get("value", 0) or 0)
    return result

def user_counters(stats):
    rows = {}
    for key, value in stats.items():
        m = STAT_RE.match(key)
        if not m:
            continue
        name = m.group(1)
        direction = m.group(2).lower()
        row = rows.setdefault(name, {"name": name, "raw_up": 0, "raw_down": 0})
        if direction == "uplink":
            row["raw_up"] = int(value)
        else:
            row["raw_down"] = int(value)
    return [rows[k] for k in sorted(rows)]

def selector_snapshot():
    try:
        raw = json.loads(SELECTOR_STATE.read_text())
    except Exception:
        raw = {}
    return {
        "policy": raw.get("policy"),
        "priority": raw.get("priority") or ["worker", "arvan", "parspack"],
        "effective_priority": raw.get("effective_priority") or raw.get("priority") or ["worker", "arvan", "parspack"],
        "preference_mode": raw.get("preference_mode") or "auto",
        "preferred": raw.get("preferred"),
        "selected": raw.get("selected"),
        "switch_reason": raw.get("switch_reason"),
        "selected_for_s": raw.get("selected_for_s"),
        "routes": raw.get("routes") or {},
    }

def read_activity(offset):
    try:
        size = ACCESS_LOG.stat().st_size
    except FileNotFoundError:
        return offset, []
    if size < offset:
        offset = 0
    with ACCESS_LOG.open("rb") as f:
        f.seek(offset)
        data = f.read()
        new_offset = f.tell()

    buckets = Counter()
    now = time.time()
    for raw in data.decode("utf-8", "ignore").splitlines():
        m = ACCESS_RE.search(raw)
        if not m:
            continue
        email = str(m.group(2) or "").strip().lower()
        if not email.startswith(EMAIL_PREFIX):
            continue
        ts = now
        tm = TS_RE.search(raw)
        if tm:
            try:
                ts = time.mktime(time.strptime(tm.group(1), "%Y/%m/%d %H:%M:%S"))
            except Exception:
                ts = now
        name = email[len(EMAIL_PREFIX):]
        category, background = classify(m.group(1))
        bucket = int(ts // 600) * 600
        buckets[(name, bucket, category, bool(background))] += 1

    events = [
        {
            "name": name,
            "bucket": bucket,
            "category": category,
            "background": background,
            "count": count,
        }
        for (name, bucket, category, background), count in sorted(buckets.items())
    ]
    return new_offset, events

def make_payload(sequence, activity_offset):
    stats = raw_stats()
    new_offset, events = read_activity(activity_offset)
    payload = {
        "version": 1,
        "ingress": INGRESS_NAME,
        "instance_id": INSTANCE_ID,
        "sequence": sequence,
        "ts": int(time.time()),
        "selector": selector_snapshot(),
        "users": user_counters(stats),
        "activity": events,
    }
    return payload, new_offset

def post(payload):
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    req = urllib.request.Request(
        TELEMETRY_URL,
        method="POST",
        data=body,
        headers={
            "content-type": "application/json",
            "authorization": "Bearer " + TELEMETRY_TOKEN,
            "user-agent": "slipnet-no95-telemetry/1",
        },
    )
    with urllib.request.urlopen(req, timeout=5) as res:
        if res.status != 200:
            raise RuntimeError(f"telemetry status {res.status}")
        data = json.loads(res.read(1024 * 1024) or b"{}")
    if not bool(data.get("success", True)):
        raise RuntimeError("telemetry rejected")

def main():
    if not TELEMETRY_URL:
        print("TELEMETRY_REPORTER_DISABLED", flush=True)
        while True:
            time.sleep(3600)
    if not TELEMETRY_TOKEN:
        raise RuntimeError("TELEMETRY_TOKEN is required when TELEMETRY_URL is set")
    if INGRESS_NAME not in ("arvan", "parspack", "shadow"):
        raise RuntimeError("invalid INGRESS_NAME")

    sequence = 1
    activity_offset = 0
    pending = None

    while True:
        try:
            if pending is None:
                payload, next_offset = make_payload(sequence, activity_offset)
                pending = (payload, next_offset)
            payload, next_offset = pending
            post(payload)
            activity_offset = next_offset
            print(
                f"TELEMETRY_REPORT_OK seq={payload['sequence']} users={len(payload['users'])} activity={len(payload['activity'])}",
                flush=True,
            )
            sequence += 1
            pending = None
            time.sleep(REPORT_INTERVAL)
        except Exception as exc:
            print(f"TELEMETRY_REPORT_WARN {type(exc).__name__}: {exc}", flush=True)
            time.sleep(min(REPORT_INTERVAL, 3))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/tmp/slipnet-shadow")
XRAY = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
APP = Path("/app")
children = []
stopping = False

def env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and (value is None or str(value).strip() == ""):
        raise RuntimeError(f"missing required environment: {name}")
    return str(value) if value is not None else ""

def load_users():
    raw = env("SHADOW_USERS_JSON", "[]")
    data = json.loads(raw)
    if not isinstance(data, list):
        raise RuntimeError("SHADOW_USERS_JSON must be a JSON list")
    out = []
    for item in data:
        if not isinstance(item, dict):
            raise RuntimeError("invalid user entry")
        uid = str(item.get("id") or "").strip()
        email = str(item.get("email") or "").strip()
        if not uid or not email:
            raise RuntimeError("user entry requires id and email")
        out.append({"id": uid, "email": email})
    return out

def write_json(name, value):
    p = ROOT / name
    p.write_text(json.dumps(value, indent=2) + "\n")
    return str(p)

def worker_config():
    address = env("WORKER_ADDRESS", "185.143.234.132")
    server_name = env("WORKER_SERVER_NAME", "new.casperkocholo2002-ichd0.arvanedge.ir")
    uid = env("WORKER_VLESS_UUID", required=True)
    path = env("WORKER_XHTTP_PATH", required=True)
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-worker",
            "listen": "127.0.0.1",
            "port": 19085,
            "protocol": "socks",
            "settings": {"udp": True},
        }],
        "outbounds": [{
            "tag": "vless-xhttp-worker",
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": address,
                "port": 443,
                "users": [{"id": uid, "encryption": "none"}],
            }]},
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {"serverName": server_name, "alpn": ["h2"]},
                "xhttpSettings": {
                    "host": server_name,
                    "path": path,
                    "mode": "packet-up",
                    "extra": {
                        "scMaxEachPostBytes": 65536,
                        "scMinPostsIntervalMs": 5,
                        "xmux": {
                            "maxConnections": 2,
                            "hMaxRequestTimes": "800-1200",
                            "hMaxReusableSecs": "300-600",
                        },
                    },
                },
            },
        }],
    }

def provider_config():
    arvan_host = env("ARVAN_DIRECT_HOST", "relaytest-fc2e226493-test.apps.ir-central1.arvancaas.ir")
    arvan_address = env("ARVAN_DIRECT_ADDRESS", arvan_host)
    pars_host = env("PARSPACK_DIRECT_HOST", "app-docker-container-ki5n1.apps.teh11.abrhapaas.com")
    pars_address = env("PARSPACK_DIRECT_ADDRESS", "176.97.218.51")
    arvan_uuid = env("ARVAN_DIRECT_UUID", required=True)
    pars_uuid = env("PARSPACK_DIRECT_UUID", required=True)
    return {
        "log": {"access": "none", "loglevel": "error", "dnsLog": False},
        "inbounds": [
            {"tag": "socks-arvan", "listen": "127.0.0.1", "port": 19186, "protocol": "socks", "settings": {"udp": False}},
            {"tag": "socks-parspack", "listen": "127.0.0.1", "port": 19187, "protocol": "socks", "settings": {"udp": False}},
        ],
        "outbounds": [
            {
                "tag": "to-arvan",
                "protocol": "vless",
                "settings": {"vnext": [{"address": arvan_address, "port": 443, "users": [{"id": arvan_uuid, "encryption": "none"}]}]},
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {"serverName": arvan_host, "allowInsecure": False, "alpn": ["http/1.1"], "fingerprint": "chrome"},
                    "wsSettings": {"path": "/direct", "headers": {"Host": arvan_host}},
                },
            },
            {
                "tag": "to-parspack",
                "protocol": "vless",
                "settings": {"vnext": [{"address": pars_address, "port": 443, "users": [{"id": pars_uuid, "encryption": "none"}]}]},
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {"serverName": pars_host, "allowInsecure": False, "alpn": ["http/1.1"], "fingerprint": "chrome"},
                    "wsSettings": {"path": "/direct", "headers": {"Host": pars_host}},
                },
            },
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["socks-arvan"], "outboundTag": "to-arvan"},
                {"type": "field", "inboundTag": ["socks-parspack"], "outboundTag": "to-parspack"},
            ],
        },
    }

def ingress_config():
    return {
        "log": {"access": str(ROOT / "vless-access.log"), "loglevel": "error", "dnsLog": False},
        "inbounds": [
            {
                "tag": "shadow-vless",
                "listen": "127.0.0.1",
                "port": 19443,
                "protocol": "vless",
                "settings": {"clients": load_users(), "decryption": "none"},
            },
            {
                "tag": "api",
                "listen": "127.0.0.1",
                "port": 19182,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
            },
        ],
        "outbounds": [
            {"tag": "to-selector", "protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": 19190}]}},
            {"tag": "api", "protocol": "freedom"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {"type": "field", "inboundTag": ["shadow-vless"], "outboundTag": "to-selector"},
            ],
        },
        "stats": {},
        "api": {"tag": "api", "services": ["HandlerService", "StatsService"]},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
    }

def validate_xray(path):
    p = subprocess.run([XRAY, "run", "-test", "-config", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
    if p.returncode != 0:
        raise RuntimeError("xray config validation failed: " + (p.stdout or "")[-1200:])

def start(name, args, extra_env=None):
    child_env = os.environ.copy()
    if extra_env:
        child_env.update(extra_env)
    p = subprocess.Popen(args, env=child_env)
    children.append((name, p))
    return p

def wait_port(port, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.15)
    raise RuntimeError(f"local port {port} did not become ready")

def stop_all():
    global stopping
    if stopping:
        return
    stopping = True
    for _, p in reversed(children):
        if p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and any(p.poll() is None for _, p in children):
        time.sleep(0.1)
    for _, p in reversed(children):
        if p.poll() is None:
            try:
                p.kill()
            except Exception:
                pass

def on_signal(_sig, _frame):
    stop_all()

def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    worker = write_json("worker.json", worker_config())
    provider = write_json("provider.json", provider_config())
    ingress = write_json("ingress.json", ingress_config())
    for cfg in (worker, provider, ingress):
        validate_xray(cfg)

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    start("worker-xray", [XRAY, "run", "-config", worker])
    start("provider-xray", [XRAY, "run", "-config", provider])
    wait_port(19085)
    wait_port(19186)
    wait_port(19187)

    start("smart-egress", ["python3", str(APP / "smart_egress.py")])
    wait_port(19190)

    start("ingress-xray", [XRAY, "run", "-config", ingress])
    wait_port(19443)

    if env("AUTHORITY_URL", "").strip():
        start("authority-sync", ["python3", str(APP / "authority_sync.py")])
        time.sleep(0.5)

    node_env = {
        "LOCAL_VLESS_ORIGIN": "1",
        "LOCAL_VLESS_HOST": "127.0.0.1",
        "LOCAL_VLESS_PORT": "19443",
    }
    start("front", ["node", str(APP / "server.js")], node_env)

    print("NO95_SHADOW_READY", flush=True)
    while not stopping:
        for name, p in children:
            rc = p.poll()
            if rc is not None:
                raise RuntimeError(f"critical child exited: {name} rc={rc}")
        time.sleep(0.5)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print(f"NO95_SHADOW_FATAL {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        stop_all()
        sys.exit(1)
    finally:
        stop_all()

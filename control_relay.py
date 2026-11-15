#!/usr/bin/env python3
import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = int(os.environ.get("CONTROL_RELAY_PORT", "19184"))
SOCKS = os.environ.get("CONTROL_SOCKS", "127.0.0.1:19190").strip()
MAX_BODY = 262144

ROUTES = {
    "/authority": {
        "method": "GET",
        "url": os.environ.get("AUTHORITY_REMOTE_URL", "").strip(),
    },
    "/telemetry": {
        "method": "POST",
        "url": os.environ.get("TELEMETRY_REMOTE_URL", "").strip(),
    },
    "/session": {
        "method": "POST",
        "url": os.environ.get("SESSION_REMOTE_URL", "").strip(),
    },
}

def _safe_remote(url):
    try:
        u = urlparse(url)
    except Exception:
        return False
    return u.scheme in ("http", "https") and bool(u.hostname) and not u.username and not u.password

def _curl(method, url, body, authorization):
    args = [
        "curl", "-sS",
        "--connect-timeout", "4",
        "--max-time", "10",
        "--socks5-hostname", SOCKS,
        "-X", method,
        "-H", "Accept: application/json",
        "-H", "Content-Type: application/json",
    ]
    if authorization:
        args.extend(["-H", "Authorization: " + authorization])
    if method == "POST":
        args.extend(["--data-binary", "@-"])
    args.extend(["-w", "\n%{http_code}", url])

    p = subprocess.run(
        args,
        input=body if method == "POST" else None,
        capture_output=True,
        timeout=12,
    )
    raw = p.stdout or b""
    if b"\n" not in raw:
        error = (p.stderr or b"").decode("utf-8", "replace")[-300:]
        raise RuntimeError(error or "upstream response missing status")
    response_body, status_raw = raw.rsplit(b"\n", 1)
    try:
        status = int(status_raw.strip() or b"0")
    except Exception:
        status = 0
    if status < 100 or status > 599:
        error = (p.stderr or b"").decode("utf-8", "replace")[-300:]
        raise RuntimeError(error or "invalid upstream status")
    return status, response_body

class Handler(BaseHTTPRequestHandler):
    server_version = "SlipNetControlRelay/1"

    def log_message(self, *_args):
        pass

    def _json(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _proxy(self, method):
        route = ROUTES.get(self.path)
        if not route or route["method"] != method:
            self._json(404, {"success": False, "error": "not_found"})
            return
        url = route["url"]
        if not _safe_remote(url):
            self._json(503, {"success": False, "error": "upstream_not_configured"})
            return

        body = b""
        if method == "POST":
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except Exception:
                length = 0
            if length < 1 or length > MAX_BODY:
                self._json(400, {"success": False, "error": "invalid_body_size"})
                return
            body = self.rfile.read(length)

        try:
            status, response = _curl(
                method,
                url,
                body,
                self.headers.get("Authorization", ""),
            )
        except Exception:
            self._json(502, {"success": False, "error": "upstream_unavailable"})
            return

        if len(response) > 2 * 1024 * 1024:
            self._json(502, {"success": False, "error": "upstream_response_too_large"})
            return
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {
                "ok": True,
                "socks": SOCKS,
                "authority": bool(ROUTES["/authority"]["url"]),
                "telemetry": bool(ROUTES["/telemetry"]["url"]),
                "session": bool(ROUTES["/session"]["url"]),
            })
            return
        self._proxy("GET")

    def do_POST(self):
        self._proxy("POST")

def main():
    for route in ROUTES.values():
        if route["url"] and not _safe_remote(route["url"]):
            raise RuntimeError("invalid configured control relay upstream")
    ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler).serve_forever()

if __name__ == "__main__":
    main()

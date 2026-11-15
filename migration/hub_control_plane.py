#!/usr/bin/env python3
import json
import os
import re
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path

from .hub_telemetry_aggregator import TelemetryAggregator

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
ROUTES = ("worker", "arvan", "parspack")

PARSPACK_HOST = "app-docker-container-ki5n1.apps.teh11.abrhapaas.com"
ARVAN_HOST = "relaytest-fc2e226493-test.apps.ir-central1.arvancaas.ir"

def _default_authority():
    return {
        "version": 1,
        "seeded": False,
        "users": {},
        "route_preference": {
            "mode": "auto",
            "preferred": None,
            "updated_at": 0,
        },
    }

class HubControlPlane:
    def __init__(self, authority_path, telemetry_path):
        self.authority_path = Path(authority_path)
        self.authority = self._load_authority()
        self.telemetry = TelemetryAggregator(telemetry_path)

    def _load_authority(self):
        try:
            data = json.loads(self.authority_path.read_text())
            if isinstance(data, dict) and int(data.get("version", 0) or 0) == 1:
                data.setdefault("users", {})
                data.setdefault("route_preference", {"mode": "auto", "preferred": None, "updated_at": 0})
                return data
        except Exception:
            pass
        return _default_authority()

    def _save_authority(self):
        self.authority_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix="." + self.authority_path.name + ".", dir=str(self.authority_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.authority, f, ensure_ascii=False, separators=(",", ":"))
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.authority_path)
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass

    @staticmethod
    def validate_name(name):
        name = str(name or "").strip()
        if not NAME_RE.fullmatch(name):
            raise ValueError("Name must be 1-32 chars: letters, numbers, _, . or -")
        return name

    def seed_from_legacy(self, agent_db, legacy_snapshot):
        if self.authority.get("seeded"):
            return {"seeded": False, "reason": "already_seeded"}

        source = (agent_db or {}).get("users")
        if not isinstance(source, dict):
            raise ValueError("legacy agent users missing")

        users = {}
        for name, row in source.items():
            name = self.validate_name(name)
            if not isinstance(row, dict):
                raise ValueError("invalid legacy user row")
            raw_uuid = str(row.get("uuid") or "").strip().lower()
            try:
                uuid.UUID(raw_uuid)
            except Exception:
                raise ValueError("invalid legacy UUID for " + name)
            users[name] = {
                "uuid": raw_uuid,
                "created_at": int(row.get("created_at", 0) or 0),
                "expires_at": int(row.get("expires_at", 0) or 0),
                "quota_bytes": max(0, int(row.get("quota_bytes", 0) or 0)),
                "enabled": bool(row.get("enabled", True)),
            }

        snapshot = legacy_snapshot if isinstance(legacy_snapshot, dict) else {}
        mode = str(snapshot.get("preference_mode") or "auto").strip().lower()
        preferred = str(snapshot.get("preferred") or "").strip().lower() or None
        if mode != "manual" or preferred not in ROUTES:
            mode, preferred = "auto", None

        self.authority["users"] = users
        self.authority["route_preference"] = {
            "mode": mode,
            "preferred": preferred,
            "updated_at": int(time.time()),
        }
        self.authority["seeded"] = True
        self.authority["seeded_at"] = int(time.time())
        self._save_authority()
        self.telemetry.seed_from_legacy_snapshot(snapshot)
        return {"seeded": True, "users": len(users)}

    def _usage(self, name):
        return max(0, int((self.telemetry.state.get("usage") or {}).get(name, 0) or 0))

    def _access_reason(self, user, now=None):
        now = int(now or time.time())
        if not bool(user.get("enabled", True)):
            return "manual"
        expires = int(user.get("expires_at", 0) or 0)
        quota = int(user.get("quota_bytes", 0) or 0)
        if expires and now >= expires:
            return "expired"
        if quota and self._usage(user["name"]) >= quota:
            return "quota"
        return None

    def _authority_user(self, name):
        row = (self.authority.get("users") or {}).get(name)
        if not row:
            raise ValueError("User not found")
        out = dict(row)
        out["name"] = name
        out["access_state"] = self._access_reason(out) or "active"
        out["used_bytes"] = self._usage(name)
        return out

    @staticmethod
    def _route_links(name, user_uuid):
        q_pp = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": PARSPACK_HOST,
            "path": "/tunnel",
            "sni": PARSPACK_HOST,
            "alpn": "http/1.1",
            "fp": "chrome",
        }
        q_ar = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": ARVAN_HOST,
            "path": "/tunnel",
            "sni": ARVAN_HOST,
            "alpn": "http/1.1",
            "fp": "chrome",
        }

        def link(host, q, label):
            return (
                f"vless://{user_uuid}@{host}:443?"
                + urllib.parse.urlencode(q, quote_via=urllib.parse.quote)
                + "#"
                + urllib.parse.quote(f"SlipNet V2Ray - {name} - {label}")
            )

        links = {
            "parspack": link(PARSPACK_HOST, q_pp, "ParsPack"),
            "arvan": link(ARVAN_HOST, q_ar, "Arvan"),
        }
        return links, "\n".join(links.values()) + "\n"

    def _public_user(self, name):
        return self.telemetry.user_public(self._authority_user(name))

    def desired_snapshot(self):
        users = []
        for name in sorted((self.authority.get("users") or {})):
            row = self._authority_user(name)
            users.append({
                "name": name,
                "uuid": row["uuid"],
                "enabled": bool(row.get("enabled", True)),
                "access_state": row["access_state"],
                "quota_bytes": int(row.get("quota_bytes", 0) or 0),
                "used_bytes": int(row.get("used_bytes", 0) or 0),
                "created_at": int(row.get("created_at", 0) or 0),
                "expires_at": int(row.get("expires_at", 0) or 0),
            })
        return {
            "version": 1,
            "generated_at": int(time.time()),
            "users": users,
            "route_preference": dict(self.authority.get("route_preference") or {}),
        }

    def dashboard_snapshot(self):
        route = self.telemetry.route_snapshot()
        users = [self._public_user(name) for name in sorted((self.authority.get("users") or {}))]
        return {
            "node": "no95-fabric",
            "ts": int(time.time()),
            "policy": route["policy"],
            "priority": route["priority"],
            "effective_priority": route["effective_priority"],
            "preference_mode": route["preference_mode"],
            "preferred": route["preferred"],
            "selected": route["selected"],
            "switch_reason": route["switch_reason"],
            "selected_for_s": route["selected_for_s"],
            "routes": route["routes"],
            "users": users,
        }

    def execute(self, op, args=None):
        args = args or {}
        op = str(op or "").strip().lower()
        if op == "add":
            return self._cmd_add(args)
        if op == "delete":
            return self._cmd_delete(args)
        if op == "limits":
            return self._cmd_limits(args)
        if op == "reset_usage":
            return self._cmd_reset_usage(args)
        if op == "config":
            return self._cmd_config(args)
        if op == "disable":
            return self._cmd_disable(args)
        if op == "enable":
            return self._cmd_enable(args)
        if op == "route_preference":
            return self._cmd_route_preference(args)
        raise ValueError("Unsupported operation")

    def _cmd_add(self, args):
        name = self.validate_name(args.get("name"))
        days = int(args.get("duration_days", 30) or 0)
        quota = int(args.get("quota_bytes", 0) or 0)
        if days < 0 or days > 3650:
            raise ValueError("duration_days must be 0..3650")
        if quota < 0:
            raise ValueError("quota_bytes cannot be negative")
        users = self.authority.setdefault("users", {})
        if name in users:
            raise ValueError("User already exists")
        created = int(time.time())
        raw_uuid = str(uuid.uuid4())
        users[name] = {
            "uuid": raw_uuid,
            "created_at": created,
            "expires_at": created + days * 86400 if days else 0,
            "quota_bytes": quota,
            "enabled": True,
        }
        self._save_authority()
        links, bundle = self._route_links(name, raw_uuid)
        return {"user": self._public_user(name), "links": links, "bundle": bundle}

    def _cmd_delete(self, args):
        name = self.validate_name(args.get("name"))
        users = self.authority.setdefault("users", {})
        if name not in users:
            raise ValueError("User not found")
        users.pop(name, None)
        self._save_authority()
        return {"name": name, "deleted": True}

    def _cmd_limits(self, args):
        name = self.validate_name(args.get("name"))
        users = self.authority.setdefault("users", {})
        user = users.get(name)
        if not user:
            raise ValueError("User not found")
        if "duration_days" in args and args.get("duration_days") is not None:
            days = int(args.get("duration_days") or 0)
            if days < 0 or days > 3650:
                raise ValueError("duration_days must be 0..3650")
            user["expires_at"] = int(time.time()) + days * 86400 if days else 0
        if "quota_bytes" in args and args.get("quota_bytes") is not None:
            quota = int(args.get("quota_bytes") or 0)
            if quota < 0:
                raise ValueError("quota_bytes cannot be negative")
            user["quota_bytes"] = quota
        self._save_authority()
        return {"user": self._public_user(name)}

    def _cmd_reset_usage(self, args):
        name = self.validate_name(args.get("name"))
        if name not in (self.authority.get("users") or {}):
            raise ValueError("User not found")
        self.telemetry.reset_usage(name)
        return {"user": self._public_user(name)}

    def _cmd_config(self, args):
        name = self.validate_name(args.get("name"))
        user = (self.authority.get("users") or {}).get(name)
        if not user:
            raise ValueError("User not found")
        links, bundle = self._route_links(name, user["uuid"])
        return {"name": name, "links": links, "bundle": bundle}

    def _cmd_disable(self, args):
        name = self.validate_name(args.get("name"))
        user = (self.authority.get("users") or {}).get(name)
        if not user:
            raise ValueError("User not found")
        user["enabled"] = False
        self._save_authority()
        return {"user": self._public_user(name)}

    def _cmd_enable(self, args):
        name = self.validate_name(args.get("name"))
        user = (self.authority.get("users") or {}).get(name)
        if not user:
            raise ValueError("User not found")
        user["enabled"] = True
        self._save_authority()
        return {"user": self._public_user(name)}

    def _cmd_route_preference(self, args):
        route = str(args.get("route") or "").strip().lower()
        if route not in {"auto", "worker", "arvan", "parspack"}:
            raise ValueError("route must be auto, worker, arvan or parspack")
        payload = {
            "mode": "auto" if route == "auto" else "manual",
            "preferred": None if route == "auto" else route,
            "updated_at": int(time.time()),
        }
        self.authority["route_preference"] = payload
        self._save_authority()
        selected = self.telemetry.route_snapshot().get("selected")
        return {
            "route": route,
            "mode": payload["mode"],
            "preferred": payload["preferred"],
            "selected": selected,
            "reflected": True,
        }

#!/usr/bin/env python3
import json
import os
import tempfile
import time
import uuid
from pathlib import Path

from .hub_control_plane import HubControlPlane

class HubCompatAdapter:
    def __init__(self, authority_path, telemetry_path, commands_path, alerts_path, legacy_state_path=None):
        self.control = HubControlPlane(authority_path, telemetry_path)
        self.commands_path = Path(commands_path)
        self.alerts_path = Path(alerts_path)
        self.legacy_state_path = Path(legacy_state_path) if legacy_state_path else None

    @staticmethod
    def _atomic_json(path, value):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(value, f, ensure_ascii=False, separators=(",", ":"))
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass

    @staticmethod
    def _load(path, default):
        try:
            data = json.loads(Path(path).read_text())
            return data if isinstance(data, dict) else default
        except Exception:
            return default

    def seed_from_legacy(self, agent_db, legacy_snapshot):
        result = self.control.seed_from_legacy(agent_db, legacy_snapshot)
        self._ensure_identity_records()
        return result

    def desired_snapshot(self):
        return self.control.desired_snapshot()

    def ingest_telemetry(self, payload, mirror=False):
        result = self.control.telemetry.ingest(payload)
        if mirror:
            self.mirror_legacy_state()
        return result

    def _identity_records(self):
        now = int(time.time())
        records = []
        for user in self.control.desired_snapshot().get("users") or []:
            name = str(user.get("name") or "")
            raw_uuid = str(user.get("uuid") or "")
            links, bundle = self.control._route_links(name, raw_uuid)
            records.append({
                "id": "no95-identity-" + name,
                "op": "_identity",
                "args": {"name": name},
                "status": "done",
                "created_at": now,
                "completed_at": now,
                "last_delivery": 0,
                "deliveries": 0,
                "result": {"name": name, "links": links, "bundle": bundle},
                "error": None,
            })
        return records

    def _ensure_identity_records(self, doc=None):
        if doc is None:
            doc = self._load(self.commands_path, {"version": 1, "commands": []})
        existing = [
            row for row in (doc.get("commands") or [])
            if not str((row or {}).get("id") or "").startswith("no95-identity-")
        ]
        identities = self._identity_records()
        keep = max(0, 500 - len(identities))
        doc["commands"] = existing[-keep:] + identities if keep else identities[-500:]
        self._atomic_json(self.commands_path, doc)
        return doc

    def mirror_legacy_state(self):
        if self.legacy_state_path is None:
            return
        snap = self.control.dashboard_snapshot()
        snap["received_at"] = int(time.time())
        self._atomic_json(self.legacy_state_path, {"version": 1, "snapshot": snap})

    def enqueue(self, op, args):
        now = int(time.time())
        cmd = {
            "id": uuid.uuid4().hex,
            "op": str(op or ""),
            "args": args if isinstance(args, dict) else {},
            "status": "pending",
            "created_at": now,
            "last_delivery": 0,
            "deliveries": 0,
            "result": None,
            "error": None,
        }

        try:
            result = self.control.execute(cmd["op"], cmd["args"])
            cmd["status"] = "done"
            cmd["completed_at"] = int(time.time())
            cmd["result"] = result
        except Exception as exc:
            cmd["status"] = "failed"
            cmd["completed_at"] = int(time.time())
            cmd["error"] = str(exc)[:1000]

        doc = self._load(self.commands_path, {"version": 1, "commands": []})
        commands = doc.setdefault("commands", [])
        commands.append(cmd)
        doc["commands"] = commands
        self._ensure_identity_records(doc)
        self.mirror_legacy_state()

        return {
            "success": True,
            "command_id": cmd["id"],
            "status": "pending",
        }

    def get_command(self, command_id):
        doc = self._load(self.commands_path, {"version": 1, "commands": []})
        for cmd in doc.get("commands") or []:
            if str(cmd.get("id") or "") == str(command_id or ""):
                return {"success": True, "command": cmd}
        return {"success": False, "error": "Command not found"}

    def _alerts(self):
        doc = self._load(self.alerts_path, {"version": 1, "alerts": []})
        alerts = doc.get("alerts")
        return alerts if isinstance(alerts, list) else []

    def get_status(self, mirror=True):
        if mirror:
            self.mirror_legacy_state()
        snap = self.control.dashboard_snapshot()
        route = self.control.telemetry.route_snapshot()
        selectors = self.control.telemetry.state.get("selectors") or {}
        now = int(time.time())
        ages = [
            max(0, now - int(row.get("received_at", 0) or 0))
            for row in selectors.values()
            if isinstance(row, dict) and int(row.get("received_at", 0) or 0) > 0
        ]
        age = min(ages) if ages else None
        active_down = [
            name for name, row in (snap.get("routes") or {}).items()
            if isinstance(row, dict) and row.get("healthy") is False
        ]
        return {
            "success": True,
            "stale": bool(route.get("stale")),
            "age_s": age,
            "snapshot": snap,
            "active_down": active_down,
            "alerts": list(reversed(self._alerts()[-50:])),
        }

#!/usr/bin/env python3
import json
import os
import re
import tempfile
import time
from collections import Counter
from pathlib import Path

_INSTANCE_RE = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
_INGRESSES = {"arvan", "parspack", "shadow"}
_ROUTES = ("worker", "arvan", "parspack")
_ACTIVITY_STRONG = {
    "Instagram", "YouTube", "SoundCloud", "OpenAI", "X", "Duolingo",
    "TikTok", "TradingView", "ForexFactory", "IranLMS", "Termius",
}
_ACTIVITY_SOFT = {"Telegram", "WhatsApp"}

def _fmt_bytes(value):
    value = max(0, int(value or 0))
    units = ("B", "KB", "MB", "GB", "TB")
    n = float(value)
    for unit in units:
        if n < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(n)} B"
            return f"{n:.2f} {unit}"
        n /= 1024.0

def _default_state():
    return {
        "version": 1,
        "seeded": False,
        "usage": {},
        "users": {},
        "reports": {},
        "selectors": {},
        "activity": {},
    }

class TelemetryAggregator:
    def __init__(self, path):
        self.path = Path(path)
        self.state = self._load()

    def _load(self):
        try:
            data = json.loads(self.path.read_text())
            if isinstance(data, dict) and int(data.get("version", 0) or 0) == 1:
                return data
        except Exception:
            pass
        return _default_state()

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix="." + self.path.name + ".", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.state, f, ensure_ascii=False, separators=(",", ":"))
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass

    def seed_from_legacy_snapshot(self, snapshot):
        if self.state.get("seeded"):
            return {"seeded": False, "reason": "already_seeded"}
        users = snapshot.get("users") if isinstance(snapshot, dict) else None
        if not isinstance(users, list):
            raise ValueError("legacy snapshot users missing")
        usage = self.state.setdefault("usage", {})
        meta = self.state.setdefault("users", {})
        now = int(time.time())
        for row in users:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "").strip()
            if not name:
                continue
            usage[name] = max(0, int(row.get("used_bytes", 0) or 0))
            last_activity = max(0, int(row.get("last_activity", 0) or 0))
            online = bool(row.get("online"))
            meta[name] = {
                "last_activity": last_activity,
                "online_until": max(last_activity + 30 if online else 0, now if online else 0),
            }
        self.state["seeded"] = True
        self.state["seeded_at"] = now
        self._save()
        return {"seeded": True, "users": len(usage)}

    def _validate_report(self, payload):
        if not isinstance(payload, dict) or int(payload.get("version", 0) or 0) != 1:
            raise ValueError("invalid telemetry version")
        ingress = str(payload.get("ingress") or "").strip().lower()
        if ingress not in _INGRESSES:
            raise ValueError("invalid ingress")
        instance_id = str(payload.get("instance_id") or "").strip()
        if not _INSTANCE_RE.fullmatch(instance_id):
            raise ValueError("invalid instance id")
        sequence = int(payload.get("sequence", 0) or 0)
        if sequence < 1:
            raise ValueError("invalid sequence")
        ts = int(payload.get("ts", 0) or 0)
        if ts < 1:
            raise ValueError("invalid timestamp")
        users = payload.get("users")
        activity = payload.get("activity")
        if not isinstance(users, list) or not isinstance(activity, list):
            raise ValueError("invalid telemetry arrays")
        return ingress, instance_id, sequence, ts

    @staticmethod
    def _counter_delta(current, previous):
        current = max(0, int(current or 0))
        if previous is None:
            return current
        previous = max(0, int(previous or 0))
        if current >= previous:
            return current - previous
        return current

    def ingest(self, payload):
        ingress, instance_id, sequence, ts = self._validate_report(payload)
        report_key = ingress + "|" + instance_id
        reports = self.state.setdefault("reports", {})
        report_state = reports.setdefault(report_key, {
            "ingress": ingress,
            "instance_id": instance_id,
            "last_sequence": 0,
            "last_seen": 0,
            "users": {},
        })

        last_sequence = int(report_state.get("last_sequence", 0) or 0)
        if sequence <= last_sequence:
            return {
                "success": True,
                "duplicate": True,
                "sequence": sequence,
                "last_sequence": last_sequence,
                "usage_delta": 0,
            }

        usage = self.state.setdefault("usage", {})
        user_meta = self.state.setdefault("users", {})
        report_users = report_state.setdefault("users", {})
        total_delta = 0
        deltas = {}

        for row in payload.get("users") or []:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "").strip()
            if not name or len(name) > 128:
                continue
            raw_up = max(0, int(row.get("raw_up", 0) or 0))
            raw_down = max(0, int(row.get("raw_down", 0) or 0))
            old = report_users.get(name) or {}
            du = self._counter_delta(raw_up, old.get("raw_up"))
            dd = self._counter_delta(raw_down, old.get("raw_down"))
            delta = du + dd
            report_users[name] = {"raw_up": raw_up, "raw_down": raw_down}
            if delta:
                usage[name] = max(0, int(usage.get(name, 0) or 0)) + delta
                meta = user_meta.setdefault(name, {})
                meta["last_activity"] = max(int(meta.get("last_activity", 0) or 0), ts)
                meta["online_until"] = max(int(meta.get("online_until", 0) or 0), ts + 30)
                deltas[name] = delta
                total_delta += delta

        self._ingest_activity(payload.get("activity") or [], ts)

        selector = payload.get("selector")
        if isinstance(selector, dict):
            self.state.setdefault("selectors", {})[ingress] = {
                "received_at": int(time.time()),
                "report_ts": ts,
                "instance_id": instance_id,
                "sequence": sequence,
                "selector": selector,
            }

        report_state["last_sequence"] = sequence
        report_state["last_seen"] = int(time.time())
        report_state["users"] = report_users
        self._prune()
        self._save()

        return {
            "success": True,
            "duplicate": False,
            "sequence": sequence,
            "usage_delta": total_delta,
            "user_deltas": deltas,
        }

    def _ingest_activity(self, events, report_ts):
        activity = self.state.setdefault("activity", {})
        for event in events:
            if not isinstance(event, dict):
                continue
            name = str(event.get("name") or "").strip()
            category = str(event.get("category") or "Other").strip()[:64] or "Other"
            bucket = int(event.get("bucket", 0) or 0)
            count = max(0, min(1000000, int(event.get("count", 0) or 0)))
            if not name or not bucket or not count:
                continue
            user = activity.setdefault(name, {})
            row = user.setdefault(str(bucket), {"fg": {}, "bg": 0, "bgcats": {}})
            if bool(event.get("background")):
                row["bg"] = int(row.get("bg", 0) or 0) + count
                if category not in ("Background", "Other"):
                    cats = row.setdefault("bgcats", {})
                    cats[category] = int(cats.get(category, 0) or 0) + count
            else:
                fg = row.setdefault("fg", {})
                fg[category] = int(fg.get(category, 0) or 0) + count

    def _prune(self):
        now = int(time.time())
        reports = self.state.setdefault("reports", {})
        for key, row in list(reports.items()):
            if now - int(row.get("last_seen", 0) or 0) > 86400:
                reports.pop(key, None)

        activity = self.state.setdefault("activity", {})
        cutoff = now - 7500
        for name, buckets in list(activity.items()):
            for key in list(buckets):
                try:
                    bucket = int(key)
                except Exception:
                    bucket = 0
                if bucket < cutoff:
                    buckets.pop(key, None)
            if not buckets:
                activity.pop(name, None)

    def activity_public(self, name, now=None):
        now = int(now or time.time())
        rows = (self.state.get("activity") or {}).get(str(name), {})
        recent_fg = Counter()
        recent_passive = Counter()
        recent_bg = 0

        for key, row in rows.items():
            try:
                bucket = int(key)
            except Exception:
                continue
            if bucket >= now - 600:
                for category, count in (row.get("fg") or {}).items():
                    if category in _ACTIVITY_STRONG or category in _ACTIVITY_SOFT:
                        recent_fg[category] += int(count)
                    else:
                        recent_bg += int(count)
                recent_passive.update({k: int(v) for k, v in (row.get("bgcats") or {}).items()})
                recent_bg += int(row.get("bg", 0) or 0)

        signals = [{"name": k, "count": v} for k, v in recent_fg.most_common(6)]
        if signals:
            total = sum(recent_fg.values())
            share = signals[0]["count"] / total if total else 0
            confidence = "High" if share >= .60 and total >= 5 else ("Medium" if share >= .35 and total >= 3 else "Low")
            likely = signals[0]["name"]
        elif recent_passive:
            likely, count = recent_passive.most_common(1)[0]
            confidence = "Medium" if count >= 2 else "Low"
        else:
            confidence = "—"
            likely = "No app signal"

        timeline = []
        start_bucket = int((now - 110 * 60) // 600) * 600
        for i in range(12):
            bucket = start_bucket + i * 600
            row = rows.get(str(bucket), {"fg": {}, "bg": 0, "bgcats": {}})
            fg = Counter({k: int(v) for k, v in (row.get("fg") or {}).items()})
            bgcats = Counter({k: int(v) for k, v in (row.get("bgcats") or {}).items()})
            strong_count = sum(v for k, v in fg.items() if k in _ACTIVITY_STRONG)
            meaningful = Counter({k: v for k, v in fg.items() if k in _ACTIVITY_STRONG or k in _ACTIVITY_SOFT})
            passive_count = int(row.get("bg", 0) or 0) + sum(v for k, v in fg.items() if k not in _ACTIVITY_STRONG and k not in _ACTIVITY_SOFT)
            if strong_count >= 4:
                state = "Active"
            elif strong_count >= 2:
                state = "Light"
            elif passive_count > 0 or meaningful:
                state = "Background"
            else:
                state = "Idle"
            if meaningful:
                top = meaningful.most_common(1)[0][0]
            elif bgcats:
                top = bgcats.most_common(1)[0][0]
            else:
                top = ""
            timeline.append({
                "ts": bucket,
                "time": time.strftime("%H:%M", time.localtime(bucket)),
                "state": state,
                "top": top,
            })

        return {
            "likely": likely,
            "confidence": confidence,
            "signals": signals,
            "background_signals": recent_bg,
            "timeline": timeline,
        }

    def route_snapshot(self, stale_after=45, preferred_ingress="arvan"):
        now = int(time.time())
        selectors = self.state.get("selectors") or {}
        fresh = {
            name: row for name, row in selectors.items()
            if now - int(row.get("received_at", 0) or 0) <= stale_after
        }
        canonical = fresh.get(preferred_ingress)
        if canonical is None and fresh:
            canonical = max(fresh.values(), key=lambda x: int(x.get("received_at", 0) or 0))
        raw = (canonical or {}).get("selector") or {}

        routes = {}
        for route in _ROUTES:
            candidates = []
            for item in fresh.values():
                r = ((item.get("selector") or {}).get("routes") or {}).get(route)
                if isinstance(r, dict):
                    candidates.append(r)
            base = dict((((raw.get("routes") or {}).get(route)) or {}))
            if candidates:
                base["healthy"] = any(bool(x.get("healthy")) for x in candidates)
                latencies = [float(x.get("latency_ms")) for x in candidates if x.get("latency_ms") is not None]
                if latencies:
                    base["latency_ms"] = round(min(latencies), 1)
            routes[route] = base

        return {
            "stale": not bool(fresh),
            "policy": raw.get("policy"),
            "priority": raw.get("priority") or ["worker", "arvan", "parspack"],
            "effective_priority": raw.get("effective_priority") or raw.get("priority") or ["worker", "arvan", "parspack"],
            "preference_mode": raw.get("preference_mode") or "auto",
            "preferred": raw.get("preferred"),
            "selected": raw.get("selected"),
            "switch_reason": raw.get("switch_reason"),
            "selected_for_s": raw.get("selected_for_s"),
            "routes": routes,
        }

    def user_public(self, authority_user, now=None):
        now = int(now or time.time())
        row = dict(authority_user)
        name = str(row.get("name") or "")
        used = max(0, int((self.state.get("usage") or {}).get(name, row.get("used_bytes", 0)) or 0))
        quota = max(0, int(row.get("quota_bytes", 0) or 0))
        expires = max(0, int(row.get("expires_at", 0) or 0))
        meta = (self.state.get("users") or {}).get(name) or {}
        last_activity = max(int(meta.get("last_activity", 0) or 0), int(row.get("last_activity", 0) or 0))
        online_until = int(meta.get("online_until", 0) or 0)
        out = {
            "name": name,
            "enabled": bool(row.get("enabled", True)),
            "access_state": row.get("access_state") or "active",
            "used_bytes": used,
            "used_f": _fmt_bytes(used),
            "quota_bytes": quota,
            "quota_f": _fmt_bytes(quota) if quota else "Unlimited",
            "remaining_bytes": max(0, quota - used) if quota else 0,
            "remaining_f": _fmt_bytes(max(0, quota - used)) if quota else "Unlimited",
            "created_at": int(row.get("created_at", 0) or 0),
            "expires_at": expires,
            "days_left": max(0, (expires - now + 86399) // 86400) if expires else None,
            "online": now <= online_until,
            "last_activity": last_activity,
            "reconcile_error": row.get("reconcile_error"),
            "activity": self.activity_public(name, now=now),
        }
        return out

#!/usr/bin/env python3
import argparse
import json
import re
import sys
import tempfile
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from migration.hub_control_plane import HubControlPlane

UUID_RE = re.compile(r"vless://([0-9a-fA-F-]{36})@")

def load_json(path):
    try:
        data=json.loads(Path(path).read_text())
    except Exception as exc:
        raise RuntimeError(f"cannot load {path}: {exc}")
    if not isinstance(data,dict):
        raise RuntimeError(f"invalid JSON object: {path}")
    return data

def current_snapshot(state_doc):
    snap=state_doc.get("snapshot")
    if not isinstance(snap,dict):
        raise RuntimeError("legacy hub snapshot missing")
    users=snap.get("users")
    if not isinstance(users,list) or not users:
        raise RuntimeError("legacy hub users missing")
    return snap

def command_uuid_map(snapshot, commands_doc):
    current_names={
        str(row.get("name") or "").strip()
        for row in snapshot.get("users") or []
        if isinstance(row,dict) and str(row.get("name") or "").strip()
    }
    mapping={}
    for cmd in reversed(commands_doc.get("commands") or []):
        if not isinstance(cmd,dict) or cmd.get("status")!="done":
            continue
        result=cmd.get("result")
        args=cmd.get("args") or {}
        name=""
        if isinstance(result,dict):
            name=str(
                ((result.get("user") or {}).get("name"))
                or result.get("name")
                or args.get("name")
                or ""
            ).strip()
        else:
            name=str(args.get("name") or "").strip()
        if not name or name not in current_names or name in mapping:
            continue

        try:
            blob=json.dumps(result,ensure_ascii=False)
        except Exception:
            blob=""
        found={raw.lower() for raw in UUID_RE.findall(blob)}
        if len(found)!=1:
            continue
        raw=next(iter(found))
        try:
            raw=str(uuid.UUID(raw))
        except Exception:
            continue
        mapping[name]=raw

    missing=sorted(current_names-set(mapping))
    if missing:
        raise RuntimeError(
            "UUID reconstruction incomplete for users: "+",".join(missing)
        )
    return mapping

def build_agent_db(snapshot, uuid_map):
    users={}
    for row in snapshot.get("users") or []:
        if not isinstance(row,dict):
            continue
        name=str(row.get("name") or "").strip()
        if not name:
            continue
        users[name]={
            "uuid": uuid_map[name],
            "created_at": int(row.get("created_at",0) or 0),
            "expires_at": int(row.get("expires_at",0) or 0),
            "quota_bytes": max(0,int(row.get("quota_bytes",0) or 0)),
            "enabled": bool(row.get("enabled",True)),
        }
    return {"version":1,"users":users}

def verify_seed(control, snapshot, agent_db):
    desired=control.desired_snapshot()
    old_by_name={
        str(row.get("name") or "").strip(): row
        for row in snapshot.get("users") or []
        if isinstance(row,dict) and str(row.get("name") or "").strip()
    }
    new_by_name={str(row.get("name") or ""):row for row in desired.get("users") or []}
    if set(old_by_name)!=set(new_by_name):
        raise RuntimeError("seed user set mismatch")

    for name,old in old_by_name.items():
        new=new_by_name[name]
        legacy=agent_db["users"][name]
        checks=(
            (str(new.get("uuid") or "").lower(), str(legacy.get("uuid") or "").lower(), "uuid"),
            (int(new.get("quota_bytes",0) or 0), int(old.get("quota_bytes",0) or 0), "quota"),
            (int(new.get("expires_at",0) or 0), int(old.get("expires_at",0) or 0), "expiry"),
            (bool(new.get("enabled",True)), bool(old.get("enabled",True)), "enabled"),
            (int(new.get("used_bytes",0) or 0), int(old.get("used_bytes",0) or 0), "usage"),
        )
        for actual,expected,label in checks:
            if actual!=expected:
                raise RuntimeError(f"seed {label} mismatch for {name}")

    old_mode=str(snapshot.get("preference_mode") or "auto").strip().lower()
    old_pref=str(snapshot.get("preferred") or "").strip().lower() or None
    if old_mode!="manual":
        old_mode,old_pref="auto",None
    pref=desired.get("route_preference") or {}
    if str(pref.get("mode") or "auto")!=old_mode or pref.get("preferred")!=old_pref:
        raise RuntimeError("seed route preference mismatch")

    return len(new_by_name)

def seed_once(authority_path, telemetry_path, agent_db, snapshot):
    control=HubControlPlane(authority_path,telemetry_path)
    result=control.seed_from_legacy(agent_db,snapshot)
    count=verify_seed(control,snapshot,agent_db)
    return result,count

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--state",default="/var/lib/slipnet-v2ray-hub/state.json")
    ap.add_argument("--commands",default="/var/lib/slipnet-v2ray-hub/commands.json")
    ap.add_argument("--authority",default="/var/lib/slipnet-v2ray-hub/no95-authority.json")
    ap.add_argument("--telemetry",default="/var/lib/slipnet-v2ray-hub/no95-telemetry.json")
    ap.add_argument("--apply",action="store_true")
    args=ap.parse_args()

    state_doc=load_json(args.state)
    commands_doc=load_json(args.commands)
    snapshot=current_snapshot(state_doc)
    uuid_map=command_uuid_map(snapshot,commands_doc)
    agent_db=build_agent_db(snapshot,uuid_map)

    if not args.apply:
        with tempfile.TemporaryDirectory(prefix="no95-seed-dryrun-") as td:
            result,count=seed_once(
                Path(td)/"authority.json",
                Path(td)/"telemetry.json",
                agent_db,
                snapshot,
            )
        print(f"SEED_VERIFY=PASS users={count}")
        print("MODE=DRY_RUN")
        return 0

    authority=Path(args.authority)
    telemetry=Path(args.telemetry)
    authority_exists=authority.exists()
    telemetry_exists=telemetry.exists()
    if authority_exists != telemetry_exists:
        raise RuntimeError("partial existing no95 seed state")

    if authority_exists and telemetry_exists:
        control=HubControlPlane(authority,telemetry)
        count=verify_seed(control,snapshot,agent_db)
        print(f"SEED_VERIFY=PASS users={count}")
        print("MODE=ALREADY_SEEDED")
        return 0

    result,count=seed_once(authority,telemetry,agent_db,snapshot)
    if not result.get("seeded"):
        raise RuntimeError("new seed was not written")
    print(f"SEED_VERIFY=PASS users={count}")
    print("MODE=APPLY")
    return 0

if __name__=="__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL_CLOSED {type(exc).__name__}: {exc}",file=sys.stderr)
        raise SystemExit(1)

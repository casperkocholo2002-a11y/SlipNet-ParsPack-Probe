#!/usr/bin/env python3
import hashlib, json, os, re, subprocess, tempfile, time, urllib.request
from pathlib import Path

XRAY = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
API = os.environ.get("XRAY_API", "127.0.0.1:19182")
CFG = Path(os.environ.get("INGRESS_CONFIG", "/etc/slipnet-shadow/ingress.json"))
MANIFEST_URL = os.environ.get("MANIFEST_URL", "").strip()
MANIFEST_TOKEN = os.environ.get("MANIFEST_TOKEN", "").strip()
MANIFEST_FILE = os.environ.get("MANIFEST_FILE", "").strip()
CACHE = Path(os.environ.get("MANIFEST_CACHE", "/var/lib/slipnet-shadow/manifest.json"))
APPLIED = Path(os.environ.get("APPLIED_STATE", "/var/lib/slipnet-shadow/applied.json"))
PREFERENCE = Path(os.environ.get("SELECTOR_PREFERENCE", "/var/lib/slipnet-smart-egress/preference.json"))
SELECTOR_STATE = Path(os.environ.get("SELECTOR_STATE", "/run/slipnet-smart-egress/state.json"))
INTERVAL = float(os.environ.get("MANIFEST_INTERVAL", "5"))
NODE_ID = os.environ.get("SHADOW_NODE_ID", "").strip().lower()
USAGE_REPORT_URL = os.environ.get("USAGE_REPORT_URL", "").strip()
USAGE_REPORT_TOKEN = os.environ.get("USAGE_REPORT_TOKEN", MANIFEST_TOKEN).strip()
USAGE_REPORT_INTERVAL = float(os.environ.get("USAGE_REPORT_INTERVAL", "15"))
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")

def atomic_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="."+path.name+".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, separators=(",", ":"))
            f.write("\n"); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp, 0o600); os.replace(tmp, path)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass

def fetch_manifest():
    if MANIFEST_FILE:
        data = json.loads(Path(MANIFEST_FILE).read_text(encoding="utf-8"))
        atomic_json(CACHE, data)
        return data, "file"
    if MANIFEST_URL:
        headers = {"accept":"application/json"}
        if MANIFEST_TOKEN: headers["authorization"] = "Bearer " + MANIFEST_TOKEN
        req = urllib.request.Request(MANIFEST_URL, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=3) as r: data = json.load(r)
            atomic_json(CACHE, data)
            return data, "remote"
        except Exception:
            pass
    if CACHE.exists():
        return json.loads(CACHE.read_text(encoding="utf-8")), "cache"
    return {"version":1,"users":[],"route_preference":{"mode":"auto","preferred":None}}, "empty"

def validate(data):
    if not isinstance(data, dict) or not isinstance(data.get("users"), list):
        raise ValueError("invalid manifest")
    seen=set(); clean=[]
    for row in data["users"]:
        if not isinstance(row, dict): raise ValueError("invalid user row")
        name=str(row.get("name") or "").strip()
        uid=str(row.get("uuid") or "").strip().lower()
        if not name or name in seen or not UUID_RE.fullmatch(uid):
            raise ValueError("invalid user identity")
        seen.add(name)
        clean.append({
            "name":name,"uuid":uid,
            "enabled":bool(row.get("enabled",True)),
            "expires_at":int(row.get("expires_at",0) or 0),
            "quota_bytes":int(row.get("quota_bytes",0) or 0),
            "used_bytes":int(row.get("used_bytes",0) or 0),
        })
    return clean

def desired(rows):
    at=int(time.time()); out={}
    for u in rows:
        if not u["enabled"]: continue
        if u["expires_at"] and at >= u["expires_at"]: continue
        if u["quota_bytes"] and u["used_bytes"] >= u["quota_bytes"]: continue
        out[u["name"]] = u["uuid"]
    return out

def run(args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=12)
    return p.returncode,(p.stdout or "")+"\n"+(p.stderr or "")

def load_applied():
    try:return json.loads(APPLIED.read_text(encoding="utf-8"))
    except Exception:return {}

def inbound_template():
    cfg=json.loads(CFG.read_text(encoding="utf-8"))
    return next(x for x in cfg["inbounds"] if x.get("tag")=="shadow-vless")

def add(name, uid):
    ib=json.loads(json.dumps(inbound_template()))
    ib["settings"]["clients"]=[{"id":uid,"email":"v2ray-"+name}]
    fd,p=tempfile.mkstemp(prefix="slipnet-add-",suffix=".json")
    os.close(fd)
    try:
        Path(p).write_text(json.dumps({"inbounds":[ib]}),encoding="utf-8")
        rc,t=run([XRAY,"api","adu","--server="+API,p])
        if rc or "Added 1 user(s)" not in t: raise RuntimeError("add failed: "+t[-500:])
    finally:
        try:os.unlink(p)
        except FileNotFoundError:pass

def remove(name):
    rc,t=run([XRAY,"api","rmu","--server="+API,"-tag=shadow-vless","v2ray-"+name])
    if rc: raise RuntimeError("remove failed: "+t[-500:])

def apply_preference(data):
    pref=data.get("route_preference") or {}
    mode=str(pref.get("mode") or "auto").lower()
    route=str(pref.get("preferred") or "").lower()
    if mode=="manual" and route in {"worker","arvan","parspack"}:
        out={"mode":"manual","preferred":route,"updated_at":int(pref.get("updated_at") or time.time())}
    else:
        out={"mode":"auto","preferred":None,"updated_at":int(pref.get("updated_at") or time.time())}
    atomic_json(PREFERENCE,out)

def apply_once():
    data, source=fetch_manifest()
    rows=validate(data); want=desired(rows); cur=load_applied()
    for name in sorted(set(cur)-set(want)): remove(name)
    for name,uid in want.items():
        if cur.get(name)!=uid:
            if name in cur: remove(name)
            add(name,uid)
    atomic_json(APPLIED,want)
    apply_preference(data)
    print(json.dumps({"event":"manifest_applied","source":source,"users":len(want)},separators=(",",":")),flush=True)
    return data

def raw_stats():
    rc,t=run([XRAY,"api","statsquery","--server="+API])
    if rc: raise RuntimeError("statsquery failed: "+t[-300:])
    d=json.loads(t.strip() or "{}")
    return {str(x.get("name") or ""):int(x.get("value",0) or 0) for x in d.get("stat",[])}

def selector_snapshot():
    try:return json.loads(SELECTOR_STATE.read_text(encoding="utf-8"))
    except Exception:return {}

def report_usage(data):
    if not USAGE_REPORT_URL or NODE_ID not in {"arvan","parspack"}: return
    stats=raw_stats(); users=[]
    for u in validate(data):
        email="v2ray-"+u["name"]
        up=int(stats.get(f"user>>>{email}>>>traffic>>>uplink",0) or 0)
        down=int(stats.get(f"user>>>{email}>>>traffic>>>downlink",0) or 0)
        users.append({
          "name":u["name"],
          "uuid_hash":hashlib.sha256(u["uuid"].encode()).hexdigest(),
          "raw_bytes":up+down,
        })
    payload={"node":NODE_ID,"ts":int(time.time()),"users":users,"selector":selector_snapshot()}
    body=json.dumps(payload,separators=(",",":")).encode()
    headers={"content-type":"application/json"}
    if USAGE_REPORT_TOKEN: headers["authorization"]="Bearer "+USAGE_REPORT_TOKEN
    req=urllib.request.Request(USAGE_REPORT_URL,data=body,headers=headers,method="POST")
    with urllib.request.urlopen(req,timeout=4) as r:
        if r.status<200 or r.status>=300: raise RuntimeError("usage report rejected")

if __name__=="__main__":
    once = "--once" in os.sys.argv
    next_report=0.0; last_data=None
    while True:
        try:last_data=apply_once()
        except Exception as e:print(json.dumps({"event":"manifest_error","error":str(e)[:300]}),flush=True)
        if last_data is not None and time.monotonic()>=next_report:
            try:
                report_usage(last_data)
                if USAGE_REPORT_URL: print(json.dumps({"event":"usage_reported","node":NODE_ID}),flush=True)
            except Exception as e:
                print(json.dumps({"event":"usage_report_error","error":str(e)[:300]}),flush=True)
            next_report=time.monotonic()+max(5.0,USAGE_REPORT_INTERVAL)
        if once:break
        time.sleep(max(1.0,INTERVAL))
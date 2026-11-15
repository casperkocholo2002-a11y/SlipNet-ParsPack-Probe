#!/usr/bin/env python3
import copy
import hashlib
import json
import re
import time
import urllib.parse
import uuid

PUBLIC_HOSTS = {
    "parspack": "app-docker-container-ki5n1.apps.teh11.abrhapaas.com",
    "arvan": "relaytest-fc2e226493-test.apps.ir-central1.arvancaas.ir",
}
ROUTES = ("worker", "arvan", "parspack")
NODES = ("arvan", "parspack")
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
VLESS_RE = re.compile(r"vless://([0-9a-fA-F-]{36})@")

def now():
    return int(time.time())

def validate_name(name):
    name = str(name or "").strip()
    if not NAME_RE.fullmatch(name):
        raise ValueError("Name must be 1-32 chars: letters, numbers, _, . or -")
    return name

def fmt_bytes(value):
    value=int(value or 0); units=("B","KB","MB","GB","TB"); n=float(value)
    for unit in units:
        if n < 1024 or unit=="TB":
            return f"{int(n)} {unit}" if unit=="B" else f"{n:.1f} {unit}"
        n/=1024
    return "0 B"

def new_state():
    return {
        "version":1,
        "updated_at":now(),
        "route_preference":{"mode":"auto","preferred":None,"updated_at":now()},
        "users":{},
        "usage_nodes":{},
        "route_reports":{},
    }

def route_links(name, user_uuid):
    q_pp={
      "encryption":"none","security":"tls","type":"ws",
      "host":PUBLIC_HOSTS["parspack"],"path":"/tunnel",
      "sni":PUBLIC_HOSTS["parspack"],"alpn":"http/1.1","fp":"chrome",
    }
    q_ar={
      "encryption":"none","security":"tls","type":"ws",
      "host":PUBLIC_HOSTS["arvan"],"path":"/tunnel",
      "sni":PUBLIC_HOSTS["arvan"],"alpn":"http/1.1","fp":"chrome",
    }
    def link(host,q,label):
        return (
          f"vless://{user_uuid}@{host}:443?"
          + urllib.parse.urlencode(q,quote_via=urllib.parse.quote)
          + "#"
          + urllib.parse.quote(f"SlipNet V2Ray - {name} - {label}")
        )
    links={
      "parspack":link(PUBLIC_HOSTS["parspack"],q_pp,"ParsPack"),
      "arvan":link(PUBLIC_HOSTS["arvan"],q_ar,"Arvan"),
    }
    return links,"\n".join(links.values())+"\n"

def total_usage(state,name):
    total=0
    for node in NODES:
        total += int((((state.get("usage_nodes") or {}).get(node) or {}).get(name) or {}).get("accum",0) or 0)
    return total

def access_reason(state,name,user,at=None):
    at=now() if at is None else int(at)
    if not bool(user.get("enabled",True)): return "manual"
    expires=int(user.get("expires_at",0) or 0)
    quota=int(user.get("quota_bytes",0) or 0)
    used=total_usage(state,name)
    if expires and at>=expires:return "expired"
    if quota and used>=quota:return "quota"
    return None

def user_public(state,name,user):
    used=total_usage(state,name)
    quota=int(user.get("quota_bytes",0) or 0)
    expires=int(user.get("expires_at",0) or 0)
    t=now()
    reason=access_reason(state,name,user,t)
    return {
      "name":name,
      "enabled":bool(user.get("enabled",True)),
      "access_state":user.get("access_state") or ("active" if reason is None else reason),
      "used_bytes":used,
      "used_f":fmt_bytes(used),
      "quota_bytes":quota,
      "quota_f":fmt_bytes(quota) if quota else "Unlimited",
      "remaining_bytes":max(0,quota-used) if quota else 0,
      "remaining_f":fmt_bytes(max(0,quota-used)) if quota else "Unlimited",
      "created_at":int(user.get("created_at",0) or 0),
      "expires_at":expires,
      "days_left":max(0,(expires-t+86399)//86400) if expires else None,
      "online":t<=int(user.get("online_until",0) or 0),
      "last_activity":int(user.get("last_activity",0) or 0),
      "reconcile_error":None,
    }

def refresh_access_states(state):
    for name,user in state["users"].items():
        reason=access_reason(state,name,user)
        user["access_state"]="active" if reason is None else reason
    state["updated_at"]=now()

def bootstrap_from_snapshot_commands(snapshot, commands):
    state=new_state()
    uuid_by_name={}
    for cmd in commands or []:
        if cmd.get("status")!="done":continue
        result=cmd.get("result")
        try: blob=json.dumps(result,ensure_ascii=False)
        except Exception: blob=""
        matches=VLESS_RE.findall(blob)
        name=str(((result or {}).get("user") or {}).get("name") or (result or {}).get("name") or (cmd.get("args") or {}).get("name") or "").strip()
        if name and matches: uuid_by_name[name]=matches[-1].lower()
    for row in (snapshot or {}).get("users") or []:
        name=validate_name(row.get("name"))
        raw=uuid_by_name.get(name)
        if not raw: raise ValueError(f"missing UUID history for {name}")
        state["users"][name]={
          "uuid":raw,
          "created_at":int(row.get("created_at",0) or 0),
          "expires_at":int(row.get("expires_at",0) or 0),
          "quota_bytes":int(row.get("quota_bytes",0) or 0),
          "enabled":bool(row.get("enabled",True)),
          "access_state":str(row.get("access_state") or "active"),
          "last_activity":int(row.get("last_activity",0) or 0),
          "online_until":now()+30 if row.get("online") else 0,
        }
        used=int(row.get("used_bytes",0) or 0)
        # Bootstrap historical usage into a synthetic legacy bucket.
        state["usage_nodes"].setdefault("arvan",{})[name]={"accum":used,"last_raw":0}
        state["usage_nodes"].setdefault("parspack",{})[name]={"accum":0,"last_raw":0}
    pref=(snapshot or {}).get("preferred")
    mode=(snapshot or {}).get("preference_mode") or ("manual" if pref else "auto")
    state["route_preference"]={"mode":mode,"preferred":pref,"updated_at":now()}
    refresh_access_states(state)
    return state

def _user(state,name):
    name=validate_name(name)
    u=state["users"].get(name)
    if not u: raise ValueError("User not found")
    return name,u

def apply_command(state,op,args):
    if op=="add":
        name=validate_name(args.get("name"))
        if name in state["users"]: raise ValueError("User already exists")
        days=int(args.get("duration_days",30) or 0); quota=int(args.get("quota_bytes",0) or 0)
        if days<0 or days>3650: raise ValueError("duration_days must be 0..3650")
        if quota<0: raise ValueError("quota_bytes cannot be negative")
        created=now()
        u={
          "uuid":str(uuid.uuid4()),"created_at":created,
          "expires_at":created+days*86400 if days else 0,
          "quota_bytes":quota,"enabled":True,"access_state":"active",
          "last_activity":0,"online_until":0,
        }
        state["users"][name]=u
        for node in NODES: state["usage_nodes"].setdefault(node,{})[name]={"accum":0,"last_raw":0}
        links,bundle=route_links(name,u["uuid"])
        state["updated_at"]=now()
        return {"user":user_public(state,name,u),"links":links,"bundle":bundle}
    if op=="delete":
        name,u=_user(state,args.get("name"))
        state["users"].pop(name,None)
        for node in NODES: state["usage_nodes"].setdefault(node,{}).pop(name,None)
        state["updated_at"]=now()
        return {"name":name,"deleted":True}
    if op=="limits":
        name,u=_user(state,args.get("name"))
        if "duration_days" in args and args.get("duration_days") is not None:
            days=int(args.get("duration_days") or 0)
            if days<0 or days>3650: raise ValueError("duration_days must be 0..3650")
            u["expires_at"]=now()+days*86400 if days else 0
        if "quota_bytes" in args and args.get("quota_bytes") is not None:
            quota=int(args.get("quota_bytes") or 0)
            if quota<0: raise ValueError("quota_bytes cannot be negative")
            u["quota_bytes"]=quota
        refresh_access_states(state)
        return {"user":user_public(state,name,u)}
    if op=="reset_usage":
        name,u=_user(state,args.get("name"))
        for node in NODES:
            row=state["usage_nodes"].setdefault(node,{}).setdefault(name,{"accum":0,"last_raw":0})
            row["accum"]=0
            row["reset_baseline_pending"]=True
        refresh_access_states(state)
        return {"user":user_public(state,name,u)}
    if op=="config":
        name,u=_user(state,args.get("name"))
        links,bundle=route_links(name,u["uuid"])
        return {"name":name,"links":links,"bundle":bundle}
    if op in ("disable","enable"):
        name,u=_user(state,args.get("name"))
        u["enabled"]=(op=="enable")
        refresh_access_states(state)
        return {"user":user_public(state,name,u)}
    if op=="route_preference":
        route=str(args.get("route") or "").strip().lower()
        if route not in {"auto","worker","arvan","parspack"}:
            raise ValueError("route must be auto, worker, arvan or parspack")
        pref=None if route=="auto" else route
        mode="auto" if route=="auto" else "manual"
        state["route_preference"]={"mode":mode,"preferred":pref,"updated_at":now()}
        state["updated_at"]=now()
        return {"route":route,"mode":mode,"preferred":pref,"selected":None,"reflected":False}
    raise ValueError("Unsupported operation")

def manifest(state):
    refresh_access_states(state)
    users=[]
    for name,u in sorted(state["users"].items()):
        users.append({
          "name":name,"uuid":u["uuid"],"enabled":bool(u.get("enabled",True)),
          "expires_at":int(u.get("expires_at",0) or 0),
          "quota_bytes":int(u.get("quota_bytes",0) or 0),
          "used_bytes":total_usage(state,name),
          "access_state":u.get("access_state"),
        })
    return {
      "version":1,"generation":int(state.get("updated_at",0) or 0),
      "route_preference":copy.deepcopy(state["route_preference"]),
      "users":users,
    }

def ingest_usage(state,node,payload):
    node=str(node or "").strip().lower()
    if node not in NODES: raise ValueError("Invalid node")
    rows=(payload or {}).get("users")
    if not isinstance(rows,list): raise ValueError("Invalid usage payload")
    bucket=state["usage_nodes"].setdefault(node,{})
    touched=[]
    for item in rows:
        name=validate_name(item.get("name"))
        u=state["users"].get(name)
        if not u: continue
        raw_uuid=str(u["uuid"]).lower()
        expected=hashlib.sha256(raw_uuid.encode()).hexdigest()
        if str(item.get("uuid_hash") or "").lower()!=expected: raise ValueError("UUID hash mismatch")
        raw=max(0,int(item.get("raw_bytes",0) or 0))
        row=bucket.setdefault(name,{"accum":0,"last_raw":0})
        prev=int(row.get("last_raw",0) or 0)
        if row.pop("reset_baseline_pending",False):
            delta=0
        else:
            delta=raw-prev if raw>=prev else raw
        row["accum"]=int(row.get("accum",0) or 0)+max(0,delta)
        row["last_raw"]=raw
        if delta>0:
            u["last_activity"]=now(); u["online_until"]=now()+30
        touched.append(name)
    if isinstance((payload or {}).get("selector"),dict):
        state["route_reports"][node]={"ts":now(),"selector":copy.deepcopy(payload["selector"])}
    refresh_access_states(state)
    return {"success":True,"node":node,"users":len(touched)}

class CompatQueue:
    def __init__(self,state):
        self.state=state
        self.commands=[]
    def enqueue(self,op,args):
        cmd={
          "id":uuid.uuid4().hex,"op":op,"args":copy.deepcopy(args or {}),
          "status":"pending","created_at":now(),"last_delivery":0,
          "deliveries":0,"result":None,"error":None,
        }
        self.commands.append(cmd)
        try:
            result=apply_command(self.state,op,args or {})
            cmd["status"]="done"; cmd["result"]=result; cmd["completed_at"]=now()
        except Exception as e:
            cmd["status"]="failed"; cmd["error"]=str(e)[:1000]; cmd["completed_at"]=now()
        return {"success":True,"command_id":cmd["id"],"status":"pending"}
    def get_command(self,cid):
        for c in self.commands:
            if c["id"]==cid:return {"success":True,"command":copy.deepcopy(c)}
        return {"success":False,"error":"Command not found"}
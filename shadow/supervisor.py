#!/usr/bin/env python3
import os, signal, subprocess, sys, time
from pathlib import Path

BASE="/opt/slipnet-shadow"
CFG="/etc/slipnet-shadow"
XRAY="/usr/local/bin/xray"

def run_check(args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=20)
    if p.returncode:
        sys.stderr.write((p.stderr or p.stdout or "check failed")[-2000:]+"\n")
        raise SystemExit(p.returncode)

run_check(["python3",BASE+"/render.py"])
for name in ("worker.json","provider.json","ingress.json"):
    run_check([XRAY,"run","-test","-config",CFG+"/"+name])

os.makedirs("/run/slipnet-smart-egress",exist_ok=True)
os.makedirs("/var/lib/slipnet-smart-egress",exist_ok=True)
os.makedirs("/var/lib/slipnet-shadow",exist_ok=True)

env=dict(os.environ)
env.setdefault("LOCAL_VLESS_ORIGIN","1")
env.setdefault("LOCAL_VLESS_HOST","127.0.0.1")
env.setdefault("LOCAL_VLESS_PORT","29443")

specs=[
 ("worker",[XRAY,"run","-config",CFG+"/worker.json"]),
 ("provider",[XRAY,"run","-config",CFG+"/provider.json"]),
 ("selector",["python3",BASE+"/smart_egress.py"]),
 ("ingress",[XRAY,"run","-config",CFG+"/ingress.json"]),
 ("controller",["python3",BASE+"/controller.py"]),
 ("front",["node","/app/server.js"]),
]
procs=[]
stopping=False

def cleanup(*_):
    global stopping
    if stopping:return
    stopping=True
    for _,p in procs:
        if p.poll() is None:
            try:p.terminate()
            except:pass
    deadline=time.time()+5
    while time.time()<deadline and any(p.poll() is None for _,p in procs):
        time.sleep(.1)
    for _,p in procs:
        if p.poll() is None:
            try:p.kill()
            except:pass

for sig in (signal.SIGTERM,signal.SIGINT):
    signal.signal(sig,cleanup)

try:
    for name,args in specs:
        p=subprocess.Popen(args,env=env)
        procs.append((name,p))
        time.sleep(.15)
    while True:
        for name,p in procs:
            rc=p.poll()
            if rc is not None:
                if not stopping:
                    sys.stderr.write(f"critical child exited: {name} rc={rc}\n")
                    cleanup()
                    raise SystemExit(rc or 1)
                raise SystemExit(0)
        time.sleep(.5)
finally:
    cleanup()
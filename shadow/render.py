#!/usr/bin/env python3
import json, os
from pathlib import Path

OUT = Path(os.environ.get("SHADOW_CONFIG_DIR", "/etc/slipnet-shadow"))
OUT.mkdir(parents=True, exist_ok=True)

def need(name, default=None):
    value = os.environ.get(name, default)
    if value is None or str(value).strip() == "":
        raise SystemExit(f"missing required env: {name}")
    return str(value).strip()

def dump(name, obj):
    p = OUT / name
    p.write_text(json.dumps(obj, separators=(",", ":")) + "\n", encoding="utf-8")
    os.chmod(p, 0o600)

worker = {
  "log":{"loglevel":"warning"},
  "inbounds":[{"tag":"socks-worker","listen":"127.0.0.1","port":19085,"protocol":"socks","settings":{"udp":True}}],
  "outbounds":[{
    "tag":"to-worker","protocol":"vless",
    "settings":{"vnext":[{"address":need("WORKER_ADDRESS"),"port":int(need("WORKER_PORT","443")),"users":[{"id":need("WORKER_UUID"),"encryption":"none"}]}]},
    "streamSettings":{
      "network":"xhttp","security":"tls",
      "tlsSettings":{"serverName":need("WORKER_SERVER_NAME"),"alpn":["h2"]},
      "xhttpSettings":{
        "host":need("WORKER_SERVER_NAME"),
        "path":need("WORKER_PATH"),
        "mode":"packet-up",
        "extra":{"scMaxEachPostBytes":65536,"scMinPostsIntervalMs":5,"xmux":{"maxConnections":2,"hMaxRequestTimes":"800-1200","hMaxReusableSecs":"300-600"}}
      }
    }
  }]
}

provider = {
  "log":{"access":"none","loglevel":"error","dnsLog":False},
  "inbounds":[
    {"tag":"socks-arvan","listen":"127.0.0.1","port":19186,"protocol":"socks","settings":{"udp":False}},
    {"tag":"socks-parspack","listen":"127.0.0.1","port":19187,"protocol":"socks","settings":{"udp":False}}
  ],
  "outbounds":[
    {
      "tag":"to-arvan","protocol":"vless",
      "settings":{"vnext":[{"address":need("ARVAN_DIRECT_ADDRESS"),"port":int(need("ARVAN_DIRECT_PORT","443")),"users":[{"id":need("ARVAN_DIRECT_UUID"),"encryption":"none"}]}]},
      "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":need("ARVAN_DIRECT_SERVER_NAME"),"allowInsecure":False,"alpn":["http/1.1"],"fingerprint":"chrome"},"wsSettings":{"path":need("ARVAN_DIRECT_PATH","/direct"),"headers":{"Host":need("ARVAN_DIRECT_SERVER_NAME")}}}
    },
    {
      "tag":"to-parspack","protocol":"vless",
      "settings":{"vnext":[{"address":need("PARSPACK_DIRECT_ADDRESS"),"port":int(need("PARSPACK_DIRECT_PORT","443")),"users":[{"id":need("PARSPACK_DIRECT_UUID"),"encryption":"none"}]}]},
      "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":need("PARSPACK_DIRECT_SERVER_NAME"),"allowInsecure":False,"alpn":["http/1.1"],"fingerprint":"chrome"},"wsSettings":{"path":need("PARSPACK_DIRECT_PATH","/direct"),"headers":{"Host":need("PARSPACK_DIRECT_SERVER_NAME")}}}
    },
    {"tag":"block","protocol":"blackhole"}
  ],
  "routing":{"domainStrategy":"AsIs","rules":[
    {"type":"field","inboundTag":["socks-arvan"],"outboundTag":"to-arvan"},
    {"type":"field","inboundTag":["socks-parspack"],"outboundTag":"to-parspack"}
  ]}
}

ingress = {
  "log":{"access":"/var/lib/slipnet-shadow/access.log","loglevel":"error","dnsLog":False},
  "inbounds":[
    {"tag":"shadow-vless","listen":"127.0.0.1","port":29443,"protocol":"vless","settings":{"clients":[],"decryption":"none"}},
    {"tag":"api","listen":"127.0.0.1","port":19182,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}}
  ],
  "outbounds":[
    {"tag":"to-selector","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":19190}]}},
    {"tag":"api","protocol":"freedom"}
  ],
  "routing":{"domainStrategy":"AsIs","rules":[
    {"type":"field","inboundTag":["api"],"outboundTag":"api"},
    {"type":"field","inboundTag":["shadow-vless"],"outboundTag":"to-selector"}
  ]},
  "stats":{},
  "api":{"tag":"api","services":["HandlerService","StatsService"]},
  "policy":{"levels":{"0":{"statsUserUplink":True,"statsUserDownlink":True}}}
}

dump("worker.json", worker)
dump("provider.json", provider)
dump("ingress.json", ingress)
print("render=ok")
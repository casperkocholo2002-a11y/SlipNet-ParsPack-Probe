#!/usr/bin/env python3
import argparse
import ipaddress
import json
import re
from pathlib import Path

PLACEHOLDER_RE = re.compile(r"^(?:<.*>|changeme|todo|replace_me|secret)$", re.I)
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")

def load_env(path):
    out = {}
    for line_no, raw in enumerate(Path(path).read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise RuntimeError(f"invalid env line {line_no}")
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if not key or key in out:
            raise RuntimeError(f"invalid or duplicate key at line {line_no}: {key}")
        out[key] = value
    return out

def nonempty(env, key):
    value = str(env.get(key, "")).strip()
    if not value or PLACEHOLDER_RE.fullmatch(value):
        raise RuntimeError(f"missing/placeholder value: {key}")
    return value

def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False

def validate(provider, env, contract):
    problems = []

    for key in contract.get("forbidden_keys", []):
        if key in env and str(env[key]).strip():
            problems.append(f"forbidden legacy primary-origin key present: {key}")

    forbidden_values = {str(x).strip() for x in contract.get("forbidden_values", [])}
    for key, value in env.items():
        if str(value).strip() in forbidden_values:
            problems.append(f"hidden origin IP exposed in {key}")

    expected = dict(contract.get("common_exact") or {})
    provider_doc = (contract.get("providers") or {}).get(provider)
    if not isinstance(provider_doc, dict):
        problems.append("unknown provider")
        provider_doc = {}
    expected.update(provider_doc.get("exact") or {})
    for key, want in expected.items():
        got = str(env.get(key, "")).strip()
        if got != str(want):
            problems.append(f"{key}: expected {want!r}, got {got!r}")

    required = list(contract.get("required_nonempty") or [])
    required.extend(provider_doc.get("required_nonempty") or [])
    for key in required:
        try:
            nonempty(env, key)
        except RuntimeError as exc:
            problems.append(str(exc))

    for key in ("WORKER_VLESS_UUID", "ARVAN_DIRECT_UUID", "PARSPACK_DIRECT_UUID"):
        value = str(env.get(key, "")).strip()
        if value and not UUID_RE.fullmatch(value):
            problems.append(f"invalid UUID: {key}")

    for key in ("WORKER_XHTTP_PATH", "DIRECT_ORIGIN_PATH",
                "WORKER_DIRECT_RELAY_PATH", "WORKER_DIRECT_PATH",
                "WORKER_FIXED_RELAY_PATH", "WORKER_FIXED_PATH"):
        if key in env:
            value = str(env.get(key, "")).strip()
            if value and not value.startswith("/"):
                problems.append(f"path must start with /: {key}")

    port = str(env.get("DIRECT_ORIGIN_PORT", "")).strip()
    if port:
        try:
            number = int(port)
            if not 1 <= number <= 65535:
                raise ValueError
        except Exception:
            problems.append("DIRECT_ORIGIN_PORT must be 1..65535")

    for key in ("DIRECT_ORIGIN_SERVERNAME", "WORKER_SERVER_NAME",
                "ARVAN_DIRECT_HOST", "PARSPACK_DIRECT_HOST"):
        value = str(env.get(key, "")).strip()
        if value and is_ip(value):
            problems.append(f"TLS server name must be a hostname: {key}")

    if provider == "arvan":
        for key in (
            "WORKER_DIRECT_RELAY_PATH", "WORKER_DIRECT_HOST", "WORKER_DIRECT_PATH",
            "WORKER_FIXED_RELAY_PATH", "WORKER_FIXED_HOST", "WORKER_FIXED_PATH",
        ):
            if key in env and str(env[key]).strip():
                problems.append(f"ParsPack-only worker relay key present on Arvan: {key}")

    if problems:
        raise RuntimeError("\n".join(problems))
    return True

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", choices=("arvan", "parspack"), required=True)
    ap.add_argument("--env", required=True)
    ap.add_argument("--contract", default="migration/provider_env_contract.json")
    args = ap.parse_args()

    contract = json.loads(Path(args.contract).read_text())
    if int(contract.get("version", 0)) != 1:
        raise RuntimeError("unsupported contract version")
    env = load_env(args.env)
    validate(args.provider, env, contract)
    print(f"PROVIDER_ENV=PASS provider={args.provider} keys={len(env)}")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"PROVIDER_ENV=FAIL {exc}")
        raise SystemExit(1)

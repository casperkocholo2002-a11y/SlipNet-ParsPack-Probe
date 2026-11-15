#!/usr/bin/env python3
import asyncio
import json
import os
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 19190
STATE_PATH = Path("/run/slipnet-smart-egress/state.json")
PERSIST_DIR = Path("/var/lib/slipnet-smart-egress")
ALERT_STATE_PATH = PERSIST_DIR / "route-health.json"
ALERT_LOG_PATH = PERSIST_DIR / "alerts.jsonl"
ALERT_HOOK = Path("/usr/local/sbin/slipnet-route-alert-deliver")

HEALTH_INTERVAL = 15.0
FAIL_STREAK_REQUIRED = 4
RECOVERY_SUCCESS_REQUIRED = 2
MIN_FAILBACK_DWELL = 60.0

ROUTES = {
    "worker": {"host": "127.0.0.1", "port": 19085},
    "parspack": {"host": "127.0.0.1", "port": 19187},
    "arvan": {"host": "127.0.0.1", "port": 19186},
}
ROUTE_ORDER = ["worker", "arvan", "parspack"]
PREFERENCE_PATH = PERSIST_DIR / "preference.json"


stats = {
    name: {
        "healthy": False,
        "success_streak": 0,
        "fail_streak": 0,
        "latency_ms": None,
        "last_health": 0.0,
        "last_success": 0.0,
        "last_error": None,
    }
    for name in ROUTES
}

selected = "worker"
last_switch = time.monotonic()
switch_reason = "startup"
stop_event = asyncio.Event()


def load_reported_health():
    try:
        data = json.loads(ALERT_STATE_PATH.read_text())
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if k in ROUTES and v in ("UP", "DOWN")}
    except Exception:
        pass
    return {}


reported_health = load_reported_health()

def load_preference():
    try:
        data = json.loads(PREFERENCE_PATH.read_text())
        mode = str(data.get("mode") or "auto").lower()
        route = str(data.get("preferred") or "").lower()
        if mode == "manual" and route in ROUTES:
            return route
    except Exception:
        pass
    return None


def effective_order():
    if preferred_route in ROUTES:
        return [preferred_route] + [name for name in ROUTE_ORDER if name != preferred_route]
    return list(ROUTE_ORDER)


preferred_route = load_preference()
preference_signature = ("manual", preferred_route) if preferred_route else ("auto", None)
preference_changed = bool(preferred_route)


def refresh_preference():
    global preferred_route, preference_signature, preference_changed
    new_route = load_preference()
    new_signature = ("manual", new_route) if new_route else ("auto", None)
    if new_signature == preference_signature:
        return False
    old_route = preferred_route
    preferred_route = new_route
    preference_signature = new_signature
    preference_changed = True
    print(
        f"PREFERENCE old={old_route or 'auto'} new={preferred_route or 'auto'}",
        flush=True,
    )
    return True


def persist_reported_health():
    PERSIST_DIR.mkdir(parents=True, exist_ok=True)
    tmp = ALERT_STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(reported_health, ensure_ascii=False, separators=(",", ":")) + "\n")
    os.replace(tmp, ALERT_STATE_PATH)


def emit_route_alert(name, state):
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "route": name,
        "state": state,
        "selected": selected,
        "fail_streak": stats[name]["fail_streak"],
        "success_streak": stats[name]["success_streak"],
        "error": stats[name]["last_error"],
    }
    PERSIST_DIR.mkdir(parents=True, exist_ok=True)
    with ALERT_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")

    print(
        f"ROUTE_ALERT route={name} state={state} selected={selected} "
        f"error={stats[name]['last_error'] or '-'}",
        flush=True,
    )

    if ALERT_HOOK.exists() and os.access(ALERT_HOOK, os.X_OK):
        try:
            subprocess.Popen(
                [
                    str(ALERT_HOOK),
                    name,
                    state,
                    selected,
                    stats[name]["last_error"] or "",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        except Exception:
            pass


def evaluate_route_alerts():
    changed = False
    for name in ROUTE_ORDER:
        s = stats[name]

        if not s["healthy"] and s["fail_streak"] >= FAIL_STREAK_REQUIRED:
            current = "DOWN"
        elif s["healthy"] and s["success_streak"] >= 2:
            current = "UP"
        else:
            continue

        previous = reported_health.get(name)
        if previous is None:
            reported_health[name] = current
            changed = True
            if current == "DOWN":
                emit_route_alert(name, current)
        elif previous != current:
            reported_health[name] = current
            changed = True
            emit_route_alert(name, current)

    if changed:
        persist_reported_health()


def ewma(old, new, alpha=0.35):
    if old is None:
        return float(new)
    return (1.0 - alpha) * float(old) + alpha * float(new)


def snapshot(name):
    s = stats[name]
    return {
        "priority": ROUTE_ORDER.index(name) + 1,
        "healthy": s["healthy"],
        "success_streak": s["success_streak"],
        "fail_streak": s["fail_streak"],
        "latency_ms": round(s["latency_ms"], 1) if s["latency_ms"] is not None else None,
        "last_health_age_s": round(max(0.0, time.monotonic() - s["last_health"]), 1) if s["last_health"] else None,
        "last_error": s["last_error"],
    }


def write_state():
    payload = {
        "policy": "health_only_priority",
        "priority": ROUTE_ORDER,
        "effective_priority": effective_order(),
        "preference_mode": "manual" if preferred_route else "auto",
        "preferred": preferred_route,
        "selected": selected,
        "switch_reason": switch_reason,
        "selected_for_s": round(time.monotonic() - last_switch, 1),
        "routes": {name: snapshot(name) for name in ROUTE_ORDER},
        "updated_unix": int(time.time()),
    }
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
    os.replace(tmp, STATE_PATH)


async def run_curl(args, timeout=10):
    proc = await asyncio.create_subprocess_exec(
        "curl", *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return None, "timeout"

    if proc.returncode != 0:
        msg = err.decode("utf-8", "replace").strip()
        return None, msg[-180:] if msg else f"curl_exit_{proc.returncode}"
    return out.decode("utf-8", "replace"), None


async def probe_health(name):
    route = ROUTES[name]
    started = time.monotonic()

    out, err = await run_curl([
        "-sS",
        "--socks5-hostname", f"{route['host']}:{route['port']}",
        "--connect-timeout", "8",
        "--max-time", "12",
        "-o", "/dev/null",
        "-w", "%{http_code}",
        "https://www.google.com/generate_204",
    ], timeout=14)

    ok = out is not None and out.strip() == "204"

    # فقط هنگام شکست تست دوم می‌زنیم تا false-positive کم شود.
    if not ok:
        out2, err2 = await run_curl([
            "-sS",
            "--socks5-hostname", f"{route['host']}:{route['port']}",
            "--connect-timeout", "8",
            "--max-time", "12",
            "https://api.ipify.org",
        ], timeout=14)
        if out2 is not None and out2.strip():
            ok = True
            err = None
        else:
            err = err2 or err or "health_failed"

    elapsed_ms = (time.monotonic() - started) * 1000.0
    now = time.monotonic()
    s = stats[name]
    s["last_health"] = now

    if ok:
        s["success_streak"] += 1
        s["fail_streak"] = 0
        s["last_success"] = now
        s["latency_ms"] = ewma(s["latency_ms"], elapsed_ms)
        s["last_error"] = None
        s["healthy"] = True
    else:
        s["success_streak"] = 0
        s["fail_streak"] += 1
        s["last_error"] = err or "health_failed"
        if s["fail_streak"] >= FAIL_STREAK_REQUIRED:
            s["healthy"] = False


def first_healthy():
    for name in effective_order():
        if stats[name]["healthy"]:
            return name
    return None


def higher_priority_than(name):
    order = effective_order()
    idx = order.index(name)
    return order[:idx]


def evaluate_selection():
    global selected, last_switch, switch_reason, preference_changed

    current = stats[selected]
    order = effective_order()

    # Actual route death always triggers health-only failover.
    if not current["healthy"] and current["fail_streak"] >= FAIL_STREAK_REQUIRED:
        target = first_healthy()
        if target and target != selected:
            old = selected
            selected = target
            last_switch = time.monotonic()
            switch_reason = f"failover:{old}->{target}"
            print(f"SWITCH {switch_reason}", flush=True)
        return

    # An operator preference change may immediately select a route that is already healthy.
    if preference_changed:
        desired = order[0]
        if stats[desired]["healthy"] and desired != selected:
            old = selected
            selected = desired
            last_switch = time.monotonic()
            switch_reason = f"operator:{old}->{desired}"
            print(f"SWITCH {switch_reason}", flush=True)
        preference_changed = False
        return

    # Fail back to the preferred/default route only after stable recovery.
    if selected != order[0] and time.monotonic() - last_switch >= MIN_FAILBACK_DWELL:
        for candidate in higher_priority_than(selected):
            route_stats = stats[candidate]
            if route_stats["healthy"] and route_stats["success_streak"] >= RECOVERY_SUCCESS_REQUIRED:
                old = selected
                selected = candidate
                last_switch = time.monotonic()
                switch_reason = f"failback:{old}->{candidate}"
                print(f"SWITCH {switch_reason}", flush=True)
                return


async def monitor_loop():
    while not stop_event.is_set():
        await asyncio.gather(*(probe_health(n) for n in ROUTE_ORDER))
        evaluate_route_alerts()
        evaluate_selection()
        write_state()

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=HEALTH_INTERVAL)
        except asyncio.TimeoutError:
            pass


async def preference_loop():
    while not stop_event.is_set():
        if refresh_preference():
            evaluate_selection()
            write_state()
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            pass


async def read_exact(reader, n):
    return await asyncio.wait_for(reader.readexactly(n), timeout=8)


async def negotiate_upstream(route_name, request_bytes):
    route = ROUTES[route_name]
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(route["host"], route["port"]), timeout=3
    )

    writer.write(b"\x05\x01\x00")
    await writer.drain()
    reply = await read_exact(reader, 2)
    if reply != b"\x05\x00":
        writer.close()
        await writer.wait_closed()
        raise ConnectionError("upstream_socks_auth")

    writer.write(request_bytes)
    await writer.drain()

    head = await read_exact(reader, 4)
    if head[0] != 5:
        raise ConnectionError("upstream_bad_version")

    atyp = head[3]
    if atyp == 1:
        tail = await read_exact(reader, 6)
    elif atyp == 3:
        ln = await read_exact(reader, 1)
        tail = ln + await read_exact(reader, ln[0] + 2)
    elif atyp == 4:
        tail = await read_exact(reader, 18)
    else:
        raise ConnectionError("upstream_bad_atyp")

    response = head + tail
    if head[1] != 0:
        writer.close()
        await writer.wait_closed()
        raise ConnectionError(f"upstream_rep_{head[1]}")
    return reader, writer, response


def route_attempt_order():
    ordered = [selected]
    for name in effective_order():
        if name != selected and stats[name]["healthy"]:
            ordered.append(name)
    for name in effective_order():
        if name not in ordered:
            ordered.append(name)
    return ordered


async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_client(reader, writer):
    try:
        hello = await read_exact(reader, 2)
        if hello[0] != 5:
            return

        methods = await read_exact(reader, hello[1])
        if 0 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return

        writer.write(b"\x05\x00")
        await writer.drain()

        head = await read_exact(reader, 4)
        if head[0] != 5 or head[1] != 1:
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        atyp = head[3]
        if atyp == 1:
            addr = await read_exact(reader, 4)
        elif atyp == 3:
            ln = await read_exact(reader, 1)
            addr = ln + await read_exact(reader, ln[0])
        elif atyp == 4:
            addr = await read_exact(reader, 16)
        else:
            writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        port = await read_exact(reader, 2)
        request_bytes = head + addr + port

        upstream = None
        response = None
        for route_name in route_attempt_order():
            try:
                upstream_reader, upstream_writer, response = await negotiate_upstream(route_name, request_bytes)
                upstream = (upstream_reader, upstream_writer)
                break
            except Exception:
                continue

        if upstream is None:
            writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        writer.write(response)
        await writer.drain()
        upstream_reader, upstream_writer = upstream
        await asyncio.gather(
            pipe(reader, upstream_writer),
            pipe(upstream_reader, writer),
            return_exceptions=True,
        )
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main():
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    print(f"SMART_EGRESS_READY policy=health_only priority={','.join(ROUTE_ORDER)} {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    monitor = asyncio.create_task(monitor_loop())
    preference_watcher = asyncio.create_task(preference_loop())

    async with server:
        await stop_event.wait()

    monitor.cancel()
    preference_watcher.cancel()
    await asyncio.gather(monitor, preference_watcher, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
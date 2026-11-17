#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def test_authority_empty_snapshot_marks_ready():
    auth = load("authority_sync_test", "authority_sync.py")
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        auth.CACHE = td / "authority-applied.json"
        auth.PREFERENCE = td / "preference.json"
        auth.runtime_add = lambda *_args, **_kwargs: None
        auth.runtime_remove = lambda *_args, **_kwargs: None
        auth.bootstrap_users = lambda: {}
        count = auth.reconcile({
            "users": [],
            "route_preference": {"mode": "auto", "preferred": None},
        })
        assert count == 0
        assert json.loads(auth.CACHE.read_text()) == {}

class AliveProcess:
    def poll(self):
        return None

class DeadProcess:
    def poll(self):
        return 7

def test_entrypoint_waits_for_valid_authority_state():
    entry = load("shadow_entrypoint_test", "shadow_entrypoint.py")
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        entry.ROOT = td

        def writer():
            time.sleep(0.15)
            (td / "authority-applied.json").write_text("{}\n")

        thread = threading.Thread(target=writer)
        thread.start()
        payload = entry.wait_authority_ready(AliveProcess(), timeout=2)
        thread.join()
        assert payload == {}

def test_entrypoint_fails_if_authority_process_dies():
    entry = load("shadow_entrypoint_dead_test", "shadow_entrypoint.py")
    with tempfile.TemporaryDirectory() as td:
        entry.ROOT = pathlib.Path(td)
        try:
            entry.wait_authority_ready(DeadProcess(), timeout=1)
        except RuntimeError as exc:
            assert "exited before readiness" in str(exc)
        else:
            raise AssertionError("authority readiness did not fail closed")

if __name__ == "__main__":
    test_authority_empty_snapshot_marks_ready()
    test_entrypoint_waits_for_valid_authority_state()
    test_entrypoint_fails_if_authority_process_dies()
    print("SHADOW_STARTUP_TESTS=PASS")

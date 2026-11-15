#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

def sha256(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def run(args, *, input_bytes=None):
    p=subprocess.run(args,input=input_bytes,capture_output=True)
    if p.returncode!=0:
        out=(p.stdout or b"")+(p.stderr or b"")
        raise RuntimeError(out.decode("utf-8","replace")[-2000:] or "command failed")
    return p

def map_target(target_root, absolute_path):
    root=Path(target_root).resolve()
    rel=str(absolute_path).lstrip("/")
    return root / rel

def load_manifest(path):
    d=json.loads(Path(path).read_text())
    if int(d.get("version",0) or 0)!=1:
        raise RuntimeError("unsupported manifest version")
    return d

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--role",choices=("server155","server95"),required=True)
    ap.add_argument("--manifest",default="migration/production_manifest.json")
    ap.add_argument("--repo-root",default=".")
    ap.add_argument("--target-root",default="/")
    ap.add_argument("--apply",action="store_true")
    ap.add_argument("--backup-dir",default="")
    args=ap.parse_args()

    repo=Path(args.repo_root).resolve()
    manifest=load_manifest(repo/args.manifest)
    entries=(manifest.get("production_inputs") or {}).get(args.role) or {}
    if not entries:
        raise RuntimeError("no manifest entries for role")

    prepared=[]
    work=Path(tempfile.mkdtemp(prefix="no95-failclosed-"))
    try:
        for original,meta in entries.items():
            target=map_target(args.target_root,original)
            if not target.is_file():
                raise RuntimeError(f"target missing: {target}")

            actual=sha256(target)
            expected=str(meta.get("expected_sha256") or "")
            if actual!=expected:
                raise RuntimeError(
                    f"INPUT_SHA_MISMATCH {original} expected={expected} actual={actual}"
                )

            patch_rel=str(meta.get("patch") or "")
            patch_path=repo/patch_rel
            if not patch_path.is_file():
                raise RuntimeError(f"patch missing: {patch_rel}")
            patch_actual=sha256(patch_path)
            patch_expected=str((manifest.get("patch_sha256") or {}).get(patch_rel) or "")
            if patch_actual!=patch_expected:
                raise RuntimeError(
                    f"PATCH_SHA_MISMATCH {patch_rel} expected={patch_expected} actual={patch_actual}"
                )

            candidate=work/(target.name+".candidate")
            shutil.copy2(target,candidate)
            patch_bytes=patch_path.read_bytes()
            run(["patch","--batch",str(candidate)],input_bytes=patch_bytes)

            if candidate.suffix==".py":
                run([sys.executable,"-m","py_compile",str(candidate)])

            patched=sha256(candidate)
            patched_expected=str(meta.get("patched_sha256") or "")
            if patched!=patched_expected:
                raise RuntimeError(
                    f"OUTPUT_SHA_MISMATCH {original} expected={patched_expected} actual={patched}"
                )
            prepared.append((original,target,candidate,actual,patched))

        print(f"VERIFY=PASS role={args.role} files={len(prepared)}")
        for original,_,_,before,after in prepared:
            print(f"FILE {original} before={before} after={after}")

        if not args.apply:
            print("MODE=DRY_RUN")
            return 0

        stamp=time.strftime("%Y%m%dT%H%M%SZ",time.gmtime())
        if args.backup_dir:
            backup=Path(args.backup_dir)
        else:
            backup=map_target(args.target_root,f"/root/slipnet-backups/no95-{args.role}-{stamp}")
        backup.mkdir(parents=True,exist_ok=False)
        os.chmod(backup,0o700)

        replaced=[]
        try:
            for original,target,candidate,_,_ in prepared:
                rel=original.lstrip("/").replace("/","__")
                saved=backup/rel
                shutil.copy2(target,saved)
                os.chmod(saved,0o600)

            for original,target,candidate,_,after in prepared:
                tmp=target.with_name("."+target.name+".no95.tmp")
                shutil.copy2(candidate,tmp)
                with open(tmp,"rb") as f:
                    os.fsync(f.fileno())
                os.replace(tmp,target)
                replaced.append((original,target))
                if sha256(target)!=after:
                    raise RuntimeError(f"post-replace hash mismatch: {original}")

            print(f"APPLY=PASS role={args.role} backup={backup}")
            print("RESTART_REQUIRED=YES")
            return 0
        except Exception:
            for original,target in reversed(replaced):
                saved=backup/(original.lstrip("/").replace("/","__"))
                if saved.is_file():
                    shutil.copy2(saved,target)
            print("ROLLBACK=APPLIED",file=sys.stderr)
            raise
    finally:
        shutil.rmtree(work,ignore_errors=True)

if __name__=="__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL_CLOSED {type(exc).__name__}: {exc}",file=sys.stderr)
        raise SystemExit(1)

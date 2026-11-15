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

def repo_file(repo, relative_path):
    candidate=(repo/str(relative_path)).resolve()
    try:
        candidate.relative_to(repo)
    except ValueError:
        raise RuntimeError(f"repo path escapes root: {relative_path}")
    return candidate

def parse_mode(value):
    raw=str(value or "0644").strip().lower()
    if raw.startswith("0o"):
        raw=raw[2:]
    try:
        mode=int(raw,8)
    except Exception:
        raise RuntimeError(f"invalid file mode: {value}")
    if mode<0 or mode>0o7777:
        raise RuntimeError(f"invalid file mode: {value}")
    return mode

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
    module_prepared=[]
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
            patch_path=repo_file(repo,patch_rel)
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

            if target.suffix==".py":
                run([sys.executable,"-m","py_compile",str(candidate)])

            patched=sha256(candidate)
            patched_expected=str(meta.get("patched_sha256") or "")
            if patched!=patched_expected:
                raise RuntimeError(
                    f"OUTPUT_SHA_MISMATCH {original} expected={patched_expected} actual={patched}"
                )
            prepared.append((original,target,candidate,actual,patched))

        bundle=((manifest.get("module_bundle") or {}).get(args.role) or {})
        bundle_files=bundle.get("files") or {}
        bundle_root_raw=str(bundle.get("destination_root") or "").strip()
        if bundle_files and not bundle_root_raw:
            raise RuntimeError("module bundle destination_root missing")
        bundle_root=map_target(args.target_root,bundle_root_raw) if bundle_root_raw else None

        for rel,meta in bundle_files.items():
            src=repo_file(repo,rel)
            if not src.is_file():
                raise RuntimeError(f"module source missing: {rel}")
            actual=sha256(src)
            expected=str(meta.get("sha256") or "")
            if actual!=expected:
                raise RuntimeError(
                    f"MODULE_SHA_MISMATCH {rel} expected={expected} actual={actual}"
                )
            if src.suffix==".py":
                run([sys.executable,"-m","py_compile",str(src)])
            mode=parse_mode(meta.get("mode","0644"))
            dest=bundle_root/rel
            module_prepared.append((rel,src,dest,actual,mode))

        print(f"VERIFY=PASS role={args.role} files={len(prepared)}")
        for original,_,_,before,after in prepared:
            print(f"FILE {original} before={before} after={after}")
        if module_prepared:
            print(
                f"MODULE_BUNDLE=PASS role={args.role} files={len(module_prepared)} "
                f"root={bundle_root_raw}"
            )
            for rel,_,dest,digest,mode in module_prepared:
                print(
                    f"MODULE {rel} dest=/{str(dest.relative_to(Path(args.target_root).resolve()))} "
                    f"sha256={digest} mode={oct(mode)}"
                )

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
        module_replaced=[]
        try:
            for original,target,candidate,_,_ in prepared:
                rel=original.lstrip("/").replace("/","__")
                saved=backup/rel
                shutil.copy2(target,saved)
                os.chmod(saved,0o600)

            for rel,src,dest,_,mode in module_prepared:
                existed=dest.is_file()
                saved=backup/("module__"+rel.replace("/","__"))
                if existed:
                    shutil.copy2(dest,saved)
                    os.chmod(saved,0o600)

                dest.parent.mkdir(parents=True,exist_ok=True)
                if bundle_root is not None:
                    bundle_root.mkdir(parents=True,exist_ok=True)
                    os.chmod(bundle_root,0o755)
                    current_dir=bundle_root
                    for part in Path(rel).parent.parts:
                        current_dir=current_dir/part
                        current_dir.mkdir(exist_ok=True)
                        os.chmod(current_dir,0o755)

                tmp=dest.with_name("."+dest.name+".no95.tmp")
                shutil.copy2(src,tmp)
                os.chmod(tmp,mode)
                if os.geteuid()==0:
                    os.chown(tmp,0,0)
                with open(tmp,"rb") as f:
                    os.fsync(f.fileno())
                os.replace(tmp,dest)
                module_replaced.append((dest,existed,saved))
                if sha256(dest)!=sha256(src):
                    raise RuntimeError(f"post-install module hash mismatch: {rel}")

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
            if module_prepared:
                print(f"MODULE_INSTALL=PASS files={len(module_prepared)} root={bundle_root_raw}")
            print("RESTART_REQUIRED=YES")
            return 0
        except Exception:
            for original,target in reversed(replaced):
                saved=backup/(original.lstrip("/").replace("/","__"))
                if saved.is_file():
                    shutil.copy2(saved,target)

            for dest,existed,saved in reversed(module_replaced):
                try:
                    if existed and saved.is_file():
                        shutil.copy2(saved,dest)
                    elif not existed:
                        dest.unlink(missing_ok=True)
                except Exception:
                    pass

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

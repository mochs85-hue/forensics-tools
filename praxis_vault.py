#!/usr/bin/env python3
"""PRAXIS VAULT - Simple forensic file collector.
Copies files, hashes them (SHA-256), skips duplicates, writes manifest JSON.
"""

import os, sys, json, hashlib, shutil
from pathlib import Path
from datetime import datetime, timezone

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk: break
            h.update(chunk)
    return h.hexdigest()

HOME = Path.home()
VAULT = HOME / "Desktop" / "PRAXIS_EVIDENCE_VAULT"
DATA = VAULT / "files"
META = VAULT / "meta"

for d in [DATA, META]:
    d.mkdir(parents=True, exist_ok=True)

# All forensic source directories
SOURCES = [
    (HOME / "Desktop" / "Anthropic Forensics", "anthropic_forensics"),
]

manifest = []
hashes_seen = {}
files_added = 0
files_duped = 0
errors = 0

for src_dir, label in SOURCES:
    if not src_dir.exists():
        print(f"SKIP (not found): {src_dir}")
        continue

    print(f"\n=== {label}: {src_dir} ===")
    for fpath in sorted(src_dir.rglob("*")):
        if not fpath.is_file():
            continue

        try:
            relpath = str(fpath.relative_to(src_dir))
            fsize = fpath.stat().st_size

            # Hash the file
            fhash = sha256_file(fpath)

            # Check for duplicate
            if fhash in hashes_seen:
                manifest.append({
                    "status": "duplicate",
                    "hash": fhash,
                    "original_path": str(fpath),
                    "original_label": label,
                    "size": fsize,
                    "vault_path": str(hashes_seen[fhash]),
                    "relative": relpath,
                })
                files_duped += 1
                continue

            # Copy to vault
            subdir = DATA / fhash[:2]
            subdir.mkdir(exist_ok=True)
            dest = subdir / (fhash + "_" + fpath.name[:50])
            shutil.copy2(str(fpath), str(dest))

            # Save metadata
            meta = {
                "hash": fhash,
                "original_path": str(fpath),
                "label": label,
                "relative": relpath,
                "size": fsize,
                "vault_path": str(dest),
                "mtime": fpath.stat().st_mtime,
            }
            meta_file = META / (fhash + ".json")
            with open(meta_file, "w") as mf:
                json.dump(meta, mf, indent=2, default=str)

            manifest.append({
                "status": "added",
                "hash": fhash,
                "original_path": str(fpath),
                "label": label,
                "size": fsize,
                "vault_path": str(dest),
                "relative": relpath,
            })
            hashes_seen[fhash] = dest
            files_added += 1

            if (files_added + files_duped) % 100 == 0:
                print(f"  Added: {files_added} | Duped: {files_duped} | Errors: {errors}", end="\r")

        except Exception as e:
            errors += 1
            manifest.append({
                "status": "error",
                "original_path": str(fpath),
                "label": label,
                "error": str(e),
            })

print(f"\nAdded: {files_added} | Duped: {files_duped} | Errors: {errors}")

# Write manifest
manifest_path = VAULT / "manifest.json"
with open(manifest_path, "w") as f:
    json.dump({
        "generated": datetime.now(timezone.utc).isoformat(),
        "vault": str(VAULT),
        "added": files_added,
        "duplicates": files_duped,
        "errors": errors,
        "files": manifest,
    }, f, indent=2, default=str)

print(f"\nManifest: {manifest_path}")
print(f"Vault:    {VAULT}")

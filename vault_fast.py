#!/usr/bin/env python3
"""
PRAXIS FAST VAULT BUILDER — TARGETED ONLY
Scans ONLY known forensic directories. No broad keyword guessing.
~5 minutes instead of 5 hours.
"""
import os, sys, json, csv, hashlib, shutil, subprocess, time
from datetime import datetime
from pathlib import Path

VAULT = Path.home() / "Desktop" / "PRAXIS_COMPLETE_VAULT"

# ONLY these specific directories. Add more if needed.
TARGET_DIRS = [
    (Path.home() / "Desktop" / "Anthropic Forensics", "anthropic_forensics"),
    (Path.home() / "Desktop" / "PRAXIS_EVIDENCE", "praxis_evidence"),
    (Path.home() / "Desktop" / "ATTACK_FORENSICS", "attack_forensics"),
    (Path.home() / "Desktop", "desktop"),
]

# For Desktop root, only keep files matching these
DESKTOP_PATTERNS = [
    "praxis", "forensic", "evidence", "chatgpt", "claude", "gemini",
    "anthropic", "attack", "breach", "destruction", "chrysalis",
    "archon", "cowork", "mcas", "telegram", "bitlocker", "eeoc",
    "discrimination", "screenshot", "export", "conversation",
    "sandbox", "guard", "audit", "deactivate", "exfiltrat",
    "manifest", "vault", "parser", "parsed", "recon", "findings",
    "report", "database", "sqlite", "log", "sql",
]

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def sha256_file(fp):
    h = hashlib.sha256()
    with open(fp, "rb") as f:
        while True:
            chunk = f.read(8*1024*1024)
            if not chunk: break
            h.update(chunk)
    return h.hexdigest()

def keep_desktop_file(name):
    nl = name.lower()
    for p in DESKTOP_PATTERNS:
        if p.lower() in nl:
            return True
    return False

def build():
    start = time.time()
    log("=" * 50)
    log("PRAXIS FAST VAULT BUILDER")
    log("=" * 50)

    if VAULT.exists():
        log("Removing old vault...")
        shutil.rmtree(VAULT)
    VAULT.mkdir(parents=True, exist_ok=True)
    (VAULT / "originals").mkdir(exist_ok=True)
    (VAULT / "hashes").mkdir(exist_ok=True)
    (VAULT / "manifest").mkdir(exist_ok=True)

    files_to_collect = []

    for src_path, label in TARGET_DIRS:
        if not src_path.exists():
            log(f"SKIP: {src_path}")
            continue

        if label == "desktop":
            # Desktop root: strict filter, skip subdirs handled separately
            for item in src_path.iterdir():
                if item.is_file() and keep_desktop_file(item.name):
                    files_to_collect.append((label, item))
                elif item.is_dir() and keep_desktop_file(item.name) and item.name not in ("Anthropic Forensics", "PRAXIS_EVIDENCE", "ATTACK_FORENSICS", "PRAXIS_COMPLETE_VAULT"):
                    for root, dirs, files in os.walk(item):
                        dirs[:] = [d for d in dirs if not d.startswith(".")]
                        for f in files:
                            if not f.startswith(".") and keep_desktop_file(f):
                                files_to_collect.append((label, Path(root) / f))
        else:
            count = 0
            for root, dirs, files in os.walk(src_path):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for f in files:
                    if f.startswith("."): continue
                    files_to_collect.append((label, Path(root) / f))
                    count += 1
            log(f"{label}: {count:,} files")

    log(f"TOTAL: {len(files_to_collect):,} files to collect")
    print()

    log("Hashing and copying...")
    entries = []
    seen_hashes = set()
    dupes = 0

    for i, (label, src) in enumerate(files_to_collect, 1):
        if i % 100 == 0:
            log(f"  {i:,}/{len(files_to_collect):,}")

        try:
            h = sha256_file(src)
            if h in seen_hashes:
                dupes += 1
                continue
            seen_hashes.add(h)

            st = os.stat(src)
            meta = {
                "size": st.st_size, "mtime": st.mtime, "ctime": st.ctime,
                "birthtime": getattr(st, "st_birthtime", None),
                "mode": oct(st.st_mode),
            }

            try:
                base = next(p[0] for p in TARGET_DIRS if src.is_relative_to(p[0]))
                rel = src.parent.relative_to(base)
                sub = VAULT / "originals" / label / rel
            except:
                sub = VAULT / "originals" / label

            sub.mkdir(parents=True, exist_ok=True)
            dst = sub / src.name.replace("/", "_")

            if dst.exists():
                for n in range(1, 1000):
                    dst = sub / f"{src.stem}_{n:03d}{src.suffix}"
                    if not dst.exists(): break

            try:
                subprocess.run(["cp", "-p", str(src), str(dst)], check=True, capture_output=True, timeout=60)
            except:
                shutil.copy2(src, dst)

            entries.append({
                "id": i, "source": label, "filename": src.name,
                "hash": h, "size": st.st_size,
                "original": str(src), "vault_path": str(dst.relative_to(VAULT)),
                "meta": meta,
            })

            hf = VAULT / "hashes" / f"{h}.sha256"
            if not hf.exists():
                hf.write_text(f"{h}  {src.name}\n")

        except Exception as e:
            log(f"  ERR {src.name}: {e}")

    log(f"Collected: {len(entries):,} | Dupes: {dupes:,}")
    print()

    log("Writing manifests...")
    manifest = {
        "vault": "PRAXIS_COMPLETE_VAULT",
        "generated": datetime.now().isoformat(),
        "total_files": len(entries),
        "total_size": sum(e["size"] for e in entries),
        "entries": entries,
    }
    with open(VAULT / "manifest" / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2, default=str)

    with open(VAULT / "manifest" / "manifest.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "source", "filename", "hash", "size", "original", "vault"])
        for e in entries:
            w.writerow([e["id"], e["source"], e["filename"], e["hash"], e["size"], e["original"], e["vault_path"]])

    with open(VAULT / "manifest" / "sha256sums.txt", "w") as f:
        for e in entries:
            f.write(f"{e['hash']}  {e['vault_path']}\n")

    log("Verifying...")
    ok = sum(1 for e in entries if sha256_file(VAULT / e["vault_path"]) == e["hash"])

    elapsed = time.time() - start
    print()
    log("=" * 50)
    log(f"VAULT: {VAULT}")
    log(f"Files: {len(entries):,} | Verified: {ok:,}")
    log(f"Size: {sum(e['size'] for e in entries) / 1024**3:.2f} GB")
    log(f"Time: {elapsed:.1f}s")
    log("=" * 50)
    print(f"\nDrag to Google Drive: {VAULT}")

if __name__ == "__main__":
    try:
        build()
    except KeyboardInterrupt:
        print("\n[!] Stopped")
    except Exception as e:
        print(f"\n[FATAL] {e}")
        import traceback; traceback.print_exc()

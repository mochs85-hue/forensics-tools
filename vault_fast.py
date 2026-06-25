#!/usr/bin/env python3
"""
PRAXIS FAST VAULT BUILDER v2 — FIXED
Scans forensic directories, hashes, preserves metadata.
"""
import os, sys, json, csv, hashlib, shutil, subprocess, time
from datetime import datetime
from pathlib import Path

VAULT = Path.home() / "Desktop" / "PRAXIS_COMPLETE_VAULT"

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

def find_anthropic_folder():
    """Find the Anthropic Forensics folder regardless of exact name."""
    desktop = Path.home() / "Desktop"
    for item in desktop.iterdir():
        if item.is_dir() and "anthropic" in item.name.lower() and "forensic" in item.name.lower():
            return item
    # Try common variants
    for name in ["Anthropic Forensics", "AnthropicForensics", "Anthropic_Forensics", 
                 "anthropic forensics", "Anthropic Evidence"]:
        p = desktop / name
        if p.exists():
            return p
    return None

def build():
    start = time.time()
    log("=" * 50)
    log("PRAXIS FAST VAULT BUILDER v2")
    log("=" * 50)

    # Find directories
    anthropic = find_anthropic_folder()
    desktop = Path.home() / "Desktop"
    
    TARGETS = []
    if anthropic:
        TARGETS.append((anthropic, "anthropic_forensics"))
        log(f"Found Anthropic: {anthropic}")
    else:
        log("WARNING: Anthropic Forensics folder not found!")
    
    # Check for other forensic dirs
    for name, label in [("PRAXIS_EVIDENCE", "praxis_evidence"), ("ATTACK_FORENSICS", "attack_forensics"),
                        ("attack-evidence", "attack_evidence"), ("Evidence", "evidence")]:
        p = desktop / name
        if p.exists():
            TARGETS.append((p, label))
            log(f"Found: {p}")

    if not TARGETS:
        log("ERROR: No forensic directories found on Desktop!")
        log("Looking for: Anthropic Forensics, PRAXIS_EVIDENCE, ATTACK_FORENSICS")
        sys.exit(1)

    if VAULT.exists():
        log("Removing old vault...")
        shutil.rmtree(VAULT)
    VAULT.mkdir(parents=True, exist_ok=True)
    (VAULT / "originals").mkdir(exist_ok=True)
    (VAULT / "hashes").mkdir(exist_ok=True)
    (VAULT / "manifest").mkdir(exist_ok=True)

    # Collect ALL files from target dirs (no filtering - they're all forensic)
    files_to_collect = []
    for src_path, label in TARGETS:
        count = 0
        for root, dirs, files in os.walk(src_path):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in files:
                if f.startswith("."): continue
                fp = Path(root) / f
                try:
                    if fp.stat().st_size > 10 * 1024**3:  # Skip >10GB
                        log(f"  SKIP (too large): {f}")
                        continue
                except: pass
                files_to_collect.append((label, fp))
                count += 1
        log(f"{label}: {count:,} files")

    # Also collect forensic files from Desktop root
    desktop_patterns = ["praxis", "forensic", "evidence", "chatgpt", "claude", "gemini",
        "anthropic", "attack", "breach", "destruction", "chrysalis", "archon", "cowork",
        "mcas", "telegram", "bitlocker", "eeoc", "discrimination", "screenshot", "export",
        "conversation", "sandbox", "guard", "audit", "deactivate", "exfiltrat",
        "manifest", "vault", "parser", "parsed", "recon", "findings", "report",
        "database", "sqlite", "log", "sql", "wipe", "deletion"]
    
    desktop_count = 0
    for item in desktop.iterdir():
        if not item.is_file(): continue
        name = item.name.lower()
        # Skip the vault itself and scripts
        if name in ("praxis_complete_vault", "vault_fast.py", "vault_builder.py"): continue
        match = any(p in name for p in desktop_patterns)
        # Also keep by extension
        if not match and item.suffix.lower() in ('.db', '.sqlite', '.sqlite3', '.sql'):
            match = any(p in name for p in desktop_patterns + ['praxis', 'forensic', 'evidence', 'anthropic', 'claude'])
        if match:
            files_to_collect.append(("desktop", item))
            desktop_count += 1
    log(f"desktop_root: {desktop_count:,} files")

    log(f"TOTAL TO PROCESS: {len(files_to_collect):,}")
    print()

    log("Hashing and copying...")
    entries = []
    seen_hashes = set()
    dupes = 0
    errors = 0

    for i, (label, src) in enumerate(files_to_collect, 1):
        if i % 100 == 0:
            log(f"  {i:,}/{len(files_to_collect):,} | collected: {len(entries):,}")

        try:
            # Get stat info safely
            try:
                st = os.stat(src)
                size = st.st_size
                f_mtime = st.st_mtime
                f_ctime = st.st_ctime
                f_birth = getattr(st, 'st_birthtime', None)
                f_mode = oct(st.st_mode)
            except Exception as e:
                log(f"  STAT ERR {src.name}: {e}")
                errors += 1
                continue

            h = sha256_file(src)
            if h in seen_hashes:
                dupes += 1
                continue
            seen_hashes.add(h)

            meta = {"size": size, "mtime": f_mtime, "ctime": f_ctime,
                    "birthtime": f_birth, "mode": f_mode}

            # Build destination path
            try:
                base = next(p for p, l in TARGETS if src.is_relative_to(p))
                rel = src.parent.relative_to(base)
                sub = VAULT / "originals" / label / rel
            except:
                sub = VAULT / "originals" / label

            sub.mkdir(parents=True, exist_ok=True)
            safe_name = src.name.replace("/", "_").replace("\\", "_")
            dst = sub / safe_name

            if dst.exists():
                for n in range(1, 1000):
                    dst = sub / f"{src.stem}_{n:03d}{src.suffix}"
                    if not dst.exists(): break

            # Copy preserving metadata
            try:
                subprocess.run(["cp", "-p", str(src), str(dst)], check=True, capture_output=True, timeout=60)
            except:
                shutil.copy2(src, dst)

            entries.append({
                "id": i, "source": label, "filename": src.name,
                "hash": h, "size": size,
                "original": str(src), "vault_path": str(dst.relative_to(VAULT)),
                "meta": meta,
            })

            hf = VAULT / "hashes" / f"{h}.sha256"
            if not hf.exists():
                hf.write_text(f"{h}  {safe_name}\n")

        except Exception as e:
            log(f"  ERR {src.name}: {e}")
            errors += 1

    log(f"Collected: {len(entries):,} | Dupes: {dupes:,} | Errors: {errors:,}")
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

    log("Verifying hashes...")
    ok = sum(1 for e in entries if sha256_file(VAULT / e["vault_path"]) == e["hash"])

    elapsed = time.time() - start
    print()
    log("=" * 50)
    log(f"VAULT: {VAULT}")
    log(f"Files: {len(entries):,} | Verified: {ok:,}/{len(entries):,}")
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

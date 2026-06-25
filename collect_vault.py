#!/usr/bin/env python3
"""
PRAXIS FORENSICS VAULT COLLECTOR
Copies ALL forensic files from ALL sources into organized vault.
Hashes (SHA-256), preserves metadata, creates working copies.
Output: ~/Desktop/PRAXIS_COMPLETE_VAULT/
"""
import os, sys, json, csv, hashlib, shutil, subprocess, time
from datetime import datetime
from pathlib import Path
from collections import defaultdict

HOME = Path.home()
DESKTOP = HOME / "Desktop"
VAULT = DESKTOP / "PRAXIS_COMPLETE_VAULT"

# =============================================================================
# FIND FORENSIC DIRECTORIES (robust)
# =============================================================================
def find_anthropic_folder():
    if not DESKTOP.exists():
        return None
    for item in DESKTOP.iterdir():
        if item.is_dir() and "anthropic" in item.name.lower():
            return item
    return None

ANTHROPIC = find_anthropic_folder()

SOURCES = []
if ANTHROPIC and ANTHROPIC.exists():
    SOURCES.append((ANTHROPIC, "anthropic_forensics"))

for name, label in [
    ("PRAXIS_EVIDENCE", "praxis_evidence"),
    ("ATTACK_FORENSICS", "attack_forensics"),
    ("attack-evidence", "attack_evidence"),
]:
    p = DESKTOP / name
    if p.exists():
        SOURCES.append((p, label))

# Always include Desktop root for forensic files
SOURCES.insert(0, (DESKTOP, "desktop"))

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)

def sha256_file(fp):
    h = hashlib.sha256()
    with open(fp, "rb") as f:
        for chunk in iter(lambda: f.read(8*1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def copy_preserve(src, dst):
    """Copy with full macOS metadata preservation."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["cp", "-p", str(src), str(dst)], check=True,
                      capture_output=True, timeout=120)
    except Exception:
        shutil.copy2(src, dst)
    try:
        subprocess.run(["xattr", "-w", "com.praxis.original_path",
                       str(src), str(dst)], capture_output=True, timeout=10)
    except Exception:
        pass

def format_size(size):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"

# Desktop keywords for filtering DESKTOP ROOT only
def is_forensic_filename(name):
    nl = name.lower()
    keywords = ["praxis", "forensic", "evidence", "chatgpt", "claude", "gemini",
        "anthropic", "attack", "breach", "destruction", "chrysalis", "archon",
        "cowork", "mcas", "telegram", "bitlocker", "eeoc", "discrimination",
        "screenshot", "export", "conversation", "sandbox", "guard", "audit",
        "deactivate", "exfiltrat", "manifest", "vault", "parser", "parsed",
        "recon", "findings", "report", "database", "sqlite", "wipe", "deletion",
        "node_modules", "claude-agent", "global-agent", "@anthropic"]
    for kw in keywords:
        if kw in nl:
            return True
    ext = Path(name).suffix.lower()
    if ext in (".db", ".sqlite", ".sqlite3", ".sql", ".json", ".csv", ".log",
               ".txt", ".md", ".pdf", ".png", ".jpg", ".jpeg", ".zip", ".tar", ".gz"):
        for kw in ["praxis", "forensic", "evidence", "anthropic", "claude"]:
            if kw in nl:
                return True
    return False

def build():
    start = time.time()
    log("=" * 55)
    log("PRAXIS FORENSICS VAULT COLLECTOR")
    log("=" * 55)

    if not SOURCES:
        log("ERROR: No forensic directories found!")
        sys.exit(1)

    log(f"Sources ({len(SOURCES)}):")
    for p, label in SOURCES:
        log(f"  [{label}] {p}")

    # Clean old vault
    if VAULT.exists():
        log("Removing old vault...")
        shutil.rmtree(VAULT)
    VAULT.mkdir(parents=True, exist_ok=True)
    (VAULT / "originals").mkdir(exist_ok=True)
    (VAULT / "working_copies").mkdir(exist_ok=True)
    (VAULT / "hashes").mkdir(exist_ok=True)
    (VAULT / "manifest").mkdir(exist_ok=True)

    # Collect files
    files_to_process = []

    for src_path, label in SOURCES:
        if not src_path.exists():
            continue

        if label == "desktop":
            # Desktop ROOT: filter by forensic keywords
            for item in src_path.iterdir():
                if not item.is_file():
                    continue
                if item.name in ("PRAXIS_COMPLETE_VAULT", "collect_vault.py"):
                    continue
                if is_forensic_filename(item.name):
                    files_to_process.append((label, item))
            # Also walk subdirs that look forensic
            for item in src_path.iterdir():
                if not item.is_dir():
                    continue
                # Skip the vault itself and common non-forensic dirs
                if item.name in ("PRAXIS_COMPLETE_VAULT", "Applications", "Trash",
                                 "node_modules", ".git", ".venv", "venv"):
                    continue
                # If dir name matches forensic keywords, walk it
                if is_forensic_filename(item.name):
                    count = 0
                    for root, dirs, files in os.walk(item):
                        dirs[:] = [d for d in dirs if not d.startswith(".")]
                        for f in files:
                            if not f.startswith("."):
                                files_to_process.append((label, Path(root) / f))
                                count += 1
                    log(f"  {label}/{item.name}: {count:,} files")
        else:
            # Forensic directories: copy EVERYTHING
            count = 0
            for root, dirs, files in os.walk(src_path):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for f in files:
                    if f.startswith("."):
                        continue
                    fp = Path(root) / f
                    try:
                        if fp.stat().st_size > 10 * 1024**3:  # Skip >10GB
                            log(f"  SKIP (>10GB): {f}")
                            continue
                    except: pass
                    files_to_process.append((label, fp))
                    count += 1
            log(f"  {label}: {count:,} files")

    total = len(files_to_process)
    log(f"TOTAL TO COLLECT: {total:,}")
    log("-" * 40)

    # Process
    entries = []
    seen_hashes = set()
    dupes = 0
    errors = 0

    for i, (label, src) in enumerate(files_to_process, 1):
        if i % 100 == 0:
            log(f"  {i:,}/{total:,} | collected: {len(entries):,} | err: {errors:,}")

        try:
            try:
                st = os.stat(src)
                size = st.st_size
                mtime = st.st_mtime
                ctime = st.st_ctime
                birth = getattr(st, 'st_birthtime', None)
            except Exception as e:
                log(f"  STAT ERR: {src.name}: {e}")
                errors += 1
                continue

            content_hash = sha256_file(src)
            if content_hash in seen_hashes:
                dupes += 1
                continue
            seen_hashes.add(content_hash)

            # Build vault path
            try:
                base = next(p for p, l in SOURCES if src.is_relative_to(p))
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

            copy_preserve(src, dst)

            # Individual hash file
            hf = VAULT / "hashes" / f"{content_hash}.sha256"
            if not hf.exists():
                hf.write_text(f"{content_hash}  {safe_name}\n")

            # Working copy
            try:
                wc = VAULT / "working_copies" / dst.relative_to(VAULT / "originals")
                wc.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(dst, wc)
            except Exception:
                pass

            entries.append({
                "id": i, "source": label, "filename": src.name,
                "hash": content_hash, "size": size,
                "original": str(src), "vault_path": str(dst.relative_to(VAULT)),
                "mtime": mtime, "birthtime": birth,
            })

        except Exception as e:
            log(f"  ERR: {src.name}: {e}")
            errors += 1

    log(f"Collected: {len(entries):,} | Dupes: {dupes:,} | Errors: {errors:,}")
    log("-" * 40)

    # Manifests
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
            w.writerow([e["id"], e["source"], e["filename"], e["hash"],
                       e["size"], e["original"], e["vault_path"]])

    with open(VAULT / "manifest" / "SHA256SUMS", "w") as f:
        for e in entries:
            f.write(f"{e['hash']}  {e['vault_path']}\n")

    # Verify hashes
    log("Verifying...")
    ok = sum(1 for e in entries if sha256_file(VAULT / e["vault_path"]) == e["hash"])

    elapsed = time.time() - start
    print()
    log("=" * 55)
    log(f"VAULT: {VAULT}")
    log(f"Files: {len(entries):,} | Verified: {ok:,}")
    log(f"Size: {sum(e['size'] for e in entries) / 1024**3:.2f} GB")
    log(f"Time: {elapsed:.1f}s")
    log("=" * 55)
    print(f"\nDrag to Google Drive: {VAULT}")

if __name__ == "__main__":
    try:
        build()
    except KeyboardInterrupt:
        print("\n[!] Stopped")
    except Exception as e:
        print(f"\n[FATAL] {e}")
        import traceback
        traceback.print_exc()

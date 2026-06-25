#!/usr/bin/env python3
"""
PRAXIS LOCAL FORENSICS VAULT BUILDER
Runs ON YOUR MAC. Collects ALL forensic files from ALL sources.
Hashes (SHA-256), preserves metadata, deduplicates, creates working copies.
Output: ~/Desktop/PRAXIS_COMPLETE_VAULT/
"""
import os, sys, json, csv, hashlib, shutil, subprocess, time
from datetime import datetime
from pathlib import Path
from collections import defaultdict

VAULT_NAME = "PRAXIS_COMPLETE_VAULT"
HOME = Path.home()
DESKTOP = HOME / "Desktop"
VAULT_ROOT = DESKTOP / VAULT_NAME

SOURCES = [
    (DESKTOP, "desktop"),
    (DESKTOP / "Anthropic Forensics", "anthropic_forensics"),
    (DESKTOP / "PRAXIS_EVIDENCE", "praxis_evidence"),
    (DESKTOP / "ATTACK_FORENSICS", "attack_forensics"),
    (HOME / "Documents", "documents"),
    (HOME / "Google Drive", "google_drive"),
    (HOME / "Library/Mobile Documents/com~apple~CloudDocs", "icloud"),
    (HOME / ".kimi", "kimi_app"),
]

VOLUMES = Path("/Volumes")
if VOLUMES.exists():
    for mount in VOLUMES.iterdir():
        if mount.is_dir() and not mount.name.startswith("."):
            SOURCES.append((mount, f"external_{mount.name.replace(' ', '_')}"))

FORENSIC_KEYWORDS = [
    "praxis", "forensic", "evidence", "chatgpt", "claude", "gemini",
    "anthropic", "openai", "attack", "breach", "database", "sqlite",
    "chrysalis", "archon", "cowork", "mcas", "telegram", "bitlocker",
    "screenshot", "export", "conversation", "log", "hash", "manifest",
    "vault", "legal", "eeoc", "discrimination", "destruction", "deactivate",
    "exfiltrat", "ransomware", "malware", "backdoor", "privilege",
    "lateral", "persistence", "tamper", "inject", "exploit",
]

FORENSIC_EXTENSIONS = {
    ".db", ".sqlite", ".sqlite3", ".sql", ".json", ".csv", ".xml",
    ".log", ".txt", ".md", ".pdf", ".png", ".jpg", ".jpeg",
    ".plist", ".db-wal", ".db-shm", ".wal", ".sh", ".py", ".js",
    ".zip", ".tar", ".gz", ".tgz", ".dmg", ".iso",
}

MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024
SKIP_PATTERNS = [
    ".DS_Store", ".Trash", ".Spotlight-V100", ".fseventsd",
    "__MACOSX", ".TemporaryItems", "node_modules", ".git",
    ".venv", "venv", "site-packages", "Library/Caches", "Library/Logs",
]

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)

def sha256_file(filepath):
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8 * 1024 * 1024)
                if not chunk: break
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        log(f"  ERROR hashing {filepath}: {e}")
        return None

def get_file_metadata(filepath):
    meta = {}
    try:
        st = os.stat(filepath)
        meta["size"] = st.st_size
        meta["mode"] = oct(st.st_mode)
        meta["uid"] = st.st_uid
        meta["gid"] = st.st_gid
        meta["atime"] = st.st_atime
        meta["mtime"] = st.st_mtime
        meta["ctime"] = st.st_ctime
        meta["birthtime"] = getattr(st, "st_birthtime", None)
        meta["inode"] = st.st_ino
    except Exception as e:
        meta["stat_error"] = str(e)
    try:
        result = subprocess.run(["xattr", "-l", str(filepath)], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            meta["xattrs"] = result.stdout.strip()
    except Exception:
        pass
    return meta

def is_forensic_file(filepath):
    name_lower = filepath.name.lower()
    stem_lower = filepath.stem.lower()
    full_lower = str(filepath).lower()
    for kw in FORENSIC_KEYWORDS:
        if kw in name_lower or kw in stem_lower:
            return True, f"keyword:{kw}"
    if filepath.suffix.lower() in FORENSIC_EXTENSIONS:
        return True, f"ext:{filepath.suffix}"
    for path_part in full_lower.split(os.sep):
        for kw in FORENSIC_KEYWORDS:
            if kw in path_part and len(path_part) < 50:
                return True, f"path:{path_part}"
    return False, None

def should_skip(path):
    path_str = str(path)
    for skip in SKIP_PATTERNS:
        if skip in path_str:
            return True
    return False

def copy_preserve_metadata(src, dst):
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["cp", "-p", str(src), str(dst)], check=True, capture_output=True, timeout=60)
    except Exception:
        shutil.copy2(src, dst)
    try:
        subprocess.run(["xattr", "-w", "com.praxis.original_path", str(src), str(dst)], capture_output=True, timeout=10)
    except Exception:
        pass

def format_size(size):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"

def build_vault():
    start_time = time.time()
    log("=" * 60)
    log("PRAXIS LOCAL FORENSICS VAULT BUILDER")
    log("=" * 60)

    if VAULT_ROOT.exists():
        log(f"Removing old vault: {VAULT_ROOT}")
        shutil.rmtree(VAULT_ROOT)

    VAULT_ROOT.mkdir(parents=True, exist_ok=True)
    (VAULT_ROOT / "originals").mkdir(exist_ok=True)
    (VAULT_ROOT / "working_copies").mkdir(exist_ok=True)
    (VAULT_ROOT / "hashes").mkdir(exist_ok=True)
    (VAULT_ROOT / "manifest").mkdir(exist_ok=True)

    log(f"Sources: {len(SOURCES)}")
    for src_path, src_label in SOURCES:
        exists = "EXISTS" if src_path.exists() else "MISSING"
        log(f"  [{exists}] {src_label}: {src_path}")
    print()

    log("PHASE 1: DISCOVERING FILES...")
    discovered = []
    total_scanned = 0

    for src_path, src_label in SOURCES:
        if not src_path.exists():
            continue
        source_files = []
        try:
            if src_path.is_file():
                source_files.append(src_path)
                total_scanned += 1
            else:
                for root, dirs, files in os.walk(src_path):
                    dirs[:] = [d for d in dirs if not should_skip(Path(root) / d)]
                    for filename in files:
                        filepath = Path(root) / filename
                        if should_skip(filepath):
                            continue
                        try:
                            if filepath.stat().st_size > MAX_FILE_SIZE:
                                continue
                        except:
                            continue
                        source_files.append(filepath)
                        total_scanned += 1
                        if total_scanned % 10000 == 0:
                            log(f"  scanned {total_scanned:,}...")
        except PermissionError:
            pass

        forensic_count = 0
        for filepath in source_files:
            is_forensic, reason = is_forensic_file(filepath)
            if is_forensic:
                discovered.append((src_label, filepath))
                forensic_count += 1
        log(f"  {src_label}: {forensic_count:,} forensic / {len(source_files):,} total")

    log(f"TOTAL DISCOVERED: {len(discovered):,} forensic files")
    print()

    log("PHASE 2: HASHING & COLLECTING...")
    vault_entries = []
    content_hashes = {}
    duplicates = []
    errors = []

    for i, (src_label, orig_path) in enumerate(discovered, 1):
        if i % 100 == 0:
            log(f"  {i:,}/{len(discovered):,}...")
        try:
            content_hash = sha256_file(orig_path)
            if content_hash is None:
                errors.append((str(orig_path), "hash_failed"))
                continue
            if content_hash in content_hashes:
                duplicates.append({
                    "path": str(orig_path),
                    "original_of": content_hashes[content_hash]["vault_path"],
                    "hash": content_hash,
                })
                continue

            metadata = get_file_metadata(orig_path)
            safe_name = orig_path.name.replace("/", "_").replace("\\", "_")

            try:
                src_base = next(s[0] for s in SOURCES if orig_path.is_relative_to(s[0]))
                rel_dir = orig_path.parent.relative_to(src_base)
                vault_subdir = VAULT_ROOT / "originals" / src_label / rel_dir
            except (StopIteration, ValueError):
                vault_subdir = VAULT_ROOT / "originals" / src_label

            vault_subdir.mkdir(parents=True, exist_ok=True)
            vault_path = vault_subdir / safe_name

            counter = 1
            original_vault_path = vault_path
            while vault_path.exists():
                stem = original_vault_path.stem
                suffix = original_vault_path.suffix
                vault_path = original_vault_path.parent / f"{stem}_{counter:03d}{suffix}"
                counter += 1

            copy_preserve_metadata(orig_path, vault_path)

            hash_file = VAULT_ROOT / "hashes" / f"{content_hash}.sha256"
            if not hash_file.exists():
                hash_file.write_text(f"{content_hash}  {safe_name}\n")

            entry = {
                "id": i,
                "source": src_label,
                "original_path": str(orig_path),
                "original_resolved": str(orig_path.resolve()),
                "vault_path": str(vault_path),
                "vault_relative": str(vault_path.relative_to(VAULT_ROOT)),
                "filename": orig_path.name,
                "content_hash": content_hash,
                "size": orig_path.stat().st_size,
                "size_human": format_size(orig_path.stat().st_size),
                "metadata": metadata,
                "collected_at": datetime.now().isoformat(),
            }
            vault_entries.append(entry)
            content_hashes[content_hash] = entry
        except Exception as e:
            errors.append((str(orig_path), str(e)))

    log(f"Collected: {len(vault_entries):,} unique")
    log(f"Duplicates: {len(duplicates):,}")
    log(f"Errors: {len(errors):,}")
    print()

    log("PHASE 3: WORKING COPIES...")
    for entry in vault_entries:
        working_path = VAULT_ROOT / "working_copies" / entry["vault_relative"].replace("originals/", "", 1)
        working_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(Path(entry["vault_path"]), working_path)
        except Exception as e:
            pass
    print()

    log("PHASE 4: MANIFEST...")
    manifest = {
        "vault_name": VAULT_NAME,
        "generated": datetime.now().isoformat(),
        "system": {"platform": sys.platform, "hostname": os.uname().nodename if hasattr(os, "uname") else "unknown", "user": os.environ.get("USER", "?")},
        "stats": {
            "scanned": total_scanned,
            "discovered": len(discovered),
            "collected": len(vault_entries),
            "duplicates": len(duplicates),
            "errors": len(errors),
            "total_size": format_size(sum(e["size"] for e in vault_entries)),
        },
        "entries": vault_entries,
        "duplicates": duplicates,
    }
    with open(VAULT_ROOT / "manifest" / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2, default=str)

    with open(VAULT_ROOT / "manifest" / "manifest.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "source", "filename", "hash", "size", "original_path", "vault_path"])
        for e in vault_entries:
            writer.writerow([e["id"], e["source"], e["filename"], e["content_hash"], e["size"], e["original_path"], e["vault_relative"]])

    with open(VAULT_ROOT / "manifest" / "sha256sums.txt", "w") as f:
        for e in vault_entries:
            f.write(f"{e['content_hash']}  {e['vault_relative']}\n")
    print()

    log("PHASE 5: VERIFYING...")
    passed = 0
    failed = 0
    for e in vault_entries:
        current = sha256_file(Path(e["vault_path"]))
        if current == e["content_hash"]:
            passed += 1
        else:
            failed += 1
    log(f"Verification: {passed:,} passed, {failed:,} failed")
    print()

    readme = f"""{'='*60}
PRAXIS_COMPLETE_VAULT
Generated: {datetime.now().isoformat()}
Files: {len(vault_entries):,} unique
Size: {format_size(sum(e['size'] for e in vault_entries))}
Verification: {passed:,} passed, {failed:,} failed

DIRECTORIES:
  originals/       <- PRESERVED originals (NEVER modify)
  working_copies/  <- Analysis copies
  hashes/          <- SHA-256 per file
  manifest/        <- JSON, CSV, hash list

NEXT: Drag this folder to Google Drive
{'='*60}"""
    (VAULT_ROOT / "README.txt").write_text(readme)

    elapsed = time.time() - start_time
    print()
    log("=" * 60)
    log("VAULT COMPLETE")
    log(f"Location: {VAULT_ROOT}")
    log(f"Files: {len(vault_entries):,}")
    log(f"Size: {format_size(sum(e['size'] for e in vault_entries))}")
    log(f"Time: {elapsed:.1f}s")
    log("=" * 60)
    print(f"\nDrag to Google Drive: {VAULT_ROOT}")

if __name__ == "__main__":
    try:
        build_vault()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n[FATAL] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

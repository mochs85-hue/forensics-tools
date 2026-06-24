#!/usr/bin/env python3
"""
PRAXIS EVIDENCE VAULT — Master Collector
=========================================
Consolidates ALL original forensic files from scattered locations into a single
tamper-evident vault. Preserves metadata, hashes (SHA-256), deduplicates,
and maintains chain-of-custody.

Usage:
    # Scan all known locations and build vault
    python3 praxis_evidence_vault.py --vault ~/Desktop/PRAXIS_EVIDENCE_VAULT --collect-all

    # Add specific directory
    python3 praxis_evidence_vault.py --vault ~/Desktop/PRAXIS_EVIDENCE_VAULT --add /path/to/files --label "HP EliteBook Original SSD"

    # Verify vault integrity
    python3 praxis_evidence_vault.py --vault ~/Desktop/PRAXIS_EVIDENCE_VAULT --verify

    # Export manifest report
    python3 praxis_evidence_vault.py --vault ~/Desktop/PRAXIS_EVIDENCE_VAULT --report
"""
import os, sys, json, hashlib, shutil, sqlite3, argparse, subprocess
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

ZERO_HASH = "0" * 64

def h(data): 
    return hashlib.sha256(str(data).encode()).hexdigest()

def file_hash(filepath, algorithm="sha256"):
    """Compute hash of file contents."""
    hasher = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192 * 1024):  # 8MB chunks
            hasher.update(chunk)
    return hasher.hexdigest()

def get_metadata(filepath):
    """Extract all available file metadata."""
    stat = os.stat(filepath)
    meta = {
        "path": str(filepath),
        "filename": filepath.name,
        "size_bytes": stat.st_size,
        "mode": oct(stat.st_mode),
        "uid": stat.st_uid,
        "gid": stat.st_gid,
        "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "atime": datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat(),
        "ctime": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
    }
    # macOS birth time
    if hasattr(stat, 'st_birthtime'):
        meta["birthtime"] = datetime.fromtimestamp(stat.st_birthtime, tz=timezone.utc).isoformat()
    # Extended attributes (macOS)
    try:
        xattrs = subprocess.run(['xattr', '-l', str(filepath)], capture_output=True, text=True, timeout=10)
        if xattrs.returncode == 0 and xattrs.stdout.strip():
            meta["xattrs"] = xattrs.stdout[:2000]  # Truncate if massive
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # Resource fork (macOS)
    rsrc_path = Path(str(filepath) + "/..namedfork/rsrc")
    if rsrc_path.exists() and rsrc_path.stat().st_size > 0:
        meta["resource_fork_size"] = rsrc_path.stat().st_size
    return meta

def copy_preserve_metadata(src, dst):
    """Copy file preserving all possible metadata."""
    # Ensure parent exists
    dst.parent.mkdir(parents=True, exist_ok=True)
    # Copy with shutil (preserves basic metadata)
    shutil.copy2(str(src), str(dst))
    # Try to preserve extended attributes
    try:
        subprocess.run(['xattr', '-w', 'com.praxis.source', str(src), str(dst)], 
                      capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return dst

class EvidenceVault:
    def __init__(self, vault_path):
        self.vault = Path(vault_path)
        self.data_dir = self.vault / "data"          # Actual file storage
        self.meta_dir = self.vault / "metadata"      # JSON metadata files
        self.manifest_path = self.vault / "manifest.db"  # SQLite manifest
        self.dup_dir = self.vault / "duplicates"     # Symlinks to duplicates
        self._init_vault()
    
    def _init_vault(self):
        """Initialize vault directory structure."""
        for d in [self.data_dir, self.meta_dir, self.dup_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        # Create append-only manifest
        conn = sqlite3.connect(str(self.manifest_path))
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                original_path TEXT NOT NULL,
                vault_path TEXT NOT NULL,
                source_label TEXT,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER,
                mtime TEXT,
                atime TEXT,
                ctime TEXT,
                birthtime TEXT,
                mode TEXT,
                uid INTEGER,
                gid INTEGER,
                collected_at TEXT,
                prev_hash TEXT,
                row_hash TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS duplicates (
                id INTEGER PRIMARY KEY,
                file_id INTEGER,
                original_path TEXT,
                source_label TEXT,
                collected_at TEXT,
                FOREIGN KEY (file_id) REFERENCES files(id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS hash_index (
                sha256 TEXT PRIMARY KEY,
                file_id INTEGER,
                vault_path TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS chain_state (
                table_name TEXT PRIMARY KEY,
                head_hash TEXT,
                row_count INTEGER
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY,
                action TEXT,
                target_table TEXT,
                target_id INTEGER,
                details TEXT,
                performed_at TEXT,
                prev_hash TEXT,
                row_hash TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY,
                path TEXT,
                label TEXT,
                scanned_at TEXT,
                files_found INTEGER,
                files_added INTEGER,
                files_deduped INTEGER
            )
        ''')
        conn.commit()
        conn.close()
        
        # Write README
        readme = self.vault / "README.txt"
        if not readme.exists():
            readme.write_text(f"""PRAXIS EVIDENCE VAULT
=====================
Created: {datetime.now(timezone.utc).isoformat()}
Owner: Michael J. Ochs
Classification: Attorney-Client Privileged / Attorney Work Product

DIRECTORY STRUCTURE:
- data/         : Original files, deduplicated, hashed
- metadata/     : JSON metadata for each file
- duplicates/   : Symlinks to duplicate originals
- manifest.db   : Tamper-evident SQLite manifest with hash chains

DO NOT MODIFY FILES IN data/ — This destroys the hash chain.

VERIFICATION:
    python3 praxis_evidence_vault.py --vault {self.vault} --verify
""")
    
    def _get_prev_hash(self):
        conn = sqlite3.connect(str(self.manifest_path))
        c = conn.cursor()
        c.execute("SELECT row_hash FROM files ORDER BY id DESC LIMIT 1")
        row = c.fetchone()
        conn.close()
        return row[0] if row else ZERO_HASH
    
    def add_file(self, filepath, source_label="unknown"):
        """Add a single file to the vault. Deduplicates by SHA-256."""
        filepath = Path(filepath)
        if not filepath.exists() or not filepath.is_file():
            return None, "not_found"
        
        # Compute hash
        sha = file_hash(filepath)
        
        conn = sqlite3.connect(str(self.manifest_path))
        c = conn.cursor()
        
        # Check for duplicate
        c.execute("SELECT file_id, vault_path FROM hash_index WHERE sha256 = ?", (sha,))
        existing = c.fetchone()
        
        if existing:
            # Duplicate — record it, don't copy
            file_id, vault_path = existing
            c.execute('''
                INSERT INTO duplicates (file_id, original_path, source_label, collected_at)
                VALUES (?, ?, ?, ?)
            ''', (file_id, str(filepath), source_label, datetime.now(timezone.utc).isoformat()))
            conn.commit()
            conn.close()
            return {"status": "duplicate", "sha256": sha, "file_id": file_id, 
                    "vault_path": vault_path, "original": str(filepath)}
        
        # New unique file — copy to vault
        meta = get_metadata(filepath)
        
        # Generate vault path: data/XX/YYYY... (first 2 chars of hash as subdir)
        vault_subdir = self.data_dir / sha[:2]
        vault_subdir.mkdir(exist_ok=True)
        vault_path = vault_subdir / f"{sha}_{filepath.name[:50]}"
        
        # Copy file
        copy_preserve_metadata(filepath, vault_path)
        
        # Save metadata JSON
        meta_file = self.meta_dir / f"{sha}.json"
        meta["sha256"] = sha
        meta["vault_path"] = str(vault_path)
        meta["original_path"] = str(filepath)
        meta["source_label"] = source_label
        meta["collected_at"] = datetime.now(timezone.utc).isoformat()
        with open(meta_file, 'w') as f:
            json.dump(meta, f, indent=2, default=str)
        
        # Insert into manifest with hash chain
        prev_hash = self._get_prev_hash()
        row_data = f"{sha}|{filepath.name}|{meta['size_bytes']}|{source_label}|{prev_hash}"
        row_hash = h(row_data)
        
        c.execute('''
            INSERT INTO files (original_path, vault_path, source_label, sha256, size_bytes,
                             mtime, atime, ctime, birthtime, mode, uid, gid, collected_at,
                             prev_hash, row_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (str(filepath), str(vault_path), source_label, sha, meta['size_bytes'],
              meta.get('mtime'), meta.get('atime'), meta.get('ctime'), 
              meta.get('birthtime'), meta.get('mode'), meta.get('uid'), meta.get('gid'),
              meta['collected_at'], prev_hash, row_hash))
        file_id = c.lastrowid
        
        # Update hash index
        c.execute("INSERT INTO hash_index (sha256, file_id, vault_path) VALUES (?, ?, ?)",
                 (sha, file_id, str(vault_path)))
        
        conn.commit()
        conn.close()
        
        return {"status": "added", "sha256": sha, "file_id": file_id,
                "vault_path": str(vault_path), "size": meta['size_bytes']}
    
    def scan_directory(self, dirpath, source_label, recursive=True, min_size=1):
        """Scan a directory and add all files."""
        dirpath = Path(dirpath)
        if not dirpath.exists():
            print(f"  ERROR: Path not found: {dirpath}")
            return {"found": 0, "added": 0, "deduped": 0, "errors": 0}
        
        print(f"\n  Scanning: {dirpath}")
        print(f"  Label: {source_label}")
        
        files_found = 0
        files_added = 0
        files_deduped = 0
        errors = 0
        
        if recursive:
            iterator = dirpath.rglob("*")
        else:
            iterator = dirpath.iterdir()
        
        for item in iterator:
            if not item.is_file():
                continue
            if item.stat().st_size < min_size:
                continue
            
            files_found += 1
            try:
                result = self.add_file(item, source_label)
                if result:
                    if result['status'] == 'added':
                        files_added += 1
                    elif result['status'] == 'duplicate':
                        files_deduped += 1
                
                if (files_found) % 100 == 0:
                    print(f"    Scanned: {files_found:,} | Added: {files_added:,} | Deduped: {files_deduped:,}", end='\r')
            except Exception as e:
                errors += 1
                print(f"\n    ERROR on {item}: {e}")
        
        print(f"\n    Scanned: {files_found:,} | Added: {files_added:,} | Deduped: {files_deduped:,} | Errors: {errors}")
        
        # Record source scan
        conn = sqlite3.connect(str(self.manifest_path))
        c = conn.cursor()
        c.execute('''
            INSERT INTO sources (path, label, scanned_at, files_found, files_added, files_deduped)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (str(dirpath), source_label, datetime.now(timezone.utc).isoformat(),
              files_found, files_added, files_deduped))
        conn.commit()
        conn.close()
        
        return {"found": files_found, "added": files_added, "deduped": files_deduped, "errors": errors}
    
    def verify(self):
        """Verify vault integrity — check all hashes match stored values."""
        print("\n" + "=" * 60)
        print("  VAULT VERIFICATION")
        print("=" * 60)
        
        conn = sqlite3.connect(str(self.manifest_path))
        c = conn.cursor()
        c.execute("SELECT id, vault_path, sha256 FROM files ORDER BY id")
        files = c.fetchall()
        conn.close()
        
        ok = 0
        failed = 0
        missing = 0
        
        for fid, vpath, stored_sha in files:
            vp = Path(vpath)
            if not vp.exists():
                missing += 1
                print(f"  MISSING: #{fid} {vpath}")
                continue
            
            actual_sha = file_hash(vp)
            if actual_sha == stored_sha:
                ok += 1
            else:
                failed += 1
                print(f"  TAMPERED: #{fid} {vp.name}")
                print(f"    Stored:  {stored_sha}")
                print(f"    Actual:  {actual_sha}")
        
        print(f"\n  Verified: {ok} OK, {failed} TAMPERED, {missing} MISSING")
        return {"ok": ok, "failed": failed, "missing": missing}
    
    def report(self):
        """Generate comprehensive vault report."""
        conn = sqlite3.connect(str(self.manifest_path))
        c = conn.cursor()
        
        print("\n" + "=" * 60)
        print("  PRAXIS EVIDENCE VAULT REPORT")
        print("=" * 60)
        
        # Files
        c.execute("SELECT COUNT(*), SUM(size_bytes) FROM files")
        count, total_size = c.fetchone()
        print(f"\n  Total unique files: {count:,}")
        size_str = f"{total_size / (1024**3):.2f} GB" if total_size else "0 GB"
        print(f"  Total size: {size_str}")
        
        # Duplicates
        c.execute("SELECT COUNT(*) FROM duplicates")
        dup_count = c.fetchone()[0]
        print(f"  Duplicate originals: {dup_count:,}")
        
        # Sources
        c.execute("SELECT label, files_found, files_added, files_deduped FROM sources ORDER BY scanned_at")
        sources = c.fetchall()
        print(f"\n  Sources scanned: {len(sources)}")
        for label, found, added, deduped in sources:
            print(f"    {label}: found={found:,}, added={added:,}, deduped={deduped:,}")
        
        # Hash chain integrity
        c.execute("SELECT id, row_hash, prev_hash FROM files ORDER BY id")
        chain = c.fetchall()
        chain_ok = 0
        chain_broken = 0
        prev = ZERO_HASH
        for fid, rh, ph in chain:
            if ph == prev:
                chain_ok += 1
            else:
                chain_broken += 1
                if chain_broken <= 5:
                    print(f"  CHAIN BREAK at #{fid}")
            prev = rh
        
        print(f"\n  Hash chain: {chain_ok} linked, {chain_broken} breaks")
        
        conn.close()

# ─── Known Forensic Locations ───────────────────────────────────────────────

KNOWN_LOCATIONS = [
    # Anthropic Forensics (already scanned, but ensure originals are in vault)
    ("~/Desktop/Anthropic Forensics", "Anthropic Forensics Desktop"),
    ("~/Desktop/AnthropicForensics", "Anthropic Forensics Desktop Alt"),
    
    # ChatGPT Export
    ("~/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/MASTER_CHRONOLOGY", "Google Drive Master Chronology"),
    ("~/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/AI Related/Forensics", "Google Drive AI Forensics"),
    
    # Claude Exports
    ("~/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/Claude Exports", "Google Drive Claude Exports"),
    ("~/Desktop/Claude Exports", "Desktop Claude Exports"),
    ("~/Library/Application Support/Claude", "Claude App Local Data"),
    
    # Gemini
    ("~/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/AI Related/Gemini", "Google Drive Gemini"),
    ("~/Desktop/Gemini Exports", "Desktop Gemini Exports"),
    
    # Forensic databases and tools
    ("~/Desktop/praxis_forensics.db", "Praxis Forensics Database"),
    ("~/Desktop/*parser*.py", "Parser Scripts"),
    
    # HP EliteBook Original SSD (if mounted)
    ("/Volumes/HP ELITEBOOK", "HP EliteBook Original SSD"),
    ("/Volumes/EliteBook", "HP EliteBook Alt"),
    
    # External drives
    ("/Volumes/My Passport", "My Passport External"),
    ("/Volumes/EASystore", "EASystore External"),
    
    # iCloud
    ("~/Library/Mobile Documents/com~apple~CloudDocs", "iCloud Drive"),
    
    # Local forensic artifacts
    ("~/Desktop/*forensic*", "Desktop Forensic Files"),
    ("~/Desktop/*FORENSIC*", "Desktop Forensic Files Upper"),
    ("~/Desktop/chatgpt*.json", "ChatGPT Parse Results"),
    ("~/Desktop/*results*.txt", "Parse Result Logs"),
]

def auto_collect_all(vault):
    """Scan all known forensic locations and add to vault."""
    print("=" * 60)
    print("  AUTO-COLLECTING ALL FORENSIC EVIDENCE")
    print("=" * 60)
    
    grand_total = {"found": 0, "added": 0, "deduped": 0}
    
    for path_template, label in KNOWN_LOCATIONS:
        # Expand glob patterns
        expanded = list(Path.home().glob(path_template.lstrip('~/')))
        if not expanded:
            # Try as direct path
            direct = Path(path_template).expanduser()
            if direct.exists():
                expanded = [direct]
        
        for path in expanded:
            if path.is_file():
                # Single file
                result = vault.add_file(path, label)
                grand_total["found"] += 1
                if result and result['status'] == 'added':
                    grand_total["added"] += 1
                elif result and result['status'] == 'duplicate':
                    grand_total["deduped"] += 1
            elif path.is_dir():
                # Directory
                result = vault.scan_directory(path, label)
                for k in grand_total:
                    grand_total[k] += result.get(k, 0)
    
    print(f"\n{'='*60}")
    print(f"  COLLECTION COMPLETE")
    print(f"  Found: {grand_total['found']:,}")
    print(f"  Added: {grand_total['added']:,}")
    print(f"  Deduped: {grand_total['deduped']:,}")
    print(f"{'='*60}")
    return grand_total

# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PRAXIS Evidence Vault")
    parser.add_argument("--vault", default="~/Desktop/PRAXIS_EVIDENCE_VAULT", help="Vault path")
    parser.add_argument("--collect-all", action="store_true", help="Auto-collect all known locations")
    parser.add_argument("--add", help="Add specific file or directory")
    parser.add_argument("--label", default="manual", help="Source label for --add")
    parser.add_argument("--verify", action="store_true", help="Verify vault integrity")
    parser.add_argument("--report", action="store_true", help="Generate report")
    parser.add_argument("--file", help="Add single file")
    args = parser.parse_args()
    
    vault_path = Path(args.vault).expanduser()
    vault = EvidenceVault(vault_path)
    
    if args.collect_all:
        auto_collect_all(vault)
    
    if args.add:
        path = Path(args.add).expanduser()
        if path.is_file():
            result = vault.add_file(path, args.label)
            print(json.dumps(result, indent=2, default=str))
        elif path.is_dir():
            vault.scan_directory(path, args.label)
        else:
            print(f"ERROR: Path not found: {path}")
    
    if args.file:
        path = Path(args.file).expanduser()
        result = vault.add_file(path, args.label)
        print(json.dumps(result, indent=2, default=str))
    
    if args.verify:
        vault.verify()
    
    if args.report:
        vault.report()
    
    if not any([args.collect_all, args.add, args.file, args.verify, args.report]):
        parser.print_help()

if __name__ == "__main__":
    main()

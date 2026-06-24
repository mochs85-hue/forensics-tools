#!/usr/bin/env python3
"""
Anthropic Forensics Folder Explorer
Comprehensive scan of the Anthropic Forensics folder on Desktop.
Usage: python3 explore_anthropic_forensics.py [path]
Default path: ~/Desktop/Anthropic Fornsics
"""
import os, sys, json
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

def scan_folder(base_path):
    base = Path(base_path)
    if not base.exists():
        return None
    results = {
        "scan_path": str(base), "scan_time": datetime.now(timezone.utc).isoformat(),
        "total_files": 0, "total_dirs": 0, "total_size": 0,
        "by_extension": defaultdict(int),
        "conversations_json": [], "databases": [], "scripts": [],
        "screenshots": [], "documents": [], "archives": [], "other": [],
        "all_files": [],
    }
    for root, dirs, files in os.walk(base):
        results["total_dirs"] += len(dirs)
        for f in sorted(files):
            filepath = Path(root) / f
            try:
                stat = filepath.stat()
                size = stat.st_size
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                ext = filepath.suffix.lower()
                rel_path = str(filepath.relative_to(base))
                file_info = {"path": rel_path, "size": size, "size_human": f"{size/1024:.1f} KB" if size < 1024**2 else f"{size/(1024**2):.1f} MB" if size < 1024**3 else f"{size/(1024**3):.2f} GB", "modified": mtime}
                results["total_files"] += 1
                results["total_size"] += size
                results["by_extension"][ext] += 1
                results["all_files"].append(file_info)
                if f == "conversations.json":
                    results["conversations_json"].append(file_info)
                elif ext in ['.db', '.sqlite', '.sqlite3']:
                    results["databases"].append(file_info)
                elif ext in ['.py', '.js', '.ps1', '.bat', '.sh']:
                    results["scripts"].append(file_info)
                elif ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp']:
                    results["screenshots"].append(file_info)
                elif ext in ['.pdf', '.doc', '.docx', '.txt', '.md', '.html', '.csv']:
                    results["documents"].append(file_info)
                elif ext in ['.zip', '.tar', '.gz', '.bz2', '.7z']:
                    results["archives"].append(file_info)
                else:
                    results["other"].append(file_info)
            except (OSError, PermissionError):
                continue
    results["all_files"].sort(key=lambda x: x["size"], reverse=True)
    return results

def main():
    paths_to_try = [
        sys.argv[1] if len(sys.argv) > 1 else None,
        str(Path.home() / "Desktop" / "Anthropic Fornsics"),
        str(Path.home() / "Desktop" / "AnthropicForensics"),
        str(Path.home() / "Desktop" / "Anthropic_Forensics"),
        str(Path.home() / "Desktop" / "anthropic forensics"),
        str(Path.home() / "Desktop" / "anthropic-forensics"),
    ]
    for p in paths_to_try:
        if p and Path(p).exists():
            print(f"Scanning: {p}...")
            results = scan_folder(p)
            if not results:
                continue
            print(f"\n{'='*70}\n  ANTHROPIC FORENSICS SCAN\n{'='*70}")
            print(f"Path: {results['scan_path']}")
            size = results['total_size']
            size_str = f"{size/1024:.1f} KB" if size < 1024**2 else f"{size/(1024**2):.1f} MB" if size < 1024**3 else f"{size/(1024**3):.2f} GB"
            print(f"Files: {results['total_files']:,} | Dirs: {results['total_dirs']:,} | Size: {size_str}")
            print(f"\n--- conversations.json FILES ---")
            for f in results['conversations_json']:
                print(f"  {f['size_human']:>10s}  {f['path']}")
            if not results['conversations_json']:
                print("  None")
            print(f"\n--- DATABASES ---")
            for f in results['databases']:
                print(f"  {f['size_human']:>10s}  {f['path']}")
            if not results['databases']:
                print("  None")
            print(f"\n--- SCRIPTS ---")
            for f in results['scripts']:
                print(f"  {f['size_human']:>10s}  {f['path']}")
            if not results['scripts']:
                print("  None")
            print(f"\n--- DOCUMENTS ---")
            for f in results['documents'][:20]:
                print(f"  {f['size_human']:>10s}  {f['path']}")
            if not results['documents']:
                print("  None")
            print(f"\n--- ARCHIVES ---")
            for f in results['archives']:
                print(f"  {f['size_human']:>10s}  {f['path']}")
            if not results['archives']:
                print("  None")
            print(f"\n--- SCREENSHOTS ---")
            for f in results['screenshots'][:15]:
                print(f"  {f['size_human']:>10s}  {f['path']}")
            if not results['screenshots']:
                print("  None")
            print(f"\n--- LARGEST FILES (Top 20) ---")
            for f in results['all_files'][:20]:
                print(f"  {f['size_human']:>10s}  {f['path']}")
            print(f"\n--- FILE TYPES ---")
            for ext, count in sorted(results['by_extension'].items(), key=lambda x: -x[1])[:15]:
                print(f"  {ext or '(none)':12s}: {count}")
            report_path = Path.home() / "Desktop" / "anthropic_forensics_scan.json"
            with open(report_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\nSaved: {report_path}")
            return
    print("ERROR: Could not find Anthropic Forensics folder. Tried:")
    for p in paths_to_try:
        if p:
            print(f"  - {p}")
    print("\nUsage: python3 explore_anthropic_forensics.py <path>")

if __name__ == "__main__":
    main()

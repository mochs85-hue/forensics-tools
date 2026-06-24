#!/usr/bin/env python3
"""PRAXIS FORENSIC DISCOVERY - Scan all surfaces, no copy."""
import os, json
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

ALL_LOCATIONS = [
    ("~/Desktop/Anthropic Forensics", "Anthropic Forensics Desktop", "local"),
    ("~/Desktop/AnthropicForensics", "AnthropicForensics Alt", "local"),
    ("~/Desktop/praxis_forensics.db", "Praxis Forensics Database", "local"),
    ("~/Desktop/praxis_db_init.py", "Praxis DB Init Script", "local"),
    ("~/Desktop/destructive_command_parser.py", "Destructive Command Parser", "local"),
    ("~/Desktop/claude_export_parser.py", "Claude Export Parser", "local"),
    ("~/Desktop/fp_filter*.py", "FP Filter Scripts", "local"),
    ("~/Desktop/forensics_inventory.py", "Forensics Inventory", "local"),
    ("~/Desktop/find_ai_exports.py", "AI Export Finder", "local"),
    ("~/Desktop/recon.py", "Recon Script", "local"),
    ("~/Desktop/takeout_scanner.py", "Takeout Scanner", "local"),
    ("~/Desktop/PRAXIS_FORENSIC_HANDOFF_REPORT.md", "Handoff Report", "local"),
    ("~/Desktop/chatgpt_results.txt", "ChatGPT Parse Results", "local"),
    ("~/Desktop/chatgpt_results.json", "ChatGPT Parse Results JSON", "local"),
    ("~/Desktop/forensic*", "Desktop Forensic Files", "local"),
    ("~/Desktop/FORENSIC*", "Desktop Forensic Upper", "local"),
    ("~/Desktop/HP ELITEBOOK*", "HP EliteBook Desktop", "local"),
    ("~/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/MASTER_CHRONOLOGY", "GDrive Master Chronology", "gdrive"),
    ("~/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/AI Related/Forensics", "GDrive AI Forensics", "gdrive"),
    ("~/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/AI Related/Gemini", "GDrive Gemini", "gdrive"),
    ("~/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/Claude Exports", "GDrive Claude Exports", "gdrive"),
    ("~/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/Legal Cases Master", "GDrive Legal Cases", "gdrive"),
    ("~/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/AI /Gemini", "GDrive AI Gemini", "gdrive"),
    ("~/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/*Takeout*", "GDrive Takeout", "gdrive"),
    ("~/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/*EXPORT*", "GDrive Exports", "gdrive"),
    ("~/Library/Application Support/Claude", "Claude App Support", "appdata"),
    ("~/.claude", "Claude Code Local", "appdata"),
    ("~/.claude/projects", "Claude Code Projects", "appdata"),
    ("~/Library/Application Support/com.openai.chat", "ChatGPT App", "appdata"),
    ("~/Desktop/Gemini*", "Desktop Gemini", "local"),
    ("~/Desktop/*Gemini*", "Desktop Gemini Alt", "local"),
    ("~/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/*Gemini*", "GDrive All Gemini", "gdrive"),
    ("/Volumes/HP ELITEBOOK", "HP EliteBook SSD", "external"),
    ("/Volumes/HP_EliteBook", "HP EliteBook SSD Alt", "external"),
    ("/Volumes/EliteBook", "EliteBook SSD", "external"),
    ("/Volumes/My Passport", "My Passport", "external"),
    ("/Volumes/My_Passport", "My Passport Alt", "external"),
    ("/Volumes/EASystore", "EASystore", "external"),
    ("/Volumes/PRAXIS", "PRAXIS Drive", "external"),
    ("~/Library/Mobile Documents/com~apple~CloudDocs", "iCloud Drive", "icloud"),
    ("~/.bash_history", "Bash History", "system"),
    ("~/.zsh_history", "Zsh History", "system"),
    ("~/.python_history", "Python History", "system"),
    ("~/Library/Logs", "macOS User Logs", "system"),
    ("~/Library/Application Support/Google/DriveFS", "Google DriveFS", "system"),
    ("~/Downloads", "Downloads Folder", "system"),
    ("~/Downloads/*forensic*", "Downloads Forensic", "system"),
    ("~/Downloads/*FORENSIC*", "Downloads FORENSIC", "system"),
    ("~/Downloads/*export*", "Downloads Exports", "system"),
    ("~/Downloads/*claude*", "Downloads Claude", "system"),
    ("~/Downloads/*chatgpt*", "Downloads ChatGPT", "system"),
    ("~/Downloads/*gemini*", "Downloads Gemini", "system"),
    ("~/Library/Application Support/Praxis", "Praxis App", "appdata"),
    ("~/Desktop/PRAXIS*", "Desktop PRAXIS", "local"),
]

def expand_path(pattern):
    path = Path(pattern).expanduser()
    if '*' in str(path):
        if str(path).startswith(str(Path.home())):
            rel = str(path)[len(str(Path.home()))+1:]
            return list(Path.home().glob(rel))
        elif str(path).startswith('/Volumes/'):
            return list(Path('/Volumes').glob(path.name))
        return list(path.parent.glob(path.name))
    elif path.exists():
        return [path]
    return []

def quick_scan(path):
    try:
        if path.is_file():
            sz = path.stat().st_size
            sh = f"{sz/(1024**2):.1f} MB" if sz < 1024**3 else f"{sz/(1024**3):.2f} GB"
            return {"ok": True, "type": "file", "size": sz, "sh": sh, "files": 1}
        elif path.is_dir():
            ts = 0; fc = 0; ti = []
            for item in path.iterdir():
                if item.is_file():
                    s = item.stat().st_size; ts += s; fc += 1
                    if len(ti) < 12: ti.append((item.name, s))
                elif item.is_dir():
                    try:
                        sf = sum(1 for _ in item.rglob("*") if _.is_file())
                        ss = sum(_.stat().st_size for _ in item.rglob("*") if _.is_file())
                        ts += ss; fc += sf
                        if len(ti) < 12: ti.append((item.name + "/", ss, sf))
                    except: pass
            hh = f"{ts/(1024**3):.2f} GB" if ts >= 1024**3 else f"{ts/(1024**2):.1f} MB"
            return {"ok": True, "type": "dir", "size": ts, "sh": hh, "files": fc, "ti": ti}
    except (PermissionError, OSError) as e:
        return {"ok": True, "type": "err", "err": str(e)}
    return {"ok": False}

print("=" * 65)
print("PRAXIS FORENSIC DISCOVERY")
print("=" * 65)

found = []; missing = []; tf = 0; tb = 0
bt = defaultdict(lambda: {"c": 0, "s": 0, "l": []})

for pat, lbl, lt in ALL_LOCATIONS:
    ps = expand_path(pat)
    if not ps: missing.append((lbl, pat, lt)); continue
    for p in ps:
        r = quick_scan(p)
        if r.get("ok") and r.get("type") != "err":
            found.append({"lbl": lbl, "pth": str(p), "typ": lt, **r})
            bt[lt]["c"] += r.get("files", 0); bt[lt]["s"] += r.get("size", 0)
            bt[lt]["l"].append(lbl); tf += r.get("files", 0); tb += r.get("size", 0)
            fs = f"{r.get('files', 0):,} files" if r.get("type") == "dir" else ""
            print(f"\n[FOUND] {lbl}\n        {p}\n        {r.get('sh', '?')}  {fs}")
            for it in r.get("ti", [])[:8]:
                if len(it) == 2: print(f"        {f'{it[1]/(1024**3):.2f} GB' if it[1] >= 1024**3 else f'{it[1]/(1024**2):.1f} MB':>10s}  {it[0]}")
                elif len(it) == 3: print(f"        {f'{it[1]/(1024**3):.2f} GB':>10s}  {it[2]:,} files  {it[0]}")

th = f"{tb/(1024**3):.2f} GB" if tb < 1024**4 else f"{tb/(1024**4):.2f} TB"
print(f"\n{'='*65}\nSUMMARY\n{'='*65}")
print(f"Found: {len(found)} locations | Missing: {len(missing)}")
print(f"Total: {tf:,} files | {th}")
for t, d in sorted(bt.items()): print(f"  {t:12s}: {d['c']:,} files, {f'{d['s']/(1024**3):.2f} GB' if d['s'] < 1024**4 else f'{d['s']/(1024**4):.2f} TB'}")

print(f"\nMISSING (may be OK):")
for lbl, pat, t in missing:
    if t not in ('external', 'system', 'appdata'): print(f"  [{t}] {lbl}: {pat}")

rp = Path.home() / "Desktop" / "praxis_discovery_report.json"
with open(rp, "w") as f: json.dump({"found": [{"label": x["lbl"], "path": x["pth"], "size": x.get("size"), "files": x.get("files"), "type": x["typ"]} for x in found], "summary": {"total_files": tf, "total_bytes": tb}}, f, indent=2)
print(f"\nReport: {rp}")

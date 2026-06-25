#!/usr/bin/env python3
"""
ANTHROPIC FORENSICS PARSER
Parses the Anthropic Forensics folder into praxis_forensics.db
Run: python3 anthropic_parser.py "/path/to/Anthropic Forensics"
Output: anthropic_insert_statements.sql, anthropic_findings.json, report.txt
"""
import os, sys, json, csv, re, hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict

DEFAULT_PATH = Path.home() / "Desktop" / "Anthropic Forensics"
MAX_FILE_SIZE = 500 * 1024 * 1024

DESTRUCTIVE = {
    "rm_rf": re.compile(r'\brm\s+-(?:rf|fr|r|f)\b', re.I),
    "rm_recursive": re.compile(r'\brm\s+.*-r', re.I),
    "format": re.compile(r'\bformat\s+[a-z]:', re.I),
    "dd_overwrite": re.compile(r'\bdd\s+.*of=', re.I),
    "shred": re.compile(r'\bshred\b', re.I),
    "destroy": re.compile(r'\bdestroy\b', re.I),
    "disable_protection": re.compile(r'\b(?:disable|turn off)\s+(?:defender|firewall|protection)', re.I),
    "kill_force": re.compile(r'\bkill(?:all)?\s+-9\b', re.I),
}

PERMISSION = {
    "icacls": re.compile(r'\bicacls\b', re.I),
    "takeown": re.compile(r'\btakeown\b', re.I),
    "cacls": re.compile(r'\bcacls\b', re.I),
    "attrib": re.compile(r'\battrib\b.*\+[hs]', re.I),
    "chmod_bad": re.compile(r'\bchmod\s+(?:777|666|000)\b', re.I),
    "chown_root": re.compile(r'\bchown\s+(?:root|0)\b', re.I),
}

FILE_DESTRUCTION = {
    "unlink": re.compile(r'\bunlink\s*\(', re.I),
    "os_remove": re.compile(r'\bos\.(?:remove|unlink)\s*\(', re.I),
    "shutil_rmtree": re.compile(r'\bshutil\.rmtree\b', re.I),
    "find_exec_rm": re.compile(r'\bfind\b.*-exec\s+rm', re.I),
}

CREDENTIALS = {
    "api_key": re.compile(r'(?:api[_\-]?key)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}', re.I),
    "secret": re.compile(r'(?:secret[_\-]?key)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}', re.I),
    "token": re.compile(r'(?:auth[_\-]?token|access[_\-]?token|bearer)\s*[:=]\s*["\']?[a-zA-Z0-9_\-\.]+', re.I),
    "password": re.compile(r'\bpassword\s*[:=]\s*["\'][^"\']{4,}["\']', re.I),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', re.I),
}

EXFIL = {
    "curl_upload": re.compile(r'\bcurl\b.*(?:-T|--upload-file)', re.I),
    "scp": re.compile(r'\bscp\s+', re.I),
    "rsync_remote": re.compile(r'\brsync\b.*:', re.I),
    "telegram": re.compile(r'(?:telegram|bot)\s*(?:api|token)|api\.telegram\.org', re.I),
    "webhook": re.compile(r'\b(?:webhook|hook\.integromat|webhook\.site)\b', re.I),
}

ALL_PATTERNS = {
    "destructive": DESTRUCTIVE,
    "permission_attack": PERMISSION,
    "file_destruction": FILE_DESTRUCTION,
    "credential_exposure": CREDENTIALS,
    "data_exfiltration": EXFIL,
}

KEYWORDS = ["destruction", "destroy", "delete", "wiped", "purged", "erased", "removed",
    "dropped", "truncated", "corrupted", "compromised", "breached", "attacked",
    "exploited", "injected", "backdoor", "exfiltrated", "stolen", "ransomware",
    "malware", "privilege escalation", "persistence", "cover tracks", "tamper",
    "evidence", "praxis", "chrysalis", "archon", "mcas", "telebit", "tunnel", "relay"]

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def scan_dir(path):
    files, total = [], 0
    for root, dirs, fnames in os.walk(path):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in fnames:
            fp = Path(root) / f
            if f.startswith("."): continue
            try:
                s = fp.stat().st_size
                total += s
                files.append({"path": str(fp), "rel": str(fp.relative_to(path)), "size": s, "ext": fp.suffix.lower()})
            except: pass
    return files, total

def extract_findings(text, source, findings):
    for line_no, line in enumerate(text.split("\n"), 1):
        line = line.strip()
        if not line or len(line) < 10: continue
        for cat, patterns in ALL_PATTERNS.items():
            for name, pat in patterns.items():
                if pat.search(line):
                    findings.append({"source": source, "line": line_no, "cat": cat, "pattern": name, "ctx": line[:500]})
        for kw in KEYWORDS:
            if kw.lower() in line.lower():
                findings.append({"source": source, "line": line_no, "cat": "keyword", "pattern": kw, "ctx": line[:500]})
                break

def parse_conversations(path, findings):
    log(f"Parsing conversations: {path.name} ({path.stat().st_size/1024/1024:.1f} MB)")
    if path.stat().st_size > MAX_FILE_SIZE:
        line_count = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_count += 1
                stripped = line.strip()
                if len(stripped) > 20:
                    extract_findings(stripped, f"{path.name}:{line_count}", findings)
                if line_count % 500000 == 0:
                    log(f"  {line_count:,} lines, {len(findings):,} findings")
        return
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            extract_findings(f.read(), path.name, findings)
        return
    text = json.dumps(data) if isinstance(data, (dict, list)) else str(data)
    extract_findings(text, path.name, findings)

def parse_file(path, findings):
    ext = path.suffix.lower()
    if ext == ".json":
        if "conversation" in path.name.lower():
            parse_conversations(path, findings)
        else:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                text = json.dumps(data) if isinstance(data, (dict, list)) else str(data)
                extract_findings(text, str(path), findings)
            except:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    extract_findings(f.read(), str(path), findings)
    elif ext in (".csv",):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                for row_no, row in enumerate(reader, 1):
                    text = " | ".join(row)
                    extract_findings(text, f"{path.name}:{row_no}", findings)
        except: pass
    elif ext in (".log", ".txt", ".md") or path.stat().st_size < 100*1024*1024:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                extract_findings(f.read(), str(path), findings)
        except: pass

def generate_sql(findings):
    lines = ["-- Anthropic Forensics SQL", f"-- {datetime.now().isoformat()}", f"-- {len(findings)} findings", "BEGIN TRANSACTION;", ""]
    by_cat = defaultdict(list)
    for f in findings: by_cat[f.get("cat", "?")].append(f)
    eid = 20000
    for f in findings:
        eid += 1
        source = f.get("source", "?").replace("'", "''")
        pattern = f.get("pattern", "").replace("'", "''")
        cat = f.get("cat", "?")
        ctx = f.get("ctx", "").replace("'", "''")[:200]
        sev = "CRITICAL" if cat in ("destructive", "file_destruction") else "HIGH" if cat in ("credential_exposure", "permission_attack") else "MEDIUM"
        desc = f"[{cat}] {pattern}: {ctx}"
        lines.append(f"INSERT INTO events (id, timestamp, event_type, description, severity, source) VALUES ({eid}, '{datetime.now().isoformat()}', '{cat}', '{desc}', '{sev}', '{source}');")
        lines.append(f"INSERT OR IGNORE INTO documents (id, title, doc_type, file_path) VALUES ({eid}, '{source}', 'anthropic', '{source}');")
        lines.append(f"INSERT INTO links (event_id, document_id, link_type, description) VALUES ({eid}, {eid}, 'found_in', 'Pattern {pattern}');")
        lines.append(f"INSERT INTO audit (event_id, action, timestamp, details) VALUES ({eid}, 'auto_insert', '{datetime.now().isoformat()}', 'anthropic parser');")
        lines.append("")
        if eid > 100000: lines.append("-- TRUNCATED"); break
    lines.append("COMMIT;")
    return "\n".join(lines)

def main():
    forensics = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PATH
    if not forensics.exists():
        print(f"ERROR: Not found: {forensics}")
        print(f"Usage: python3 anthropic_parser.py [path]")
        sys.exit(1)

    log("=" * 60)
    log(f"ANTHROPIC FORENSICS PARSER: {forensics}")
    log("=" * 60)

    files, total = scan_dir(forensics)
    log(f"Found {len(files):,} files ({total/1024/1024/1024:.2f} GB)")

    json_files = [f for f in files if f["ext"] == ".json"]
    csv_files = [f for f in files if f["ext"] == ".csv"]
    log_files = [f for f in files if f["ext"] in (".log", ".txt", ".md")]
    other = [f for f in files if f["ext"] not in (".json", ".csv", ".log", ".txt", ".md", ".sha256", ".png", ".jpg")]
    log(f"JSON: {len(json_files)}, CSV: {len(csv_files)}, Log: {len(log_files)}, Other: {len(other)}")

    log("Parsing...")
    findings = []
    for f in json_files:
        parse_file(Path(f["path"]), findings)
        if findings: log(f"  {Path(f['path']).name}: {len(findings):,} total findings")
    for f in csv_files + log_files:
        parse_file(Path(f["path"]), findings)

    log(f"TOTAL: {len(findings):,} findings")

    log("Writing outputs...")
    sql = generate_sql(findings)
    with open("anthropic_insert_statements.sql", "w") as f: f.write(sql)
    log(f"SQL: {len(sql.splitlines()):,} lines")

    with open("anthropic_findings.json", "w") as f: json.dump(findings, f, indent=2, default=str)
    log(f"JSON: {len(findings):,} findings")

    by_cat = defaultdict(list)
    for f in findings: by_cat[f.get("cat", "?")].append(f)
    report = ["ANTHROPIC FORENSICS REPORT", f"Generated: {datetime.now().isoformat()}",
        f"Files: {len(files):,}", f"Findings: {len(findings):,}", "", "BY CATEGORY:"]
    for cat in sorted(by_cat.keys(), key=lambda c: -len(by_cat[c])):
        report.append(f"  {cat}: {len(by_cat[cat]):,}")
    report += ["", "CRITICAL/HIGH FINDINGS:"]
    for f in findings:
        if f.get("cat") in ("destructive", "file_destruction", "credential_exposure", "permission_attack"):
            report.append(f"  [{f['cat']}] {f['pattern']}: {f['ctx'][:120]}")
    report += ["", "NEXT: sqlite3 praxis_forensics.db < anthropic_insert_statements.sql"]
    report_text = "\n".join(report)
    with open("anthropic_parsed_report.txt", "w") as f: f.write(report_text)

    print("\n" + report_text)
    log("DONE")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    except Exception as e:
        print(f"\n[FATAL] {e}")
        import traceback
        traceback.print_exc()

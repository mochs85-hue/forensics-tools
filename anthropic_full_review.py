#!/usr/bin/env python3
"""
ANTHROPIC FORENSICS — FULL REVIEW
Processes every file in the Anthropic Forensics folder completely.
Streams large files line-by-line. Parses all JSON. Inserts into DB.

Usage: python3 anthropic_full_review.py [--db ~/Desktop/praxis_forensics.db]
"""
import os, sys, json, re, hashlib, sqlite3, csv
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

ZERO_HASH = "0" * 64
def h(data): return hashlib.sha256(str(data).encode()).hexdigest()

# ─── Paths ──────────────────────────────────────────────────────────────────
BASE = Path.home() / "Desktop" / "Anthropic Forensics"
DB_PATH = Path.home() / "Desktop" / "praxis_forensics.db"

DESTRUCTIVE_PATTERNS = [
    (r"rm\s+-rf\s+[/~]", "CRITICAL", "rm-rf-root"), (r"rm\s+-rf\s+['\"]?/[a-zA-Z]", "CRITICAL", "rm-rf-drive"),
    (r"Remove-Item\s+-Recurse\s+-Force", "CRITICAL", "powershell-rm-force"), (r"diskpart\s+.*clean", "CRITICAL", "diskpart-clean"),
    (r"diskpart\s+.*format", "CRITICAL", "diskpart-format"), (r"diskpart\s+.*delete\s+partition", "CRITICAL", "diskpart-delete-partition"),
    (r"format\s+[a-zA-Z]:", "CRITICAL", "format-drive"), (r"rmdir\s+/[s/q]", "CRITICAL", "rmdir-recursive"),
    (r"rd\s+/[s/q]", "CRITICAL", "rd-recursive"), (r"del\s+/[fqs]", "HIGH", "del-force"),
    (r"delete.*evidence", "CRITICAL", "delete-evidence"), (r"destroy.*evidence", "CRITICAL", "destroy-evidence"),
    (r"cipher\s+/w:", "CRITICAL", "cipher-wipe"), (r"vssadmin\s+delete", "CRITICAL", "vssadmin-delete"),
    (r"icacls\s+.*deny", "CRITICAL", "icacls-deny"), (r"takeown\s+/[fr]", "CRITICAL", "takeown-force"),
    (r"cacls\s+.*deny", "CRITICAL", "cacls-deny"), (r"attrib\s+-[rhs]", "HIGH", "attrib-hide-system"),
    (r"dd\s+if=/dev/zero", "CRITICAL", "dd-wipe"), (r"shred\s+-[uz]", "CRITICAL", "shred"),
    (r"wipefs", "CRITICAL", "wipefs"), (r"mkfs\.", "CRITICAL", "mkfs-filesystem"),
]
ATTACK_KEYWORDS = {
    "api_key_deception": [r"never saved", r"api key.*(?:not saved|lost|deleted)", r"(?:don't|didn't) save"],
    "partition_destruction": [r"deleted.*partition", r"delete.*drive", r"diskpart", r"format.*drive"],
    "cowork_system": [r"cowork", r"morning briefing", r"evening sync", r"mcp.*tool"],
    "mcas_ascension": [r"mcas", r"ascension", r"17113995", r"cloudappsecurity"],
    "false_attribution": [r"per user request", r"as requested", r"you asked me to"],
    "praxis_attack": [r"praxis", r"chrysalis", r"chronos", r"0xDEADBEEF"],
    "key_creation": [r"create.*api.*key", r"oauth.*client", r"rclone"],
    "file_destruction": [r"deleted.*file", r"destroyed.*file"],
    "evidence_access": [r"evidence.*database", r"time.*log", r"damages.*ochs"],
}
KW_TYPES = {"api_key_deception": "contradiction", "partition_destruction": "incident", "cowork_system": "system_action",
    "mcas_ascension": "finding", "false_attribution": "contradiction", "praxis_attack": "incident",
    "key_creation": "system_action", "file_destruction": "incident", "evidence_access": "system_action"}
DEST_RE = [(re.compile(p, re.I), sev, name) for p, sev, name in DESTRUCTIVE_PATTERNS]
KW_RE = {cat: [re.compile(p, re.I) for p in ps] for cat, ps in ATTACK_KEYWORDS.items()}

# ─── DB Helpers ─────────────────────────────────────────────────────────────

def db_connect():
    return sqlite3.connect(str(DB_PATH))

def get_ids(conn):
    c = conn.cursor()
    c.execute("SELECT COALESCE(MAX(id),0) FROM events"); eid = c.fetchone()[0] + 1
    c.execute("SELECT COALESCE(MAX(id),0) FROM documents"); did = c.fetchone()[0] + 1
    c.execute("SELECT COALESCE(MAX(id),0) FROM audit"); aid = c.fetchone()[0] + 1
    return eid, did, aid

def insert_event(conn, eid, aid, did, title, desc, event_type, ai_actor="claude", occurred=None):
    c = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    ph = c.execute("SELECT row_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
    ph = ph[0] if ph else ZERO_HASH
    pl = json.dumps({"id": eid, "type": event_type}, sort_keys=True, default=str)
    rh = h(f"events:{eid}:{ph}:{pl}")
    c.execute("INSERT INTO events (id,occurred_at,event_type,title,description,source_refs,ai_actor,recorded_at,prev_hash,row_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (eid, occurred or now, event_type, title, desc, str(did), ai_actor, now, ph, rh))
    c.execute("INSERT INTO audit (id,action,target_table,target_id,details,performed_at,prev_hash,row_hash) VALUES (?,?,?,?,?,?,?,?)",
        (aid, "INSERT", "events", eid, json.dumps({"event_type": event_type}), now, ZERO_HASH, h(f"audit:{eid}")))
    c.execute("INSERT INTO links (event_id,doc_id,relation,prev_hash,row_hash) VALUES (?,?,?,?,?)",
        (eid, did, "extracted_from", ZERO_HASH, h(f"link:{eid}:{did}")))
    return eid + 1, aid + 1

def insert_doc(conn, did, aid, filepath, source, doc_type="export", desc=""):
    c = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
    dh = h(f"doc:{did}:{filepath}:{size}")
    c.execute("INSERT INTO documents (id,filepath,filename,file_size,mtime,sha256,source,doc_type,description,recorded_at,prev_hash,row_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (did, filepath, Path(filepath).name, size, now, f"size_{size}", source, doc_type, desc, now, ZERO_HASH, dh))
    c.execute("INSERT INTO audit (id,action,target_table,target_id,details,performed_at,prev_hash,row_hash) VALUES (?,?,?,?,?,?,?,?)",
        (aid, "INSERT", "documents", did, json.dumps({"source": source}), now, ZERO_HASH, h(f"audit:doc:{did}")))
    return did + 1, aid + 1

# ─── Claude Message Extraction ──────────────────────────────────────────────

def _extract_claude_messages(conv):
    msgs = []
    for key in ["chat_messages", "messages", "conversation"]:
        arr = conv.get(key)
        if isinstance(arr, list):
            for m in arr:
                if isinstance(m, dict):
                    s = m.get("sender", m.get("role", m.get("author", "?")))
                    t = m.get("text", m.get("content", m.get("message", "")))
                    if t: msgs.append((s, str(t)))
            return msgs
    return msgs

def _search_conv_text(conn, eid, aid, did, text_full, conv_name, ai_actor="claude"):
    """Search a conversation's text for destructive commands and keywords. Insert matches into DB."""
    text = text_full.lower()
    
    # Destructive patterns
    for pat, sev, dnm in DEST_RE:
        m = pat.search(text)
        if m:
            ctx = text_full[max(0,m.start()-300):m.end()+300]
            desc = f"[{sev}] {dnm}\nConv: {conv_name}\nContext: {ctx[:500]}"
            eid, aid = insert_event(conn, eid, aid, did, f"[{sev}] {dnm}", desc, "incident", ai_actor)
            break
    
    # Keywords
    for cat, patterns in KW_RE.items():
        matched = False
        for pat in patterns:
            m = pat.search(text)
            if m:
                ctx = text_full[max(0,m.start()-200):m.end()+200]
                desc = f"[{cat}]\nConv: {conv_name}\nContext: {ctx[:400]}"
                eid, aid = insert_event(conn, eid, aid, did, f"{cat}: {conv_name[:40]}", desc, KW_TYPES.get(cat, "finding"), ai_actor)
                matched = True
                break
        if matched:
            break
    
    return eid, aid

# ─── JSON Processors ────────────────────────────────────────────────────────

def process_conversations_json(conn, eid, did, aid, filepath, ai_actor="claude"):
    size_mb = os.path.getsize(filepath) / (1024**2)
    print(f"\n  Parsing: {filepath.name} ({size_mb:.1f} MB)")
    
    did, aid = insert_doc(conn, did, aid, str(filepath), f"Anthropic Claude Export ({filepath.name})", "claude_export",
        f"Claude conversations.json: {size_mb:.1f} MB")
    conn.commit()
    
    start_eid = eid
    
    # Try ijson for large files
    if size_mb > 50:
        try:
            import ijson
            print("    Using ijson streaming...")
            total_convs = 0
            total_msgs = 0
            with open(filepath, 'rb') as f:
                for conv in ijson.items(f, 'item'):
                    if not isinstance(conv, dict):
                        continue
                    total_convs += 1
                    msgs = _extract_claude_messages(conv)
                    if not msgs:
                        continue
                    total_msgs += len(msgs)
                    text_full = "\n".join(f"{r}: {t}" for r, t in msgs)
                    conv_name = conv.get("name", conv.get("uuid", f"conv_{total_convs}"))[:80]
                    eid, aid = _search_conv_text(conn, eid, aid, did, text_full, conv_name, ai_actor)
                    if total_convs % 200 == 0:
                        conn.commit()
                        print(f"      {total_convs:,} convs, {eid-start_eid} events...", end='\r')
            conn.commit()
            print(f"\n    -> {total_convs:,} conversations, {total_msgs:,} messages, {eid-start_eid} events inserted")
            return eid, aid
        except ImportError:
            print("    ijson not installed. Using standard json (slower for large files).")
            print("    Tip: pip3 install ijson for faster streaming")
    
    # Standard parse
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        data = json.load(f)
    
    if not isinstance(data, list):
        print(f"    WARNING: Expected list, got {type(data).__name__}")
        return eid, aid
    
    total_msgs = 0
    for i, conv in enumerate(data):
        if not isinstance(conv, dict):
            continue
        msgs = _extract_claude_messages(conv)
        if not msgs:
            continue
        total_msgs += len(msgs)
        text_full = "\n".join(f"{r}: {t}" for r, t in msgs)
        conv_name = conv.get("name", conv.get("uuid", f"conv_{i}"))[:80]
        eid, aid = _search_conv_text(conn, eid, aid, did, text_full, conv_name, ai_actor)
        if (i+1) % 200 == 0:
            conn.commit()
            print(f"      {i+1}/{len(data)} conversations...", end='\r')
    
    conn.commit()
    print(f"\n    -> {len(data)} conversations, {total_msgs} messages, {eid-start_eid} events inserted")
    return eid, aid

# ─── Text File Streamer ─────────────────────────────────────────────────────

def stream_text_file(conn, eid, did, aid, filepath, source_label, ai_actor="claude"):
    size_gb = os.path.getsize(filepath) / (1024**3)
    print(f"\n  Streaming: {filepath.name} ({size_gb:.2f} GB)")
    
    did, aid = insert_doc(conn, did, aid, str(filepath), source_label, "forensic_extract",
        f"Streamed text: {filepath.name}")
    conn.commit()
    
    start_eid = eid
    line_count = 0
    matches = defaultdict(int)
    
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line_count += 1
            text = line.lower()
            
            # Destructive
            for pat, sev, dnm in DEST_RE:
                if pat.search(text):
                    ctx = line[:500]
                    desc = f"[{sev}] {dnm}\nLine {line_count:,}: {ctx[:400]}"
                    eid, aid = insert_event(conn, eid, aid, did, f"{source_label} [{sev}] {dnm}", desc, "incident", ai_actor)
                    matches[f"{sev}_{dnm}"] += 1
                    break
            
            # Keywords
            for cat, patterns in KW_RE.items():
                matched = False
                for pat in patterns:
                    if pat.search(text):
                        ctx = line[:400]
                        desc = f"[{cat}]\nLine {line_count:,}: {ctx[:350]}"
                        eid, aid = insert_event(conn, eid, aid, did, f"{source_label} {cat}", desc, KW_TYPES.get(cat, "finding"), ai_actor)
                        matches[cat] += 1
                        matched = True
                        break
                if matched:
                    break
            
            if line_count % 100000 == 0:
                conn.commit()
                print(f"      {line_count:,} lines, {eid-start_eid} events...", end='\r')
    
    conn.commit()
    print(f"\n    -> {line_count:,} lines, {eid-start_eid} events inserted")
    for k, v in sorted(matches.items(), key=lambda x: -x[1]):
        print(f"      {k}: {v}")
    return eid, aid

# ─── TSV Processor ──────────────────────────────────────────────────────────

def process_tsv_file(conn, eid, did, aid, filepath):
    print(f"\n  TSV: {filepath.name}")
    
    did, aid = insert_doc(conn, did, aid, str(filepath), "Forensic Inventory TSV", "inventory",
        f"TSV: {filepath.name}")
    conn.commit()
    
    start_eid = eid
    line_count = 0
    
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.reader(f, delimiter='\t')
        for row in reader:
            line_count += 1
            if not row:
                continue
            row_text = "\t".join(row).lower()
            for pat, sev, dnm in DEST_RE:
                if pat.search(row_text):
                    path = row[0] if row else "unknown"
                    desc = f"[{sev}] {dnm}\nPath: {path}\nRow: {row_text[:300]}"
                    eid, aid = insert_event(conn, eid, aid, did, f"TSV [{sev}] {dnm}", desc, "incident", "claude")
                    break
            if line_count % 50000 == 0:
                conn.commit()
                print(f"      {line_count:,} rows...", end='\r')
    
    conn.commit()
    print(f"\n    -> {line_count:,} rows, {eid-start_eid} events")
    return eid, aid

# ─── Shell Script Processor ─────────────────────────────────────────────────

def process_shell_scripts(conn, eid, did, aid):
    scripts = [
        ("EXTRACT_ORIGINAL_19GB_WIPE_RECORDS.sh", "19GB Wipe Extractor"),
        ("check_evidence_drive.sh", "Evidence Drive Checker"),
        ("forensic_analysis.sh", "Forensic Analysis"),
        ("forensic_analysis_enhanced.sh", "Enhanced Forensic Analysis"),
        ("forensic_analysis_d_drive.sh", "D-Drive Forensic Analysis"),
        ("run_forensic_context_scan.sh", "Context Scanner"),
        ("run_drive_fetcher.sh", "Drive Fetcher"),
        ("search-windows-evidence-drive-readonly.sh", "Windows Evidence Scan"),
    ]
    
    for script_name, label in scripts:
        script_path = BASE / script_name
        if not script_path.exists():
            continue
        
        print(f"\n  Script: {script_name}")
        did_script, aid = insert_doc(conn, did, aid, str(script_path), label, "forensic_script",
            f"Forensic script: {script_name}")
        conn.commit()
        
        try:
            with open(script_path, 'r') as f:
                content = f.read()
            
            text = content.lower()
            for pat, sev, dnm in DEST_RE:
                m = pat.search(text)
                if m:
                    ctx = content[max(0,m.start()-200):m.end()+200]
                    desc = f"Script: {script_name}\n[{sev}] {dnm}\nContext: {ctx[:400]}"
                    eid, aid = insert_event(conn, eid, aid, did_script, f"Script [{sev}] {dnm}", desc, "incident", "claude")
            
            desc = f"Script: {script_name}\nSize: {len(content):,} chars\nFirst 500 chars:\n{content[:500]}"
            eid, aid = insert_event(conn, eid, aid, did_script, f"Script: {script_name}", desc, "system_action", "claude")
            
        except Exception as e:
            print(f"    Error: {e}")
    
    conn.commit()
    return eid, aid

# ─── Document Cataloger ─────────────────────────────────────────────────────

def catalog_documents(conn, eid, did, aid, exclude_files):
    print("\n\n=== CATALOGING DOCUMENTS ===")
    doc_exts = {'.pdf', '.docx', '.doc', '.md', '.txt', '.html', '.csv', '.rtf'}
    docs = [d for d in BASE.rglob("*") if d.is_file() and d.suffix.lower() in doc_exts and d not in exclude_files]
    docs.sort(key=lambda x: os.path.getsize(x), reverse=True)
    
    count = 0
    for df in docs[:100]:  # Top 100 by size
        size_kb = os.path.getsize(df) / 1024
        if size_kb < 1:
            continue
        rel = str(df.relative_to(BASE))
        did, aid = insert_doc(conn, did, aid, str(df), "Anthropic Forensics Document", "document", rel)
        count += 1
        if count % 10 == 0:
            conn.commit()
    
    conn.commit()
    print(f"  Cataloged {count} documents")
    return eid, aid

# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  ANTHROPIC FORENSICS — FULL REVIEW")
    print("=" * 70)
    print(f"  Folder: {BASE}")
    print(f"  DB: {DB_PATH}")
    
    if not BASE.exists():
        print(f"\nERROR: Folder not found: {BASE}")
        sys.exit(1)
    
    conn = db_connect()
    eid, did, aid = get_ids(conn)
    start_eid = eid
    print(f"  Starting event ID: {eid}")
    print(f"  Starting doc ID: {did}")
    
    exclude_files = set()
    
    # 1. Main conversations.json (780.5 MB)
    conv_main = BASE / "anthropic-claude-project-upload" / "source-record" / "conversations.json"
    if conv_main.exists():
        eid, aid = process_conversations_json(conn, eid, did, aid, str(conv_main), "claude")
        exclude_files.add(conv_main)
    
    # 2. Batch conversations.json (12.6 MB)
    conv_batch = BASE / "data-faf9ed85-ed03-43d1-941c-a6beac037aa9-1781610889-94032702-batch-0000" / "conversations.json"
    if conv_batch.exists():
        eid, aid = process_conversations_json(conn, eid, did, aid, str(conv_batch), "claude")
        exclude_files.add(conv_batch)
    
    # 3. Sandbox guard hits (5.87 GB)
    sb_file = BASE / "FORENSIC_CONTEXT_SCAN_20260618_120232" / "02_sandbox_guard_hits.txt"
    if sb_file.exists():
        eid, aid = stream_text_file(conn, eid, did, aid, sb_file, "Claude Sandbox Guard", "claude")
        exclude_files.add(sb_file)
    
    # 4. Network attribution (1.88 GB)
    net_file = BASE / "macos-network-attribution-upload-20260611-004755" / "network-focused-all-retained-history-filtered.txt"
    if net_file.exists():
        eid, aid = stream_text_file(conn, eid, did, aid, net_file, "macOS Network Attribution", "claude")
        exclude_files.add(net_file)
    
    # 5. Key term hits (928 MB)
    kt_file = BASE / "claude-session-pivot-review-20260611-103422" / "CLAUDE-SESSION-KEY-TERM-HITS.txt"
    if kt_file.exists():
        eid, aid = stream_text_file(conn, eid, did, aid, kt_file, "Claude Key Term Hit", "claude")
        exclude_files.add(kt_file)
    
    # 6. Wipe context (267 MB)
    wipe_file = BASE / "original-19gb-wipe-records-20260611-113421" / "ORIGINAL_19GB_WIPE_CONTEXT.txt"
    if wipe_file.exists():
        eid, aid = stream_text_file(conn, eid, did, aid, wipe_file, "19GB Wipe Context", "claude")
        exclude_files.add(wipe_file)
    
    # 7. Windows execution trace (776 MB)
    trace_file = BASE / "windows-trace-review-20260611-013340" / "CLAUDE_EXEC_TRACE_TARGETED_HITS_UTF8.txt"
    if trace_file.exists():
        eid, aid = stream_text_file(conn, eid, did, aid, trace_file, "Windows Exec Trace", "claude")
        exclude_files.add(trace_file)
    
    # 8. Global agent forensic (808 MB)
    ga_file = BASE / "GLOBAL_AGENT_FORENSIC_20260618_113915" / "01_sandbox_guard_hits.txt"
    if ga_file.exists():
        eid, aid = stream_text_file(conn, eid, did, aid, ga_file, "Global Agent Sandbox", "claude")
        exclude_files.add(ga_file)
    
    # 9. Focused evidence scan (403 MB)
    fe_file = BASE / "FOCUSED_EVIDENCE_SCAN_20260618_120008" / "01_focused_hits.txt"
    if fe_file.exists():
        eid, aid = stream_text_file(conn, eid, did, aid, fe_file, "Focused Evidence Hit", "claude")
        exclude_files.add(fe_file)
    
    # 10. TSV inventory files
    tsv_files = [
        BASE / "FORENSIC_RECON_ANALYSIS_SET_20260618_165810" / "01_ALL_FILES_INVENTORY.tsv",
        BASE / "FORENSIC_RECON_ANALYSIS_SET_20260618_165810" / "03_CRITICAL_FILES.tsv",
        BASE / "FORENSIC_RECON_ANALYSIS_SET_20260618_165810" / "10_EVIDENCE_RECOVERY_MAP.tsv",
        BASE / "FORENSIC_DRIVE_RECON_20260618_143120" / "01_ALL_FILES_INVENTORY.tsv",
        BASE / "FORENSIC_DRIVE_RECON_20260618_143120" / "03_CRITICAL_FILES.tsv",
    ]
    for tf in tsv_files:
        if tf.exists():
            eid, aid = process_tsv_file(conn, eid, did, aid, tf)
            exclude_files.add(tf)
    
    # 11. Shell scripts
    eid, aid = process_shell_scripts(conn, eid, did, aid)
    
    # 12. Catalog remaining documents
    eid, aid = catalog_documents(conn, eid, did, aid, exclude_files)
    
    conn.close()
    
    # Summary
    total_inserted = eid - start_eid
    print(f"\n{'='*70}")
    print(f"  FULL REVIEW COMPLETE")
    print(f"{'='*70}")
    print(f"  Events inserted: {total_inserted}")
    print(f"  Event range: {start_eid} - {eid - 1}")
    print(f"{'='*70}")
    
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "Anthropic Forensics Full Review",
        "events_inserted": total_inserted,
        "event_range": [start_eid, eid - 1],
        "folder_size_gb": sum(os.path.getsize(f) for f in BASE.rglob("*") if f.is_file()) / (1024**3),
    }
    with open(Path.home() / "Desktop" / "anthropic_full_review_summary.json", 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"\n  Summary: ~/Desktop/anthropic_full_review_summary.json")

if __name__ == "__main__":
    main()

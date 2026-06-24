#!/usr/bin/env python3
"""
ChatGPT Minimal Parser -- Hardcoded for conversations-000/001/002.json format.
Usage: python3 chatgpt_minimal_parser.py "/path/to/OPENAIJUNE2026DATAEXPORT.zip" [--all] [--db ~/Desktop/praxis_forensics.db]
"""
import zipfile, json, re, hashlib, sqlite3, sys
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

ZERO_HASH = "0" * 64
def _hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

CONV_FILES = ["conversations-000.json", "conversations-001.json", "conversations-002.json"]

DESTRUCTIVE = [
    (re.compile(r"rm\s+-rf\s+[/~]", re.I), "CRITICAL", "rm -rf root/home"),
    (re.compile(r"rm\s+-rf\s+['\"]?/[a-zA-Z]", re.I), "CRITICAL", "rm -rf drive"),
    (re.compile(r"rm\s+-r\s+['\"]?/[a-zA-Z]", re.I), "CRITICAL", "rm -r drive"),
    (re.compile(r"del\s+/[fqs]\s+.*[/\*]", re.I), "CRITICAL", "del force recursive"),
    (re.compile(r"rmdir\s+/[s/q]*\s+['\"]?[a-zA-Z]:\\\\", re.I), "CRITICAL", "rmdir drive"),
    (re.compile(r"rd\s+/[s/q]*\s+['\"]?[a-zA-Z]:\\\\", re.I), "CRITICAL", "rd drive"),
    (re.compile(r"Remove-Item\s+-Recurse\s+-Force", re.I), "CRITICAL", "PowerShell remove recursive force"),
    (re.compile(r"diskpart\s+.*clean", re.I), "CRITICAL", "diskpart clean"),
    (re.compile(r"diskpart\s+.*format", re.I), "CRITICAL", "diskpart format"),
    (re.compile(r"diskpart\s+.*delete\s+partition", re.I), "CRITICAL", "diskpart delete partition"),
    (re.compile(r"format\s+[a-zA-Z]:\s+/[yqs]*", re.I), "CRITICAL", "format drive"),
    (re.compile(r"format\s+[a-zA-Z]:\s+/fs:", re.I), "CRITICAL", "format filesystem"),
    (re.compile(r"dd\s+if=/dev/zero\s+of=", re.I), "CRITICAL", "dd wipe"),
    (re.compile(r"shred\s+-[uz]*", re.I), "CRITICAL", "shred"),
    (re.compile(r"cipher\s+/w:", re.I), "CRITICAL", "cipher wipe"),
    (re.compile(r"vssadmin\s+delete\s+shadows", re.I), "CRITICAL", "delete shadow copies"),
    (re.compile(r"wipefs\s+-[a]*", re.I), "CRITICAL", "wipefs"),
    (re.compile(r"rm\s+-rf\s+\w+", re.I), "HIGH", "rm -rf directory"),
    (re.compile(r"format\s+[a-zA-Z]:", re.I), "HIGH", "format drive simple"),
    (re.compile(r"delete\s+(?:all\s+)?files?\s+(?:in\s+|on\s+|from\s+)[a-zA-Z]:", re.I), "CRITICAL", "NL delete drive files"),
    (re.compile(r"(?:clear|clean|wipe|erase)\s+(?:the\s+)?[dD]\s*[dD]rive", re.I), "CRITICAL", "NL wipe D drive"),
    (re.compile(r"(?:permanently\s+)?delete\s+.*evidence", re.I), "CRITICAL", "NL delete evidence"),
    (re.compile(r"destroy\s+.*evidence", re.I), "CRITICAL", "NL destroy evidence"),
]

KEYWORDS = {
    "api_key_deception": [r"never saved", r"api key.*(?:not saved|lost|deleted)", r"(?:don't|didn't) save"],
    "partition_destruction": [r"deleted.*partition", r"delete.*drive", r"diskpart", r"format.*drive"],
    "cowork_system": [r"cowork", r"morning briefing", r"evening sync", r"mcp.*tool"],
    "mcas_ascension": [r"mcas", r"ascension", r"17113995", r"cloudappsecurity"],
    "false_attribution": [r"per user request", r"as requested", r"you asked me to"],
    "praxis_attack": [r"praxis", r"chrysalis", r"chronos", r"0xDEADBEEF"],
    "key_creation": [r"create.*api.*key", r"oauth.*client", r"rclone"],
    "file_destruction": [r"deleted.*file", r"destroyed.*file", r"rm\s+-rf"],
    "evidence_access": [r"evidence.*database", r"time.*log", r"damages.*ochs"],
}
KEYWORD_TYPES = {
    "api_key_deception": "contradiction", "partition_destruction": "incident",
    "cowork_system": "system_action", "mcas_ascension": "finding",
    "false_attribution": "contradiction", "praxis_attack": "incident",
    "key_creation": "system_action", "file_destruction": "incident",
    "evidence_access": "system_action",
}

def extract_messages(conv):
    msgs = []
    mapping = conv.get("mapping", {})
    if not isinstance(mapping, dict):
        return msgs
    for node in mapping.values():
        if not isinstance(node, dict):
            continue
        msg = node.get("message")
        if not msg or not isinstance(msg, dict):
            continue
        author = msg.get("author", {})
        role = author.get("role", "unknown") if isinstance(author, dict) else str(author)
        content = msg.get("content", {})
        if isinstance(content, dict):
            parts = content.get("parts", [])
            text = " ".join(str(p) for p in parts if p) if isinstance(parts, list) else str(parts)
        else:
            text = str(content)
        if text.strip():
            msgs.append((role, text))
    return msgs

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("zip_path")
    parser.add_argument("--destructive", action="store_true")
    parser.add_argument("--keywords", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--db", type=Path)
    parser.add_argument("--output", type=Path, default=Path.cwd() / "chatgpt_results.json")
    args = parser.parse_args()
    if args.all:
        args.destructive = args.keywords = True

    print("=" * 60)
    print("  CHATGPT MINIMAL PARSER")
    print("=" * 60)

    zip_path = Path(args.zip_path)
    zf = zipfile.ZipFile(zip_path, 'r')
    found = [cf for cf in CONV_FILES if cf in zf.namelist()]
    print(f"Found {len(found)}/3 conversation files")

    db = None
    doc_id = None
    if args.db and args.db.exists():
        try:
            sys.path.insert(0, str(Path(__file__).parent))
            from praxis_db_init import PraxisDB
            db = PraxisDB(args.db)
        except ImportError:
            db = sqlite3.connect(str(args.db))
        if hasattr(db, 'add_document'):
            try:
                doc_id = db.add_document(filepath=str(zip_path), source="OpenAI ChatGPT Export",
                    doc_type="export", description=f"ChatGPT export: {len(found)} files",
                    date_tag=datetime.now(timezone.utc).strftime("%Y-%m"))
                print(f"Document ID: {doc_id}")
            except Exception as e:
                print(f"Doc warning: {e}")

    total_convs = 0
    total_msgs = 0
    all_destructive = []
    all_keywords = []
    cat_counts = defaultdict(int)
    sev_counts = defaultdict(int)

    for cf in found:
        print(f"\n  Reading {cf}...")
        data = json.loads(zf.read(cf))
        file_msgs = 0
        file_destr = 0
        file_kw = 0

        for conv in data:
            if not isinstance(conv, dict):
                continue
            total_convs += 1
            msgs = extract_messages(conv)
            msg_count = len(msgs)
            total_msgs += msg_count
            file_msgs += msg_count
            if msg_count == 0:
                continue

            full_text_lines = [f"{role}: {text}" for role, text in msgs]
            full_text = "\n".join(full_text_lines)
            full_lower = full_text.lower()
            conv_id = conv.get("conversation_id", conv.get("id", f"unk_{total_convs}"))
            conv_title = conv.get("title", "Untitled")

            if args.destructive:
                for pat, sev, dnm in DESTRUCTIVE:
                    matched = False
                    for m in pat.finditer(full_lower):
                        start = max(0, m.start() - 300)
                        end = min(len(full_text), m.end() + 300)
                        pos = m.start()
                        sender = "unknown"
                        cumulative = 0
                        for role, text in msgs:
                            tl = len(text) + 1
                            if cumulative <= pos < cumulative + tl:
                                sender = role
                                break
                            cumulative += tl
                        all_destructive.append({"severity": sev, "pattern_name": dnm,
                            "matched": m.group(), "sender": sender,
                            "context": full_text[start:end], "conversation_id": conv_id,
                            "conversation_title": conv_title})
                        sev_counts[sev] += 1
                        file_destr += 1
                        matched = True
                        if db:
                            try:
                                now = datetime.now(timezone.utc).isoformat()
                                desc = f"[{sev}] {dnm}\nMatch: {m.group()}\nSender: {sender}\nContext: ...{full_text[start:end][:400]}..."
                                title = f"GPT DESTRUCTIVE [{sev}]: {dnm}"
                                if hasattr(db, 'add_event'):
                                    db.add_event(occurred_at=now, title=title, description=desc,
                                        event_type="incident", ai_actor="chatgpt", source_refs=[doc_id] if doc_id else None)
                                else:
                                    cur = db.cursor()
                                    cur.execute("SELECT COALESCE(MAX(id),0)+1 FROM events")
                                    eid = cur.fetchone()[0]
                                    cur.execute("SELECT row_hash FROM events ORDER BY id DESC LIMIT 1")
                                    row = cur.fetchone()
                                    ph = row[0] if row else ZERO_HASH
                                    row_data = f"{eid}|{now}|{now}|{title}|{desc}|incident|chatgpt|{json.dumps([doc_id] if doc_id else [])}|{ph}"
                                    rh = _hash(row_data)
                                    cur.execute("INSERT INTO events (id,occurred_at,recorded_at,title,description,event_type,ai_actor,source_refs,prev_hash,row_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                                        (eid, now, now, title, desc, "incident", "chatgpt", json.dumps([doc_id] if doc_id else []), ph, rh))
                                    db.commit()
                            except Exception as e:
                                print(f"      DB error: {e}")
                    if matched:
                        break

            if args.keywords:
                for cat, patterns in KEYWORDS.items():
                    matches = []
                    for pat in patterns:
                        for m in re.finditer(pat, full_lower, re.I):
                            st = max(0, m.start() - 200)
                            en = min(len(full_text), m.end() + 200)
                            matches.append({"pattern": pat, "matched": m.group(), "ctx": full_text[st:en]})
                    if matches:
                        all_keywords.append({"category": cat, "conversation_id": conv_id,
                            "conversation_title": conv_title, "matches": matches})
                        cat_counts[cat] += 1
                        file_kw += len(matches)
                        if db:
                            try:
                                now = datetime.now(timezone.utc).isoformat()
                                desc = f"Category: {cat}\nConv: {conv_title}\nMatches: {len(matches)}\n"
                                for m in matches[:3]:
                                    desc += f"\nPattern: {m['pattern']}\nContext: ...{m['ctx']}..."
                                title = f"GPT {cat}: {conv_title[:50]}"
                                et = KEYWORD_TYPES.get(cat, "finding")
                                if hasattr(db, 'add_event'):
                                    db.add_event(occurred_at=now, title=title, description=desc,
                                        event_type=et, ai_actor="chatgpt", source_refs=[doc_id] if doc_id else None)
                            except Exception as e:
                                print(f"      DB error: {e}")

        print(f"    -> {file_msgs} msgs, {file_destr} destructive, {file_kw} keyword matches")

    print(f"\n{'='*60}")
    print(f"  SUMMARY: {total_convs} conversations, {total_msgs} messages")
    if args.destructive:
        print(f"  Destructive: {len(all_destructive)}")
        for sev, cnt in sorted(sev_counts.items(), key=lambda x: -x[1]):
            print(f"    {sev}: {cnt}")
    if args.keywords:
        print(f"  Keywords: {len(all_keywords)}")
        for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
            print(f"    {cat}: {cnt}")

    critical = [d for d in all_destructive if d["severity"] == "CRITICAL"]
    if critical:
        print(f"\n  CRITICAL ({len(critical)}):")
        for d in critical[:15]:
            print(f"\n    [{d['severity']}] {d['pattern_name']}")
            print(f"    Match: {d['matched']} | Sender: {d['sender']}")
            print(f"    Conv: {d['conversation_title'][:50]}")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": str(zip_path), "total_conversations": total_convs,
        "total_messages": total_msgs, "destructive_count": len(all_destructive),
        "keyword_count": len(all_keywords), "severity_breakdown": dict(sev_counts),
        "category_breakdown": dict(cat_counts),
        "destructive_findings": all_destructive, "keyword_findings": all_keywords,
    }
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\nSaved: {args.output}")

    if db and hasattr(db, 'verify'):
        print("\nDB verification:")
        for t, r in db.verify().items():
            print(f"  {t}: {'OK' if r['ok'] else 'BROKEN'} ({r['rows']} rows)")
    if db and hasattr(db, 'close'):
        db.close()
    print("\nDONE")

if __name__ == "__main__":
    main()

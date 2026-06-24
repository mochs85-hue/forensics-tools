#!/usr/bin/env python3
"""
ChatGPT Findings DB Inserter
Inserts all ChatGPT destructive commands and keyword findings into praxis_forensics.db
"""
import zipfile, json, re, hashlib, sqlite3
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

ZERO_HASH = "0" * 64
def h(data): return hashlib.sha256(data.encode()).hexdigest()

CONV_FILES = ["conversations-000.json", "conversations-001.json", "conversations-002.json"]
DESTRUCTIVE = [
    (r"rm\s+-rf\s+[/~]", "CRITICAL", "rm-rf-root"), (r"rm\s+-rf\s+['\"]?/[a-zA-Z]", "CRITICAL", "rm-rf-drive"),
    (r"Remove-Item\s+-Recurse\s+-Force", "CRITICAL", "powershell-rm-force"), (r"diskpart\s+.*clean", "CRITICAL", "diskpart-clean"),
    (r"diskpart\s+.*format", "CRITICAL", "diskpart-format"), (r"diskpart\s+.*delete\s+partition", "CRITICAL", "diskpart-delete-partition"),
    (r"format\s+[a-zA-Z]:", "CRITICAL", "format-drive"), (r"rmdir\s+/[s/q]", "CRITICAL", "rmdir-recursive"), (r"rd\s+/[s/q]", "CRITICAL", "rd-recursive"),
    (r"del\s+/[fqs]", "HIGH", "del-force"), (r"delete\s+.*partition", "CRITICAL", "delete-partition"),
    (r"delete.*evidence", "CRITICAL", "delete-evidence"), (r"destroy.*evidence", "CRITICAL", "destroy-evidence"),
    (r"cipher\s+/w:", "CRITICAL", "cipher-wipe"), (r"vssadmin\s+delete", "CRITICAL", "vssadmin-delete"),
    (r"icacls\s+.*deny", "CRITICAL", "icacls-deny"), (r"takeown\s+/[fr]", "CRITICAL", "takeown-force"),
    (r"cacls\s+.*deny", "CRITICAL", "cacls-deny"), (r"attrib\s+-[rhs]", "HIGH", "attrib-hide-system"),
    (r"dd\s+if=/dev/zero", "CRITICAL", "dd-wipe"), (r"shred\s+-[uz]", "CRITICAL", "shred"),
    (r"rm\s+-rf\s+\w+", "HIGH", "rm-rf-dir"),
]
KEYWORDS = {
    "partition_destruction": [r"deleted.*partition", r"diskpart", r"format.*drive", r"delete.*drive"],
    "cowork_system": [r"cowork", r"morning briefing", r"evening sync"],
    "mcas_ascension": [r"mcas", r"ascension", r"17113995"],
    "praxis_attack": [r"praxis", r"chrysalis", r"chronos"],
    "evidence_access": [r"evidence.*database", r"damages.*ochs"],
    "false_attribution": [r"per user request", r"you asked me to"],
    "permission_attack": [r"icacls", r"takeown", r"cacls", r"attrib.*system"],
}
KW_TYPES = {"partition_destruction": "incident", "cowork_system": "system_action", "mcas_ascension": "finding",
    "praxis_attack": "incident", "evidence_access": "system_action", "false_attribution": "contradiction",
    "permission_attack": "incident"}

def get_msgs(conv):
    msgs = []
    for node in conv.get("mapping", {}).values():
        if not isinstance(node, dict): continue
        m = node.get("message", {})
        if not m: continue
        role = m.get("author", {}).get("role", "?")
        parts = m.get("content", {}).get("parts", [])
        text = " ".join(str(p) for p in parts if p)
        if text.strip(): msgs.append((role, text))
    return msgs

def main():
    DB = Path.home() / "Desktop" / "praxis_forensics.db"
    ZIP = "/Users/mjoshomefolder/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/MASTER_CHRONOLOGY/OPENAIJUNE2026DATAEXPORT.zip"
    print("=" * 60); print("  CHATGPT DB INSERTER"); print("=" * 60)
    conn = sqlite3.connect(str(DB))
    c = conn.cursor()
    c.execute("SELECT COALESCE(MAX(id),0) FROM events"); start_eid = c.fetchone()[0] + 1; eid = start_eid
    c.execute("SELECT COALESCE(MAX(id),0) FROM documents"); did = c.fetchone()[0] + 1
    c.execute("SELECT COALESCE(MAX(id),0) FROM audit"); aid = c.fetchone()[0] + 1
    now = datetime.now(timezone.utc).isoformat()
    c.execute("INSERT INTO documents (id,filepath,filename,source,doc_type,recorded_at,prev_hash,row_hash) VALUES (?,?,?,?,?,?,?,?)",
        (did, ZIP, "OPENAIJUNE2026DATAEXPORT.zip", "OpenAI ChatGPT Export", "export", now, ZERO_HASH, h(f"docs:{did}:{now}")))
    conn.commit()
    zf = zipfile.ZipFile(ZIP, 'r')
    files = [f for f in CONV_FILES if f in zf.namelist()]
    total_destr = total_kw = 0
    for cf in files:
        print(f"  Processing {cf}...")
        data = json.loads(zf.read(cf))
        for conv in data:
            if not isinstance(conv, dict): continue
            msgs = get_msgs(conv)
            if not msgs: continue
            text_full = "\n".join(f"{r}: {t}" for r, t in msgs)
            text = text_full.lower()
            conv_id = conv.get("conversation_id", conv.get("id", "?"))
            conv_title = conv.get("title", "Untitled")
            for pat, sev, dnm in DESTRUCTIVE:
                m = re.search(pat, text, re.I)
                if m:
                    ctx = text_full[max(0,m.start()-300):m.end()+300]
                    ph = c.execute("SELECT row_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
                    ph = ph[0] if ph else ZERO_HASH
                    desc = f"[{sev}] {dnm}\nPattern: {pat}\nMatch: {m.group()}\nConv: {conv_title}\nConvID: {conv_id}\nContext: ...{ctx[:500]}..."
                    pl = json.dumps({"id": eid, "type": "chatgpt_destructive", "severity": sev, "command": dnm}, sort_keys=True, default=str)
                    rh = h(f"events:{eid}:{ph}:{pl}")
                    c.execute("INSERT INTO events (id,occurred_at,event_type,title,description,source_refs,ai_actor,recorded_at,prev_hash,row_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (eid, now, "incident", f"GPT [{sev}] {dnm}", desc, str(did), "chatgpt", now, ph, rh))
                    c.execute("INSERT INTO audit (id,action,target_table,target_id,details,performed_at,prev_hash,row_hash) VALUES (?,?,?,?,?,?,?,?)",
                        (aid, "INSERT", "events", eid, json.dumps({"severity": sev, "command": dnm}), now, ZERO_HASH, h(f"audit:{eid}")))
                    c.execute("INSERT INTO links (event_id,doc_id,relation,prev_hash,row_hash) VALUES (?,?,?,?,?)",
                        (eid, did, "extracted_from", ZERO_HASH, h(f"link:{eid}:{did}")))
                    eid += 1; aid += 1; total_destr += 1; break
            for cat, pats in KEYWORDS.items():
                matches = []
                for pat in pats:
                    for m in re.finditer(pat, text, re.I):
                        matches.append({"pattern": pat, "matched": m.group(), "ctx": text_full[max(0,m.start()-200):m.end()+200]})
                if matches:
                    ph = c.execute("SELECT row_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
                    ph = ph[0] if ph else ZERO_HASH
                    desc = f"Category: {cat}\nConv: {conv_title}\nConvID: {conv_id}\nMatches: {len(matches)}\n"
                    for mm in matches[:3]: desc += f"\nPattern: {mm['pattern']}\nMatch: {mm['matched']}\nContext: {mm['ctx'][:350]}"
                    pl = json.dumps({"id": eid, "category": cat, "matches": len(matches)}, sort_keys=True, default=str)
                    rh = h(f"events:{eid}:{ph}:{pl}")
                    c.execute("INSERT INTO events (id,occurred_at,event_type,title,description,source_refs,ai_actor,recorded_at,prev_hash,row_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (eid, now, KW_TYPES.get(cat, "finding"), f"GPT {cat}: {conv_title[:50]}", desc, str(did), "chatgpt", now, ph, rh))
                    c.execute("INSERT INTO audit (id,action,target_table,target_id,details,performed_at,prev_hash,row_hash) VALUES (?,?,?,?,?,?,?,?)",
                        (aid, "INSERT", "events", eid, json.dumps({"category": cat}), now, ZERO_HASH, h(f"audit:{eid}")))
                    c.execute("INSERT INTO links (event_id,doc_id,relation,prev_hash,row_hash) VALUES (?,?,?,?,?)",
                        (eid, did, "extracted_from", ZERO_HASH, h(f"link:{eid}:{did}")))
                    eid += 1; aid += 1; total_kw += 1
        conn.commit()
    conn.close()
    print(f"\n{'='*60}")
    print(f"  INSERTED: {total_destr + total_kw} events ({total_destr} destructive, {total_kw} keywords)")
    print(f"  Event range: {start_eid} - {eid - 1}")
    print(f"{'='*60}")
if __name__ == "__main__":
    main()

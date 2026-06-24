#!/usr/bin/env python3
"""
ChatGPT Parser v2 — Adds permission attack patterns (icacls, takeown, cacls, attrib)
Run this to find permission-manipulation commands missed by v1.
"""
import zipfile, json, re
from collections import defaultdict

PERM_PATTERNS = [
    (r"icacls\s+.*deny", "CRITICAL", "icacls-deny"),
    (r"icacls\s+.*remove", "HIGH", "icacls-remove"),
    (r"icacls\s+.*grant", "HIGH", "icacls-grant"),
    (r"icacls\s+.*setintegrity", "HIGH", "icacls-integrity"),
    (r"takeown\s+/f", "CRITICAL", "takeown-force"),
    (r"takeown\s+/r", "CRITICAL", "takeown-recursive"),
    (r"cacls\s+.*deny", "CRITICAL", "cacls-deny"),
    (r"cacls\s+.*remove", "HIGH", "cacls-remove"),
    (r"attrib\s+-[rhs]", "HIGH", "attrib-hide-system"),
    (r"attrib\s+\+[rhs]", "HIGH", "attrib-set-system"),
    (r"set-acl\s+-recurse", "CRITICAL", "set-acl-recursive"),
]

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

zf = zipfile.ZipFile("/Users/mjoshomefolder/Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive/MASTER_CHRONOLOGY/OPENAIJUNE2026DATAEXPORT.zip", 'r')
files = [f for f in ["conversations-000.json","conversations-001.json","conversations-002.json"] if f in zf.namelist()]
total_perms = defaultdict(int)
found_details = []

for cf in files:
    print(f"\n=== {cf} ===")
    data = json.loads(zf.read(cf))
    for conv in data:
        if not isinstance(conv, dict): continue
        msgs = get_msgs(conv)
        if not msgs: continue
        text_full = "\n".join(f"{r}: {t}" for r, t in msgs)
        text = text_full.lower()
        conv_title = conv.get("title", "Untitled")
        for pat, sev, name in PERM_PATTERNS:
            m = re.search(pat, text, re.I)
            if m:
                ctx = text_full[max(0,m.start()-300):m.end()+300]
                print(f"  [{sev}] {name:25s} | {conv_title[:40]:40s} | {ctx[:80]}")
                total_perms[name] += 1
                found_details.append({"name": name, "severity": sev, "match": m.group(), "conv": conv_title, "ctx": ctx[:250]})

print(f"\n{'='*60}")
print(f"PERMISSION ATTACK SUMMARY:")
for name, count in sorted(total_perms.items(), key=lambda x: -x[1]):
    print(f"  {name}: {count}")
print(f"  TOTAL: {sum(total_perms.values())}")

# Save report
import json as J, pathlib
report = {"generated": "2026-06-25", "total": sum(total_perms.values()), "by_type": dict(total_perms), "findings": found_details}
with open(pathlib.Path.home() / "Desktop" / "chatgpt_permission_attacks.json", 'w') as f:
    J.dump(report, f, indent=2, ensure_ascii=False)
print(f"\nSaved: ~/Desktop/chatgpt_permission_attacks.json")

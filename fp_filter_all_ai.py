#!/usr/bin/env python3
"""
False Positive Filter - ALL AI ACTORS (Claude + ChatGPT + Gemini)
"""
import sqlite3, re, os
from pathlib import Path

DB_PATH = os.path.expanduser("~/Desktop/praxis_forensics.db")

FP_PATTERNS = [
    r"delete[d\s].*file[s\s]\s*(?:from|in|on|to)", r"deleted.*(?:by|after|when|because|from|the|your|my)",
    r"(?:was|were|had been|have been)\s+deleted", r"delete.*(?:account|entry|record|note|message|email|post|comment|tweet|button|option|menu|link|icon|tab|window|history|cache|cookie|bookmark|password)",
    r"i\s+(?:can|will|would|could|should)\s+delete", r"you\s+(?:can|will|would|could|should)\s+delete",
    r"(?:don't|do not|didn't|cannot|can't)\s+delete", r"(?:how|what|where|why|when)\s+to\s+delete",
    r"deleted\s+(?:items|folder|message|conversation)", r"format.*(?:drive cycle|specification|standard|type|version)",
    r"(?:file|document|image|video|audio)\s+format", r"format.*(?:as|into|to|from)",
    r"(?:different|new|old|same|proper)\s+format", r"^(?:the|a|an|this|that|these|those|it|they|we|you|i)\s",
    r"(?:please|thank|sorry|hello|hi|hey|ok|okay)", r"(?:i'm|i am|you're|he's|she's|it's|we're|they're)",
    r"(?:however|therefore|meanwhile|additionally|furthermore|moreover)", r"\?\s*$",
    r"(?:can you|could you|would you|will you|do you)\s", r"(?:i think|i believe|i suggest|i recommend|in my opinion)",
    r"rm\s+-rf.*(?:is|was|means|stands for|like|similar to)", r"(?:called|named|known as|referred to as)\s+rm\s+-rf",
    r"rm\s+-rf\s+(?:command|option|flag|switch|parameter)", r"del\s+/[fqs].*(?:command|option|flag|parameter)",
    r"(?:command|syntax)\s+del\s+/[fqs]", r"Remove-Item.*(?:cmdlet|command|function|parameter)",
    r"(?:using|with|via)\s+Remove-Item", r"i\s+(?:just|also|already|might|may)\s+.*delete",
    r"you\s+(?:just|also|already|might|may)\s+.*delete", r"ice\s+melt",
    r"8300\s+ice", r"magnesium\s+chloride", r"50\s+lb\s+bag",
]
FP_RE = [re.compile(p, re.I) for p in FP_PATTERNS]

GENUINE = [
    r"^\s*rm\s+-rf\s+\S", r"^\s*del\s+/[fqs]\s+\S", r"^\s*Remove-Item\s+-Recurse\s+-Force",
    r"^\s*diskpart\s", r"^\s*format\s+[a-zA-Z]:", r"^\s*cipher\s+/w:", r"^\s*dd\s+if=/dev/zero",
    r"^\s*shred\s+-", r"^\s*icacls\s+.*deny", r"^\s*takeown\s+/[fr]", r"^\s*cacls\s+.*deny",
    r"^\s*attrib\s+-[rhs]", r"```\s*\n\s*rm\s+-rf", r"```\s*\n\s*del\s+/",
    r"```\s*\n\s*Remove-Item", r"```\s*\n\s*icacls", r"```\s*\n\s*takeown",
    r"\$\s+rm\s+-rf", r"C:\\\\>\s*del\s+/", r"C:\\\\>\s*format\s+",
]
GEN_RE = [re.compile(p, re.I) for p in GENUINE]

def is_fp(content):
    fp_score = sum(1 for p in FP_RE if p.search(content))
    genuine_score = sum(2 for p in GEN_RE if p.search(content))
    if genuine_score >= 2: return False
    if fp_score >= 2 and genuine_score == 0: return True
    if len(content.split()) > 20 and genuine_score == 0: return True
    return False

def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    print("=" * 70); print("FALSE POSITIVE FILTER - ALL AI ACTORS"); print("=" * 70)
    cur.execute("""SELECT id, event_type, source_refs, description, title, ai_actor FROM events WHERE (event_type LIKE '%destructive%' OR event_type LIKE '%file_destruction%' OR event_type LIKE '%partition%' OR event_type LIKE '%permission%' OR description LIKE '%rm -rf%' OR description LIKE '%del /%' OR description LIKE '%Remove-Item%' OR description LIKE '%diskpart%' OR description LIKE '%format %:%' OR description LIKE '%cipher /w%' OR description LIKE '%dd if=/dev/zero%' OR description LIKE '%shred -%' OR description LIKE '%icacls%' OR description LIKE '%takeown%' OR description LIKE '%cacls%' OR description LIKE '%attrib%' OR title LIKE '%rm-rf%' OR title LIKE '%format%' OR title LIKE '%delete-partition%' OR title LIKE '%delete-evidence%' OR title LIKE '%destroy-evidence%' OR title LIKE '%cipher%' OR title LIKE '%diskpart%' OR title LIKE '%icacls%' OR title LIKE '%takeown%') ORDER BY ai_actor, id""")
    events = cur.fetchall()
    print(f"\nTotal destructive events: {len(events)}")
    fps, genuine_list, uncertain = [], [], []
    by_actor = {"claude": [0,0,0], "chatgpt": [0,0,0], "gemini": [0,0,0], "other": [0,0,0]}
    for ev in events:
        text = ev['description'] or ev['title'] or ""
        actor = ev['ai_actor'] or 'other'
        if actor not in by_actor: actor = 'other'
        if is_fp(text): fps.append(ev); by_actor[actor][0] += 1
        elif any(p.search(text) for p in GEN_RE): genuine_list.append(ev); by_actor[actor][1] += 1
        else: uncertain.append(ev); by_actor[actor][2] += 1
    print(f"\nRESULTS: FP={len(fps)}, Genuine={len(genuine_list)}, Uncertain={len(uncertain)}")
    for actor, (fp, gen, unc) in by_actor.items():
        total = fp + gen + unc
        if total > 0: print(f"  {actor:10s}: FP={fp}, Genuine={gen}, Uncertain={unc} (total={total})")
    if genuine_list:
        print(f"\nGENUINE DESTRUCTIVE ({len(genuine_list)}):")
        for ev in genuine_list[:20]:
            print(f"  [#{ev['id']}] {ev['ai_actor']} | {ev['title'][:80]}")
    cur.execute("CREATE TABLE IF NOT EXISTS filtered_destructive_commands (filter_id INTEGER PRIMARY KEY, event_id INTEGER UNIQUE, filter_result TEXT, confidence REAL, reviewed INTEGER DEFAULT 0)")
    for ev in fps: cur.execute("INSERT OR REPLACE INTO filtered_destructive_commands (event_id, filter_result, confidence) VALUES (?, 'false_positive', 0.8)", (ev['id'],))
    for ev in genuine_list: cur.execute("INSERT OR REPLACE INTO filtered_destructive_commands (event_id, filter_result, confidence) VALUES (?, 'genuine', 0.9)", (ev['id'],))
    for ev in uncertain: cur.execute("INSERT OR REPLACE INTO filtered_destructive_commands (event_id, filter_result, confidence) VALUES (?, 'uncertain', 0.5)", (ev['id'],))
    conn.commit(); conn.close()
    print(f"\nSaved to filtered_destructive_commands table")
if __name__ == "__main__":
    main()

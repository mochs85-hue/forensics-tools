#!/usr/bin/env python3
"""
Sample Critical Evidence Files from Anthropic Forensics Folder
Peeks into the most important files to understand their structure and content.
"""
import os, json, zipfile
from pathlib import Path
from collections import defaultdict

BASE = Path.home() / "Desktop" / "Anthropic Fornsics"

def head(filepath, lines=20):
    """Return first N lines of a text file."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            return [f.readline().rstrip() for _ in range(lines)]
    except Exception as e:
        return [f"ERROR: {e}"]

def sample_large_txt(filepath, max_bytes=50000):
    """Read first max_bytes and return structure summary."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            data = f.read(max_bytes)
        lines = data.split('\n')
        return {
            "total_lines_estimate": f"{os.path.getsize(filepath) / max(len(data),1) * len(lines):.0f}" if data else "0",
            "first_10_lines": lines[:10],
            "line_count_sampled": len(lines),
            "file_size_gb": f"{os.path.getsize(filepath) / (1024**3):.2f}",
            "delimiter": "tab" if '\t' in data else "pipe" if '|' in data[:1000] else "comma" if ',' in data[:1000] else "other",
        }
    except Exception as e:
        return {"error": str(e)}

def check_conversations_json(filepath):
    """Check structure of a conversations.json file without loading fully."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            first_char = f.read(1)
        if first_char == '[':
            return "Format: JSON Array (list of conversations)"
        elif first_char == '{':
            return "Format: JSON Object (single conversation or mapping)"
        else:
            return f"Format: Unknown (starts with '{first_char}')"
    except Exception as e:
        return f"Error: {e}"

def main():
    print("=" * 70)
    print("  CRITICAL EVIDENCE SAMPLER")
    print("=" * 70)
    
    # 1. Check conversations.json files
    print("\n\n=== 1. CONVERSATIONS.JSON FILES ===\n")
    conv_files = [
        BASE / "anthropic-claude-project-upload" / "source-record" / "conversations.json",
        BASE / "data-faf9ed85-ed03-43d1-941c-a6beac037aa9-1781610889-94032702-batch-0000" / "conversations.json",
    ]
    for cf in conv_files:
        if cf.exists():
            size_gb = os.path.getsize(cf) / (1024**3)
            print(f"\n  File: {cf.name}")
            print(f"  Size: {size_gb:.2f} GB")
            print(f"  Format: {check_conversations_json(cf)}")
            # Try to count conversations
            try:
                with open(cf, 'r', encoding='utf-8', errors='replace') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    print(f"  Conversations: {len(data)}")
                    if len(data) > 0:
                        first = data[0]
                        keys = list(first.keys())[:10]
                        print(f"  First conv keys: {keys}")
                        if 'chat_messages' in first and len(first['chat_messages']) > 0:
                            msg_keys = list(first['chat_messages'][0].keys())
                            print(f"  Message keys: {msg_keys}")
                        if 'name' in first:
                            print(f"  First conv name: {first['name'][:80]}")
                elif isinstance(data, dict):
                    print(f"  Top-level keys: {list(data.keys())[:15]}")
            except Exception as e:
                print(f"  Parse error: {e}")
        else:
            print(f"  NOT FOUND: {cf}")
    
    # 2. Sandbox Guard Hits (5.87 GB)
    print("\n\n=== 2. SANDBOX GUARD HITS (5.87 GB) ===\n")
    sb_file = BASE / "FORENSIC_CONTEXT_SCAN_20260618_120232" / "02_sandbox_guard_hits.txt"
    if sb_file.exists():
        print(f"  File: {sb_file}")
        sample = sample_large_txt(sb_file, 100000)
        for k, v in sample.items():
            if k == "first_10_lines":
                print(f"\n  First 10 lines:")
                for i, line in enumerate(v):
                    print(f"    {i+1}: {line[:150]}")
            else:
                print(f"  {k}: {v}")
    else:
        print(f"  NOT FOUND: {sb_file}")
    
    # 3. Original 19GB Wipe Context (267 MB)
    print("\n\n=== 3. ORIGINAL 19GB WIPE CONTEXT (267 MB) ===\n")
    wipe_file = BASE / "original-19gb-wipe-records-20260611-113421" / "ORIGINAL_19GB_WIPE_CONTEXT.txt"
    if wipe_file.exists():
        print(f"  File: {wipe_file}")
        sample = sample_large_txt(wipe_file, 100000)
        for k, v in sample.items():
            if k == "first_10_lines":
                print(f"\n  First 10 lines:")
                for i, line in enumerate(v):
                    print(f"    {i+1}: {line[:150]}")
            else:
                print(f"  {k}: {v}")
    else:
        print(f"  NOT FOUND: {wipe_file}")
    
    # 4. Claude Session Key Term Hits (928 MB)
    print("\n\n=== 4. CLAUDE SESSION KEY TERM HITS (928 MB) ===\n")
    kt_file = BASE / "claude-session-pivot-review-20260611-103422" / "CLAUDE-SESSION-KEY-TERM-HITS.txt"
    if kt_file.exists():
        print(f"  File: {kt_file}")
        sample = sample_large_txt(kt_file, 100000)
        for k, v in sample.items():
            if k == "first_10_lines":
                print(f"\n  First 10 lines:")
                for i, line in enumerate(v):
                    print(f"    {i+1}: {line[:150]}")
            else:
                print(f"  {k}: {v}")
    else:
        print(f"  NOT FOUND: {kt_file}")
    
    # 5. Forensic Analysis Scripts
    print("\n\n=== 5. FORENSIC ANALYSIS SCRIPTS ===\n")
    scripts = [
        BASE / "EXTRACT_ORIGINAL_19GB_WIPE_RECORDS.sh",
        BASE / "forensic_analysis.sh",
        BASE / "forensic_analysis_enhanced.sh",
    ]
    for sf in scripts:
        if sf.exists():
            print(f"\n  Script: {sf.name}")
            lines = head(sf, 30)
            for i, line in enumerate(lines):
                print(f"    {i+1}: {line[:120]}")
        else:
            print(f"  NOT FOUND: {sf}")
    
    # 6. Network Attribution
    print("\n\n=== 6. NETWORK ATTRIBUTION (1.88 GB) ===\n")
    net_file = BASE / "macos-network-attribution-upload-20260611-004755" / "network-focused-all-retained-history-filtered.txt"
    if net_file.exists():
        print(f"  File: {net_file}")
        sample = sample_large_txt(net_file, 50000)
        for k, v in sample.items():
            if k == "first_10_lines":
                print(f"\n  First 10 lines:")
                for i, line in enumerate(v):
                    print(f"    {i+1}: {line[:150]}")
            else:
                print(f"  {k}: {v}")
    else:
        print(f"  NOT FOUND: {net_file}")
    
    print("\n" + "=" * 70)
    print("  SAMPLING COMPLETE")
    print("=" * 70)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import os, csv, hashlib, datetime, subprocess, shutil

HOME = os.path.expanduser("~")
GDRIVE = os.path.join(HOME, "Library/CloudStorage/GoogleDrive-mochs85@gmail.com/My Drive")

SOURCE_LABEL  = "Mac-local"

# EXPLICIT TARGETS: Desktops, Documents, Downloads, Full iCloud Drive, and Google Drive
TARGET_ROOTS = [
    os.path.join(HOME, "Desktop"),                                              # Normal Desktop
    os.path.join(HOME, "Documents"),                                            # Normal Documents
    os.path.join(HOME, "Downloads"),                                            # Normal Downloads
    os.path.join(HOME, "Library/Mobile Documents/com~apple~CloudDocs"),         # Full iCloud Drive (includes iCloud Desktop & Documents)
    GDRIVE                                                                      # Google Drive (My Drive)
]

MASTER_CSV    = os.path.join(GDRIVE, "_forensic_output/forensic_inventory_master.csv")
GDRIVE_ROOT   = os.path.join(HOME, "Library/CloudStorage")
RECENT_FLAG_DATE = "2026-01-01"

FIELDS = ["source_label","root_type","full_path","filename","extension","size_bytes",
          "created_utc","modified_utc","sha256","status","scanned_utc",
          "prev_hash","row_hash"]

RECENT_TS = datetime.datetime.fromisoformat(RECENT_FLAG_DATE).timestamp()

# Backup locations for tamper protection
BACKUP_DIRS = [
    os.path.join(HOME, "Desktop", "_forensic_output_backup"),
    os.path.join(HOME, "Documents", "_forensic_output_backup"),
]


def iso(ts): return datetime.datetime.utcfromtimestamp(ts).isoformat()+"Z"
def abs_norm(path): return os.path.abspath(os.path.expanduser(path))

def chflags_uchg(path):
    """Set macOS user-immutable flag to prevent tampering."""
    try:
        subprocess.run(["chflags", "uchg", str(path)], check=True, capture_output=True, timeout=10)
        return True
    except Exception:
        return False

def chflags_nouchg(path):
    """Remove immutable flag so we can append."""
    try:
        subprocess.run(["chflags", "nouchg", str(path)], check=True, capture_output=True, timeout=10)
        return True
    except Exception:
        return False

def sidecar_hash(filepath):
    """Write SHA-256 sidecar file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    hexhash = h.hexdigest()
    sidecar = filepath + ".sha256"
    with open(sidecar, "w") as f:
        f.write(f"{hexhash}  {os.path.basename(filepath)}\n")
    chflags_uchg(sidecar)
    return hexhash, sidecar

def verify_chain(csv_path):
    """Verify hash chain integrity. Returns (ok, rows, message)."""
    if not os.path.exists(csv_path):
        return False, 0, "file_not_found"
    prev = "0" * 64
    row_num = 0
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row_num += 1
            expected = hashlib.sha256((
                row.get("source_label", "") + "|" +
                row.get("full_path", "") + "|" +
                str(row.get("size_bytes", "")) + "|" +
                row.get("sha256", "") + "|" +
                row.get("status", "") + "|" +
                prev
            ).encode()).hexdigest()
            actual = row.get("row_hash", "")
            if expected != actual:
                return False, row_num, f"BROKEN row {row_num}: exp={expected[:16]}... got={actual[:16]}..."
            prev = actual
    return True, row_num, "chain_intact"

def already_done(master, label):
    done = set()
    if os.path.exists(master):
        with open(master, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if r.get("source_label") == label:
                    done.add(r.get("full_path"))
    return done

def is_local(st, name):
    if name.endswith(".icloud"): return False
    if st.st_size == 0: return True
    blocks = getattr(st, "st_blocks", None)
    if blocks is not None: return (blocks*512) >= (st.st_size*0.9)
    return True

def is_cloud_tree(path, root_type):
    if root_type == "OtherComputers-backup": return True
    return "/library/cloudstorage/" in abs_norm(path).lower()

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def find_other_computers_roots(gdrive_root):
    roots = []
    if not gdrive_root or not os.path.isdir(gdrive_root): return roots
    for dirpath, dirnames, _ in os.walk(gdrive_root):
        for d in dirnames:
            low = d.lower()
            if "other comput" in low or low == "computers":
                roots.append(os.path.join(dirpath, d))
        if dirpath.count(os.sep) - gdrive_root.count(os.sep) > 4:
            dirnames[:] = []
    return roots

def scan(scan_root, label, root_type, master_csv, writer, done, scanned, prev_hash):
    n = skip = 0
    master_csv_abs = abs_norm(master_csv)
    out_dir_abs = abs_norm(os.path.dirname(master_csv))
    for root, dirs, files in os.walk(scan_root, followlinks=False):
        # Ignore the forensic output directory to prevent infinite loops
        if abs_norm(root) == out_dir_abs:
            dirs[:] = []
            continue
        # Also ignore backup directories
        if any(abs_norm(root) == abs_norm(b) for b in BACKUP_DIRS if os.path.exists(b)):
            dirs[:] = []
            continue
        for name in files:
            path = os.path.join(root, name)
            if abs_norm(path) == master_csv_abs:
                skip += 1
                continue
            if path in done:
                skip += 1
                continue
            row = {k: "" for k in FIELDS}
            row.update(source_label=label, root_type=root_type, full_path=path,
                       filename=name, extension=os.path.splitext(name)[1].lower(),
                       scanned_utc=scanned, prev_hash=prev_hash)
            try:
                if os.path.islink(path):
                    row["status"] = "SYMLINK_skipped"
                else:
                    st = os.stat(path)
                    row["size_bytes"] = st.st_size
                    row["modified_utc"] = iso(st.st_mtime)
                    row["created_utc"] = iso(getattr(st, "st_birthtime", st.st_ctime))
                    recent = st.st_mtime >= RECENT_TS
                    local = is_local(st, name)
                    
                    # Prevent mass cloud downloads by skipping hashes for online files
                    if is_cloud_tree(path, root_type):
                        row["status"] = "CLOUD_TREE_local_present" if local else "CLOUD_TREE_web_only_metadata_only"
                    elif local:
                        row["sha256"] = sha256_of(path)
                        row["status"] = "OK"
                    else:
                        row["status"] = "ONLINE_ONLY_not_opened"
                    if root_type == "OtherComputers-backup" and recent:
                        row["status"] += " | RECENT_IN_BACKUP_REVIEW"
            except (OSError, PermissionError) as e:
                row["status"] = f"ERROR_{type(e).__name__}"
            
            # HASH CHAIN: each row hash includes previous row's hash
            row_data = (
                row["source_label"] + "|" + row["full_path"] + "|" +
                str(row["size_bytes"]) + "|" + row["sha256"] + "|" +
                row["status"] + "|" + prev_hash
            )
            row_hash = hashlib.sha256(row_data.encode()).hexdigest()
            row["row_hash"] = row_hash
            prev_hash = row_hash  # propagate forward
            
            writer.writerow(row)
            n += 1
            if n % 500 == 0:
                print(f"  ...{n} in {label}")
    print(f"  [{label}] {n} new rows, {skip} skipped.")
    return n, prev_hash

def main():
    scanned = datetime.datetime.utcnow().isoformat() + "Z"
    os.makedirs(os.path.dirname(MASTER_CSV), exist_ok=True)
    for d in BACKUP_DIRS:
        os.makedirs(d, exist_ok=True)
    
    roots = find_other_computers_roots(abs_norm(GDRIVE_ROOT))
    new = not os.path.exists(MASTER_CSV)
    
    # Remove immutability so we can append
    if os.path.exists(MASTER_CSV):
        chflags_nouchg(MASTER_CSV)
    
    prev_hash = "0" * 64  # Genesis hash for chain
    
    with open(MASTER_CSV, "a", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=FIELDS)
        if new:
            w.writeheader()
        done = already_done(MASTER_CSV, SOURCE_LABEL)
        
        print(f"Scanning active sources '{SOURCE_LABEL}' ...")
        # Loop through explicit target directories
        for target in TARGET_ROOTS:
            if os.path.exists(target):
                print(f" -> Scanning path: {target}")
                n, prev_hash = scan(target, SOURCE_LABEL, "active", MASTER_CSV, w, done, scanned, prev_hash)
            else:
                print(f" -> SKIP: Path not found or inaccessible: {target}")
                
        # Handle 'Other computers' dynamically 
        if roots:
            print(f"\nFound {len(roots)} 'Other computers' backup root(s).")
        for r in roots:
            for machine in sorted(os.listdir(r)):
                mpath = os.path.join(r, machine)
                if not os.path.isdir(mpath):
                    continue
                label = f"OtherComputers-{machine}"
                try:
                    entries = os.listdir(mpath)
                except OSError as e:
                    row = {k: "" for k in FIELDS}
                    row.update(source_label=label, root_type="OtherComputers-backup",
                               full_path=mpath, status=f"ROOT_UNREADABLE_{type(e).__name__}",
                               scanned_utc=scanned, prev_hash=prev_hash)
                    # Hash chain even for error rows
                    rd = label + "|" + mpath + "|||" + row["status"] + "|" + prev_hash
                    rh = hashlib.sha256(rd.encode()).hexdigest()
                    row["row_hash"] = rh
                    prev_hash = rh
                    w.writerow(row)
                    continue
                if not entries:
                    row = {k: "" for k in FIELDS}
                    row.update(source_label=label, root_type="OtherComputers-backup",
                               full_path=mpath, status="ROOT_EMPTY_possibly_web_only",
                               scanned_utc=scanned, prev_hash=prev_hash)
                    rd = label + "|" + mpath + "|||" + row["status"] + "|" + prev_hash
                    rh = hashlib.sha256(rd.encode()).hexdigest()
                    row["row_hash"] = rh
                    prev_hash = rh
                    w.writerow(row)
                    print(f"  GAP: {label} empty/web-only -- logged.")
                    continue
                done = already_done(MASTER_CSV, label)
                print(f"Scanning backup root '{label}' ...")
                n, prev_hash = scan(mpath, label, "OtherComputers-backup", MASTER_CSV, w, done, scanned, prev_hash)
    
    # =====================================================================
    # TAMPER PROTECTION LAYER
    # =====================================================================
    print("\n" + "="*50)
    print("APPLYING TAMPER PROTECTIONS")
    print("="*50)
    
    # 1. Sidecar hash
    print("1. Writing sidecar hash...")
    mh, msc = sidecar_hash(MASTER_CSV)
    print(f"   {msc}")
    print(f"   Hash: {mh}")
    
    # 2. Immutable flag on master CSV
    print("2. Setting immutable flag...")
    chflags_uchg(MASTER_CSV)
    
    # 3. GPG signature (optional)
    print("3. Attempting GPG signature...")
    try:
        subprocess.run(["gpg", "--detach-sign", "--armor", "-o",
                       MASTER_CSV + ".asc", MASTER_CSV],
                      check=True, capture_output=True, timeout=30)
        chflags_uchg(MASTER_CSV + ".asc")
        print(f"   GPG signature: {MASTER_CSV}.asc")
    except Exception:
        print("   GPG not available, skipped")
    
    # 4. Backup copies
    print("4. Creating backup copies...")
    for backup_dir in BACKUP_DIRS:
        try:
            dst = os.path.join(backup_dir, "forensic_inventory_master.csv")
            shutil.copy2(MASTER_CSV, dst)
            # Copy sidecar
            sc = MASTER_CSV + ".sha256"
            if os.path.exists(sc):
                shutil.copy2(sc, dst + ".sha256")
            chflags_uchg(dst)
            print(f"   Backup: {backup_dir}")
        except Exception as e:
            print(f"   Backup skipped: {e}")
    
    # 5. Verify chain
    print("5. Verifying hash chain...")
    ok, rows, msg = verify_chain(MASTER_CSV)
    status = "PASS" if ok else "FAIL"
    print(f"   {status}: {msg} ({rows:,} rows)")
    
    # Re-lock after verification
    chflags_uchg(MASTER_CSV)
    
    print("="*50)
    print(f"Done. Master CSV: {MASTER_CSV}")
    print(f"Chain verification: {status}")
    
    # Print verification one-liner
    print("\nTo verify later:")
    print("python3 -c \"import csv,hashlib; prev='0'*64; f=open('" + MASTER_CSV + "'); r=csv.DictReader(f); [(__import__('sys').exit(f'BREAK row {i}') if hashlib.sha256((row['source_label']+'|'+row['full_path']+'|'+str(row['size_bytes'])+'|'+row['sha256']+'|'+row['status']+'|'+prev).encode()).hexdigest()!=row['row_hash'] else None, (prev:=row['row_hash'])) for i,row in enumerate(r,1)]; print('CHAIN OK')\"")

if __name__ == "__main__":
    main()

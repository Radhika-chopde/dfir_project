import psutil
import os
import psycopg2
import hashlib
from flask import Flask, request, jsonify
from config import DB_CONFIG
from db_utils import save_to_db

app = Flask(__name__)


def get_process_hash(pid):
    """Attempts to hash the executable of a running process."""
    try:
        p = psutil.Process(pid)
        exe_path = p.exe()
        if not exe_path or not os.path.exists(exe_path):
            return None
        sha256_hash = hashlib.sha256()
        with open(exe_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def analyze_memory():
    findings = []
    CORE_SYSTEM_PIDS = {0, 4}

    # Build a PID→name map first for parent-child checks
    pid_name_map = {}
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid_name_map[proc.info['pid']] = (proc.info['name'] or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Suspicious parent-child pairs: child → [legitimate parents]
    SUSPICIOUS_PARENTS = {
        "powershell.exe": ["explorer.exe", "cmd.exe"],    # Unexpected: word.exe → powershell.exe
        "cmd.exe":        ["explorer.exe", "powershell.exe"],
        "wscript.exe":    ["explorer.exe"],
        "mshta.exe":      ["explorer.exe"],
    }
    EXPECTED_PARENTS = {
        "svchost.exe":  ["services.exe"],
        "lsass.exe":    ["wininit.exe"],
        "csrss.exe":    ["smss.exe"],
        "wininit.exe":  ["smss.exe"],
    }

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'status', 'ppid']):
        try:
            pinfo = proc.info
            pid   = pinfo['pid']
            if pid in CORE_SYSTEM_PIDS:
                continue

            name   = (pinfo['name'] or "").lower()
            exe    = (pinfo['exe']  or "").lower()
            ppid   = pinfo.get('ppid', 0)
            parent_name = pid_name_map.get(ppid, "unknown")

            score   = 0
            reasons = []

            # Path anomaly
            if any(p in exe for p in ["\\temp\\", "\\appdata\\local\\temp", "\\users\\public"]):
                if "setup" not in name and "update" not in name:
                    score += 7
                    reasons.append("Executing from user-writable directory")

            # Masquerade
            system_names = ["svchost.exe", "lsass.exe", "wininit.exe", "csrss.exe"]
            if any(s in name for s in system_names):
                if exe and "system32" not in exe and "syswow64" not in exe:
                    score += 9
                    reasons.append("System process masquerading (wrong path)")

            # Ghost process
            if not exe and pinfo['status'] == 'running':
                score += 8
                reasons.append("Ghost process: no disk-binary accessible")

            # NEW: Suspicious parent-child relationship
            if name in SUSPICIOUS_PARENTS:
                allowed = SUSPICIOUS_PARENTS[name]
                if parent_name not in allowed and parent_name != "unknown":
                    score += 6
                    reasons.append(f"Suspicious parent: {parent_name} → {name}")

            if name in EXPECTED_PARENTS:
                expected = EXPECTED_PARENTS[name]
                if parent_name not in expected:
                    score += 8
                    reasons.append(f"Critical parent mismatch: {parent_name} → {name} (expected {expected[0]})")

            if score >= 6:
                findings.append({
                    "pid": pid, "name": name, "score": score,
                    "reasons": reasons, "exe": exe,
                    "parent": parent_name,
                    "hash": get_process_hash(pid)
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return findings

@app.route('/scan_memory', methods=['POST'])
def scan_memory():
    data = request.get_json()
    investigation_id = data.get('investigation_id')
    
    print(f"[*] Memory Agent: Starting RAM Triage (Noise Filter Enabled)...")
    memory_hits = analyze_memory()
    
    for hit in memory_hits:
        desc = f"Risk {hit['score']}/10: {', '.join(hit['reasons'])}. PID: {hit['pid']} | Hash: {hit['hash']}"
        save_to_db("MemoryAgent", "Volatile Memory Anomaly", desc, investigation_id, f"RAM: {hit['name']}")

    return jsonify({"status": "complete", "matches_found": len(memory_hits)})

if __name__ == '__main__':
    app.run(port=5008, debug=False)
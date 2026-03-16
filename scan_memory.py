import psutil
import os
import psycopg2
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_CONFIG = {
    "dbname": "dfir_db",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": "5432"
}

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
    """
    Scans live RAM with improved filtering to eliminate system False Positives.
    """
    findings = []
    # CORE SYSTEM PIDs: 0 (Idle), 4 (System). These never have standard EXE paths.
    CORE_SYSTEM_PIDS = [0, 4]
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'status']):
        try:
            pinfo = proc.info
            pid = pinfo['pid']
            
            # 1. WHITELIST: Ignore core kernel processes that trigger "Ghost Process" flags
            if pid in CORE_SYSTEM_PIDS:
                continue
                
            name = (pinfo['name'] or "").lower()
            exe = (pinfo['exe'] or "").lower()
            
            score = 0
            reasons = []

            # 2. Path Anomaly (Running from Temp/AppData)
            if any(path in exe for path in ["\\temp\\", "\\appdata\\local\\temp", "\\users\\public"]):
                # Lower risk if the process name clearly indicates an installer/updater
                if "setup" not in name and "update" not in name:
                    score += 7
                    reasons.append("Process executing from volatile user-writable directory")

            # 3. Masquerading (e.g. svchost.exe NOT in system32)
            system_names = ["svchost.exe", "lsass.exe", "wininit.exe", "csrss.exe"]
            if any(s in name for s in system_names):
                if exe and "system32" not in exe and "syswow64" not in exe:
                    score += 9
                    reasons.append("Critical: System process masquerading detected (path mismatch)")

            # 4. Ghost Process Logic (Refined)
            # Only flag if it's NOT a kernel process and truly has no executable path
            if not exe and pinfo['status'] == 'running':
                # Note: Some system services may deny access to non-admin users, 
                # appearing as 'no exe'. We flag this but with context.
                score += 8
                reasons.append("Ghost Process: In-memory execution without accessible disk-binary")

            if score >= 6:
                findings.append({
                    "pid": pid,
                    "name": name,
                    "score": score,
                    "reasons": reasons,
                    "exe": exe,
                    "hash": get_process_hash(pid)
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings

def save_to_db(agent_name, finding_type, description, investigation_id, file_path):
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        sql = "INSERT INTO findings (agent_name, finding_type, description, investigation_id, file_path) VALUES (%s, %s, %s, %s, %s);"
        cur.execute(sql, (agent_name, finding_type, description, investigation_id, file_path))
        conn.commit()
        cur.close()
    except Exception as e:
        print(f"Memory Agent DB Error: {e}")
    finally:
        if conn is not None: conn.close()

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
    app.run(port=5008, debug=True)
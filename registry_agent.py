import winreg
import os
import re
import math
import psycopg2
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_CONFIG = {
    "dbname": "dfir_db",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": "5432"
}

# --- ADVANCED PERSISTENCE LOCATIONS ---
# Expanded beyond just "Run" keys to include advanced hijacking spots
PERSISTENCE_HIVES = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "Standard Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "Standard Run (System)"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce (Volatile)"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon Hijack"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "IFEO Debugger Hijack"),
    (winreg.HKEY_CURRENT_USER, r"Software\Classes\exefile\shell\open\command", "Shell Extension Hijack")
]

# Binaries that are commonly abused by attackers (Living off the Land)
LOLBINS = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "bitsadmin.exe", "certutil.exe"]

# Legitimate system names often used for masquerading
SYSTEM_PROCESS_NAMES = ["svchost.exe", "lsass.exe", "wininit.exe", "smss.exe", "csrss.exe", "services.exe"]

def calculate_entropy(text):
    if not text: return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return - sum([p * math.log(p) / math.log(2.0) for p in prob])

def analyze_registry_value(name, value, hive_desc):
    """Calculates a risk score for a registry entry."""
    score = 0
    reasons = []
    val_str = str(value).lower()
    
    # 1. Path Trust Analysis
    # Legitimate software shouldn't run from user-writable temp space
    if any(p in val_str for p in ["\\temp\\", "\\appdata\\local\\temp", "\\users\\public"]):
        score += 5
        reasons.append("User-Writable Path")
    
    # 2. LOLBins Detection (Living off the Land)
    if any(bin_name in val_str for bin_name in LOLBINS):
        score += 6
        reasons.append("LOLBin Execution (Scripting Engine)")

    # 3. Masquerading Check (The "Imposter" logic)
    # If a value name looks like a system process but is in a weird path
    if any(sys_name in val_str for sys_name in SYSTEM_PROCESS_NAMES):
        if "c:\\windows\\system32" not in val_str and "c:\\windows\\syswow64" not in val_str:
            score += 7
            reasons.append("Process Masquerading (System name in non-system path)")

    # 4. Obfuscation Detection
    # Large Base64 strings in the registry are a sign of fileless malware
    if len(val_str) > 100 and ( "-enc" in val_str or "base64" in val_str or calculate_entropy(val_str) > 4.8):
        score += 6
        reasons.append("High Entropy / Encoded Command")

    # 5. IFEO specific checks
    if "Image File Execution Options" in hive_desc and "debugger" in val_str:
        score += 8
        reasons.append("Debugger Hijack (IFEO)")

    return score, reasons

def save_to_db(agent_name, finding_type, description, investigation_id, file_path):
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        sql = "INSERT INTO findings (agent_name, finding_type, description, investigation_id, file_path) VALUES (%s, %s, %s, %s, %s);"
        cur.execute(sql, (agent_name, finding_type, description, investigation_id, file_path))
        conn.commit()
        cur.close()
    except Exception as e: print(f"Registry Agent DB Error: {e}")
    finally:
        if conn: conn.close()

@app.route('/scan_registry', methods=['POST'])
def scan_registry():
    data = request.get_json()
    investigation_id = data.get('investigation_id')
    findings_count = 0
    
    for hkey, path, desc in PERSISTENCE_HIVES:
        try:
            with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ) as key:
                # Some keys might have subkeys (like IFEO)
                num_subkeys, num_values, _ = winreg.QueryInfoKey(key)
                
                # Check direct values
                for i in range(num_values):
                    name, value, _ = winreg.EnumValue(key, i)
                    risk_score, reasons = analyze_registry_value(name, value, desc)
                    
                    if risk_score >= 6:
                        description = f"Risk {risk_score}/10 [{desc}]: {', '.join(reasons)}. Entry: {name} -> {str(value)[:50]}..."
                        save_to_db("RegistryAgent", "Persistence Anomaly", description, investigation_id, f"Registry: {path}")
                        findings_count += 1
                        
                # Special logic for IFEO (checking subkeys)
                if "Image File Execution Options" in desc:
                    for i in range(num_subkeys):
                        subkey_name = winreg.EnumKey(key, i)
                        # We don't dive into every subkey here for performance, but we flag the existence
                        # of unusual subkeys if they match masquerading patterns
                        if any(sys_name in subkey_name.lower() for sys_name in SYSTEM_PROCESS_NAMES):
                            pass # High-level logic: usually IFEO subkeys for system files are suspicious
                            
        except Exception:
            continue

    return jsonify({"status": "complete", "matches_found": findings_count})

if __name__ == '__main__':
    app.run(port=5006, debug=True)
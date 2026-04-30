import sys
if sys.platform != 'win32':
    raise RuntimeError("RegistryAgent is only supported on Windows.")
import winreg
import os
import math
from flask import Flask, request, jsonify
from config import DB_CONFIG

# Ensure this matches your project structure
try:
    from db_utils import save_to_db
except ImportError:
    def save_to_db(agent, ftype, desc, inv_id, path):
        print(f"[DB LOG] {agent} | {ftype} | {desc} | {path}")

app = Flask(__name__)

# --- UPDATED HIVES ---
PERSISTENCE_HIVES = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "Standard Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "Standard Run (System)"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce (Volatile)"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon Hijack"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "IFEO Debugger Hijack"),
    (winreg.HKEY_CURRENT_USER, r"Software\Classes\exefile\shell\open\command", "Shell Extension Hijack"), # FIXED: Added Comma
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services", "Services (Persistence)") # FIXED: Added Comma
]

LOLBINS = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "bitsadmin.exe", "certutil.exe"]
SYSTEM_PROCESS_NAMES = ["svchost.exe", "lsass.exe", "wininit.exe", "smss.exe", "csrss.exe", "services.exe"]

def calculate_entropy(text):
    if not text: return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return - sum([p * math.log2(p) for p in prob])

def analyze_registry_value(name, value):
    """Focuses on risk scoring the string content."""
    score = 0
    reasons = []
    val_str = str(value).lower()
    
    if any(p in val_str for p in ["\\temp\\", "\\users\\public", "\\appdata\\local\\temp"]):
        score += 5
        reasons.append("User-Writable Path")
    
    if any(bin_name in val_str for bin_name in LOLBINS):
        score += 6
        reasons.append("LOLBin/Scripting Engine")

    if any(sys_name in val_str for sys_name in SYSTEM_PROCESS_NAMES):
        if "system32" not in val_str and "syswow64" not in val_str:
            score += 7
            reasons.append("Process Masquerading")

    # Lowered entropy threshold slightly for shorter strings like your 'Updater_Script'
    if "-enc" in val_str or calculate_entropy(val_str) > 4.5:
        if len(val_str) > 20: # Minimal length check
            score += 6
            reasons.append("Obfuscation/Encoded Command")

    return score, reasons

@app.route('/scan_registry', methods=['POST'])
def scan_registry():
    data = request.get_json()
    investigation_id = data.get('investigation_id')
    findings_count = 0
    
    for hkey, path, hive_desc in PERSISTENCE_HIVES:
        try:
            # Added KEY_WOW64_64KEY to bypass 32-bit redirection
            access_flags = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            with winreg.OpenKey(hkey, path, 0, access_flags) as key:
                num_subkeys, num_values, _ = winreg.QueryInfoKey(key)
                
                # 1. Analyze direct values (Standard Run keys)
                for i in range(num_values):
                    name, value, _ = winreg.EnumValue(key, i)
                    risk_score, reasons = analyze_registry_value(name, value)
                    
                    if risk_score >= 6:
                        description = f"Risk {risk_score}/10 [{hive_desc}]: {', '.join(reasons)}. Entry: {name}"
                        save_to_db("RegistryAgent", "Persistence Anomaly", description, investigation_id, f"Registry: {path}")
                        findings_count += 1
                
                # 2. IFEO Logic (Iterating through subkeys like notepad.exe)
                if "Image File Execution Options" in hive_desc:
                    for i in range(num_subkeys):
                        subkey_name = winreg.EnumKey(key, i)
                        try:
                            with winreg.OpenKey(key, subkey_name, 0, access_flags) as sub:
                                debugger_val, _ = winreg.QueryValueEx(sub, "Debugger")
                                desc_out = f"IFEO Hijack: {subkey_name} redirected to {str(debugger_val)[:60]}"
                                save_to_db("RegistryAgent", "Debugger Hijack", desc_out, investigation_id, f"Registry: IFEO\\{subkey_name}")
                                findings_count += 1
                        except FileNotFoundError: pass

        except Exception: continue

    return jsonify({"status": "complete", "matches_found": findings_count})

if __name__ == '__main__':
    app.run(port=5006, debug=False)
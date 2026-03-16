import sys
import os
import requests
import time
import psycopg2
import merkle_utils 

# --- AGENT MICROSERVICE ENDPOINTS ---
HASH_AGENT_URL = "http://127.0.0.1:5001/analyze_file"
KEYWORD_AGENT_URL = "http://127.0.0.1:5002/search_keywords"
FILE_SIGNATURE_AGENT_URL = "http://127.0.0.1:5003/verify_signature"
TIMELINE_AGENT_URL = "http://127.0.0.1:5004/get_timestamps"
THREAT_INTEL_AGENT_URL = "http://127.0.0.1:5005/check_hash"
REGISTRY_AGENT_URL = "http://127.0.0.1:5006/scan_registry"
BROWSER_AGENT_URL = "http://127.0.0.1:5007/scan_browser"
MEMORY_AGENT_URL = "http://127.0.0.1:5008/scan_memory" 

DB_CONFIG = {
    "dbname": "dfir_db",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": "5432"
}

def call_agent(url, payload, agent_name, retries=3, delay=2):
    """Helper function to communicate with the Flask microservice agents."""
    for i in range(retries):
        try:
            response = requests.post(url, json=payload, timeout=25)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            if i == retries - 1:
                print(f"[!] Agent {agent_name} failed at {url}")
            time.sleep(delay)
    return None

def run_investigation(directory_path, investigation_id):
    """
    Orchestrates the 8-agent investigation and seals 
    all results with a Hardware-Bound Merkle Root.
    """
    print(f"--- Starting Full Investigation [{investigation_id}] ---")
    
    # ADVANCED FEATURE: CAPTURE HARDWARE ID FOR INTEGRITY BINDING
    hw_id = merkle_utils.get_hardware_id()
    print(f"[*] Integrity Layer: Binding Seal to Hardware ID {hw_id}")

    # 1. Initialize the record in the investigations table
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO investigations (investigation_id, status) VALUES (%s, %s)",
            (investigation_id, "RUNNING")
        )
        conn.commit()
    except Exception as e:
        print(f"[!] Database Init Error: {e}")
        return

    # 2. File-Based Forensics (Disk Analysis)
    files_to_process = []
    for root, _, files in os.walk(directory_path):
        for filename in files:
            files_to_process.append(os.path.join(root, filename))

    for file_path in files_to_process:
        print(f"\n[*] Analyzing File: {os.path.basename(file_path)}")
        
        # AGENT 1: HASHING
        hash_res = call_agent(HASH_AGENT_URL, {"file_path": file_path, "investigation_id": investigation_id}, "Hash Agent")
        file_hash = hash_res.get('hash') if hash_res else None

        # AGENT 2: KEYWORD SCAN (Using Forensic Library)
        key_res = call_agent(KEYWORD_AGENT_URL, {
            "file_path": file_path, 
            "keywords": ["internal_project", "confidential"], 
            "investigation_id": investigation_id
        }, "Keyword Agent")
        keyword_hit = key_res and key_res.get('matches_found', 0) > 0

        # AGENT 3: FILE SIGNATURE
        sig_res = call_agent(FILE_SIGNATURE_AGENT_URL, {"file_path": file_path, "investigation_id": investigation_id}, "Signature Agent")
        signature_mismatch = sig_res and sig_res.get('mismatch_found')

        # AGENT 4: TIMELINE ANALYSIS
        call_agent(TIMELINE_AGENT_URL, {"file_path": file_path, "investigation_id": investigation_id}, "Timeline Agent")

        # AGENT 5: THREAT INTEL (Escalation)
        if (signature_mismatch or keyword_hit) and file_hash:
            print(f"    [!] Escalating {os.path.basename(file_path)} to Threat Intel...")
            call_agent(THREAT_INTEL_AGENT_URL, {
                "hash_to_check": file_hash, 
                "investigation_id": investigation_id,
                "file_path": file_path
            }, "Threat Intel Agent")

    # 3. System-Level Forensics (OS Artifacts)
    print("\n[*] Running System-Level Persistence & Behavioral Scans...")
    
    # AGENT 6: REGISTRY HIVE AGENT
    print("    [>] Checking Registry Hives for Hijacks...")
    call_agent(REGISTRY_AGENT_URL, {"investigation_id": investigation_id}, "Registry Agent")

    # AGENT 7: BROWSER FORENSIC AGENT
    print("    [>] Analyzing Browser Behavioral History...")
    call_agent(BROWSER_AGENT_URL, {"investigation_id": investigation_id}, "Browser Agent")

    # 4. Volatile Memory Forensics (Live RAM)
    # AGENT 8: MEMORY AGENT
    print("\n[*] Conducting Live Memory Triage (RAM)...")
    call_agent(MEMORY_AGENT_URL, {"investigation_id": investigation_id}, "Memory Agent")

    # 5. GENERATE MERKLE ROOT (The Forensic Integrity Seal)
    print("\n[*] All agents finished. Fetching findings to generate Hardware-Bound Seal...")
    
    try:
        cur.execute("SELECT file_path, finding_type, description FROM findings WHERE investigation_id = %s", (investigation_id,))
        rows = cur.fetchall()
        
        # Format the data for the Merkle utility
        all_findings = [{"file_path": r[0], "finding_type": r[1], "description": r[2]} for r in rows]
        
        # ADVANCED: Pass hw_id to bind the root hash to this machine
        root_hash = merkle_utils.generate_investigation_integrity(all_findings, hw_id=hw_id)
        
        # Finalize Investigation Record
        cur.execute(
            "UPDATE investigations SET merkle_root = %s, status = %s WHERE investigation_id = %s",
            (root_hash, "COMPLETED", investigation_id)
        )
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"[+] Investigation Signed Successfully.")
        print(f"[+] Final Merkle Root: {root_hash}")
        
    except Exception as e:
        print(f"[!] Integrity Sealing Error: {e}")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python controller.py <directory_path> <investigation_id>")
    else:
        run_investigation(sys.argv[1], sys.argv[2])
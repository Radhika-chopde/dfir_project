import sys
import os
import requests
import time

HASH_AGENT_URL = "http://127.0.0.1:5001/analyze_file"
KEYWORD_AGENT_URL = "http://127.0.0.1:5002/search_keywords"
FILE_SIGNATURE_AGENT_URL = "http://127.0.0.1:5003/verify_signature"
TIMELINE_AGENT_URL = "http://127.0.0.1:5004/get_timestamps"
THREAT_INTEL_AGENT_URL = "http://127.0.0.1:5005/check_hash" # The "slow" agent

SUSPICIOUS_EXTENSIONS = [
    '.exe', '.dll', '.bat', '.ps1', '.vbs', '.sh', '.py', '.jar', '.com', 
    '.scr', '.msi', '.cmd', '.cpl', '.hta', '.wsf', '.jse'
]

def call_agent(url, payload, agent_name, retries=3, delay=2):
    """Utility function to call an agent with retry logic."""
    for i in range(retries):
        try:
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError:
            print(f"  [!] Error connecting to {agent_name} Agent.")
        except requests.exceptions.RequestException as e:
            print(f"  [!] Error from {agent_name} Agent: {e}")
            break
        
        time.sleep(delay)
    
    return None

def main():
    if len(sys.argv) < 3:
        print("Usage: python controller.py <directory_to_analyze> <investigation_id>")
        return
    
    target_directory = sys.argv[1]
    investigation_id = sys.argv[2]
    
    if not os.path.isdir(target_directory):
        print(f"Error: '{target_directory}' is not a valid directory.")
        return

    print(f"--- Controller starting investigation [{investigation_id}] on: {target_directory} ---")

    files_to_process = []
    for root, dirs, files in os.walk(target_directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            files_to_process.append(file_path)

    if not files_to_process:
        print("No files found.")
        return
        
    print(f"Found {len(files_to_process)} files to analyze...")

    for file_path in files_to_process:
        print(f"\n>>> Analyzing: {file_path}")
        
        is_suspicious = False
        triage_reason = "N/A"
        current_hash = None
        hash_payload = {"file_path": file_path, "investigation_id": investigation_id}
        hash_result = call_agent(HASH_AGENT_URL, hash_payload, "Hash")
        if hash_result and 'hash' in hash_result:
            current_hash = hash_result['hash']
            print("  - Hash:", current_hash)
        else:
            print("  - Could not get hash. Skipping file.")
            continue
        keyword_payload = {
            "file_path": file_path,
            "keywords": ["secret", "password", "admin", "confidential", "private"],
            "investigation_id": investigation_id
        }
        keyword_result = call_agent(KEYWORD_AGENT_URL, keyword_payload, "Keyword")
        if keyword_result and keyword_result.get('matches_found', 0) > 0:
            is_suspicious = True
            triage_reason = "Keyword Hit"
            print("  - Keyword: Found", keyword_result.get('matches_found'), "matches.")

        signature_payload = {"file_path": file_path, "investigation_id": investigation_id}
        sig_result = call_agent(FILE_SIGNATURE_AGENT_URL, signature_payload, "Signature")
        if sig_result and sig_result.get('mismatch_found', False):
            is_suspicious = True
            triage_reason = "Signature Mismatch"
            print("  - Signature: Mismatch found!")
        timeline_payload = {"file_path": file_path, "investigation_id": investigation_id}
        call_agent(TIMELINE_AGENT_URL, timeline_payload, "Timeline")
        if not is_suspicious:
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in SUSPICIOUS_EXTENSIONS:
                is_suspicious = True
                triage_reason = "Suspicious by Default (File Type)"
        if is_suspicious:
            print(f"    [!] Triage escalation ({triage_reason}). Sending hash to Threat Intel Agent...")
            intel_payload = {
                "hash_to_check": current_hash,
                "file_path": file_path,
                "investigation_id": investigation_id
            }
            intel_result = call_agent(THREAT_INTEL_AGENT_URL, intel_payload, "Threat Intel")
            if intel_result:
                print("    [!] Threat Intel Response:", intel_result.get('status'))
        else:
            print(f"  - Triage: File appears normal. Skipping Threat Intel.")

    print(f"\n--- Controller finished investigation [{investigation_id}]. ---")

if __name__ == '__main__':
    main()
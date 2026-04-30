import os
import hashlib
from flask import Flask, request, jsonify
from config import DB_CONFIG
from db_utils import save_to_db

app = Flask(__name__)

# --- FORENSIC BLOCKLIST ---
# These are SHA-256 signatures of high-impact threats for your demo.
KNOWN_BAD_HASHES = {
    # EICAR Test File (Use this for your live "Malware Hit" demo)
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR Anti-Virus Test File (Standardized Detection Match)",
    
    # WannaCry Ransomware
    "24d00d3158a35510ca3f610c61f370834163901309354067a806c352df9d6b5e": "WannaCry Ransomware Payload (T1486)",
    
    # Metasploit/Meterpreter Reverse Shell
    "094f79174442031737e5436691459a35e45a07142b78b0244458319f69747209": "Metasploit Meterpreter Payload (C2 Activity)",

    # Empty File (Anti-Forensic Evasion Check)
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Zero-Byte Artifact (Possible Evasion/Wiping Indicator)"
}

def calculate_hash(file_path):
    """Computes the SHA-256 hash of a file using block-reads to save RAM."""
    sha256_hash = hashlib.sha256()
    try:
        if not os.path.exists(file_path):
            return None
        with open(file_path, "rb") as f:
            # Read in 4KB chunks to avoid crashing your 8GB RAM ASUS Vivobook
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"[HashAgent] Error hashing {file_path}: {e}")
        return None

def analyze_file_hash(file_path, investigation_id):
    """Checks the file hash against the local blocklist and saves results."""
    file_hash = calculate_hash(file_path)
    if not file_hash:
        return None

    # 1. Check for Critical Malware Hit (Highest Priority)
    if file_hash in KNOWN_BAD_HASHES:
        malware_name = KNOWN_BAD_HASHES[file_hash]
        description = f"CRITICAL: {malware_name} | SHA256: {file_hash}"
        save_to_db(
            agent_name="HashAgent", 
            finding_type="Known Malware (Local)", 
            description=description, 
            investigation_id=investigation_id, 
            file_path=file_path
        )
    
    # 2. Standard Logging (Every file gets hashed for the Merkle Seal)
    standard_desc = f"SHA256: {file_hash}"
    save_to_db(
        agent_name="HashAgent", 
        finding_type="File Hash", 
        description=standard_desc, 
        investigation_id=investigation_id, 
        file_path=file_path
    )
    
    return file_hash

@app.route('/analyze_file', methods=['POST'])
def analyze_file():
    data = request.get_json()
    if not data or 'file_path' not in data or 'investigation_id' not in data:
        return jsonify({"error": "Missing 'file_path' or 'investigation_id'"}), 400
        
    file_path = data['file_path']
    investigation_id = data['investigation_id']
    
    # Executes the full hashing + blocklist check logic
    file_hash = analyze_file_hash(file_path, investigation_id)
    
    if file_hash:
        return jsonify({
            "message": "Hash Analysis complete",
            "file": file_path, 
            "hash": file_hash
        }), 200
    else:
        return jsonify({"error": "File processing failed. Ensure the path is accessible."}), 500

if __name__ == '__main__':
    # Running on Port 5001 as defined in your controller.py
    print("[*] Hash Agent active on Port 5001")
    app.run(port=5001, debug=False)
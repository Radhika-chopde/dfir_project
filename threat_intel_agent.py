import os
import requests
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

VIRUSTOTAL_API_KEY = "26718f04a11db2877e03a6aa81e58e79bb2e45416509b8dd3baa6aadd7ce982c"
VT_API_URL = "https://www.virustotal.com/api/v3/files/"

def save_to_db(agent_name, finding_type, description, investigation_id, file_path):
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        sql = """
            INSERT INTO findings (agent_name, finding_type, description, investigation_id, file_path) 
            VALUES (%s, %s, %s, %s, %s);
        """
        cur.execute(sql, (agent_name, finding_type, description, investigation_id, file_path))
        conn.commit()
        cur.close()
    except Exception as e:
        print(f"Database error: {e}")
    finally:
        if conn is not None:
            conn.close()
@app.route('/check_hash', methods=['POST'])
def check_hash_endpoint():
    data = request.get_json()
    if not data or 'hash_to_check' not in data or 'investigation_id' not in data or 'file_path' not in data:
        return jsonify({"error": "Missing required data: hash, investigation_id, and file_path are required."}), 400
    
    hash_to_check = data['hash_to_check']
    investigation_id = data['investigation_id']
    file_path = data['file_path']

    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        print("[!] ThreatIntelAgent: API key is not set.")
        return jsonify({"error": "Server API key not configured"}), 500

    print(f"ThreatIntelAgent: Received hash {hash_to_check} for file {file_path}")

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = f"{VT_API_URL}{hash_to_check}"

    try:
        response = requests.get(url, headers=headers, timeout=15, verify=False) 
        requests.packages.urllib3.disable_warnings()
        
        if response.status_code == 404:
            print(f"ThreatIntelAgent: Hash {hash_to_check} not found in VirusTotal.")
            return jsonify({"status": "clean", "hash": hash_to_check, "message": "Hash not found in VT"}), 200

        response.raise_for_status()
        
        vt_data = response.json()
        attributes = vt_data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)

        if malicious_count > 0 or suspicious_count > 0:
            print(f"    [!!!] MALWARE DETECTED: {file_path}")
            description = (
                f"Known Malware Found! File: {file_path}, Hash: {hash_to_check}. "
                f"VirusTotal Detections: {malicious_count} Malicious, {suspicious_count} Suspicious."
            )
            save_to_db(
                agent_name="ThreatIntelAgent",
                finding_type="Known Malware",
                description=description,
                investigation_id=investigation_id,
                file_path=file_path
            )
            return jsonify({"status": "malicious", "detections": malicious_count}), 200
        else:
            print(f"ThreatIntelAgent: Hash {hash_to_check} found but is clean.")
            return jsonify({"status": "clean", "message": "Hash found and clean"}), 200

    except requests.exceptions.RequestException as e:
        print(f"[!] ThreatIntelAgent: Could not connect to VirusTotal. {e}")
        return jsonify({"error": f"Could not connect to VirusTotal: {e}"}), 503

if __name__ == '__main__':
    print("Threat Intel Agent starting on port 5005...")
    app.run(port=5005, debug=True)
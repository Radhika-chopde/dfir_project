# threat_intel_agent.py
import requests
from flask import Flask, request, jsonify
from config import DB_CONFIG, VIRUSTOTAL_API_KEY
from db_utils import save_to_db

app = Flask(__name__)

VT_API_URL = "https://www.virustotal.com/api/v3/files/"

@app.route('/check_hash', methods=['POST'])
def check_hash_endpoint():
    data = request.get_json()
    if not data or 'hash_to_check' not in data or 'investigation_id' not in data or 'file_path' not in data:
        return jsonify({"error": "Missing required data: hash, investigation_id, and file_path are required."}), 400

    hash_to_check   = data['hash_to_check']
    investigation_id = data['investigation_id']
    file_path       = data['file_path']

    if not VIRUSTOTAL_API_KEY:
        print("[!] ThreatIntelAgent: API key is not set.")
        return jsonify({"error": "Server API key not configured"}), 500

    print(f"ThreatIntelAgent: Checking hash {hash_to_check} for file {file_path}")

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = f"{VT_API_URL}{hash_to_check}"

    try:
        # FIXED: verify=True (default). VirusTotal has a valid certificate.
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 404:
            return jsonify({"status": "clean", "hash": hash_to_check, "message": "Hash not found in VT"}), 200

        response.raise_for_status()

        vt_data    = response.json()
        attributes = vt_data.get("data", {}).get("attributes", {})
        stats      = attributes.get("last_analysis_stats", {})

        malicious_count  = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)

        if malicious_count > 0 or suspicious_count > 0:
            print(f"    [!!!] MALWARE DETECTED: {file_path}")
            description = (
                f"Known Malware Found! File: {file_path}, Hash: {hash_to_check}. "
                f"VirusTotal Detections: {malicious_count} Malicious, {suspicious_count} Suspicious."
            )
            save_to_db("ThreatIntelAgent", "Known Malware", description, investigation_id, file_path)
            return jsonify({"status": "malicious", "detections": malicious_count}), 200
        else:
            return jsonify({"status": "clean", "message": "Hash found and clean"}), 200

    except requests.exceptions.RequestException as e:
        print(f"[!] ThreatIntelAgent: Could not connect to VirusTotal. {e}")
        return jsonify({"error": f"Could not connect to VirusTotal: {e}"}), 503

if __name__ == '__main__':
    print("Threat Intel Agent starting on port 5005...")
    app.run(port=5005, debug=False)
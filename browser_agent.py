import os
import sqlite3
import shutil
import psycopg2
import re
import math
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_CONFIG = {
    "dbname": "dfir_db",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": "5432"
}

# --- REFINED REPUTATION HEURISTICS ---

SAFE_INFRASTRUCTURE = [
    r".*\.google\.com$", r".*\.microsoft\.com$", r".*\.amazonaws\.com$",
    r".*\.cloudfront\.net$", r".*\.akamaihd\.net$", r".*\.gstatic\.com$",
    r".*\.apple\.com$", r".*\.windowsupdate\.com$", r".*\.github\.com$"
]

TLD_REPUTATION = {
    "high_trust": [".gov", ".edu", ".mil", ".int"],
    "suspicious": [".onion", ".pw", ".bid", ".cc", ".icu", ".top", ".xyz", ".to"],
    "critical_risk": [".zip", ".mov", ".sh"] 
}

RISK_FACTORS = {
    "Data_Exfiltration": {
        "pattern": r"(temp-mail|transfer\.sh|mega\.nz/file/|mediafire\.com/file/|dropbox\.com/s/|anonfiles\.com|sendspace\.com)", 
        "weight": 5
    },
    "C2_Indicators": {
        "pattern": r"(adsterra|popads|pophost|clk\.php|click\.php\?|/[a-z0-9]{12,}\.php)", 
        "weight": 4
    },
    "Anonymization": {
        "pattern": r"(torproject|protonvpn|mullvad|nordvpn|tunnelbear|bridge/index\.html)", 
        "weight": 4
    },
    "Piracy_Source": {
        "pattern": r"(anime|watch|stream|torrent|crack|keygen|movie|free|hianime)", 
        "weight": 3
    }
}

def calculate_entropy(domain):
    if not domain: return 0
    prob = [float(domain.count(c)) / len(domain) for c in dict.fromkeys(list(domain))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def calculate_url_risk(url, visit_count):
    score = 0
    reasons = []
    url_lower = url.lower()
    
    # IMPROVED: More robust domain extraction
    domain = url_lower.split('://')[-1].split('/')[0].split('?')[0]

    # 1. Infrastructure Trust Check
    if any(re.match(pattern, domain) for pattern in SAFE_INFRASTRUCTURE):
        return 0, []

    # 2. IP Host Detection
    if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", domain):
        if not (domain.startswith("127.") or domain.startswith("192.168.") or domain.startswith("10.")):
            score += 5
            reasons.append("Direct Public IP Access")

    # 3. Behavioral Pattern Matching
    for category, info in RISK_FACTORS.items():
        if re.search(info["pattern"], url_lower):
            score += info["weight"]
            reasons.append(category.replace("_", " "))

    # 4. TLD Reputation Analysis
    if any(domain.endswith(tld) for tld in TLD_REPUTATION["suspicious"]):
        score += 3
        reasons.append("Low-Reputation TLD")
    elif any(domain.endswith(tld) for tld in TLD_REPUTATION["critical_risk"]):
        score += 6
        reasons.append("High-Risk TLD")

    # 5. DGA Detection
    entropy_score = calculate_entropy(domain)
    if entropy_score > 4.2 and len(domain) > 12:
        score += 4
        reasons.append("High Entropy Domain")

    # 6. Trust over Time
    if score > 0 and visit_count > 30:
        score -= 3
        reasons.append("Habitual Trust")
    elif score > 0 and visit_count < 2:
        score += 2
        reasons.append("New Domain Visit")

    # DEBUG PRINT: Check your terminal to see why sites are/aren't flagging
    if score > 2:
        print(f"[DEBUG] Analyzing: {domain} | Score: {score} | Reasons: {reasons}")

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
    except Exception as e: print(f"DB Error: {e}")
    finally:
        if conn: conn.close()

@app.route('/scan_browser', methods=['POST'])
def scan_browser():
    data = request.get_json()
    investigation_id = data.get('investigation_id')
    username = os.getlogin()
    history_path = f"C:\\Users\\{username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
    
    if not os.path.exists(history_path):
        return jsonify({"message": "History file not found"}), 200

    findings_count = 0
    temp_history = f"history_{investigation_id}.db"
    
    try:
        shutil.copy2(history_path, temp_history)
        conn = sqlite3.connect(temp_history)
        cursor = conn.cursor()
        # Increased limit and pulled more data for analysis
        cursor.execute("SELECT url, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 500")
        rows = cursor.fetchall()
        
        for url, visit_count in rows:
            risk_score, reasons = calculate_url_risk(url, visit_count)
            # Threshold lowered to 5 to be slightly more aggressive
            if risk_score >= 5:
                description = f"Risk Score {risk_score}: {', '.join(reasons)}. URL: {url[:80]}..."
                save_to_db("BrowserAgent", "Heuristic Web Alert", description, investigation_id, "Chrome History")
                findings_count += 1
        
        conn.close()
        os.remove(temp_history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"status": "complete", "matches_found": findings_count})

if __name__ == '__main__':
    app.run(port=5007, debug=True)
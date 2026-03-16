import os
import psycopg2
import re
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_CONFIG = {
    "dbname": "dfir_db",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": "5432"
}

# --- ADVANCED FORENSIC KEYWORD LIBRARY ---
# Categorized patterns used to identify malicious intent or sensitive data exposure.
# Using Regex allows us to catch patterns (like SSNs) rather than just static words.
FORENSIC_LIBRARY = {
    "PII_Confidential": [
        r"\b\d{3}-\d{2}-\d{4}\b",                             # Social Security Numbers
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", # Email addresses
        r"(?i)(password|secret|confidential|private_key|ssh-rsa|access_token)"
    ],
    "WebShell_Hacking": [
        r"(?i)(eval\(|base64_decode\(|shell_exec\(|system\(|passthru\(|exec\()", # Dangerous PHP/Python functions
        r"(?i)(cmd\.exe|/bin/sh|/bin/bash|powershell\.exe -enc|nc -e|ncat -e)"   # Reverse shell indicators
    ],
    "Persistence_Discovery": [
        r"(?i)(schtasks|reg add|net user|net localgroup|whoami|netstat -anob|tasklist|attrib \+h)"
    ],
    "Malware_Artifacts": [
        r"(?i)(mimikatz|cobaltstrike|metasploit|meterpreter|beacon|backdoor|exploit|payload)"
    ]
}

def search_forensic_patterns(file_path, custom_keywords=None):
    """
    Scans a file using the high-level forensic library 
    and optional user-defined keywords.
    """
    found_hits = []
    
    # 1. Prepare patterns
    all_patterns = []
    for category, patterns in FORENSIC_LIBRARY.items():
        for p in patterns:
            all_patterns.append((category, p))
    
    # Add any extra keywords provided by the controller
    if custom_keywords:
        for k in custom_keywords:
            all_patterns.append(("User Defined", re.escape(k)))

    try:
        # Read as bytes to prevent crashing on non-UTF-8 binary data
        with open(file_path, 'rb') as f:
            # Read first 2MB to maintain performance during rapid triage
            raw_data = f.read(2 * 1024 * 1024)
            content = raw_data.decode('utf-8', errors='ignore')
            
            for category, pattern in all_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    # Capture 20 chars of context for the investigator
                    start = max(0, match.start() - 20)
                    end = min(len(content), match.end() + 20)
                    context = content[start:end].replace('\n', ' ').strip()
                    
                    found_hits.append({
                        "category": category,
                        "match": match.group(),
                        "context": f"...{context}..."
                    })
                    
                    # Limit to 10 hits per file to avoid database bloat
                    if len(found_hits) >= 10:
                        return found_hits
                        
    except Exception as e:
        print(f"Error scanning {file_path}: {e}")
        return []
        
    return found_hits

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
        if conn: conn.close()

@app.route('/search_keywords', methods=['POST'])
def search_keywords_endpoint():
    data = request.get_json()
    if not data or 'file_path' not in data or 'investigation_id' not in data:
        return jsonify({"error": "Missing 'file_path' or 'investigation_id'"}), 400
    
    file_path = data['file_path']
    investigation_id = data['investigation_id']
    custom_keywords = data.get('keywords', [])
    
    hits = search_forensic_patterns(file_path, custom_keywords)
    
    if hits:
        # Deduplicate matches and group by category for the report
        categories_found = set(h['category'] for h in hits)
        for cat in categories_found:
            cat_matches = list(set(h['match'] for h in hits if h['category'] == cat))
            
            description = f"[{cat}] Forensic Match: {', '.join(cat_matches[:5])}"
            if len(cat_matches) > 5: description += " ..."

            save_to_db(
                agent_name="KeywordAgent", 
                finding_type="Keyword Hit", 
                description=description, 
                investigation_id=investigation_id,
                file_path=file_path
            )
        
        return jsonify({
            "message": "Forensic Keyword Search complete", 
            "file": file_path, 
            "matches_found": len(hits),
            "categories": list(categories_found)
        }), 200
    else:
        return jsonify({"message": "No forensic patterns detected", "file": file_path, "matches_found": 0}), 200

if __name__ == '__main__':
    app.run(port=5002, debug=True)
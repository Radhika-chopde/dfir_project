import os
import psycopg2
import re
from flask import Flask, request, jsonify
from config import DB_CONFIG
from db_utils import save_to_db

app = Flask(__name__)

FORENSIC_LIBRARY = {
    "PII_Confidential": [
        r"\b\d{3}-\d{2}-\d{4}\b",                             # Social Security Numbers
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", # Email addresses
        r"\b4[0-9]{12}(?:[0-9]{3})?\b",                     # Visa card numbers
        r"\b5[1-5][0-9]{14}\b",
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
    found_hits = []
    all_patterns = []
    for category, patterns in FORENSIC_LIBRARY.items():
        for p in patterns:
            all_patterns.append((category, p))
    if custom_keywords:
        for k in custom_keywords:
            all_patterns.append(("User Defined", re.escape(k)))

    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(2 * 1024 * 1024)
            content = raw_data.decode('utf-8', errors='ignore')

        for category, pattern in all_patterns:
            cat_hits = 0
            for match in re.finditer(pattern, content):
                start = max(0, match.start() - 20)
                end   = min(len(content), match.end() + 20)
                context = content[start:end].replace('\n', ' ').strip()
                found_hits.append({
                    "category": category,
                    "match":    match.group(),
                    "context":  f"...{context}..."
                })
                cat_hits += 1
                if cat_hits >= 5:   # cap per-pattern, not per-file
                    break

    except Exception as e:
        print(f"Error scanning {file_path}: {e}")

    return found_hits


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
    app.run(port=5002, debug=False)
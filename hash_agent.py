import os
import hashlib
import psycopg2
from flask import Flask, request, jsonify
import requests # Make sure to import requests

app = Flask(__name__)

DB_CONFIG = {
    "dbname": "dfir_db",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": "5432"
}

THREAT_INTEL_AGENT_URL = "http://127.0.0.1:5005/check_hash"


def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error calculating hash: {e}")
        return None

def save_to_db(agent_name, finding_type, description, investigation_id, file_path):
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        sql = """
            INSERT INTO findings (agent_name, finding_type, description, investigation_id, file_path) 
            VALUES (%s, %s, %s, %s, %s);
        """
        cur.execute(sql,(agent_name, finding_type, description, investigation_id, file_path))
        conn.commit()
        cur.close()
        print("Successfully saved finding to the database.")
    except Exception as e:
        print(f"Database error: {e}")
    finally:
        if conn is not None:
            conn.close()
@app.route('/analyze_file', methods=['POST'])
def analyze_file():
    data = request.get_json()
    if not data or 'file_path' not in data or 'investigation_id' not in data:
        return jsonify({"error": "Missing file_path or investigation_id in request"}), 400
        
    file_path = data['file_path']
    investigation_id = data['investigation_id']
    file_hash = calculate_hash(file_path)
    
    if file_hash:
        description = f"File: {file_path}, SHA256: {file_hash}"
        save_to_db(
            agent_name="HashAgent", 
            finding_type="File Hash", 
            description=description, 
            investigation_id=investigation_id,
            file_path=file_path
        )
        return jsonify({
            "message": "Analysis complete",
            "file": file_path, 
            "hash": file_hash
        }), 200
    else:
        return jsonify({"error":"File not found or could not be processed"}), 400
if __name__=='__main__':
    app.run(port=5001, debug=True)

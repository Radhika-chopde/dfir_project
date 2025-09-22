import os
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

MAGIC_NUMBERS = {
    "ffd8ffe0": "JPEG",
    "89504e47": "PNG",
    "25504446": "PDF",
    "504b0304": "ZIP",
    "4d5a": "EXE"
}

def verify_signature(file_path):
    try:
        with open(file_path, 'rb') as f:
            header_bytes = f.read(4)
        hex_signature = header_bytes.hex()

        for signature, file_type in MAGIC_NUMBERS.items():
            if hex_signature.startswith(signature):
                return file_type
        return "Unknown"
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error reading file signature: {e}")
        return "Error"
    
def save_to_db(agent_name, finding_type, description):
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        sql = "INSERT INTO findings (agent_name, finding_type, description) VALUES (%s, %s, %s);"
        cur.execute(sql,(agent_name,finding_type,description))
        conn.commit()
        cur.close()
    except Exception as e:
        print(f"Database error: {e}")
    finally:
        if conn is not None:
            conn.close()

@app.route('/verify_signature', methods=['POST'])
def verify_signature_endpoint():
    data = request.get_json()
    if not data or 'file_path' not in data:
        return jsonify({"error":"Missing 'file_path' "}), 400
    file_path = data['file_path']
    file_extension = os.path.splitext(file_path)[1].lower()
    detected_type = verify_signature(file_path)
    if detected_type is None:
        return jsonify({"error": "File not found"}), 404
    is_mismatch = False
    if (detected_type == "JPEG" and file_extension not in ['.jpeg','.jpg']) or (detected_type=='PNG' and file_extension != '.png') or (detected_type == 'PDF' and file_extension != '.pdf') or (detected_type == 'ZIP' and file_extension != '.zip') or (detected_type == 'EXE' and file_extension!='.exe'):
        is_mismatch = True
        description = f"File Signature Mismatch! File '{file_path}' has extetension '{file_extension}' but is detected as a '{detected_type}' file."
        save_to_db("Signature Agent","Signature Mismatch", description)
    return jsonify(
        {
            "file": file_extension,
            "extension": file_extension,
            "detected_type": detected_type,
            "mismatch_found": is_mismatch
        }
    ), 200

if __name__ == '__main__':
    app.run(port=5003, debug=True)
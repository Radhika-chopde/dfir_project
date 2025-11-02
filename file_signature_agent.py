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
    "4d5a": "EXE/DLL"
}

EXECUTABLE_EXTENSIONS = ['.exe', '.dll', '.com', '.msi', '.scr', '.cpl']

def verify_signature(file_path):
    try:
        with open(file_path, 'rb') as f:
            header_bytes = f.read(8) 
        hex_signature = header_bytes.hex()

        for signature, file_type in MAGIC_NUMBERS.items():
            if hex_signature.startswith(signature):
                return file_type

        if all(32 <= b <= 126 or b in (9, 10, 13) for b in header_bytes):
             return "TXT"
             
        return "Unknown"
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error reading file signature: {e}")
        return "Error"
    
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

@app.route('/verify_signature', methods=['POST'])
def verify_signature_endpoint():
    data = request.get_json()
    if not data or 'file_path' not in data or 'investigation_id' not in data:
        return jsonify({"error":"Missing 'file_path' or 'investigation_id'"}), 400
        
    file_path = data['file_path']
    investigation_id = data['investigation_id']
    file_extension = os.path.splitext(file_path)[1].lower()
    
    detected_type = verify_signature(file_path)
    
    if detected_type is None:
        return jsonify({"error": "File not found"}), 404
    if detected_type == "Error":
        return jsonify({"error": "Error reading file"}), 500

    is_mismatch = False
    description = ""

    if (detected_type == "JPEG" and file_extension not in ['.jpeg','.jpg']) or \
       (detected_type == 'PNG' and file_extension != '.png') or \
       (detected_type == 'PDF' and file_extension != '.pdf') or \
       (detected_type == 'ZIP' and file_extension not in ['.zip', '.docx', '.xlsx', '.pptx']) or \
       (detected_type == 'EXE/DLL' and file_extension not in ['.exe', '.dll', '.scr', '.com']):
        
        is_mismatch = True
        description = f"File Signature Mismatch! File '{file_path}' has extension '{file_extension}' but is detected as a '{detected_type}' file."

    elif detected_type in ["TXT", "Unknown"] and file_extension in EXECUTABLE_EXTENSIONS:
        is_mismatch = True
        description = f"File Signature Mismatch! File '{file_path}' has an executable extension '{file_extension}' but its signature is '{detected_type}'."
    if is_mismatch:
        save_to_db(
            agent_name="Signature Agent",
            finding_type="Signature Mismatch", 
            description=description, 
            investigation_id=investigation_id,
            file_path=file_path
        )

    return jsonify(
        {
            "file": file_path,
            "extension": file_extension,
            "detected_type": detected_type,
            "mismatch_found": is_mismatch
        }
    ), 200

if __name__ == '__main__':
    app.run(port=5003, debug=True)
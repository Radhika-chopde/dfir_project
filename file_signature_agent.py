import os
import psycopg2
import math
from flask import Flask, request, jsonify
from config import DB_CONFIG
from db_utils import save_to_db

app = Flask(__name__)


MAGIC_NUMBERS = {
    "ffd8ffe0": "JPEG", "ffd8ffe1": "JPEG", "ffd8ffe2": "JPEG",
    "89504e47": "PNG",
    "25504446": "PDF",
    "504b0304": "ZIP/Office",
    "504b0506": "ZIP/Office",
    "4d5a":     "EXE/DLL",
    "52617221": "RAR",
    "377abcaf": "7-ZIP",
    "7f454c46": "ELF",          # Linux executable
    "d0cf11e0": "OLE2/Office",  # Legacy .doc, .xls, .ppt
    "4c000000": "LNK Shortcut", # .lnk files — often malicious
    "4d534346": "CAB Archive",
    "cafebabe": "Java CLASS",
    "1f8b08":   "GZIP",
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

def calculate_entropy(file_path):
    """Calculates Shannon Entropy to identify encrypted/packed files."""
    try:
        with open(file_path, 'rb') as f:
            # Read 1MB for speed to maintain sub-120s triage time
            data = f.read(1024 * 1024) 
        if not data: return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x))/len(data)
            if p_x > 0:
                # Shannon Entropy Formula: -sum(p_i * log2(p_i))
                entropy += - p_x * math.log(p_x, 2)
        return entropy
    except Exception as e:
        print(f"Entropy Calculation Error: {e}")
        return 0
    
@app.route('/verify_signature', methods=['POST'])
def verify_signature_endpoint():
    data = request.get_json()
    if not data or 'file_path' not in data or 'investigation_id' not in data:
        return jsonify({"error":"Missing 'file_path' or 'investigation_id'"}), 400
        
    file_path = data['file_path']
    investigation_id = data['investigation_id']
    file_extension = os.path.splitext(file_path)[1].lower()
    
    detected_type = verify_signature(file_path)
    
    if detected_type is None: return jsonify({"error": "File not found"}), 404
    if detected_type == "Error": return jsonify({"error": "Error reading file"}), 500

    # --- 1. Obfuscation Detection (Entropy) ---
    entropy_val = calculate_entropy(file_path)
    if entropy_val > 7.5: 
        obs_desc = f"High Entropy Detected ({entropy_val:.2f}). File is likely encrypted or packed."
        save_to_db("Signature Agent", "Obfuscation Alert", obs_desc, investigation_id, file_path)

    # --- 2. Advanced Signature Mismatch Logic ---
    # Mapping detected_type to allowed extensions
    TYPE_TO_EXTENSIONS = {
        "JPEG":        ['.jpg', '.jpeg'],
        "PNG":         ['.png'],
        "PDF":         ['.pdf'],
        "ZIP/Office":  ['.zip', '.docx', '.xlsx', '.pptx', '.jar'],
        "EXE/DLL":     ['.exe', '.dll', '.scr', '.com', '.sys', '.efi'],
        "RAR":         ['.rar'],
        "7-ZIP":       ['.7z'],
        "ELF":         ['', '.bin', '.elf', '.so'], # Linux binaries often have no extension
        "OLE2/Office": ['.doc', '.xls', '.ppt', '.msi'],
        "LNK Shortcut":['.lnk'],
        "CAB Archive": ['.cab'],
        "Java CLASS":  ['.class'],
        "GZIP":        ['.gz', '.tgz'],
        "TXT":         ['.txt', '.log', '.ini', '.conf', '.py', '.js', '.php']
    }

    is_mismatch = False
    mismatch_desc = ""

    # Check if we have a mapping for this detected type
    if detected_type in TYPE_TO_EXTENSIONS:
        allowed_extensions = TYPE_TO_EXTENSIONS[detected_type]
        if file_extension not in allowed_extensions:
            is_mismatch = True
            mismatch_desc = f"Signature Mismatch! File header is '{detected_type}' but extension is '{file_extension}'."

    # Special case: Executable extension with no/unknown signature (Classic Malware Tactic)
    elif file_extension in EXECUTABLE_EXTENSIONS and detected_type in ["Unknown", "TXT"]:
        is_mismatch = True
        mismatch_desc = f"Security Alert! File has executable extension '{file_extension}' but detected as '{detected_type}'."

    # --- 3. Save Findings ---
    if is_mismatch:
        save_to_db(
            agent_name="Signature Agent",
            finding_type="Signature Mismatch", 
            description=mismatch_desc, 
            investigation_id=investigation_id,
            file_path=file_path
        )

    return jsonify({
        "file": file_path,
        "extension": file_extension,
        "detected_type": detected_type,
        "entropy": round(entropy_val, 2),
        "mismatch_found": is_mismatch
    }), 200
if __name__ == '__main__':
    app.run(port=5003, debug=False)
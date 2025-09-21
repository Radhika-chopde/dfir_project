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

def search_keyword_in_file(file_path, keywords):
    found_lines = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f,1):
                for keyword in keywords:
                    if keyword.lower() in line.lower():
                        found_lines.append(f"L{line_num}: {line.strip()}")
                        break
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []
    return found_lines

def save_to_db(agent_name, finding_type, description):
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        sql = "INSERT INTO FINDINGS (agent_name,finding_type,description) VALUES (%s, %s, %s)"
        cur.execute(sql,(agent_name,finding_type,description))
        conn.commit()
        cur.close()
        print("Successfully saved finding to the database.")
    except Exception as e:
        print(f"Database error: {e}")
    finally:
        if conn is not None:
            conn.close()

#API Endpoint
@app.route('/search_keywords', methods=['POST'])
def search_keywords_endpoint():
    data = request.get_json()
    if not data or 'file_path' not in data or 'keywords' not in data:
        return jsonify({"error": "Missing 'file_path' or 'keywords' in request"}), 400
    file_path = data['file_path']
    keywords = data['keywords']
    matching_lines = search_keyword_in_file(file_path, keywords)
    if matching_lines is None:
        return jsonify({"error": "File not found"}), 404
    if matching_lines:
        for line in matching_lines:
            description = f"Found keyword in '{file_path}'. Details: {line}"
            save_to_db(agent_name="KeywordAgent", finding_type="Keyword Hit", description=description)
        return jsonify({"message": "Keyword Search complete", "file": file_path, "matches_found": len(matching_lines)}), 200
    else:
        return jsonify({"message": "Keyword search complete", "file": file_path, "matches_found": 0}), 200


if __name__ == '__main__':
    app.run(port=5002, debug=True)
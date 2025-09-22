from flask import Flask, jsonify, render_template, request
import psycopg2
import json
import os
import subprocess
import sys
import threading
import datetime

app = Flask(__name__)

DB_CONFIG = {
    "dbname": "dfir_db",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": "5432"
}

def run_controller_in_background(directory_path, investigation_id):
    """Runs the controller.py script in a non-blocking way."""
    try:
        python_executable = sys.executable
        controller_script = os.path.join(os.path.dirname(__file__), 'controller.py')

        subprocess.Popen([python_executable, controller_script, directory_path, investigation_id])
        
    except Exception as e:
        print(f"Failed to start controller subprocess: {e}")

@app.route('/api/start_analysis', methods=['POST'])
def start_analysis():
    data = request.get_json()
    directory_path = data.get('directory_path')

    if not directory_path or not os.path.isdir(directory_path):
        return jsonify({"error": "Valid directory_path is required"}), 400

    investigation_id = f"investigation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"

    thread = threading.Thread(target=run_controller_in_background, args=(directory_path, investigation_id))
    thread.start()
    
    return jsonify({"message": f"Analysis started with ID: {investigation_id}"}), 200

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

@app.route('/api/findings/latest')
def get_latest_findings():
    """Fetches findings only from the most recent investigation."""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT investigation_id FROM findings ORDER BY timestamp DESC LIMIT 1;")
        latest_id_row = cur.fetchone()
        if not latest_id_row:
            return jsonify([])

        latest_id = latest_id_row[0]

        cur.execute("SELECT id, agent_name, finding_type, description, timestamp FROM findings WHERE investigation_id = %s ORDER BY timestamp DESC;", (latest_id,))
        
        rows = cur.fetchall()
        colnames = [desc[0] for desc in cur.description]
        results = [dict(zip(colnames, row)) for row in rows]
        
        cur.close()
        return json.dumps(results, indent=4, sort_keys=True, default=str)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn is not None:
            conn.close()


@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(port=8000, debug=True)


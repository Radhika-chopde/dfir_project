from flask import Flask, jsonify, render_template, request, g
import psycopg2
import json
import os
import subprocess
import sys
import threading
import datetime
from psycopg2.extras import DictCursor

app = Flask(__name__)

DB_CONFIG = {
    "dbname": "dfir_db",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": "5432"
}

def get_db_connection():
    if 'db' not in g:
        g.db = psycopg2.connect(**DB_CONFIG)
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def run_controller_in_background(directory_path, investigation_id):
    try:
        python_executable = sys.executable
        controller_script = os.path.join(os.path.dirname(__file__), 'controller.py')
        
        print(f"Starting controller: {python_executable} {controller_script} {directory_path} {investigation_id}")
        subprocess.Popen([python_executable, controller_script, directory_path, investigation_id])
    except Exception as e:
        print(f"Failed to start controller subprocess: {e}")

def correlate_and_score(raw_findings):
    correlated_artifacts = {}
    
    for finding in raw_findings:
        file_path = finding.get('file_path')
        
        if not file_path:
            continue

        artifact_data = correlated_artifacts.setdefault(file_path, {
            'file_path': file_path,
            'findings': [],
            'score': 0,
            'hash': None,
            'known_bad': False
        })
        
        finding_type = finding['finding_type']
        description = finding['description']
        agent_name = finding['agent_name']
        timestamp = finding['timestamp'].strftime('%H:%M:%S')
        
        finding_type_clean = finding_type.strip().lower()

        if finding_type_clean == 'known malware':
            artifact_data['known_bad'] = True
            artifact_data['score'] += 10
        elif finding_type_clean == 'signature mismatch':
            artifact_data['score'] += 5
        elif finding_type_clean == 'keyword hit':
            artifact_data['score'] += 2
        elif finding_type_clean == 'suspicious timeline':
            artifact_data['score'] += 3
        
        artifact_data['findings'].append(f"[{agent_name} @ {timestamp}] {description}")
        
        if finding_type_clean == 'file hash':
            try:
                artifact_data['hash'] = description.split('SHA256: ')[1]
            except Exception:
                pass
    
    sorted_artifacts = sorted(correlated_artifacts.values(), key=lambda x: x['score'], reverse=True)
    return sorted_artifacts

@app.route('/api/start_analysis', methods=['POST'])
def start_analysis():
    data = request.get_json()
    directory_path = data.get('directory_path')

    if not directory_path or not os.path.isdir(directory_path):
        return jsonify({"error": "Valid directory_path is required"}), 400

    investigation_id = f"investigation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"

    thread = threading.Thread(target=run_controller_in_background, args=(directory_path, investigation_id))
    thread.start()
    
    return jsonify({"message": f"Analysis started with ID: {investigation_id}", "investigation_id": investigation_id}), 200

@app.route('/api/report/latest')
def get_latest_report():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        
        cur.execute("SELECT investigation_id FROM findings ORDER BY timestamp DESC LIMIT 1;")
        latest_id_row = cur.fetchone()
        
        if not latest_id_row:
            return jsonify({"investigation_id": "N/A", "artifacts": []})

        latest_id = latest_id_row['investigation_id']

        sql = """
            SELECT agent_name, finding_type, description, timestamp, file_path 
            FROM findings 
            WHERE investigation_id = %s 
            ORDER BY timestamp;
        """
        cur.execute(sql, (latest_id,))
        raw_findings = cur.fetchall()
        
        cur.close()
        
        correlated_report = correlate_and_score(raw_findings)
        
        return jsonify({
            "investigation_id": latest_id,
            "artifacts": correlated_report
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        pass

@app.route('/api/findings/latest')
def get_latest_findings_raw():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        
        cur.execute("SELECT investigation_id FROM findings ORDER BY timestamp DESC LIMIT 1;")
        latest_id_row = cur.fetchone()
        if not latest_id_row:
            return jsonify([])

        latest_id = latest_id_row['investigation_id']

        cur.execute("SELECT id, agent_name, finding_type, description, timestamp, file_path FROM findings WHERE investigation_id = %s ORDER BY timestamp ASC;", (latest_id,))
        
        results = [dict(row) for row in cur.fetchall()]
        cur.close()
        
        return json.dumps(results, indent=4, default=str)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        pass


@app.route('/raw_log')
def raw_log_page():
    investigation_id = "N/A"
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT investigation_id FROM findings ORDER BY timestamp DESC LIMIT 1;")
        latest_id_row = cur.fetchone()
        if latest_id_row:
            investigation_id = latest_id_row[0]
        cur.close()
    except Exception:
        pass
    return render_template('raw_log.html', investigation_id=investigation_id)

@app.route('/report')
def report_page():
    investigation_id = "Loading..."
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT investigation_id FROM findings ORDER BY timestamp DESC LIMIT 1;")
        latest_id_row = cur.fetchone()
        if latest_id_row:
            investigation_id = latest_id_row[0]
        cur.close()
    except Exception:
        pass
        
    return render_template('report.html', investigation_id=investigation_id)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(port=8000, debug=True)
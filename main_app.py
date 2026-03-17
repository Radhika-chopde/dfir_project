from flask import Flask, jsonify, render_template, request, g, send_file
import psycopg2
import json
import os
import shutil
import subprocess
import sys
import threading
import datetime
import io
import html 
import psutil
import winreg
from psycopg2.extras import DictCursor


# PDF Libraries
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

# Custom Forensic Modules
import merkle_utils
import ai_analyst

app = Flask(__name__)

# --- CONFIGURATION ---
DB_CONFIG = {
    "dbname": "dfir_db",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": "5432"
}

# Folder for isolated files
QUARANTINE_DIR = "D:\\DigitalForensics\\Quarantine"
if not os.path.exists(QUARANTINE_DIR):
    try:
        os.makedirs(QUARANTINE_DIR)
    except Exception as e:
        print(f"[!] Warning: Could not create Quarantine folder: {e}")

# --- DATABASE HELPERS ---
def get_db_connection():
    if 'db' not in g:
        g.db = psycopg2.connect(**DB_CONFIG)
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# --- BACKGROUND ORCHESTRATION ---
def run_full_analysis(directory_path, investigation_id):
    """Orchestrates the 8-agent scan and AI analysis."""
    try:
        python_executable = sys.executable
        controller_script = os.path.join(os.path.dirname(__file__), 'controller.py')
        
        print(f"[*] Launching 8-Agent Controller: {investigation_id}")
        process = subprocess.Popen([python_executable, controller_script, directory_path, investigation_id])
        process.wait() 
        
        print(f"[+] Scan Phase Complete. Initializing Local AI Synthesis...")
        ai_analyst.run_analysis_on_scan(investigation_id)
        
    except Exception as e:
        print(f"[!] Controller Execution Error: {e}")

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/report')
def report_page():
    return render_template('report.html')

@app.route('/logs')
def logs_page():
    return render_template('raw_log.html')

@app.route('/api/start_analysis', methods=['POST'])
def start_analysis():
    data = request.get_json()
    directory_path = data.get('directory_path')
    if not directory_path or not os.path.isdir(directory_path):
        return jsonify({"error": "Invalid directory path provided."}), 400

    investigation_id = f"investigation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    thread = threading.Thread(target=run_full_analysis, args=(directory_path, investigation_id))
    thread.start()
    
    return jsonify({"message": "Analysis engine started.", "investigation_id": investigation_id}), 200

@app.route('/api/report/latest')
def get_latest_report():
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        
        cur.execute("SELECT investigation_id, merkle_root FROM investigations ORDER BY start_time DESC LIMIT 1;")
        res = cur.fetchone()
        if not res: return jsonify({"artifacts": []})
        
        inv_id = res['investigation_id']
        merkle_root = res['merkle_root'] or "CALCULATING..."
        
        cur.execute("SELECT * FROM findings WHERE investigation_id = %s", (inv_id,))
        rows = cur.fetchall()
        
        artifacts = {}
        for r in rows:
            path = r.get('file_path') or "System/Registry Artifacts"
            if path not in artifacts:
                artifacts[path] = {
                    'file_path': path, 
                    'score': 0, 
                    'findings': [], 
                    'known_bad': False, 
                    'ai_insight': r.get('ai_insight')
                }
            
            ftype = (r.get('finding_type') or "").lower()
            
            # Weighted Scoring Engine
            if 'malware' in ftype: 
                artifacts[path]['known_bad'] = True
                artifacts[path]['score'] += 10
            elif 'memory' in ftype: artifacts[path]['score'] += 9
            elif 'registry' in ftype: artifacts[path]['score'] += 8
            elif 'mismatch' in ftype: artifacts[path]['score'] += 7
            elif 'browser' in ftype: artifacts[path]['score'] += 6
            elif 'keyword' in ftype: artifacts[path]['score'] += 5
            elif 'suspicious timeline' in ftype: artifacts[path]['score'] += 4
            
            artifacts[path]['findings'].append(f"[{r.get('agent_name')}] {r.get('description')}")
            
        return jsonify({
            "investigation_id": inv_id, 
            "merkle_root": merkle_root,
            "artifacts": list(artifacts.values())
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/findings/latest')
def get_raw_findings():
    """Returns raw findings for the log viewer."""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute("SELECT investigation_id FROM investigations ORDER BY start_time DESC LIMIT 1;")
        res = cur.fetchone()
        if not res: return jsonify([])
        
        cur.execute("SELECT * FROM findings WHERE investigation_id = %s ORDER BY timestamp DESC", (res['investigation_id'],))
        return jsonify([dict(r) for r in cur.fetchall()])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/quarantine', methods=['POST'])
def quarantine_file():
    """Enhanced Quarantine Engine with Path Integrity Check."""
    data = request.get_json()
    raw_path = data.get('file_path', '')
    
    # STEP 1: Fix potential mangled paths from JS
    # If path arrives without backslashes but has a drive letter (e.g. D:FolderFile)
    # This logic attempts to reconstruct common drive-based forensic paths
    if ":" in raw_path and "\\" not in raw_path and "/" not in raw_path:
        # Emergency reconstruction: Re-inserting slashes after drive and common keywords
        # This is a fallback if the frontend JS fix fails
        raw_path = raw_path.replace("D:", "D:\\").replace("DigitalForensics", "DigitalForensics\\").replace("Evidence", "Evidence\\")

    # STEP 2: Normalize and convert to absolute path
    clean_path = raw_path.strip().strip('"').strip("'").replace('/', '\\')
    file_path = os.path.abspath(clean_path)
    
    print(f"[*] Quarantine System: Processing path: {file_path}")

    if not os.path.exists(file_path):
        # Last resort: try the path as-is without abspath
        if os.path.exists(clean_path):
            file_path = clean_path
        else:
            return jsonify({"error": f"File not found. Ensure the tool has access to: {file_path}"}), 404

    try:
        file_name = os.path.basename(file_path)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = os.path.join(QUARANTINE_DIR, f"{timestamp}_{file_name}.isolated")
        
        shutil.move(file_path, dest)
        return jsonify({"message": f"Artifact successfully isolated to evidence locker: {dest}"}), 200
    except PermissionError:
        return jsonify({"error": "Permission Denied. Ensure the server is running as Admin."}), 403
    except Exception as e:
        return jsonify({"error": f"Isolation failed: {str(e)}"}), 500

@app.route('/api/export_pdf')
def export_pdf():
    """Full ReportLab Forensic Report Generation."""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute("SELECT investigation_id, merkle_root FROM investigations ORDER BY start_time DESC LIMIT 1;")
        res = cur.fetchone()
        if not res: return "No data found", 404
        
        inv_id = res['investigation_id']
        root_seal = res['merkle_root'] or "N/A"
        
        cur.execute("SELECT * FROM findings WHERE investigation_id = %s", (inv_id,))
        rows = cur.fetchall()

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        elements.append(Paragraph("Forensic Investigation Case Report", styles['Title']))
        elements.append(Paragraph(f"Investigation ID: {inv_id}", styles['Normal']))
        elements.append(Paragraph(f"Integrity Seal (Merkle Root): {root_seal}", styles['Normal']))
        elements.append(Spacer(1, 15))

        data = [['Agent', 'Artifact Path', 'Risk/Finding']]
        for r in rows:
            p = r.get('file_path') or "System"
            p_short = (p[:40] + '...') if len(p) > 40 else p
            data.append([
                r.get('agent_name'),
                Paragraph(html.escape(p_short), styles['Normal']),
                Paragraph(html.escape(r.get('description')[:100]), styles['Normal'])
            ])

        t = Table(data, colWidths=[100, 200, 240])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.black),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('FONTSIZE', (0,0), (-1,-1), 8)
        ]))
        elements.append(t)
        
        elements.append(Spacer(1, 20))
        elements.append(Paragraph("Automated Intelligence Briefs", styles['Heading2']))
        
        seen = set()
        for r in rows:
            insight = r.get('ai_insight')
            path = r.get('file_path')
            if insight and path and path not in seen:
                elements.append(Paragraph(f"Artifact: {path}", styles['Heading3']))
                elements.append(Paragraph(f"Analysis: {insight}", styles['Italic']))
                seen.add(path)

        doc.build(elements)
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name=f"Report_{inv_id}.pdf", mimetype='application/pdf')
    except Exception as e:
        return f"Internal PDF Error: {e}", 500

@app.route('/api/verify_integrity', methods=['POST'])
def verify_integrity():
    data = request.get_json()
    inv_id = data.get('investigation_id', '').strip()
    
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute("SELECT merkle_root FROM investigations WHERE investigation_id = %s", (inv_id,))
        stored = cur.fetchone()
        
        if not stored: return jsonify({"status": "error", "message": "ID not found"}), 200
        
        cur.execute("SELECT file_path, finding_type, description FROM findings WHERE investigation_id = %s", (inv_id,))
        rows = cur.fetchall()
        current = [{"file_path": r[0], "finding_type": r[1], "description": r[2]} for r in rows]
        calc_root = merkle_utils.generate_investigation_integrity(current)

        if stored['merkle_root'] == calc_root:
            return jsonify({"status": "verified", "calculated": calc_root, "stored": stored['merkle_root']})
        else:
            return jsonify({"status": "tampered", "calculated": calc_root, "stored": stored['merkle_root']})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 200

@app.route('/api/remediate/kill_process', methods=['POST'])
def kill_process():
    """Remediation: Terminate a malicious process by PID."""
    data = request.get_json()
    pid = data.get('pid')
    try:
        proc = psutil.Process(int(pid))
        name = proc.name()
        proc.terminate()
        return jsonify({"message": f"Successfully terminated process {name} (PID: {pid})"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to kill process: {str(e)}"}), 500
    
@app.route('/api/remediate/registry_wipe', methods=['POST'])
def registry_wipe():
    """Remediation: Delete a malicious persistence key."""
    data = request.get_json()
    full_path = data.get('path', '') # Expecting "HKCU\Software\...\Key"
    try:
        # Example logic for HKLM/HKCU splitting
        root_str, subkey = full_path.split('\\', 1)
        root = winreg.HKEY_LOCAL_MACHINE if "LOCAL_MACHINE" in root_str else winreg.HKEY_CURRENT_USER
        
        # Split key name from value
        parent_key, value_name = os.path.split(subkey)
        
        with winreg.OpenKey(root, parent_key, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, value_name)
            
        return jsonify({"message": f"Successfully wiped persistence key: {value_name}"}), 200
    except Exception as e:
        return jsonify({"error": f"Registry wipe failed: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(port=8000, debug=True)
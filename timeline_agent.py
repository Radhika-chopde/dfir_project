import os, sys, datetime
from flask import Flask, request, jsonify
from db_utils import save_to_db

app = Flask(__name__)

def get_timelines(file_path):
    try:
        stat = os.stat(file_path)
        # st_ctime is CREATION TIME on Windows, INODE CHANGE TIME on Linux/Mac
        is_windows = sys.platform == 'win32'
        return {
            "mtime": stat.st_mtime,
            "atime": stat.st_atime,
            "ctime": stat.st_ctime,
            "ctime_meaning": "creation" if is_windows else "inode_change",
            "mtime_str": datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "atime_str": datetime.datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M:%S"),
            "ctime_str": datetime.datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
        }
    except (FileNotFoundError, PermissionError):
        return None

@app.route('/get_timestamps', methods=['POST'])
def get_timestamps_endpoint():
    data             = request.get_json()
    file_path        = data.get('file_path')
    investigation_id = data.get('investigation_id')

    if not file_path or not investigation_id:
        return jsonify({'error': "Missing file_path or investigation_id"}), 400

    ts = get_timelines(file_path)
    if ts is None:
        return jsonify({"error": "File not found or permission denied"}), 404

    is_suspicious = False

    # Only flag mtime < ctime anomaly on Windows where ctime = creation time
    if sys.platform == 'win32' and ts['mtime'] < ts['ctime']:
        is_suspicious = True
        # Explicitly mentioning the risk score helps the AI Analyst later
        desc = (
            f"Risk 8/10: Timestomping Detected. mtime ({ts['mtime_str']}) is OLDER than "
            f"ctime ({ts['ctime_str']}). File: {file_path}"
        )
        save_to_db("TimelineAgent", "Timestamp Anomaly", desc, investigation_id, file_path)

    # Flag if accessed very recently but not modified (possible staging/reconnaissance)
    now = datetime.datetime.now().timestamp()
    if (now - ts['atime']) < 3600 and (now - ts['mtime']) > 86400:
        is_suspicious = True
        desc = f"Recent Access on Old File: accessed within last hour but not modified in >24h. File: {file_path}"
        save_to_db("TimelineAgent", "Recent Access Anomaly", desc, investigation_id, file_path)

    # ONLY log clean files as a summarized batch, not one record per file
    return jsonify({
        "is_suspicious": is_suspicious,
        "timelines": ts
    }), 200

if __name__ == '__main__':
    app.run(port=5004, debug=False)
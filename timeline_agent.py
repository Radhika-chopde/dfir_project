import os
import psycopg2
from flask import Flask, request, jsonify
import datetime

app = Flask(__name__)

DB_CONFIG = {
    "dbname": "dfir_db",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": "5432"
}

def get_timelines(file_path):
    try:
        stat = os.stat(file_path)
        creation_time = stat.st_ctime
        modification_time = stat.st_mtime
        access_time = stat.st_atime

        time = {
            "creation_time_ts": creation_time,
            "modification_time_ts": modification_time,
            "access_time_ts": access_time,
            "creation_time_str": datetime.datetime.fromtimestamp(creation_time).strftime("%Y-%m-%d %H:%M:%S"),
            "modification_time_str": datetime.datetime.fromtimestamp(modification_time).strftime("%Y-%m-%d %H:%M:%S"),
            "access_time_str": datetime.datetime.fromtimestamp(access_time).strftime("%Y-%m-%d %H:%M:%S")
        }
        return time
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error getting timestamp for file: {e}")
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
        conn.close()
        print("Successfully saved findings to the database.")
    except Exception as e:
        print(f"Database error: {e}")
        return None
    finally:
        if conn is not None:
            conn.close()

@app.route('/get_timestamps',methods=['POST'])
def get_timestamps_endpoint():
    data = request.get_json()
    if not data or 'file_path' not in data or 'investigation_id' not in data:
        return jsonify({'error': "Missing 'file_path' or 'investigation_id'"}), 400
        
    file_path = data['file_path']
    investigation_id = data['investigation_id']
    timelines = get_timelines(file_path)
    
    if timelines is None:
        return jsonify({"error": "File not found"}), 404

    is_suspicious = False
    description = ""
    if timelines['modification_time_ts'] < timelines['creation_time_ts']:
        is_suspicious = True
        description = (
            f"Suspicious Timeline! File: {file_path}. "
            f"Modification Time ({timelines['modification_time_str']}) is OLDER than Creation Time ({timelines['creation_time_str']})."
        )
        save_to_db(
            agent_name='Timeline Agent', 
            finding_type='Suspicious Timeline', 
            description=description, 
            investigation_id=investigation_id,
            file_path=file_path
        )
    else:
        description = (
            f"File: {file_path}, Creation Time: {timelines['creation_time_str']}, "
            f"Modification Time: {timelines['modification_time_str']}, Access Time: {timelines['access_time_str']}"
        )
        save_to_db(
            agent_name='Timeline Agent', 
            finding_type='File modification timelines', 
            description=description, 
            investigation_id=investigation_id,
            file_path=file_path
        )

    return jsonify({
        "message": "Timelines found successfully", 
        "is_suspicious": is_suspicious, 
        "timelines": timelines
    }), 200

if __name__ == '__main__':
    app.run(port=5004, debug=True)

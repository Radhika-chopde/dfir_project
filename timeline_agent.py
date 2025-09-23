import os
import psycopg2
from flask import Flask, request, jsonify
import datetime

app = Flask(__name__)

DB_CONFIG = {
    "dbname": "dfir_db",
    "user": "postgres",
    "password": "postgres",
    "port": "5432"
}

def get_timelines(file_path):
    try:
        creationTime = os.path.getctime(file_path)
        modificationTime = os.path.getmtime(file_path)
        accessTime = os.path.getatime(file_path)

        time = {
            "creation_time": datetime.datetime.fromtimestamp(creationTime).strftime("%Y-%m-%d %H:%M:%S"),
            "modification_time": datetime.datetime.fromtimestamp(modificationTime).strftime("%Y-%m-%d %H:%M:%S"),
            "access_time": datetime.datetime.fromtimestamp(accessTime).strftime("%Y-%m-%d %H:%M:%S")
        }

        return time
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error getting timestamp for file: {file_path}")
        return None
    
def save_to_db(agent_name, finding_type, description, investigation_id):
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        sql = "INSERT INTO findings (agent_name,finding_type,description,investigation_id) values (%s,%s,%s,%s)"
        cur.execute(sql,(agent_name,finding_type,description,investigation_id))
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
    if timelines:
        description = f"Creation Time: {timelines['creation_time']} Modification Time: {timelines['modification_time']} Access Time: {timelines['access_time']}"
        save_to_db(agent_name='Timeline Agent', finding_type='File modification timelines', description=description, investigation_id=investigation_id)
        return jsonify({"message": "Timelines found successfully"}), 200
    

if __name__ == '__main__':
    app.run(port=5004, debug=True)
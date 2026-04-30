# db_utils.py
import psycopg2
from config import DB_CONFIG

def save_to_db(agent_name, finding_type, description, investigation_id, file_path):
    """
    Shared database helper used by all agents.
    Replaces the copy-pasted version in every agent file.
    """
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        sql = """
            INSERT INTO findings
                (agent_name, finding_type, description, investigation_id, file_path)
            VALUES (%s, %s, %s, %s, %s);
        """
        cur.execute(sql, (agent_name, finding_type, description, investigation_id, file_path))
        conn.commit()
        cur.close()
        print(f"[DB] Saved finding: [{agent_name}] {finding_type}")
    except Exception as e:
        print(f"[DB Error] {agent_name}: {e}")
    finally:
        if conn is not None:
            conn.close()
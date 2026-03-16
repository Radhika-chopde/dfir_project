import ollama
import psycopg2

DB_CONFIG = {
    "dbname": "dfir_db",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": "5432"
}

def get_ai_insight(file_path, findings_list):
    """
    Generates forensic insights and maps them to the MITRE ATT&CK Framework.
    """
    if not findings_list:
        return "No suspicious findings recorded for this artifact."

    # ENHANCED PROMPT: Forcing MITRE ATT&CK Mapping
    system_prompt = (
        "You are a Senior Digital Forensics Investigator and MITRE ATT&CK Specialist. "
        "Analyze the provided findings. Your task is to: "
        "1. Identify the specific MITRE ATT&CK technique being used (e.g., T1547.001). "
        "2. Explain the risk in a technical but concise manner. "
        "3. Provide exactly three sentences of analysis."
    )
    user_query = f"Artifact: {file_path}\nTelemetry Data: {', '.join(findings_list)}"
    
    try:
        response = ollama.chat(model='phi3', messages=[
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_query},
        ])
        return response['message']['content'].strip()
    except Exception as e:
        return f"Intelligence Synthesis Failed: {str(e)}"

def run_analysis_on_scan(investigation_id):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("SELECT DISTINCT file_path FROM findings WHERE investigation_id = %s", (investigation_id,))
        files = cur.fetchall()

        if not files: return

        print(f"[*] AI Analyst: Mapping {len(files)} artifacts to MITRE ATT&CK...")

        for (file_path,) in files:
            cur.execute(
                "SELECT description FROM findings WHERE investigation_id = %s AND file_path = %s", 
                (investigation_id, file_path)
            )
            findings_list = [f[0] for f in cur.fetchall()]
            insight = get_ai_insight(file_path, findings_list)
            
            cur.execute(
                "UPDATE findings SET ai_insight = %s WHERE investigation_id = %s AND file_path = %s",
                (insight, investigation_id, file_path)
            )
            conn.commit()
        
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[!] Intelligence Layer Error: {str(e)}")
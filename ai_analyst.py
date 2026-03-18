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
    if not findings_list:
        return "No suspicious findings recorded for this artifact."

    # Update this to 'phi4' or 'llama3.1:8b'
    SELECTED_MODEL = 'phi4' 

    system_prompt = (
        "You are a Senior DFIR Analyst. Analyze the following telemetry. "
        "Ground your reasoning in the provided scores. "
        "1. Map to MITRE ATT&CK (e.g., T1547). "
        "2. Explain why the behavior is suspicious. "
        "3. Keep the summary exactly three sentences long."
    )
    
    user_query = f"Artifact: {file_path}\nFindings: {', '.join(findings_list)}"
    
    try:
        response = ollama.chat(model=SELECTED_MODEL, messages=[
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_query},
        ])
        return response['message']['content'].strip()
    except Exception as e:
        return f"Intelligence Layer Error: {str(e)}"

def run_analysis_on_scan(investigation_id):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("SELECT DISTINCT file_path FROM findings WHERE investigation_id = %s", (investigation_id,))
        files = cur.fetchall()

        if not files:
            print("[!] AI Analyst: No artifacts found to analyze.")
            return

        print(f"[*] AI Analyst: Starting MITRE ATT&CK Synthesis for {len(files)} artifacts...")

        for index, (file_path,) in enumerate(files):
            # Fetch findings for this specific file
            cur.execute(
                "SELECT description FROM findings WHERE investigation_id = %s AND file_path = %s", 
                (investigation_id, file_path)
            )
            findings_list = [f[0] for f in cur.fetchall()]
            
            # Print status so you know the AI is working
            print(f"    [>] Analyzing ({index + 1}/{len(files)}): {file_path.split('\\')[-1]}")
            
            insight = get_ai_insight(file_path, findings_list)
            
            cur.execute(
                "UPDATE findings SET ai_insight = %s WHERE investigation_id = %s AND file_path = %s",
                (insight, investigation_id, file_path)
            )
            conn.commit() # Committing per file is safer for a triage tool
        
        print(f"[+] AI Analyst: Synthesis complete for {investigation_id}.")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[!] Intelligence Layer Error: {str(e)}")
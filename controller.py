import sys
import os
import requests

HASH_AGENT_URL = "http://127.0.0.1:5001/analyze_file"
KEYWORD_AGENT_URL = "http://127.0.0.1:5002/search_keywords"
FILE_SIGNATURE_AGENT_URL = "http://127.0.0.1:5003/verify_signature"

def main():
    if len(sys.argv)<2:
        print("Usage: python controller.py <directory_to_analyze")
        return
    
    target_directory = sys.argv[1]
    if not os.path.isdir(target_directory):
        print(f"Error: '{target_directory}' is not a valid directory.")
        return
    print(f"STARTING INVESTIGATION ON DIRECTORY: '{target_directory}'")

    files_to_process = []
    for root, dirs, files in os.walk(target_directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            files_to_process.append(file_path)
        
    if not files_to_process:
        print("No files found in the directory.")
        return
    print(f"Found {len(files_to_process)} files to analyze. Beginning processing...")

    for file_path in files_to_process:
        print(f"\n>>> Analyzing: {file_path} <<<")

        try:
            hash_payload = {"file_path": file_path}
            response = requests.post(HASH_AGENT_URL, json=hash_payload)
            print(" - Hash Agent Response:", response.json())
        except:
            print(" - [!] Error connecting to Hash Agent.")

        try:
            keyword_payload = {
                "file_path": file_path,
                "keywords": ["secret", "password", "admin", "confidential"]
            }
            response = requests.post(KEYWORD_AGENT_URL, json=keyword_payload)
        except:
            print(" - [!] Error connecting to Keyword Agent")

        try:
            signature_payload = {"file_path": file_path}
            response = requests.post(FILE_SIGNATURE_AGENT_URL,json=signature_payload)
            print(" - Signature Agent Response:", response.json())
        except:
            print(" - [!] Error connecting to Signature Agent")

    print("\n--- Directory Investigation Complete. Check the database for all findings. ---")

if __name__ == '__main__':
    main()
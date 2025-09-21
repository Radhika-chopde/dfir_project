import sys
import requests

HASH_AGENT_URL = "http://127.0.0.1:5001/analyze_file"
KEYWORD_AGENT_URL = "http://127.0.0.1:5002/search_keywords"

def main():
    if len(sys.argv)<2:
        print("Usage: python controller.py <file_to_analyze>")
        return
    target_file = sys.argv[1]
    print(f"----- Starting investigation on file: {target_file} -----")

    try:
        print("\n[+] Contacting Hash Agent...")
        hash_payload = {"file_path": target_file}
        response = requests.post(HASH_AGENT_URL, json=hash_payload)
        if response.status_code == 200:
            print("Hash Agent Response:", response.json())
        else:
            print(f"Error from Hash Agent: {response.status_code} - {response.text}")
    except requests.exceptions.ConnectionError:
        print("[!] Error: Could not connect to the Hash Agent. Is it running?")

    try:
        print("\n[+] Contacting Keyword Agent...")
        keyword_payload = {
            "file_path": target_file,
            "keywords": ["secret", "password", "admin", "confidential"]
        }
        response = requests.post(KEYWORD_AGENT_URL, json=keyword_payload)
        if response.status_code == 200:
            print("Keyword Agent Response: ", response.json())
        else:
            print(f"Error from Keyword Agent: {response.status_code} - {response.text}")
    except requests.exceptions.ConnectionError:
        print("[!] Error: Could not connect to the Keyword Agent. Is it running?")
    
    print("\n ----- Investigation complete. Check the database for findings. -----")

if __name__ == '__main__':
    main()
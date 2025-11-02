import subprocess
import time
import sys

scripts_to_run = [
    "hash_agent.py",
    "keyword_agent.py",
    "file_signature_agent.py",
    "timeline_agent.py",
    "main_app.py",
]

processes = []

print("--- Starting all DFIR services ---")

try:
    python_executable = sys.executable
    for script in scripts_to_run:
        process = subprocess.Popen([python_executable, script])
        processes.append(process)
        print(f"  - Started {script} (PID: {process.pid})")
    
    print("\n--- All services are running. Press Ctrl+C to stop all services. ---")
    
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    print("\n--- Shutdown signal received. Stopping all services... ---")
    for process in processes:
        print(f"  - Terminating {process.pid}...")
        process.terminate()
    print("--- All services stopped. ---")
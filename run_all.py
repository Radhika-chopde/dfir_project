import sys
import subprocess
import time
import os
from threading import Thread


# Updated list to include all 8 specialized forensic agents
agent_scripts = [
    "hash_agent.py",
    "keyword_agent.py",
    "file_signature_agent.py",
    "timeline_agent.py",
    "threat_intel_agent.py",
    "registry_agent.py",
    "browser_agent.py",
    "scan_memory.py"
]

processes = []

def print_output(pipe, script_name):
    """Reads output from an agent process and prints it with a prefix."""
    try:
        for line in iter(pipe.readline, ''):
            if line:
                print(f"[{script_name}]: {line.strip()}", flush=True)
    except Exception:
        pass 
    finally:
        pipe.close()

try:
    python_executable = sys.executable
    
    print(f"[*] Starting Intelligence DFIR Multi-Agent Suite...")
    print(f"[*] Python Executable: {python_executable}")
    print(f"[*] Launching {len(agent_scripts)} specialized agents...\n")

    for script in agent_scripts:
        # Check if the path exists to prevent immediate crashes
        if not os.path.exists(script):
            print(f"[!] Error: {script} not found. Skipping...")
            continue

        process = subprocess.Popen(
            [python_executable, script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        processes.append(process)
        
        # Start a thread to monitor this specific agent's logs
        script_name = script.split('/')[-1]
        t = Thread(target=print_output, args=(process.stdout, script_name))
        t.daemon = True
        t.start()
        
        print(f"[+] Launched {script_name} (PID: {process.pid})")
        time.sleep(0.5) # Brief pause to allow port binding

    print("\n--- All agents are operational ---")
    print("--- Press CTRL+C to stop the entire forensic suite ---\n")

    # Keep the main thread alive to catch KeyboardInterrupt
    while True:
        time.sleep(1)
        # Optional: Check if any process died unexpectedly
        for i, p in enumerate(processes):
            if p.poll() is not None:
                print(f"[!] Warning: Agent {agent_scripts[i]} has stopped unexpectedly.")

except KeyboardInterrupt:
    print("\n\n--- [!] Shutdown Signal Received: Stopping all agents ---")
    for i, process in enumerate(processes):
        try:
            process.terminate()
            process.wait(timeout=5)
            print(f"[-] Stopped {agent_scripts[i].split('/')[-1]}")
        except Exception:
            process.kill()
            print(f"[!] Force killed {agent_scripts[i].split('/')[-1]}")
            
    print("--- Forensic Suite Offline. ---")
except Exception as e:
    print(f"[!] A system error occurred: {e}")
    for process in processes:
        process.terminate()
finally:
    sys.exit()
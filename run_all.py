import sys
import subprocess
import time

agent_scripts = [
    "hash_agent.py",
    "keyword_agent.py",
    "file_signature_agent.py",
    "timeline_agent.py",
    "threat_intel_agent.py"
]

processes = []

try:
    python_executable = sys.executable
    
    print(f"Using Python executable: {python_executable}")
    print(f"Starting {len(agent_scripts)} agents...")

    for script in agent_scripts:
        process = subprocess.Popen(
            [python_executable, script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        processes.append(process)
        print(f"Launched {script} (PID: {process.pid})")
        time.sleep(1)

    print("\n--- All agents are running. ---")
    print("--- Output from all agents will appear below ---")
    print("--- Press CTRL+C in this terminal to stop all agents ---\n")

    def print_output(pipe, script_name):
        try:
            for line in iter(pipe.readline, ''):
                print(f"[{script_name}]: {line.strip()}", flush=True)
        except Exception:
            pass 
        finally:
            pipe.close()

    from threading import Thread
    threads = []
    
    for i, process in enumerate(processes):
        script_name = agent_scripts[i].split('/')[-1]
        t = Thread(target=print_output, args=(process.stdout, script_name))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

except KeyboardInterrupt:
    print("\n--- Shutting down all agents... ---")
    for i, process in enumerate(processes):
        process.terminate()
        process.wait()
        print(f"Stopped {agent_scripts[i]}")
    print("--- All agents stopped. ---")
except Exception as e:
    print(f"An error occurred: {e}")
    for process in processes:
        process.terminate()
        process.wait()
finally:
    sys.exit()
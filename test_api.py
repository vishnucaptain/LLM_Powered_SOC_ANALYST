import requests
import json
import time

API_URL = "http://127.0.0.1:8000/investigate"
LOG_DATA = """
2024-01-15 03:22:11 Failed password for admin from 185.220.101.5 port 54231 ssh2
2024-01-15 03:22:14 Failed password for admin from 185.220.101.5 port 54234 ssh2
2024-01-15 03:22:17 Failed password for root from 185.220.101.5 port 54237 ssh2
2024-01-15 03:22:31 Accepted password for admin from 185.220.101.5 port 54251 ssh2
2024-01-15 03:23:10 Suspicious process: mimikatz executed as root
"""

print("==================================================")
print(" 🚀 Submitting Investigation Request to Local API")
print("==================================================")
print("This may take 1-2 minutes. Processing locally without the browser...")

t0 = time.time()
try:
    response = requests.post(
        API_URL, 
        json={"logs": LOG_DATA.strip()},
        timeout=300 # 5 minute timeout limit
    )
    t1 = time.time()
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n✅ Investigation Completed in {t1 - t0:.1f} seconds!\n")
        print("=== 📊 AUTOMATED SUMMARY ===")
        print(f"Severity   : {data.get('severity', 'UNKNOWN')}")
        print(f"Confidence : {data.get('confidence', 0)*100}%")
        print(f"Mitre      : {', '.join(data.get('mitre_techniques', []))}")
        print("\n=== 🧠 PHI-3.5 ANALYST EXPLANATION ===")
        print(data.get("llm_explanation", "No explanation retrieved."))
        print("\n=== 🛡️ RECOMMENDED RESPONSE ===")
        for action in data.get("recommended_response", []):
            print(f"- {action}")
        print("==================================================")
    else:
        print(f"❌ Server returned error: {response.status_code}")
        print(response.text)
        
except Exception as e:
    print(f"\n❌ Request failed: {e}")

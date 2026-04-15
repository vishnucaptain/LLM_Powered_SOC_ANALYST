import requests
import time

url = "http://127.0.0.1:8000/investigate"
data = {
    "logs": "test error user login failure"
}

start_time = time.time()
print("Sending request to server...")
try:
    response = requests.post(url, json=data, timeout=300) # 5 min timeout
    print(f"Status Code: {response.status_code}")
    print(f"Time taken: {time.time() - start_time:.2f} seconds")
    try:
        print(response.json())
    except:
        print("Response text:", response.text)
except Exception as e:
    print("Error:", e)

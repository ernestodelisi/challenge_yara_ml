import requests
from fastapi import FastAPI, UploadFile, HTTPException, Form, Depends, status

#malicioso
file_hash = '500d4fc5fa4a192033151be25ee84f1089868990eb4e2fe8680030cc7d415bab'
#sano
#file_hash = '7f3343c96bf1d4a329047f0d8f082ff9b383f294b00edb9b35144aa91a82dabe'

api_key = ''
def check_virustotal(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        return result
    elif response.status_code == 404:
        return {"malicious": 0}
    else:
        raise HTTPException(status_code=500, detail="Error en la verificación con VirusTotal")

result = check_virustotal(file_hash, api_key)
print(result)

malicious_count = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
undetected = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("undetected", 0)

print(f"malicioso: {malicious_count}")
print(f" {undetected}")

import os
import requests
import time
from fastapi import FastAPI
from pydantic import BaseModel
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware

# This loads the VIRUSTOTAL_API_KEY from your .env file
load_dotenv()

# --- 1. Initial Setup ---
app = FastAPI()
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# --- 2. CORS Middleware ---
# THE FIX IS HERE: We now allow all origins by using ["*"]
origins = ["*"] 
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 3. Pydantic Models ---
class URLRequest(BaseModel):
    url: str

class CheckResponse(BaseModel):
    status: str
    url: str

# --- 4. API Endpoints ---
@app.get("/")
def read_root():
    return {"message": "Phishing Checker API is running!"}

@app.post("/check-url", response_model=CheckResponse)
def check_url(request: URLRequest):
    headers = {"x-apikey": API_KEY}
    scan_url = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": request.url}

    try:
        scan_response = requests.post(scan_url, headers=headers, data=payload)
        scan_response.raise_for_status()

        analysis_id = scan_response.json()["data"]["id"]
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        time.sleep(15) 
        
        report_response = requests.get(report_url, headers=headers)
        report_response.raise_for_status()
            
        report_data = report_response.json()
        malicious_count = report_data["data"]["attributes"]["stats"]["malicious"]
        
        if malicious_count > 0:
            return {"status": "DANGEROUS", "url": request.url}
        else:
            return {"status": "SAFE", "url": request.url}
            
    except requests.exceptions.RequestException as e:
        print(f"An error occurred with VirusTotal API: {e}")
        return {"status": "ERROR", "url": request.url}


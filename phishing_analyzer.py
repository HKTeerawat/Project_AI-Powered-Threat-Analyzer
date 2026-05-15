import os
import re
import json
import requests
import google.generativeai as genai
from dotenv import load_dotenv

# ==========================================
# 1. Configuration & API Setup
# ==========================================
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-3-flash-preview')

# ==========================================
# 2. Core Functions
# ==========================================
def extract_iocs(text):
    """Extracts URLs and IPs from raw text."""
    urls = re.findall(r'https?://[a-zA-Z0-9./\-_?=]+', text)
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    return {"urls": list(set(urls)), "ips": list(set(ips))}

def check_virustotal_ip(ip):
    """Queries VirusTotal API for IP reputation."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()['data']['attributes']['last_analysis_stats']
    return None

# ==========================================
# 3. Main Analysis Pipeline
# ==========================================
def analyze_threat(raw_email):
    print("[*] Extracting IoCs from email...")
    iocs = extract_iocs(raw_email)
    
    vt_results = {}
    print(f"[*] Checking {len(iocs['ips'])} IP(s) against VirusTotal...")
    for ip in iocs['ips']:
        # Filter out private network IPs
        if not ip.startswith(("192.168.", "10.", "172.")): 
            vt_results[ip] = check_virustotal_ip(ip)

    print("[*] Generating AI Threat Analysis Report...")
    prompt = f"""
    Act as a Senior SOC Analyst. Analyze this threat data and provide a concise Incident Report.
    
    1. Suspicious Email Content:
    {raw_email}
    
    2. VirusTotal Threat Intelligence:
    {json.dumps(vt_results, indent=2)}
    
    Provide the following in markdown format:
    - Severity Level (Low, Medium, High, Critical)
    - Threat Summary (Attacker's objective, attack vector)
    - Recommended Actions for SOC Level 1
    """
    
    response = model.generate_content(prompt)
    return response.text

# ==========================================
# 4. Execution
# ==========================================
if __name__ == "__main__":
    sample_phishing_email = """
    Subject: URGENT: Server 146.148.24.141 is under attack!
    From: admin-alert@it-support-update.com

    Hello,
    We detected malicious activity on IP 146.148.24.141. 
    Please login immediately to secure your server via this link:
    http://malicious-login-update.com/admin
    """

    print("-" * 50)
    final_report = analyze_threat(sample_phishing_email)
    print("-" * 50)
    print(f"\n{final_report}")
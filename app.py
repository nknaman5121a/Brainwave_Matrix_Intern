from flask import Flask, render_template, request
from dotenv import load_dotenv
import os
import re
from urllib.parse import urlparse
import requests
import base64

app = Flask(__name__)
#give api here
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'banking', 'secure', 'account', 'webscr']

def is_ip_address(url):
    return re.match(r'http[s]?://\d{1,3}(\.\d{1,3}){3}', url) is not None

def has_suspicious_keywords(url):
    return any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS)

def has_multiple_hyphens(url):
    return url.count('-') > 3

def has_at_symbol(url):
    return '@' in url


def check_with_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        return "Skipped (no API key)"
    
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    # VirusTotal
    submit_resp = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )
    
    if submit_resp.status_code != 200:
        return "Error submitting to VirusTotal"

    # for encoding
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    report = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
        headers=headers
    )

    if report.status_code == 200:
        stats = report.json()["data"]["attributes"]["last_analysis_stats"]
        return f"{stats['malicious']} malicious, {stats['suspicious']} suspicious"
    return "Error retrieving VirusTotal report"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        url = request.form['url'].strip()
        parsed = urlparse(url)

        result = {
            "url": url,
            "ip": is_ip_address(url),
            "keywords": has_suspicious_keywords(url),
            "hyphens": has_multiple_hyphens(url),
            "atsymbol": has_at_symbol(url),
            "domain_len": len(parsed.netloc),
            "path_len": len(parsed.path),
            "virustotal": check_with_virustotal(url)
        }
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)

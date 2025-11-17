import requests
import time
from dotenv import load_dotenv
import os
load_dotenv()

API_KEY = os.getenv("API_KEY")

def check_url_phishing(url):
    try:
        headers = {
            "x-apikey": API_KEY
        }

      
        scan_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        if scan_response.status_code != 200:
            return f"❌ Failed to submit URL: {scan_response.text}"

        scan_id = scan_response.json()['data']['id']
        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"

       
        while True:
            result_response = requests.get(report_url, headers=headers)
            result_json = result_response.json()

            status = result_json['data']['attributes']['status']
            if status == "completed":
                break
            time.sleep(2)

        # Extract detection stats
        stats = result_json['data']['attributes']['stats']
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)

        if malicious > 0 or suspicious > 0:
            return f"⚠️ Warning: Detected by {malicious + suspicious} engines!"
        else:
            return "✅ This URL appears safe according to VirusTotal."

    except Exception as e:
        return f"❌ Error checking URL: {e}"

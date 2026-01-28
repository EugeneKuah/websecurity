# InjeXpose

**InjeXpose** is a modular, educational web-security testing framework that orchestrates established tools such as **SQLMap**, **OWASP ZAP**, and **VirusTotal** to automate **dynamic application security testing (DAST)** and basic **URL reputation analysis**. It provides a simple menu-driven interface to run scans and generate structured vulnerability reports for learning and authorised testing.

⚠️ **Legal & Ethical Notice**  
InjeXpose is intended **only for educational use and authorised security testing** (e.g., DVWA, Juice Shop, personal labs). **Do NOT** scan systems you do not own or have explicit permission to test.

---

## Features

- SQL Injection testing via SQLMap  
- Broad vulnerability scanning via OWASP ZAP (spider + active scan)  
- URL reputation analysis via VirusTotal  
- HTML, JSON & text reports generated automatically  
- Modular design – easy to add more tools later  
- Designed for local labs (DVWA, Juice Shop)

---

## Project Structure

injexpose/
├─ injexpose.py              # Main menu runner
├─ tools/
│  ├─ sqlmap_scan.py         # SQLMap integration
│  ├─ zap_scan.py            # OWASP ZAP integration
│  └─ virustotal_scan.py     # VirusTotal URL reputation scanning
├─ reports/
│  ├─ sqlmap/                # SQLMap outputs
│  ├─ zap/                   # ZAP HTML/JSON reports
│  └─ virustotal/            # VirusTotal JSON & summary outputs
└─ venv/                     # Python virtual environment (recommended on Kali)

---

## System Requirements

- OS: Linux (Kali Linux recommended)  
- Python: 3.10+  
- Tools:
  - sqlmap
  - zaproxy (OWASP ZAP)
  - VirusTotal API key (free tier supported)
- Target: Deliberately vulnerable app (e.g., DVWA)

---

## One-Time Setup

### 1) Install required system tools

sudo apt update  
sudo apt install -y sqlmap zaproxy python3-venv

---

### 2) Create & activate a Python virtual environment (recommended on Kali)

cd injexpose  
python3 -m venv venv  
source venv/bin/activate

---

### 3) Install Python dependencies

pip install python-owasp-zap-v2.4 requests

Verify ZAP API:

python -c "from zapv2 import ZAPv2; print('ZAP API OK')"

---

### 4) Configure VirusTotal API Key (Required)

Register at: https://www.virustotal.com/

Export your API key:

export VT_API_KEY="YOUR_VIRUSTOTAL_API_KEY"

or

export VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY"

Do NOT hardcode API keys or commit them to GitHub.

---

## Running OWASP ZAP (Required)

ZAP must be running before using InjeXpose ZAP features.

Start ZAP in daemon mode:

/usr/share/zaproxy/zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=true

Verify:

ss -lntp | grep 8080

or

curl http://127.0.0.1:8080/JSON/core/view/version/

---

## Using InjeXpose

cd injexpose  
source venv/bin/activate  
python injexpose.py

Menu:

=== InjeXpose ===  
Target URL:  
1) SQLMap (SQL Injection)  
2) OWASP ZAP (Spider + Active Scan)  
3) Run BOTH  
4) VirusTotal (URL Reputation Scan)  
5) Run ALL (SQLMap + ZAP + VirusTotal)

---

## Tool Modes

### 1) SQLMap Mode

Choose 1  
Provide a URL with parameters

Example:

http://127.0.0.1/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit

Cookies (DVWA):

PHPSESSID=xxxx; security=low

Output:

reports/sqlmap/sqlmap_output.txt

---

### 2) OWASP ZAP Mode

Choose 2  
ZAP crawls and actively scans target

Outputs:

reports/zap/zap_report.html  
reports/zap/zap_report.json

---

### 3) Run BOTH

Runs SQLMap first, then OWASP ZAP  
Results saved in separate folders

---

### 4) VirusTotal (URL Reputation Scan)

Choose 4  
Submits URL to VirusTotal for reputation analysis

Outputs:

reports/virustotal/virustotal_report.json  
reports/virustotal/virustotal_summary.txt

Notes:
- VirusTotal cannot scan localhost / 127.0.0.1
- Use a publicly accessible URL
- Free API keys are rate-limited

---

## Understanding Results

High – Critical vulnerabilities  
Medium – Security weaknesses  
Low – Hardening issues  
Informational – Observations  

Many findings are expected on intentionally vulnerable apps like DVWA.

---

## Known Limitations

- Authenticated scanning is limited without ZAP context setup
- Designed for local labs, not production
- VirusTotal requires a publicly accessible URL

---

## Roadmap

- Authenticated ZAP scanning
- Additional tools (XSSer, Commix, Nikto)
- Unified summary report
- CLI flags (non-interactive mode)
- VirusTotal file hash / file upload scanning

---

## License

Educational / Academic Use

---

## Disclaimer

This software is provided for learning and authorised testing only. The author assumes no responsibility for misuse or damage caused by unauthorised scanning.

# InjeXpose

**InjeXpose** is a modular, educational web‑security testing framework that orchestrates established tools such as **SQLMap** and **OWASP ZAP** to automate **dynamic application security testing (DAST)**. It provides a simple menu-driven interface to run scans and generate structured vulnerability reports for learning and authorised testing.

> ⚠️ **Legal & Ethical Notice**
> InjeXpose is intended **only for educational use and authorised security testing** (e.g., DVWA, Juice Shop, personal labs). **Do NOT** scan systems you do not own or have explicit permission to test.

---

## Features

* 🔍 **SQL Injection testing** via SQLMap
* 🕷️ **Broad vulnerability scanning** via OWASP ZAP (spider + active scan)
* 📄 **HTML & JSON reports** generated automatically
* 🧩 **Modular design** – easy to add more tools later
* 🧪 Designed for **local labs** (DVWA, Juice Shop)

---

## Project Structure

```
injexpose/
├─ injexpose.py              # Main menu runner
├─ tools/
│  ├─ sqlmap_scan.py         # SQLMap integration
│  └─ zap_scan.py            # OWASP ZAP integration
├─ reports/
│  ├─ sqlmap/                # SQLMap outputs
│  └─ zap/                   # ZAP HTML/JSON reports
└─ venv/                     # Python virtual environment (recommended on Kali)
```

---

## System Requirements

* **OS:** Linux (Kali Linux recommended)
* **Python:** 3.10+
* **Tools:**

  * `sqlmap`
  * `zaproxy` (OWASP ZAP)
* **Target:** Deliberately vulnerable app (e.g., DVWA)

---

## One‑Time Setup

### 1) Install required system tools

```bash
sudo apt update
sudo apt install -y sqlmap zaproxy python3-venv
```

### 2) Create & activate a Python virtual environment (recommended on Kali)

Kali Linux enforces PEP 668, so a virtual environment is the safe way to install Python packages.

```bash
cd injexpose
python3 -m venv venv
source venv/bin/activate
```

### 3) Install Python dependencies

```bash
pip install python-owasp-zap-v2.4
```

Verify:

```bash
python -c "from zapv2 import ZAPv2; print('ZAP API OK')"
```

---

## Running OWASP ZAP (Required)

ZAP **must be running** before you use InjeXpose’s ZAP features. If ZAP is not running or is on a different port, InjeXpose will fail with a `Connection refused` / `ProxyError`.

### Start ZAP in daemon (headless) mode (Kali Linux)

```bash
/usr/share/zaproxy/zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=true
```

* Leave this terminal **open**
* ZAP listens on **127.0.0.1:8080** (this must match the port in `zap_scan.py`)

### Verify ZAP is running

```bash
ss -lntp | grep 8080
```

Or via the API:

```bash
curl http://127.0.0.1:8080/JSON/core/view/version/
```

### If port 8080 is already in use

Start ZAP on another port (example **8090**):

```bash
/usr/share/zaproxy/zap.sh -daemon -host 127.0.0.1 -port 8090 -config api.disablekey=true
```

Then update `tools/zap_scan.py`:

```python
zap_proxy = "http://127.0.0.1:8090"
```

(Optional) Add ZAP to PATH:

```bash
sudo ln -s /usr/share/zaproxy/zap.sh /usr/local/bin/zap.sh
```

---

## Using InjeXpose

In a **new terminal**:

```bash
cd injexpose
source venv/bin/activate
python injexpose.py
```

You will see a menu similar to:

```
=== InjeXpose ===
Target URL:
1) SQLMap (SQL Injection)
2) OWASP ZAP (Spider + Active Scan)
3) Run BOTH
```

---

## Tool Modes

### 1) SQLMap Mode

* Choose **1**
* Provide a URL with parameters

Example (DVWA SQLi page):

```
http://127.0.0.1/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit
```

**Cookies (required for authenticated apps like DVWA):**

```
PHPSESSID=xxxx; security=low
```

**Output:**

```
reports/sqlmap/sqlmap_output.txt
```

---

### 2) OWASP ZAP Mode

* Choose **2**
* ZAP will crawl and actively scan the target

**Outputs:**

```
reports/zap/zap_report.html
reports/zap/zap_report.json
```

Open the HTML report:

```bash
xdg-open reports/zap/zap_report.html
```

---

### 3) Run BOTH (Recommended)

* Runs SQLMap first
* Then runs OWASP ZAP
* Saves results in separate folders

Ideal for demonstrations and coursework submissions.

---

## Understanding Results

* 🔴 **High** – Critical, exploitable vulnerabilities (e.g., SQL Injection, Path Traversal)
* 🟠 **Medium** – Security weaknesses (e.g., CSRF, missing headers)
* 🟡 **Low** – Hardening issues
* 🔵 **Informational** – Observations

> Note: Many findings are **expected** on intentionally vulnerable apps like DVWA.

---

## Known Limitations

* Authenticated scanning (e.g., DVWA after login) is limited without ZAP context/user setup
* Designed for **local labs**, not production environments

---

## Roadmap (Optional Enhancements)

* Add authenticated ZAP scanning (contexts & users)
* Add more tools (XSSer, Commix, Nikto)
* Unified summary report across tools
* CLI flags (non‑interactive mode)

---

## License

Educational / Academic Use

---

## Disclaimer

This software is provided for learning and authorised testing only. The author assumes no responsibility for misuse or damage caused by unauthorised scanning.

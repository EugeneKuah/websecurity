# InjeXpose (DVWA Scanner + Local LLM Report)

InjeXpose is a CLI-based web security scanner workflow that integrates:
- SQLMap (SQL Injection testing)
- OWASP ZAP (Spider + Active Scan)
- Nikto (Web server scan)
- VirusTotal (URL reputation scan)
- **Local LLM Report via Ollama** (no OpenAI API key required)

This README is written so teammates can clone the repo and get everything working reliably on Kali Linux / VMware.

---

## 1. System Requirements

### OS
- Kali Linux (recommended)
- Other Debian-based Linux distros should also work

### Hardware (important for LLM)
- Minimum: **8 GB RAM**
- Recommended: **16 GB RAM**
- CPU: 2–4 cores minimum

If your system has less RAM, use a smaller Ollama model.

---

## 2. Install System Dependencies

Update system:
```bash
sudo apt update
```

Install required packages:
```bash
sudo apt install -y python3 python3-venv python3-pip git curl ca-certificates docker.io
sudo update-ca-certificates
```

Enable Docker:
```bash
sudo systemctl enable --now docker
```

(Optional) Avoid using sudo for Docker:
```bash
sudo usermod -aG docker $USER
newgrp docker
```

---

## 3. Clone the Repository

```bash
git clone <YOUR_GITHUB_REPO_URL>
cd injexpose
```

---

## 4. Python Virtual Environment (Required on Kali)

Kali blocks global pip installs. Always use a virtual environment.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Upgrade pip and install Python dependencies:
```bash
pip install -U pip
pip install requests
```

---

## 5. Run DVWA Using Docker (Port 8081)

Start DVWA:
```bash
sudo docker run -d   --name dvwa   -p 8081:80   vulnerables/web-dvwa
```

If the container already exists:
```bash
sudo docker start dvwa
```

Verify:
```bash
sudo docker ps
```

Open in browser:
```
http://localhost:8081
```

Login:
- Username: `admin`
- Password: `password`

Set:
- **DVWA Security → Low**

---

## 6. Install and Configure Ollama (Local LLM)

Install Ollama:
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Enable and start Ollama:
```bash
sudo systemctl enable --now ollama
```

Verify:
```bash
curl -s http://localhost:11434/api/tags
```

Pull a model (recommended):
```bash
ollama pull qwen2.5:7b
```

Test:
```bash
ollama run qwen2.5:7b "Reply with one word: OK"
```

### Low RAM systems
If you get a memory error:
```bash
ollama pull qwen2.5:3b
# or
ollama pull qwen2.5:1.5b
```

---

## 7. Running InjeXpose

Activate venv:
```bash
source .venv/bin/activate
```

Run:
```bash
python3 injexpose.py
```

Example target URL:
```
http://localhost:8081/vulnerabilities/sqli/?id=&Submit=Submit
```

Menu options:
- **6** – Run ALL scans (recommended first)
- **7** – Generate LLM report from scan outputs

### Best Workflow
1. Start DVWA
2. Set DVWA Security = Low
3. Run **Option 6**
4. Run **Option 7**

---

## 8. Output Files

Reports are generated under:
```
reports/
├── sqlmap/
├── zap/
├── nikto/
├── virustotal/
└── llm/
```

LLM outputs:
- `llm_report_YYYYMMDD_HHMMSS.json`
- `llm_report_YYYYMMDD_HHMMSS.md`

---

## 9. Troubleshooting

### Docker permission denied
```bash
sudo docker ps
```

### DVWA container name conflict
```bash
sudo docker stop dvwa
sudo docker rm dvwa
sudo docker run -d --name dvwa -p 8081:80 vulnerables/web-dvwa
```

### Ollama already running
This is normal. Verify with:
```bash
curl -s http://localhost:11434/api/tags
```

### LLM report looks generic
- Run scans first (Option 6)
- Use authenticated DVWA pages
- Ensure reports exist before Option 7

### Kali pip error (externally-managed-environment)
Always use:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## 10. GitHub Hygiene

Do NOT commit:
- `.venv/`
- `reports/`
- API keys

Recommended `.gitignore`:
```gitignore
.venv/
reports/
__pycache__/
*.pyc
.env
```

---

## Quick Start

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip docker.io git curl ca-certificates
sudo systemctl enable --now docker
sudo systemctl enable --now ollama

git clone <YOUR_GITHUB_REPO_URL>
cd injexpose

python3 -m venv .venv
source .venv/bin/activate
pip install requests

sudo docker run -d --name dvwa -p 8081:80 vulnerables/web-dvwa

ollama pull qwen2.5:7b

python3 injexpose.py
```

---

## License
(Add your license here)

# InjeXpose

## Enterprise-Oriented Web Vulnerability Scanning Framework with LLM-Based Reporting

InjeXpose is a modular web application vulnerability scanning framework
designed to integrate multiple industry-standard security tools into a
unified workflow. It consolidates technical findings into a structured,
executive-ready report using a Large Language Model (LLM).

The system is intended for controlled environments, security
laboratories, academic research, and authorized application security
assessments.

------------------------------------------------------------------------

## 1. Overview

Modern web security assessments often require the orchestration of
multiple tools, each producing fragmented outputs. InjeXpose addresses
this by:

-   Executing multiple security scanners in a coordinated manner
-   Standardizing output storage and structure
-   Automatically detecting the most recent scan artifacts
-   Generating a consolidated, structured security report via LLM
    summarization

The framework emphasizes modularity, extensibility, and professional
reporting.

------------------------------------------------------------------------

## 2. Core Capabilities

### 2.1 Integrated Security Tools

-   **SQLMap** -- Automated SQL Injection detection and exploitation
    testing
-   **OWASP ZAP** -- Spidering and active web application scanning
-   **Nikto** -- Web server misconfiguration and exposure detection
-   **VirusTotal API** -- External URL reputation intelligence
-   **Ollama (LLM)** -- Consolidated vulnerability reporting and
    executive summary generation

### 2.2 Reporting Features

-   Executive summary generation
-   Cross-tool vulnerability correlation
-   Structured issue breakdown
-   Remediation recommendations
-   Risk contextualization
-   Automatic latest-report detection
-   Graceful handling of unsupported targets (e.g., localhost for
    VirusTotal)

------------------------------------------------------------------------

## 3. System Architecture

InjeXpose\
├── injexpose.py (Main CLI Interface)\
├── tools/\
│ ├── sqlmap_scan.py\
│ ├── zap_scan.py\
│ ├── nikto_scan.py\
│ ├── virustotal_scan.py\
│ └── llm_report.py\
└── reports/\
├── sqlmap/\
├── zap/\
├── nikto/\
├── virustotal/\
└── llm/

Each scanner operates independently and persists structured output
within its respective directory.\
The LLM module aggregates the latest scan outputs and produces a
consolidated analytical report.

------------------------------------------------------------------------

## 4. Installation Requirements

### 4.1 Operating System

-   Kali Linux (recommended)
-   Ubuntu or Debian-based distributions

### 4.2 Required System Tools

Install core dependencies:

    sudo apt install sqlmap nikto zip

Install OWASP ZAP from:

    https://www.zaproxy.org/download/

Ensure ZAP is available in the system PATH.

### 4.3 Python Dependencies

    pip install requests zapv2

### 4.4 LLM Environment (Ollama)

Install Ollama:

    curl -fsSL https://ollama.com/install.sh | sh

Pull required model:

    ollama pull qwen2.5:7b

------------------------------------------------------------------------

## 5. VirusTotal API Configuration

1.  Create an account at https://www.virustotal.com\

2.  Generate a personal API key\

3.  Insert the API key inside:

    tools/virustotal_scan.py

Replace:

    API_KEY = "YOUR_API_KEY_HERE"

Note: VirusTotal does not support private or localhost targets. The
system automatically detects and skips unsupported targets without
interrupting execution.

------------------------------------------------------------------------

## 6. Execution

Launch the framework:

    python3 injexpose.py

Main Menu Options:

1)  SQLMap (SQL Injection Testing)\
2)  OWASP ZAP (Spider + Active Scan)\
3)  Run BOTH\
4)  VirusTotal (URL Reputation)\
5)  Nikto (Web Server Assessment)\
6)  Run ALL\
7)  Generate LLM Report\
8)  Exit

The LLM report should be generated after completing the desired scans.

------------------------------------------------------------------------

## 7. Example Controlled Test Environment

Example using DVWA (Docker-based deployment):

    docker run --rm -it -p 8081:80 vulnerables/web-dvwa

Example target:

    http://localhost:8081/vulnerabilities/sqli/

------------------------------------------------------------------------

## 8. Output Structure

Each tool produces structured output:

-   SQLMap → Text reports
-   ZAP → JSON and HTML reports
-   Nikto → Text reports
-   VirusTotal → JSON and text summaries
-   LLM → Consolidated analytical report

All outputs are stored under the `reports/` directory hierarchy.

------------------------------------------------------------------------

## 9. Security and Compliance Notice

This framework is intended strictly for:

-   Authorized penetration testing
-   Educational laboratories
-   Academic research
-   Controlled security environments

Unauthorized scanning of external systems may violate applicable laws
and organizational policies.

Users are responsible for ensuring proper authorization before
conducting any security testing.

------------------------------------------------------------------------

## 10. Design Principles

-   Modular architecture
-   Tool abstraction
-   Structured reporting
-   Automation-first workflow
-   Professional output standardization
-   Extensibility for future tool integration

------------------------------------------------------------------------

## 11. Future Enhancements

-   CVSS-based scoring integration
-   PDF and HTML executive report exports
-   Multi-target batch scanning
-   Dockerized full-stack deployment
-   Role-based reporting profiles
-   Centralized dashboard interface

------------------------------------------------------------------------

## Author

Developed as part of a professional web security systems project.

------------------------------------------------------------------------

## License

Provided for academic, research, and authorized security assessment
purposes.

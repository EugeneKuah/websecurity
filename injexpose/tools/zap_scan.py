import os
import shutil
import socket
import subprocess
import time
import json
from typing import Optional, Tuple

import requests

ZAP_PORT = 8080  # ZAP daemon port (DVWA is on 8081)
ZAP_HOST = "127.0.0.1"

# Dedicated ZAP home directory to avoid "~/.ZAP" lock conflicts
ZAP_HOME_DIR = os.path.join(os.path.dirname(__file__), "..", ".zap_home")
ZAP_HOME_DIR = os.path.abspath(ZAP_HOME_DIR)

# Output directory for reports (standardized to match other scanners)
# All scanner outputs now go under: injexpose/reports/<tool>/
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "reports", "zap")
OUTPUT_DIR = os.path.abspath(OUTPUT_DIR)


def is_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def find_zap_command() -> Optional[str]:
    """
    Tries common Kali ZAP launchers.
    Returns the command to execute, or None if not found.
    """
    for cmd in ["zaproxy", "zap.sh"]:
        path = shutil.which(cmd)
        if path:
            return path

    # Common fallback location (sometimes zap.sh lives here)
    fallback = "/usr/share/zaproxy/zap.sh"
    if os.path.exists(fallback):
        return fallback

    return None


def start_zap_daemon(port: int = ZAP_PORT) -> subprocess.Popen:
    """
    Starts ZAP in daemon mode, returns the Popen handle.
    """
    zap_cmd = find_zap_command()
    if not zap_cmd:
        raise RuntimeError(
            "ZAP not found. Install it first: sudo apt update && sudo apt install zaproxy"
        )

    # Ensure our dedicated home dir exists (prevents ~/.ZAP lock conflicts)
    os.makedirs(ZAP_HOME_DIR, exist_ok=True)

    args = [
        zap_cmd,
        "-daemon",
        "-port", str(port),

        # Avoid: "The home directory is already in use" on ~/.ZAP
        "-dir", ZAP_HOME_DIR,

        # Local-only lab. If you expose ZAP beyond localhost, do NOT disable API key.
        "-config", "api.disablekey=true",
    ]

    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    return proc


def ensure_zap_running(
    host: str = ZAP_HOST,
    port: int = ZAP_PORT,
    wait_sec: int = 25
) -> Optional[subprocess.Popen]:
    """
    If ZAP is already running on (host, port), do nothing.
    Otherwise start it and wait until it is listening.
    Returns Popen handle if we launched it, else None.
    """
    if is_port_open(host, port):
        print(f"[OK] ZAP already running on {host}:{port}")
        return None

    print(f"[INFO] ZAP not running on {host}:{port} — starting daemon...")
    proc = start_zap_daemon(port)

    deadline = time.time() + wait_sec
    while time.time() < deadline:
        if is_port_open(host, port):
            print(f"[OK] ZAP started on {host}:{port}")
            return proc
        time.sleep(0.5)

    try:
        out = (proc.stdout.read(2000) if proc.stdout else "")
    except Exception:
        out = ""
    raise RuntimeError(f"ZAP failed to start within {wait_sec}s.\nOutput:\n{out}")


def stop_zap_on_port(port: int = ZAP_PORT) -> None:
    """
    Stops whatever is listening on the port.
    """
    res = subprocess.run(
        ["bash", "-lc", f"lsof -t -i :{port}"],
        capture_output=True,
        text=True
    )
    pids = [p.strip() for p in res.stdout.splitlines() if p.strip()]
    if not pids:
        print(f"[OK] Nothing listening on port {port}")
        return
    for pid in pids:
        subprocess.run(["sudo", "kill", "-9", pid])
    print(f"[OK] Killed process(es) on port {port}: {', '.join(pids)}")


def _make_report_paths() -> Tuple[str, str]:
    """
    Creates output directory and returns unique html/json report paths.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    html_path = os.path.join(OUTPUT_DIR, f"zap_report_{ts}.html")
    json_path = os.path.join(OUTPUT_DIR, f"zap_report_{ts}.json")
    return html_path, json_path


def _zap_get(zap_base: str, path: str, params: Optional[dict] = None, timeout: float = 30.0) -> dict:
    url = f"{zap_base}{path}"
    r = requests.get(url, params=params or {}, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _wait_until(name: str, status_fn, sleep_s: float = 2.0, timeout_s: int = 600) -> None:
    """
    Polls status_fn() until it returns >= 100, or timeout.
    status_fn must return an int percentage.
    """
    start = time.time()
    last = -1
    while True:
        pct = status_fn()
        if pct != last:
            print(f"[INFO] {name} progress: {pct}%")
            last = pct

        if pct >= 100:
            print(f"[OK] {name} complete (100%).")
            return

        if time.time() - start > timeout_s:
            raise RuntimeError(f"{name} timed out after {timeout_s}s (stuck at {pct}%).")

        time.sleep(sleep_s)



def _normalize_cookie_string(cookies: str) -> str:
    """
    Accepts either:
      - "PHPSESSID=...; security=low"
      - "Cookie: PHPSESSID=...; security=low"
    Returns a clean cookie header value (no leading "Cookie:").
    """
    c = (cookies or "").strip()
    if c.lower().startswith("cookie:"):
        c = c.split(":", 1)[1].strip()
    return c


def _set_cookie_via_core(zap_base: str, cookies: str, url: str) -> None:
    """
    Sets cookies for the given URL in ZAP's internal HTTP state.
    This is usually more reliable than Replacer alone for authenticated scans.
    """
    clean = _normalize_cookie_string(cookies)
    try:
        _zap_get(
            zap_base,
            "/JSON/core/action/setCookie/",
            params={"cookie": clean, "url": url},
            timeout=20.0
        )
        print("[OK] Set cookies via core/setCookie.")
    except Exception as e:
        print(f"[WARN] core/setCookie failed (continuing): {e}")

def _set_cookie_replacer_rule(zap_base: str, cookies: str) -> None:
    """
    Adds a ZAP Replacer rule to force Cookie header on outgoing requests.
    If the Replacer add-on isn't available, we warn and continue.
    """
    desc = f"injexpose_cookie_{int(time.time())}"
    replacement = _normalize_cookie_string(cookies)

    try:
        _zap_get(
            zap_base,
            "/JSON/replacer/action/addRule/",
            params={
                "description": desc,
                "enabled": "true",
                "matchType": "REQ_HEADER",
                "matchRegex": "false",
                "matchString": "Cookie",
                "replacement": replacement,
            },
            timeout=20.0
        )
        print("[OK] Added ZAP Replacer rule for cookies.")
    except Exception as e:
        print(f"[WARN] Could not add Replacer cookie rule (addon missing or API changed). Continuing. Details: {e}")


def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def run_zap_scan(
    target: str,
    cookies: Optional[str] = None,
    seed_url: Optional[str] = None,
    zap_host: str = ZAP_HOST,
    zap_port: int = ZAP_PORT
) -> Tuple[str, str]:
    """
    Ensures ZAP daemon is running, runs spider + active scan, exports:
    - JSON alerts (stable)
    - HTML report we generate (stable; includes severity counts + table)

    Returns (html_path, json_path).

    seed_url:
      Optional "baseline" URL to seed the sites tree (useful for DVWA forms).
      Example: http://localhost:8081/vulnerabilities/sqli/?id=1&Submit=Submit
    """
    _ = ensure_zap_running(host=zap_host, port=zap_port)

    zap_base = f"http://{zap_host}:{zap_port}"
    print(f"[INFO] ZAP API: {zap_base}")
    print(f"[INFO] Target: {target}")

    if cookies:
        print(f"[INFO] Cookies provided to ZAP runner: {cookies}")
        _set_cookie_via_core(zap_base, cookies, seed_url or target)
        _set_cookie_replacer_rule(zap_base, cookies)

    html_path, json_path = _make_report_paths()

    # 1) Seed target (use seed_url if provided)
    seed = seed_url or target
    try:
        _zap_get(
            zap_base,
            "/JSON/core/action/accessUrl/",
            params={"url": seed, "followRedirects": "true"},
            timeout=30.0
        )
        print(f"[OK] Seeded target via core/accessUrl: {seed}")
    except Exception as e:
        print(f"[WARN] core/accessUrl failed (continuing): {e}")

    # 2) Spider scan
    spider = _zap_get(
        zap_base,
        "/JSON/spider/action/scan/",
        params={"url": target, "maxChildren": "", "recurse": "true", "subtreeOnly": "false"},
        timeout=30.0
    )
    spider_id = spider.get("scan")
    if spider_id is None:
        raise RuntimeError(f"Unexpected spider response: {spider}")

    print(f"[INFO] Spider scan started. scanId={spider_id}")

    def spider_status():
        st = _zap_get(zap_base, "/JSON/spider/view/status/", params={"scanId": spider_id}, timeout=30.0)
        return int(st.get("status", 0))

    _wait_until("Spider", spider_status, sleep_s=2.0, timeout_s=600)

    # 3) Active scan
    #
    # IMPORTANT:
    #   For DVWA-style pages (form-driven GET/POST), ZAP can end up only seeing
    #   empty parameters (e.g., id=) unless we actively scan a URL that includes
    #   a real baseline value.
    #
    #   Therefore: if seed_url is provided, we run the ACTIVE scan on seed_url
    #   (parameterized), while still spidering the page URL (target).
    scan_url = seed_url or target

    ascan = _zap_get(
        zap_base,
        "/JSON/ascan/action/scan/",
        params={
            "url": scan_url,
            "recurse": "true",
            "inScopeOnly": "false",
            "scanPolicyName": "",
            "method": "",
            "postData": ""
        },
        timeout=30.0
    )
    ascan_id = ascan.get("scan")
    if ascan_id is None:
        raise RuntimeError(f"Unexpected ascan response: {ascan}")

    print(f"[INFO] Active scan started. scanId={ascan_id} (url={scan_url})")

    def ascan_status():
        st = _zap_get(zap_base, "/JSON/ascan/view/status/", params={"scanId": ascan_id}, timeout=30.0)
        return int(st.get("status", 0))

    _wait_until("Active Scan", ascan_status, sleep_s=3.0, timeout_s=900)

    # 4) Pull alerts (stable) and save JSON
    try:
        alerts = _zap_get(
            zap_base,
            "/JSON/core/view/alerts/",
            params={"baseurl": target},
            timeout=60.0
        )
    except Exception as e:
        alerts = {"alerts": [], "error": str(e)}

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)
    print(f"[OK] Saved JSON alerts: {json_path}")

    # 5) Generate HTML report (stable)
    items = alerts.get("alerts", []) if isinstance(alerts, dict) else []
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for a in items:
        risk = (a.get("risk") or "Informational").strip()
        if risk not in counts:
            counts[risk] = 0
        counts[risk] += 1

    rows = []
    for a in items:
        rows.append(
            "<tr>"
            f"<td>{_esc(a.get('risk'))}</td>"
            f"<td>{_esc(a.get('name'))}</td>"
            f"<td>{_esc(a.get('url'))}</td>"
            f"<td>{_esc(a.get('param'))}</td>"
            f"<td>{_esc(a.get('confidence'))}</td>"
            "</tr>"
        )

    with open(html_path, "w", encoding="utf-8") as f:
        f.write("<html><head><meta charset='utf-8'><title>ZAP Alerts Report</title></head><body>")
        f.write("<h1>OWASP ZAP Alerts Report</h1>")
        f.write(f"<p><b>ZAP API:</b> {_esc(zap_base)}</p>")
        f.write(f"<p><b>Target:</b> {_esc(target)}</p>")
        if cookies:
            f.write(f"<p><b>Cookies:</b> {_esc(cookies)}</p>")

        f.write("<h2>Summary (by Risk)</h2><ul>")
        for k in ["High", "Medium", "Low", "Informational"]:
            f.write(f"<li><b>{k}:</b> {counts.get(k, 0)}</li>")
        f.write("</ul>")

        f.write("<h2>Findings</h2>")
        f.write("<table border='1' cellpadding='6' cellspacing='0'>")
        f.write("<tr><th>Risk</th><th>Alert</th><th>URL</th><th>Param</th><th>Confidence</th></tr>")
        f.write("".join(rows) if rows else "<tr><td colspan='5'>No alerts found.</td></tr>")
        f.write("</table>")

        f.write("</body></html>")

    print(f"[OK] Saved HTML report: {html_path}")

    return html_path, json_path


if __name__ == "__main__":
    ensure_zap_running(port=ZAP_PORT)
    target = "http://127.0.0.1:8081/vulnerabilities/sqli/"
    run_zap_scan(target, cookies=None, seed_url=target + "?id=1&Submit=Submit")

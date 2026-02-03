import os
import shutil
import socket
import subprocess
import time
import json
from typing import Optional, Tuple

ZAP_PORT = 8080  # ZAP daemon port (DVWA is on 8081)
ZAP_HOST = "127.0.0.1"

# Dedicated ZAP home directory to avoid "~/.ZAP" lock conflicts
ZAP_HOME_DIR = os.path.join(os.path.dirname(__file__), "..", ".zap_home")
ZAP_HOME_DIR = os.path.abspath(ZAP_HOME_DIR)

# Output directory for reports
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")
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

        "-config", "api.disablekey=true",
    ]

    # Run in background; capture output so your terminal doesn't get spammed
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
    wait_sec: int = 20
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

    # If it didn't come up, print some output to help debug
    try:
        out = (proc.stdout.read(1200) if proc.stdout else "")
    except Exception:
        out = ""
    raise RuntimeError(f"ZAP failed to start within {wait_sec}s.\nOutput:\n{out}")


def stop_zap_on_port(port: int = ZAP_PORT) -> None:
    """
    Stops whatever is listening on the port (useful if you want to clean up).
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


def run_zap_scan(
    target: str,
    cookies: Optional[str] = None,
    zap_host: str = ZAP_HOST,
    zap_port: int = ZAP_PORT
) -> Tuple[str, str]:
    """
    Ensures ZAP daemon is running, and ALWAYS returns (html_path, json_path)
    so your injexpose.py can unpack it safely.

    Notes:
    - Accepts cookies=... to match your injexpose.py call signature.
    - This currently writes a placeholder report so the pipeline doesn't crash.
      You can later expand this function to call ZAP API: spider + active scan + export.
    """
    _ = ensure_zap_running(host=zap_host, port=zap_port)

    print(f"[INFO] ZAP ready at http://{zap_host}:{zap_port}")
    print(f"[INFO] Target: {target}")

    if cookies:
        print(f"[INFO] Cookies provided to ZAP runner: {cookies}")

    html_path, json_path = _make_report_paths()

    # Placeholder outputs (so your program continues)
    placeholder = {
        "tool": "OWASP ZAP",
        "zap_api": f"http://{zap_host}:{zap_port}",
        "target": target,
        "cookies": cookies or "",
        "status": "ZAP running. Spider/Active scan export not yet implemented in tools/zap_scan.py.",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(placeholder, f, indent=2)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write("<html><head><meta charset='utf-8'><title>ZAP Report (Placeholder)</title></head><body>")
        f.write("<h1>OWASP ZAP Report (Placeholder)</h1>")
        f.write(f"<p><b>ZAP API:</b> http://{zap_host}:{zap_port}</p>")
        f.write(f"<p><b>Target:</b> {target}</p>")
        if cookies:
            f.write(f"<p><b>Cookies:</b> {cookies}</p>")
        f.write("<p>Status: ZAP is running. Actual spider/active scan + export is not implemented yet.</p>")
        f.write("</body></html>")

    return html_path, json_path


if __name__ == "__main__":
    # 1) Ensure ZAP is up
    zap_proc = ensure_zap_running(port=ZAP_PORT)

    # 2) Your code continues here
    target = "http://127.0.0.1:8081"
    print(f"[INFO] Ready to scan target: {target}")

    # Optional: if you want to stop ZAP when your script exits AND you started it:
    # if zap_proc is not None:
    #     zap_proc.terminate()

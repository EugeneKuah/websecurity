import os
import shutil
import subprocess
from typing import Optional


class NiktoError(Exception):
    pass


def run_nikto_scan(
    target_url: str,
    cookies: Optional[str] = None,
    out_dir: str = "reports/nikto",
    timeout_seconds: Optional[int] = None,
) -> str:
    """
    Runs Nikto against target_url and saves output to:
      reports/nikto/nikto_report.txt
    If cookies provided, sends them using -C "<cookie-string>"
    """
    if shutil.which("nikto") is None:
        raise NiktoError("Nikto is not installed or not in PATH. Install with: sudo apt install nikto")

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "nikto_report.txt")

    cmd = ["nikto", "-h", target_url, "-output", out_path, "-Format", "txt"]

    if cookies:
        cmd.extend(["-C", cookies])

    try:
        result = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            input="n\n",
        )
    except subprocess.TimeoutExpired as e:
        raise NiktoError(f"Nikto scan timed out after {timeout_seconds}s") from e
    except Exception as e:
        raise NiktoError(f"Failed to run Nikto: {e}") from e

    if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        raise NiktoError(
            "Nikto did not produce a report.\n"
            f"STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}"
        )

    with open(out_path, "a", encoding="utf-8") as f:
        if result.stdout:
            f.write("\n\n===== Nikto STDOUT (captured) =====\n")
            f.write(result.stdout)
        if result.stderr:
            f.write("\n\n===== Nikto STDERR (captured) =====\n")
            f.write(result.stderr)

    return out_path

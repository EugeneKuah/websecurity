import subprocess
import os

def run_sqlmap(target: str, cookies: str | None = None, out_dir: str = "reports/sqlmap"):
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "sqlmap_output.txt")

    cmd = [
        "sqlmap",
        "-u", target,
        "--batch",
        "--level=5",
        "--risk=3",
        "--random-agent",
    ]

    if cookies:
        cmd.append(f"--cookie={cookies}")

    with open(out_file, "w", encoding="utf-8") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)

    return out_file

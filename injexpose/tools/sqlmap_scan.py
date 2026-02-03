import os
import subprocess


def _preset_to_level_risk(preset: int) -> tuple[int, int]:
    if preset == 1:
        return 1, 1
    if preset == 2:
        return 3, 1
    return 5, 3


def run_sqlmap(
    target: str,
    cookies: str | None = None,
    level_preset: int = 1,
    out_dir: str = "reports/sqlmap",
) -> str:
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "sqlmap_output.txt")

    level, risk = _preset_to_level_risk(level_preset)

    cmd = [
        "sqlmap",
        "-u", target,
        "--batch",
        "--random-agent",
        f"--level={level}",
        f"--risk={risk}",
        "--crawl=3",
        "--forms",
        "--all",
    ]

    if cookies:
        cmd.append(f"--cookie={cookies}")

    print(f"[SQLMap] Running preset={level_preset} (level={level}, risk={risk})")
    print(f"[SQLMap] Cookies: {'✅ provided' if cookies else '⚠️ none'}")
    print(f"[SQLMap] Command: {' '.join(cmd)}")
    print(f"[SQLMap] Saving output to: {out_file}")

    with open(out_file, "w", encoding="utf-8") as f:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in proc.stdout:
            print(line.rstrip())
            f.write(line)

    return out_file

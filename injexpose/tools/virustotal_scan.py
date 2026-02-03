# tools/virustotal_scan.py

import os
import time
import json
import base64
from typing import Any, Dict, Tuple, Optional

import requests


VT_API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalError(Exception):
    pass


def _get_api_key(explicit_key: Optional[str] = None) -> str:
    api_key = explicit_key or os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise VirusTotalError(
            "VirusTotal API key not found. Set VT_API_KEY (recommended) or VIRUSTOTAL_API_KEY."
        )
    return api_key


def _headers(api_key: str) -> Dict[str, str]:
    return {
        "x-apikey": api_key,
        "accept": "application/json",
    }


def _url_id(url: str) -> str:
    """
    VirusTotal URL identifier:
    base64(url) urlsafe, without '=' padding.
    """
    b = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8")
    return b.rstrip("=")


def run_virustotal_url_scan(
    target_url: str,
    out_dir: str = "reports/virustotal",
    api_key: Optional[str] = None,
    poll_interval: int = 5,
    timeout_seconds: int = 300,
) -> Tuple[str, str]:
    """
    Submits a URL to VirusTotal for analysis, polls until completion, and saves:
      - reports/virustotal/virustotal_report.json
      - reports/virustotal/virustotal_summary.txt

    Returns: (json_path, summary_path)
    """
    os.makedirs(out_dir, exist_ok=True)

    api_key = _get_api_key(api_key)
    hdrs = _headers(api_key)

    # 1) Submit URL for scanning
    submit_url = f"{VT_API_BASE}/urls"
    try:
        resp = requests.post(
            submit_url,
            headers=hdrs,
            data={"url": target_url},
            timeout=30,
        )
    except requests.RequestException as e:
        raise VirusTotalError(f"VirusTotal request failed while submitting URL: {e}") from e

    if resp.status_code not in (200, 201):
        raise VirusTotalError(
            f"VirusTotal submit failed ({resp.status_code}): {resp.text}"
        )

    data = resp.json()
    analysis_id = data.get("data", {}).get("id")
    if not analysis_id:
        raise VirusTotalError(f"VirusTotal submit returned unexpected response: {data}")

    # 2) Poll analysis until completed
    analysis_url = f"{VT_API_BASE}/analyses/{analysis_id}"
    start = time.time()
    analysis_json: Dict[str, Any] = {}

    while True:
        if time.time() - start > timeout_seconds:
            raise VirusTotalError(
                f"VirusTotal analysis timed out after {timeout_seconds}s. "
                f"Try increasing timeout_seconds or poll_interval."
            )

        try:
            r = requests.get(analysis_url, headers=hdrs, timeout=30)
        except requests.RequestException as e:
            raise VirusTotalError(f"VirusTotal request failed while polling: {e}") from e

        if r.status_code != 200:
            raise VirusTotalError(f"VirusTotal poll failed ({r.status_code}): {r.text}")

        analysis_json = r.json()
        status = (
            analysis_json.get("data", {})
            .get("attributes", {})
            .get("status", "")
        )

        if status == "completed":
            break

        time.sleep(poll_interval)

    # 3) (Optional) Fetch the URL object (gives aggregated last_analysis_stats, etc.)
    url_obj_json: Dict[str, Any] = {}
    try:
        url_obj = requests.get(
            f"{VT_API_BASE}/urls/{_url_id(target_url)}",
            headers=hdrs,
            timeout=30,
        )
        if url_obj.status_code == 200:
            url_obj_json = url_obj.json()
    except requests.RequestException:
        # Non-fatal; we still have the analysis result.
        url_obj_json = {}

    # 4) Save outputs
    json_path = os.path.join(out_dir, "virustotal_report.json")
    summary_path = os.path.join(out_dir, "virustotal_summary.txt")

    combined = {
        "target_url": target_url,
        "analysis": analysis_json,
        "url_object": url_obj_json,
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2, ensure_ascii=False)

    # Build a compact summary
    stats = (
        url_obj_json.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )

    # Fallback to analysis.stats if url_object isn't available
    if not stats:
        stats = (
            analysis_json.get("data", {})
            .get("attributes", {})
            .get("stats", {})
        ) or {}

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout_ct = stats.get("timeout", 0)

    lines = [
        "=== VirusTotal URL Scan Summary ===",
        f"Target: {target_url}",
        "",
        "Detection Stats:",
        f"  malicious   : {malicious}",
        f"  suspicious  : {suspicious}",
        f"  harmless    : {harmless}",
        f"  undetected  : {undetected}",
        f"  timeout     : {timeout_ct}",
        "",
        f"Full JSON report: {json_path}",
    ]

    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return json_path, summary_path

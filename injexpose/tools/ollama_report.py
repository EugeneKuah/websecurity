import os
import json
import time
import threading
from typing import Any, Dict, Optional

import requests


def _safe_read_text(path: Optional[str], max_chars: int = 12000) -> str:
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()[:max_chars]
    except Exception:
        return ""


def _spinner(stop_event: threading.Event, label: str = "Generating LLM report") -> None:
    frames = ["|", "/", "-", "\\"]
    i = 0
    while not stop_event.is_set():
        print(f"\r[LLM] {label}... {frames[i % len(frames)]}", end="", flush=True)
        i += 1
        time.sleep(0.15)
    print("\r", end="", flush=True)


def _ollama_generate_streaming(
    prompt: str,
    model: str = "qwen2.5:7b",
    timeout: int = 600,
) -> str:
    """
    Streams tokens from Ollama so user sees progress.
    Returns the full text response.
    """
    stop = threading.Event()
    sp = threading.Thread(target=_spinner, args=(stop, "Ollama is generating"), daemon=True)
    sp.start()

    token_chars = 0
    out_parts = []

    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": model, "prompt": prompt, "stream": True},
            stream=True,
            timeout=timeout,
        )
        r.raise_for_status()

        last_print = time.time()
        for line in r.iter_lines(decode_unicode=True):
            if not line:
                continue

            try:
                obj = json.loads(line)
            except Exception:
                # Ignore malformed lines
                continue

            chunk = obj.get("response", "")
            if chunk:
                out_parts.append(chunk)
                token_chars += len(chunk)

            # Update a light progress indicator every ~0.8s
            now = time.time()
            if now - last_print > 0.8:
                print(f"\r[LLM] Ollama is generating... ({token_chars} chars received)", end="", flush=True)
                last_print = now

            if obj.get("done") is True:
                break

        return "".join(out_parts).strip()

    finally:
        stop.set()
        sp.join(timeout=1.0)
        print(f"\r[LLM] Ollama generation finished. ({token_chars} chars received)           ")


def generate_llm_report(*args, **kwargs) -> Dict[str, str]:
    """
    Drop-in replacement for OpenAI-based generate_llm_report.
    This version uses Ollama locally and does NOT require OPENAI_API_KEY.

    Returns: {"json": <path>, "md": <path>}
    """

    # Try to infer common fields from kwargs (and fallback)
    target = kwargs.get("target") or kwargs.get("url") or (args[0] if len(args) > 0 else "")
    cookies = kwargs.get("cookies") or kwargs.get("cookie") or ""
    cookies_used = bool(cookies)

    sqlmap_out = kwargs.get("sqlmap_out") or kwargs.get("sqlmap_path") or kwargs.get("sqlmap_report") or ""
    zap_json   = kwargs.get("zap_json")   or kwargs.get("zap_out")     or kwargs.get("zap_path")   or kwargs.get("zap_report")   or ""
    nikto_out  = kwargs.get("nikto_out")  or kwargs.get("nikto_path")  or kwargs.get("nikto_report")  or ""
    vt_json    = kwargs.get("vt_json")    or kwargs.get("virustotal_json") or ""
    vt_summary = kwargs.get("vt_summary") or kwargs.get("virustotal_summary") or ""

    out_dir = kwargs.get("out_dir") or "reports/llm"
    model = kwargs.get("model") or "qwen2.5:7b"

    os.makedirs(out_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_json = os.path.join(out_dir, f"llm_report_{ts}.json")
    out_md = os.path.join(out_dir, f"llm_report_{ts}.md")

    sqlmap_text = _safe_read_text(sqlmap_out)
    zap_text    = _safe_read_text(zap_json)
    nikto_text  = _safe_read_text(nikto_out)
    vtj_text    = _safe_read_text(vt_json)
    vts_text    = _safe_read_text(vt_summary)

    # Prompt is defensive: no payloads, no attack steps.
    prompt = f"""
You are a defensive security report assistant for a web vulnerability scanner.
Use ONLY the provided scan outputs. Do NOT invent vulnerabilities.
Do NOT provide exploit payloads or step-by-step attack instructions.

Return VALID JSON ONLY (no markdown, no extra text).

Target: {target}
Cookies used: {cookies_used}

SQLMap excerpt:
{sqlmap_text}

ZAP excerpt:
{zap_text}

Nikto excerpt:
{nikto_text}

VirusTotal summary excerpt:
{vts_text}

VirusTotal JSON excerpt:
{vtj_text}

Output JSON schema:
{{
  "ok": true,
  "overall_risk": "Low|Medium|High|Critical",
  "issues": [
    {{
      "title": "string",
      "severity": "Low|Medium|High|Critical",
      "confidence": 0.0,
      "evidence": ["string"],
      "remediation": ["string"]
    }}
  ],
  "limitations": ["string"]
}}
""".strip()

    print(f"[LLM] Using Ollama model: {model}")
    raw = _ollama_generate_streaming(prompt, model=model, timeout=600)

    # Parse JSON (fallback if model outputs extra text)
    obj: Dict[str, Any]
    try:
        obj = json.loads(raw)
    except Exception:
        # Try to salvage JSON if the model included extra lines
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                obj = json.loads(raw[start:end + 1])
            except Exception:
                obj = {"ok": False, "error": "Invalid JSON from model", "raw_excerpt": raw[:2000]}
        else:
            obj = {"ok": False, "error": "Invalid JSON from model", "raw_excerpt": raw[:2000]}

    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

    # Simple markdown companion
    md = [
        "# InjeXpose LLM Report (Ollama)",
        "",
        f"**Target:** {target}",
        f"**Cookies used:** {'Yes' if cookies_used else 'No'}",
        "",
    ]

    if obj.get("ok") is True:
        md += [f"## Overall risk: {obj.get('overall_risk','Unknown')}", "", "## Issues"]
        for i, it in enumerate(obj.get("issues", [])[:30], 1):
            md += [
                f"### {i}. {it.get('title','')}",
                f"- Severity: {it.get('severity','')}",
                f"- Confidence: {it.get('confidence','')}",
                "- Evidence:",
            ]
            for e in it.get("evidence", [])[:6]:
                md.append(f"  - {e}")
            md.append("- Remediation:")
            for r in it.get("remediation", [])[:6]:
                md.append(f"  - {r}")
            md.append("")

        if obj.get("limitations"):
            md.append("## Limitations")
            for l in obj["limitations"][:10]:
                md.append(f"- {l}")
            md.append("")
    else:
        md += ["## LLM output error", "```", obj.get("raw_excerpt", "")[:2000], "```"]

    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    print(f"[LLM] Report saved: {out_json}")
    print(f"[LLM] Report saved: {out_md}")
    return {"json": out_json, "md": out_md}

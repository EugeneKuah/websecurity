import os
import json
import time
import threading
from typing import Any, Dict, Optional, List

import requests


def _extract_sqlmap_high_signal(text: str, max_lines: int = 120) -> str:
    """Keep high-signal SQLMap lines, but redact payloads (no exploit strings)."""
    if not text:
        return ""
    keep_keys = (
        "back-end dbms",
        "the back-end dbms",
        "parameter:",
        "type:",
        "title:",
        "sql injection",
        "is vulnerable",
        "identified",
        "testing",
        "heuristic",
        "resuming",
        "warning",
        "critical",
        "info:",
    )

    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        low = line.lower()

        # Redact payload lines completely.
        if "payload" in low:
            out.append("[REDACTED] SQLMap payload output removed")
            continue

        if any(k in low for k in keep_keys):
            out.append(line)

        if len(out) >= max_lines:
            break

    # Fallback: if nothing matched, provide tail excerpt.
    if not out:
        out = ["(No high-signal SQLMap markers found; showing tail excerpt)"]
        tail = text.splitlines()[-80:]
        out.extend(tail)

    return "\n".join(out)


def _extract_nikto_high_signal(text: str, max_lines: int = 160) -> str:
    """Nikto output is mostly lines starting with '+'. Keep those and totals."""
    if not text:
        return ""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("+") or line.lower().startswith("- nikto") or "requests" in line.lower() or "item(s) reported" in line.lower():
            out.append(line)
        if len(out) >= max_lines:
            break
    if not out:
        out = text.splitlines()[:120]
    return "\n".join(out)


def _safe_read_text(path: Optional[str], max_chars: int = 18000) -> str:
    """
    High-signal excerpt:
    - Many tools (esp. SQLMap/Nikto) put the most important findings near the END.
    - So we keep HEAD + TAIL instead of only the start.
    """
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        if not content:
            return ""

        if len(content) <= max_chars:
            return content

        head_len = max_chars // 2
        tail_len = max_chars - head_len
        head = content[:head_len]
        tail = content[-tail_len:]

        return (
            head
            + "\n\n--- [TRUNCATED: MIDDLE REMOVED TO KEEP HIGH-SIGNAL HEAD+TAIL] ---\n\n"
            + tail
        )
    except Exception:
        return ""


def _safe_read_json(path: Optional[str], max_chars: int = 18000) -> str:
    """
    If it's ZAP JSON, extract a compact alert digest so the LLM won't miss issues.
    Falls back to text head+tail if parsing fails.
    """
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()

        obj = json.loads(raw)

        # ZAP alerts format: {"site":[...]} in core.jsonreport(), OR {"alerts":[...]} in some exports
        # We'll try both.
        alerts: List[dict] = []

        if isinstance(obj, dict) and "alerts" in obj and isinstance(obj["alerts"], list):
            alerts = obj["alerts"]

        # core.jsonreport format includes: {"site":[{"alerts":[...]}]}
        if not alerts and isinstance(obj, dict) and "site" in obj and isinstance(obj["site"], list):
            for site in obj["site"]:
                if isinstance(site, dict) and "alerts" in site and isinstance(site["alerts"], list):
                    alerts.extend(site["alerts"])

        if alerts:
            lines: List[str] = []
            lines.append(f"ZAP Alerts count: {len(alerts)}")

            breakdown: Dict[str, int] = {}
            for a in alerts:
                risk = (a.get("riskdesc") or a.get("risk") or "Informational").strip()
                # riskdesc often like "Medium (Medium)"
                risk_key = risk.split(" ")[0]
                breakdown[risk_key] = breakdown.get(risk_key, 0) + 1
            lines.append(f"Risk breakdown: {breakdown}")

            # Keep the first 40 alerts entries
            for a in alerts[:40]:
                name = (a.get("name") or "").strip()
                risk = (a.get("riskdesc") or a.get("risk") or "").strip()
                confidence = (a.get("confidence") or "").strip()

                # Instances may have uri/param/method
                uri = ""
                param = ""
                if isinstance(a.get("instances"), list) and a["instances"]:
                    inst0 = a["instances"][0]
                    if isinstance(inst0, dict):
                        uri = (inst0.get("uri") or inst0.get("url") or "").strip()
                        param = (inst0.get("param") or "").strip()

                # Evidence can be large; keep small snippet
                evidence = (a.get("evidence") or "").strip()
                if evidence and len(evidence) > 160:
                    evidence = evidence[:160] + "..."

                lines.append(
                    f"- Risk={risk} | Alert={name} | Param={param} | Confidence={confidence} | URL={uri} | Evidence={evidence}"
                )

            return "\n".join(lines)

        # Other JSON (VirusTotal etc.) -> head+tail
        return _safe_read_text(path, max_chars=max_chars)

    except Exception:
        return _safe_read_text(path, max_chars=max_chars)


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
                continue

            chunk = obj.get("response", "")
            if chunk:
                out_parts.append(chunk)
                token_chars += len(chunk)

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
    Uses Ollama locally and returns: {"json": <path>, "md": <path>}
    """

    target = kwargs.get("target") or kwargs.get("url") or (args[0] if len(args) > 0 else "")
    cookies = kwargs.get("cookies") or kwargs.get("cookie") or ""
    cookies_used = bool(kwargs.get("cookies_used")) if "cookies_used" in kwargs else bool(cookies)

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

    sqlmap_text = _extract_sqlmap_high_signal(_safe_read_text(sqlmap_out, max_chars=18000), max_lines=140)
    zap_text    = _safe_read_json(zap_json, max_chars=18000)  # digest if ZAP JSON
    nikto_text  = _extract_nikto_high_signal(_safe_read_text(nikto_out, max_chars=18000), max_lines=180)
    vtj_text    = _safe_read_json(vt_json, max_chars=16000)
    vts_text    = _safe_read_text(vt_summary, max_chars=8000)

    prompt = f"""
You are a defensive security report assistant for a student web vulnerability scanner.
Use ONLY the provided scan outputs. Do NOT invent vulnerabilities.
Do NOT provide exploit payloads, exact attack strings, or step-by-step attack instructions.

Return VALID JSON ONLY (no markdown, no extra text).

Priorities:
1) Prefer confirmed findings (e.g., SQLMap confirms injectable parameter) over generic best-practice headers.
2) If only security headers are missing, keep them but label as "hardening" (Low/Medium).
3) If a tool output is missing/empty, mention it in limitations.
4) Do NOT drop issues when evidence exists. Merge duplicates across tools.
5) Include up to 25 issues if present. If fewer than 8 issues exist, explain why (e.g., only hardening findings).

Target: {target}
Cookies used: {cookies_used}

SQLMap high-signal excerpt (payloads redacted):
{sqlmap_text}

ZAP digest (from JSON if provided):
{zap_text}

Nikto high-signal excerpt:
{nikto_text}

VirusTotal summary excerpt:
{vts_text}

VirusTotal JSON excerpt:
{vtj_text}

Output JSON schema (strict):
{{
  "ok": true,
  "overall_risk": "Very Low|Low|Medium|High|Critical",
  "executive_summary": ["string"],
  "tool_summaries": {{
    "sqlmap": ["string"],
    "zap": ["string"],
    "nikto": ["string"],
    "virustotal": ["string"]
  }},
  "issues": [
    {{
      "title": "string",
      "category": "Injection|Auth|Config|Headers|InfoLeak|Other",
      "severity": "Low|Medium|High|Critical",
      "confidence": 0.0,
      "evidence": ["string"],
      "impact": ["string"],
      "remediation": ["string"],
      "tools": ["SQLMap|ZAP|Nikto|VirusTotal"]
    }}
  ],
  "recommended_next_steps": ["string"],
  "limitations": ["string"]
}}
""".strip()

    print(f"[LLM] Using Ollama model: {model}")
    raw = _ollama_generate_streaming(prompt, model=model, timeout=600)

    obj: Dict[str, Any]
    try:
        obj = json.loads(raw)
    except Exception:
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

    md = [
        "# InjeXpose LLM Report (Ollama)",
        "",
        f"**Target:** {target}",
        f"**Cookies used:** {'Yes' if cookies_used else 'No'}",
        "",
    ]

    if obj.get("ok") is True:
        md += [f"## Overall risk: {obj.get('overall_risk','Unknown')}", ""]

        if obj.get("executive_summary"):
            md.append("## Executive summary")
            for s in obj.get("executive_summary", [])[:10]:
                md.append(f"- {s}")
            md.append("")

        if obj.get("tool_summaries"):
            md.append("## Tool summaries")
            ts = obj.get("tool_summaries") or {}
            for k in ("sqlmap", "zap", "nikto", "virustotal"):
                if ts.get(k):
                    md.append(f"### {k.upper()}")
                    for s in ts.get(k, [])[:10]:
                        md.append(f"- {s}")
                    md.append("")

        md += ["## Issues"]
        for i, it in enumerate(obj.get("issues", [])[:30], 1):
            md += [
                f"### {i}. {it.get('title','')}",
                f"- Category: {it.get('category','')}",
                f"- Severity: {it.get('severity','')}",
                f"- Confidence: {it.get('confidence','')}",
                f"- Tools: {', '.join(it.get('tools', []) or [])}",
                "- Evidence:",
            ]
            for e in it.get("evidence", [])[:8]:
                md.append(f"  - {e}")

            if it.get("impact"):
                md.append("- Impact:")
                for imp in it.get("impact", [])[:6]:
                    md.append(f"  - {imp}")

            md.append("- Remediation:")
            for r in it.get("remediation", [])[:8]:
                md.append(f"  - {r}")
            md.append("")

        if obj.get("recommended_next_steps"):
            md.append("## Recommended next steps")
            for s in obj.get("recommended_next_steps", [])[:12]:
                md.append(f"- {s}")
            md.append("")

        if obj.get("limitations"):
            md.append("## Limitations")
            for l in obj["limitations"][:12]:
                md.append(f"- {l}")
            md.append("")
    else:
        md += ["## LLM output error", "```", obj.get("raw_excerpt", "")[:2000], "```"]

    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    print(f"[LLM] Report saved: {out_json}")
    print(f"[LLM] Report saved: {out_md}")
    return {"json": out_json, "md": out_md}

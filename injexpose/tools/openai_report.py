import os
import json
import time
from typing import Any, Dict, Optional

from openai import OpenAI


def _safe_read_text(path: Optional[str], max_chars: int = 12000) -> str:
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
        return data[:max_chars]
    except Exception:
        return ""


def _safe_read_json(path: Optional[str], max_chars: int = 12000) -> Any:
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        raw = raw[:max_chars]
        return json.loads(raw)
    except Exception:
        return {}


def generate_llm_report(
    *,
    target: str,
    cookies_used: bool,
    sqlmap_out: Optional[str] = None,
    zap_json: Optional[str] = None,
    nikto_out: Optional[str] = None,
    vt_json: Optional[str] = None,
    vt_summary: Optional[str] = None,
    out_dir: str = "reports/llm",
    model: str = "gpt-5.2",
) -> Dict[str, str]:
    """
    Reads your scanner outputs and produces:
      - reports/llm/llm_report_<timestamp>.json
      - reports/llm/llm_report_<timestamp>.md

    Returns dict with saved paths.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set in environment.")

    os.makedirs(out_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_json_path = os.path.join(out_dir, f"llm_report_{ts}.json")
    out_md_path = os.path.join(out_dir, f"llm_report_{ts}.md")

    # Load tool outputs (truncate to keep prompts small + reduce injection risk)
    sqlmap_text = _safe_read_text(sqlmap_out)
    nikto_text = _safe_read_text(nikto_out)
    vt_summary_text = _safe_read_text(vt_summary)
    vt_json_obj = _safe_read_json(vt_json)
    zap_json_obj = _safe_read_json(zap_json)

    findings: Dict[str, Any] = {
        "target": target,
        "cookies_used": cookies_used,
        "artifacts": {
            "sqlmap_out": sqlmap_out or "",
            "zap_json": zap_json or "",
            "nikto_out": nikto_out or "",
            "vt_json": vt_json or "",
            "vt_summary": vt_summary or "",
        },
        "tool_outputs": {
            "sqlmap_output_excerpt": sqlmap_text,
            "nikto_output_excerpt": nikto_text,
            "virustotal_summary_excerpt": vt_summary_text,
            "virustotal_json_excerpt": vt_json_obj,
            "zap_json_excerpt": zap_json_obj,
        },
        "notes": [
            "You are analyzing scanner outputs, not the website itself.",
            "Do not invent vulnerabilities not supported by the outputs.",
            "No exploit payloads or step-by-step attack instructions.",
        ],
    }

    # We force JSON-only output first, so your code can validate it.
    system_instructions = (
        "You are a defensive security report assistant for a web vulnerability scanner.\n"
        "Use ONLY the provided scanner outputs.\n"
        "Do NOT provide exploitation steps, payloads, or attack instructions.\n"
        "Do NOT invent endpoints/vulns.\n"
        "Return VALID JSON ONLY (no markdown, no extra text).\n"
    )

    schema_example = {
        "ok": True,
        "overall_risk": "Low|Medium|High|Critical",
        "highlights": [
            {
                "title": "string",
                "severity": "Low|Medium|High|Critical",
                "confidence": 0.0,
                "evidence": ["string"]
            }
        ],
        "issues": [
            {
                "title": "string",
                "category": "SQLi|XSS|Auth|Config|InfoLeak|Reputation|Other",
                "severity": "Low|Medium|High|Critical",
                "confidence": 0.0,
                "affected_url_or_component": "string",
                "evidence": ["string"],
                "false_positive_checks": ["string"],
                "remediation": ["string"],
                "references": ["CWE-xx", "OWASP Axx"]
            }
        ],
        "limitations": ["string"]
    }

    user_payload = {
        "task": "Generate a structured assessment from these scan findings.",
        "output_schema_example": schema_example,
        "findings": findings,
    }

    client = OpenAI(api_key=api_key)
    resp = client.responses.create(
        model=model,
        input=[
            {"role": "system", "content": system_instructions},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
    )

    raw = (resp.output_text or "").strip()

    try:
        report_obj = json.loads(raw)
    except Exception:
        report_obj = {
            "ok": False,
            "error": "Model did not return valid JSON",
            "raw_excerpt": raw[:2000],
        }

    # Save JSON
    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(report_obj, f, indent=2)

    # Also render a simple Markdown report for humans
    md_lines = []
    md_lines.append(f"# InjeXpose LLM Report")
    md_lines.append("")
    md_lines.append(f"**Target:** {target}")
    md_lines.append(f"**Cookies used:** {'Yes' if cookies_used else 'No'}")
    md_lines.append("")

    if report_obj.get("ok") is True:
        md_lines.append(f"## Overall risk: {report_obj.get('overall_risk', 'Unknown')}")
        md_lines.append("")
        md_lines.append("## Highlights")
        for h in report_obj.get("highlights", [])[:10]:
            md_lines.append(f"- **{h.get('title','')}** ({h.get('severity','')}, conf={h.get('confidence','')})")
        md_lines.append("")
        md_lines.append("## Issues")
        for i, issue in enumerate(report_obj.get("issues", [])[:30], 1):
            md_lines.append(f"### {i}. {issue.get('title','')}")
            md_lines.append(f"- Severity: {issue.get('severity','')}")
            md_lines.append(f"- Confidence: {issue.get('confidence','')}")
            md_lines.append(f"- Category: {issue.get('category','')}")
            md_lines.append(f"- Affected: {issue.get('affected_url_or_component','')}")
            ev = issue.get("evidence", [])
            if ev:
                md_lines.append(f"- Evidence:")
                for e in ev[:6]:
                    md_lines.append(f"  - {e}")
            fixes = issue.get("remediation", [])
            if fixes:
                md_lines.append(f"- Remediation:")
                for r in fixes[:6]:
                    md_lines.append(f"  - {r}")
            md_lines.append("")
        lim = report_obj.get("limitations", [])
        if lim:
            md_lines.append("## Limitations")
            for l in lim[:10]:
                md_lines.append(f"- {l}")
            md_lines.append("")
    else:
        md_lines.append("## LLM output error")
        md_lines.append("")
        md_lines.append("The model did not return valid JSON.")
        md_lines.append("")
        md_lines.append("Raw excerpt:")
        md_lines.append("```")
        md_lines.append(str(report_obj.get("raw_excerpt", ""))[:2000])
        md_lines.append("```")

    with open(out_md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    return {"json": out_json_path, "md": out_md_path}

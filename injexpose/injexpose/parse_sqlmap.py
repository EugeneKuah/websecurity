from __future__ import annotations
import re
from typing import List, Optional
from injexpose.model import Finding


PARAM_BLOCK_RE = re.compile(r"^Parameter:\s*(.+)$", re.IGNORECASE)
TYPE_RE = re.compile(r"^Type:\s*(.+)$", re.IGNORECASE)
TITLE_RE = re.compile(r"^Title:\s*(.+)$", re.IGNORECASE)
PAYLOAD_RE = re.compile(r"^Payload:\s*(.+)$", re.IGNORECASE)
URL_HINT_RE = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)

# Alternate sqlmap-style lines (fallback)
VULN_LINE_RE = re.compile(r"parameter\s+'([^']+)'\s+is\s+vulnerable", re.IGNORECASE)
INJECTABLE_RE = re.compile(r"appears\s+to\s+be\s+injectable", re.IGNORECASE)


def _extract_url(text: str) -> str:
    m = URL_HINT_RE.search(text)
    return m.group(1) if m else "UNKNOWN_URL"


def _parse_param_line(line: str) -> tuple[Optional[str], Optional[str]]:
    """
    Examples:
      "id (GET)"
      "username (POST)"
      "id"
    """
    raw = line.strip()
    m = re.match(r"(.+?)\s*\((GET|POST)\)\s*$", raw, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip(), m.group(2).upper()
    return raw, None


def parse_sqlmap_output(text: str, default_url: Optional[str] = None) -> List[Finding]:
    """
    Parses a *text output* produced by sqlmap into Finding objects.
    Pattern-based parsing for MVP robustness.

    Strategy:
    - Prefer "Parameter:" blocks (structured)
    - Fall back to "parameter 'x' is vulnerable" lines
    - Merge duplicates by (url, parameter), preferring entries with technique details.
    """
    lines = text.splitlines()
    url = default_url or _extract_url(text)

    findings: List[Finding] = []
    current: Optional[Finding] = None

    def flush_current():
        nonlocal current
        if current is not None:
            current.evidence = [e for e in current.evidence if e.strip()]
            findings.append(current)
            current = None

    for i, line in enumerate(lines):
        s = line.strip()

        # Start of a structured Parameter block
        m = PARAM_BLOCK_RE.match(s)
        if m:
            flush_current()
            param_raw = m.group(1).strip()
            param, method = _parse_param_line(param_raw)
            current = Finding(
                vuln_type="SQL Injection",
                url=url,
                parameter=param,
                method=method,
                vulnerabilities=["SQL Injection"],
                evidence=[f"Parameter block detected: {param_raw}"],
            )
            continue

        # Parse fields inside a Parameter block
        if current is not None:
            tm = TYPE_RE.match(s)
            if tm:
                current.technique = tm.group(1).strip()
                current.evidence.append(f"Type: {current.technique}")
                continue

            ttm = TITLE_RE.match(s)
            if ttm:
                title = ttm.group(1).strip()
                # If technique not set, use title as hint
                if not current.technique:
                    current.technique = title
                current.evidence.append(f"Title: {title}")
                continue

            pm = PAYLOAD_RE.match(s)
            if pm:
                payload = pm.group(1).strip()
                current.evidence.append(f"Payload: {payload}")
                continue

            # End of block on blank line (common formatting)
            if s == "" and i > 0:
                flush_current()
                continue

        # Fallback: single-line vulnerability mention
        vm = VULN_LINE_RE.search(s)
        if vm:
            param = vm.group(1).strip()
            f = Finding(
                vuln_type="SQL Injection",
                url=url,
                parameter=param,
                vulnerabilities=["SQL Injection"],
                evidence=[s],
            )

            # Try to infer confidence from nearby lines
            window = "\n".join(lines[max(0, i - 4): min(len(lines), i + 6)])
            if INJECTABLE_RE.search(window):
                f.confidence = "HIGH"
                f.evidence.append("Context indicates parameter appears injectable.")

            findings.append(f)

    flush_current()

    # Merge duplicates by (url, parameter), preferring the finding with technique/method
    merged: dict[tuple[str, str], Finding] = {}

    for f in findings:
        base_key = (f.url, f.parameter or "")

        if base_key not in merged:
            merged[base_key] = f
            continue

        g = merged[base_key]

        # Prefer technique details if the existing one lacks it
        if (not g.technique) and f.technique:
            g.technique = f.technique

        # Prefer method if missing (GET/POST)
        if (not g.method) and f.method:
            g.method = f.method

        # Merge vulnerabilities (avoid duplicates)
        for v in f.vulnerabilities:
            if v not in g.vulnerabilities:
                g.vulnerabilities.append(v)

        # Merge evidence (avoid duplicates)
        for e in f.evidence:
            if e not in g.evidence:
                g.evidence.append(e)

        # Prefer higher confidence if any
        # (simple rule: HIGH beats MEDIUM beats LOW)
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        if order.get((f.confidence or "MEDIUM").upper(), 1) > order.get((g.confidence or "MEDIUM").upper(), 1):
            g.confidence = f.confidence

    return list(merged.values())

from __future__ import annotations
from typing import List
from injexpose.model import Finding
from injexpose.triage import summarize_counts


def _bullet(lines: List[str]) -> str:
    return "\n".join([f" - {x}" for x in lines]) if lines else " - (none)"


def render_terminal_report(findings: List[Finding], target: str, run_label: str = "N/A") -> str:
    counts = summarize_counts(findings)
    out = []
    out.append("=== InjeXpose Triage Report ===")
    out.append(f"Target: {target}")
    out.append(f"Run:    {run_label}")
    out.append("")
    out.append("Summary:")
    out.append(f" CRITICAL: {counts['CRITICAL']}")
    out.append(f" HIGH:     {counts['HIGH']}")
    out.append(f" MEDIUM:   {counts['MEDIUM']}")
    out.append(f" LOW:      {counts['LOW']}")
    out.append("")

    if not findings:
        out.append("No findings parsed from input.")
        return "\n".join(out)

    for idx, f in enumerate(findings, start=1):
        out.append(f"[{idx}] [{f.severity}] {f.vuln_type}")
        loc = f.url
        if f.parameter:
            loc += f"  (param: {f.parameter}" + (f", {f.method}" if f.method else "") + ")"
        out.append(f"Location: {loc}")
        out.append(f"Technique: {f.technique or 'UNKNOWN'}")

        # REQUIRED SECTIONS
        out.append("Vulnerabilities:")
        out.append(_bullet(f.vulnerabilities))

        out.append("Potential Impact:")
        out.append(_bullet(f.potential_impact))

        out.append(f"Severity rating: {f.severity}")

        # Extras (helpful, but not required)
        out.append(f"Confidence: {f.confidence}")
        if f.evidence:
            out.append("Evidence:")
            for e in f.evidence[:8]:
                out.append(f" - {e}")

        out.append("-" * 36)

    return "\n".join(out)

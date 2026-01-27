from __future__ import annotations
from typing import List
from injexpose.model import Finding


def _norm(s: str) -> str:
    return (s or "").strip().lower()


def assign_severity_and_impact(f: Finding) -> Finding:
    """
    Deterministic rubric based on technique keywords.
    Produces: severity + confidence + potential impact list.
    """
    tech = _norm(f.technique)

    # Baseline impacts for confirmed SQL Injection
    impacts = [
        "Unauthorized data access (read sensitive records)",
        "Data tampering (modify/delete records)",
        "Authentication/session bypass risk (context-dependent)",
        "Service disruption risk (context-dependent)",
    ]

    # Severity mapping (simple and explainable)
    if any(k in tech for k in ["stacked", "error-based", "union"]):
        f.severity = "CRITICAL"
        f.confidence = "HIGH"
    elif any(k in tech for k in ["boolean-based", "time-based", "blind"]):
        f.severity = "HIGH"
        f.confidence = "HIGH"
    elif tech:
        f.severity = "MEDIUM"
        f.confidence = "MEDIUM"
    else:
        f.severity = "MEDIUM"
        f.confidence = "MEDIUM"

    f.potential_impact = impacts
    if not f.vulnerabilities:
        f.vulnerabilities = ["SQL Injection"]
    return f


def summarize_counts(findings: List[Finding]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = (f.severity or "MEDIUM").upper()
        if sev not in counts:
            sev = "MEDIUM"
        counts[sev] += 1
    return counts

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    vuln_type: str
    url: str
    parameter: Optional[str] = None
    method: Optional[str] = None
    technique: Optional[str] = None
    severity: str = "MEDIUM"
    confidence: str = "MEDIUM"
    vulnerabilities: List[str] = field(default_factory=list)
    potential_impact: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

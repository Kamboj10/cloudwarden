"""Data model shared by every check and by the report generator."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import List

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def severity_rank(severity: str) -> int:
    """Lower number means more severe. Unknown values sort last."""
    try:
        return SEVERITIES.index(severity.upper())
    except ValueError:
        return len(SEVERITIES)


@dataclass
class Finding:
    """One security problem found on one resource."""

    check_id: str
    title: str
    severity: str
    provider: str  # "aws" or "azure"
    resource: str
    region: str
    detail: str
    remediation: str
    reference: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    """Everything a scan produced: findings, plus checks that could not run."""

    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def merge(self, other: "ScanResult") -> None:
        self.findings.extend(other.findings)
        self.errors.extend(other.errors)

"""Turn a ScanResult into text, JSON or an HTML report."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from typing import Dict, List, Optional

from .models import SEVERITIES, Finding, ScanResult, severity_rank

SEVERITY_COLORS = {
    "CRITICAL": "#b00020",
    "HIGH": "#d9480f",
    "MEDIUM": "#b7791f",
    "LOW": "#2b6cb0",
}


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (severity_rank(f.severity), f.provider, f.check_id, f.resource),
    )


def summarize(findings: List[Finding]) -> Dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
    return counts


def should_fail(findings: List[Finding], threshold: str) -> bool:
    """True if any finding is at or above the threshold severity."""
    if threshold.lower() == "none":
        return False
    limit = severity_rank(threshold)
    return any(severity_rank(f.severity) <= limit for f in findings)


def _now(generated_at: Optional[datetime]) -> str:
    return (generated_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")


def render_json(result: ScanResult, generated_at: Optional[datetime] = None) -> str:
    findings = sort_findings(result.findings)
    return json.dumps(
        {
            "generated_at": _now(generated_at),
            "summary": summarize(findings),
            "findings": [f.to_dict() for f in findings],
            "errors": result.errors,
        },
        indent=2,
    )


def render_text(result: ScanResult, generated_at: Optional[datetime] = None) -> str:
    findings = sort_findings(result.findings)
    counts = summarize(findings)
    lines = [
        f"CloudWarden scan  {_now(generated_at)}",
        "Summary: " + "  ".join(f"{s}={counts[s]}" for s in SEVERITIES),
        "",
    ]
    if not findings:
        lines.append("No findings. Nice work.")
    for finding in findings:
        lines += [
            f"[{finding.severity}] {finding.check_id}  {finding.title}",
            f"    resource: {finding.resource}  ({finding.provider}, {finding.region})",
            f"    detail:   {finding.detail}",
            f"    fix:      {finding.remediation}",
            "",
        ]
    if result.errors:
        lines.append("Checks that could not run:")
        lines += [f"  - {error}" for error in result.errors]
    return "\n".join(lines).rstrip() + "\n"


def render_html(result: ScanResult, generated_at: Optional[datetime] = None) -> str:
    findings = sort_findings(result.findings)
    counts = summarize(findings)

    cards = "".join(
        f'<div class="card" style="border-top:4px solid {SEVERITY_COLORS[s]}">'
        f'<div class="num">{counts[s]}</div><div class="lbl">{s.title()}</div></div>'
        for s in SEVERITIES
    )

    rows = "".join(
        "<tr>"
        f'<td><span class="sev" style="background:{SEVERITY_COLORS.get(f.severity, "#555")}">'
        f"{escape(f.severity)}</span></td>"
        f"<td>{escape(f.check_id)}</td>"
        f"<td><strong>{escape(f.title)}</strong><br>{escape(f.detail)}</td>"
        f"<td>{escape(f.resource)}<br><small>{escape(f.provider)} / {escape(f.region)}</small></td>"
        f"<td>{escape(f.remediation)}</td>"
        "</tr>"
        for f in findings
    )
    if not rows:
        rows = '<tr><td colspan="5">No findings.</td></tr>'

    errors = ""
    if result.errors:
        items = "".join(f"<li>{escape(e)}</li>" for e in result.errors)
        errors = f"<h2>Checks that could not run</h2><ul>{items}</ul>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>CloudWarden report</title>
<style>
body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:2rem auto;max-width:1100px;color:#1a202c;padding:0 1rem}}
h1{{margin-bottom:0}} .meta{{color:#555;margin-top:.25rem}}
.cards{{display:flex;gap:1rem;margin:1.5rem 0}}
.card{{flex:1;background:#f7fafc;border-radius:6px;padding:.75rem 1rem}}
.num{{font-size:2rem;font-weight:700}} .lbl{{color:#555}}
table{{border-collapse:collapse;width:100%}}
th,td{{text-align:left;vertical-align:top;padding:.6rem;border-bottom:1px solid #e2e8f0;font-size:.92rem}}
th{{background:#edf2f7}}
.sev{{color:#fff;padding:.15rem .5rem;border-radius:4px;font-size:.75rem;font-weight:700}}
</style></head><body>
<h1>CloudWarden report</h1>
<p class="meta">Generated {escape(_now(generated_at))}. Read-only scan.</p>
<div class="cards">{cards}</div>
<table>
<tr><th>Severity</th><th>Check</th><th>Finding</th><th>Resource</th><th>How to fix</th></tr>
{rows}
</table>
{errors}
</body></html>
"""


RENDERERS = {"text": render_text, "json": render_json, "html": render_html}

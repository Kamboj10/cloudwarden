import json

from cloudwarden.models import Finding, ScanResult
from cloudwarden.report import (
    render_html,
    render_json,
    render_text,
    should_fail,
    sort_findings,
    summarize,
)


def finding(sev="HIGH", resource="sg-1", **kw):
    base = dict(
        check_id="AWS-EC2-001",
        title="Open admin port",
        severity=sev,
        provider="aws",
        resource=resource,
        region="us-east-1",
        detail="detail",
        remediation="fix it",
    )
    base.update(kw)
    return Finding(**base)


def sample():
    return ScanResult(
        findings=[finding("LOW", "a"), finding("CRITICAL", "b"), finding("HIGH", "c")],
        errors=["aws check_x: AccessDenied"],
    )


def test_sorted_by_severity():
    assert [f.severity for f in sort_findings(sample().findings)] == [
        "CRITICAL",
        "HIGH",
        "LOW",
    ]


def test_summary_counts():
    assert summarize(sample().findings) == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 1}


def test_should_fail_threshold():
    findings = [finding("MEDIUM")]
    assert should_fail(findings, "medium")
    assert should_fail(findings, "low")
    assert not should_fail(findings, "high")
    assert not should_fail(findings, "none")


def test_json_is_valid_and_complete():
    data = json.loads(render_json(sample()))
    assert data["summary"]["CRITICAL"] == 1
    assert len(data["findings"]) == 3
    assert data["errors"] == ["aws check_x: AccessDenied"]


def test_html_escapes_resource_names():
    result = ScanResult(findings=[finding(resource="<script>alert(1)</script>")])
    html = render_html(result)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_text_report_mentions_errors_and_fix():
    text = render_text(sample())
    assert "fix it" in text and "could not run" in text

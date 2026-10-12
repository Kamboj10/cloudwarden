import pytest

pytest.importorskip("boto3")

from cloudwarden import aws_checks, cli  # noqa: E402
from cloudwarden.models import Finding, ScanResult  # noqa: E402


def finding(sev="HIGH", resource="sg-1"):
    return Finding(
        check_id="AWS-EC2-001",
        title="Open admin port",
        severity=sev,
        provider="aws",
        resource=resource,
        region="us-east-1",
        detail="detail",
        remediation="fix it",
    )


def test_cli_requires_a_provider(capsys):
    assert cli.main([]) == 2


def test_cli_exit_code_follows_fail_on(monkeypatch, capsys):
    monkeypatch.setattr(
        aws_checks, "run_all", lambda session, regions=None: ScanResult([finding("HIGH")])
    )
    assert cli.main(["--aws", "--format", "json", "--fail-on", "high"]) == 1
    assert cli.main(["--aws", "--format", "json", "--fail-on", "critical"]) == 0
    assert cli.main(["--aws", "--format", "json", "--fail-on", "none"]) == 0


def test_cli_writes_output_file(monkeypatch, tmp_path):
    monkeypatch.setattr(
        aws_checks, "run_all", lambda session, regions=None: ScanResult([finding("LOW")])
    )
    out = tmp_path / "report.html"
    code = cli.main(["--aws", "--format", "html", "--output", str(out), "--fail-on", "none"])
    assert code == 0 and "CloudWarden report" in out.read_text()


def test_cli_azure_needs_subscription(monkeypatch):
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    assert cli.main(["--azure"]) == 2

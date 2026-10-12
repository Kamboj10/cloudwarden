from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

pytest.importorskip("boto3")
pytest.importorskip("moto")

from cloudwarden import aws_checks as aws  # noqa: E402

REGION = "us-east-1"


def _make_sg(session, cidr, from_port, to_port, protocol="tcp"):
    ec2 = session.client("ec2", region_name=REGION)
    sg = ec2.create_security_group(GroupName="test-sg", Description="test")
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": protocol,
                "FromPort": from_port,
                "ToPort": to_port,
                "IpRanges": [{"CidrIp": cidr}],
            }
        ],
    )
    return sg["GroupId"]


# ---- security groups ------------------------------------------------------
def test_ssh_open_to_world_is_high(session):
    sg_id = _make_sg(session, "0.0.0.0/0", 22, 22)
    findings = aws.check_security_groups(session, REGION)
    flagged = [f for f in findings if f.resource.startswith(sg_id)]
    assert len(flagged) == 1
    assert flagged[0].severity == "HIGH"
    assert flagged[0].check_id == "AWS-EC2-001"


def test_rdp_inside_open_port_range_is_flagged(session):
    sg_id = _make_sg(session, "0.0.0.0/0", 3000, 4000)
    findings = aws.check_security_groups(session, REGION)
    assert any(f.resource.startswith(sg_id) for f in findings)


def test_ssh_from_private_range_is_not_flagged(session):
    sg_id = _make_sg(session, "10.0.0.0/8", 22, 22)
    findings = aws.check_security_groups(session, REGION)
    assert not any(f.resource.startswith(sg_id) for f in findings)


def test_https_open_to_world_is_not_flagged(session):
    sg_id = _make_sg(session, "0.0.0.0/0", 443, 443)
    findings = aws.check_security_groups(session, REGION)
    assert not any(f.resource.startswith(sg_id) for f in findings)


def test_all_traffic_open_is_critical(session):
    ec2 = session.client("ec2", region_name=REGION)
    sg = ec2.create_security_group(GroupName="wide-open", Description="test")
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    findings = aws.check_security_groups(session, REGION)
    flagged = [f for f in findings if f.resource.startswith(sg["GroupId"])]
    assert flagged and flagged[0].severity == "CRITICAL"


# ---- S3 -------------------------------------------------------------------
def test_bucket_without_public_access_block_is_flagged(session):
    session.client("s3").create_bucket(Bucket="cg-no-block")
    findings = aws.check_s3_public_access(session)
    assert [f.resource for f in findings] == ["cg-no-block"]
    assert findings[0].severity == "HIGH"


def test_bucket_with_full_block_is_clean(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="cg-blocked")
    s3.put_public_access_block(
        Bucket="cg-blocked",
        PublicAccessBlockConfiguration={k: True for k in aws.PUBLIC_ACCESS_KEYS},
    )
    assert aws.check_s3_public_access(session) == []


def test_bucket_with_partial_block_is_flagged(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="cg-partial")
    config = {k: True for k in aws.PUBLIC_ACCESS_KEYS}
    config["BlockPublicPolicy"] = False
    s3.put_public_access_block(Bucket="cg-partial", PublicAccessBlockConfiguration=config)
    findings = aws.check_s3_public_access(session)
    assert len(findings) == 1
    assert "BlockPublicPolicy" in findings[0].detail


# ---- IAM ------------------------------------------------------------------
def test_console_user_without_mfa_is_flagged(session):
    iam = session.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Str0ng!Passw0rd#1")
    findings = aws.check_iam_mfa(session)
    assert [f.resource for f in findings] == ["alice"]


def test_user_without_console_access_is_not_flagged(session):
    session.client("iam").create_user(UserName="svc-bot")
    assert aws.check_iam_mfa(session) == []


def test_console_user_with_mfa_is_clean(session):
    iam = session.client("iam")
    iam.create_user(UserName="carol")
    iam.create_login_profile(UserName="carol", Password="Str0ng!Passw0rd#1")
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName="carol-mfa")
    iam.enable_mfa_device(
        UserName="carol",
        SerialNumber=device["VirtualMFADevice"]["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )
    assert aws.check_iam_mfa(session) == []


def test_old_access_key_is_flagged(session):
    iam = session.client("iam")
    iam.create_user(UserName="dave")
    key = iam.create_access_key(UserName="dave")["AccessKey"]
    future = datetime.now(timezone.utc) + timedelta(days=200)
    findings = aws.check_iam_access_keys(session, now=future)
    assert len(findings) == 1
    assert key["AccessKeyId"] in findings[0].resource


def test_new_access_key_is_clean(session):
    iam = session.client("iam")
    iam.create_user(UserName="erin")
    iam.create_access_key(UserName="erin")
    assert aws.check_iam_access_keys(session) == []


def test_root_access_keys_flagged_as_critical():
    fake_iam = SimpleNamespace(
        get_account_summary=lambda: {"SummaryMap": {"AccountAccessKeysPresent": 1}}
    )
    fake_session = SimpleNamespace(client=lambda name, **kw: fake_iam)
    findings = aws.check_root_access_keys(fake_session)
    assert len(findings) == 1 and findings[0].severity == "CRITICAL"


def test_no_root_keys_is_clean(session):
    assert aws.check_root_access_keys(session) == []


# ---- EBS ------------------------------------------------------------------
def test_unencrypted_volume_is_flagged(session):
    ec2 = session.client("ec2", region_name=REGION)
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=1, Encrypted=False)
    findings = aws.check_ebs_encryption(session, REGION)
    assert [f.resource for f in findings] == [vol["VolumeId"]]


def test_encrypted_volume_is_clean(session):
    ec2 = session.client("ec2", region_name=REGION)
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=1, Encrypted=True)
    assert aws.check_ebs_encryption(session, REGION) == []


# ---- VPC flow logs --------------------------------------------------------
def test_vpc_without_flow_logs_is_flagged_then_fixed(session):
    ec2 = session.client("ec2", region_name=REGION)
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    assert any(f.resource == vpc_id for f in aws.check_vpc_flow_logs(session, REGION))

    session.client("s3").create_bucket(Bucket="cg-flow-logs")
    ec2.create_flow_logs(
        ResourceIds=[vpc_id],
        ResourceType="VPC",
        TrafficType="ALL",
        LogDestinationType="s3",
        LogDestination="arn:aws:s3:::cg-flow-logs",
    )
    assert not any(f.resource == vpc_id for f in aws.check_vpc_flow_logs(session, REGION))


# ---- runner ---------------------------------------------------------------
def test_run_all_collects_findings_and_survives_errors(session, monkeypatch):
    _make_sg(session, "0.0.0.0/0", 22, 22)

    def boom(_session):
        raise RuntimeError("AccessDenied")

    monkeypatch.setattr(aws, "GLOBAL_CHECKS", [boom])
    result = aws.run_all(session, [REGION])
    assert result.findings, "regional checks should still run"
    assert any("AccessDenied" in e for e in result.errors)

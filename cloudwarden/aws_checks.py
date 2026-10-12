"""AWS checks.

Every check takes a boto3 ``Session`` (and sometimes a region) and returns a
list of ``Finding`` objects. All calls are read-only (List, Get, Describe).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Iterable, List, Optional

from botocore.exceptions import ClientError

from .models import Finding, ScanResult

ADMIN_PORTS = (22, 3389)
PUBLIC_ACCESS_KEYS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


def _paginate(client, method: str, key: str, **kwargs) -> Iterable[dict]:
    """Yield every item of ``key`` across all pages of a paginated API call."""
    for page in client.get_paginator(method).paginate(**kwargs):
        yield from page.get(key, [])


# --------------------------------------------------------------------------
# EC2: security groups open to the internet
# --------------------------------------------------------------------------
def _open_to_world(rule: dict) -> bool:
    v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
    v6 = any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []))
    return v4 or v6


def _exposes_admin_port(rule: dict) -> bool:
    protocol = str(rule.get("IpProtocol"))
    if protocol == "-1":  # all protocols, all ports
        return True
    if protocol not in ("tcp", "6"):
        return False
    low, high = rule.get("FromPort"), rule.get("ToPort")
    if low is None or high is None:
        return True
    return any(low <= port <= high for port in ADMIN_PORTS)


def _port_text(rule: dict) -> str:
    low, high = rule.get("FromPort"), rule.get("ToPort")
    if low is None or high is None:
        return "Inbound rule allows all ports"
    if low == high:
        return f"Inbound rule allows port {low}"
    return f"Inbound rule allows ports {low}-{high}"


def check_security_groups(session, region: str) -> List[Finding]:
    ec2 = session.client("ec2", region_name=region)
    findings: List[Finding] = []
    for sg in _paginate(ec2, "describe_security_groups", "SecurityGroups"):
        for rule in sg.get("IpPermissions", []):
            if not (_open_to_world(rule) and _exposes_admin_port(rule)):
                continue
            all_traffic = str(rule.get("IpProtocol")) == "-1"
            findings.append(
                Finding(
                    check_id="AWS-EC2-001",
                    title="Security group allows admin access from the internet",
                    severity="CRITICAL" if all_traffic else "HIGH",
                    provider="aws",
                    resource=f"{sg['GroupId']} ({sg.get('GroupName', '')})",
                    region=region,
                    detail=(
                        "Inbound rule allows all traffic from 0.0.0.0/0"
                        if all_traffic
                        else _port_text(rule) + " from the internet"
                    ),
                    remediation=(
                        "Restrict the source to your own IP or a VPN range, or "
                        "use AWS Systems Manager Session Manager instead of "
                        "opening SSH/RDP."
                    ),
                    reference="CIS AWS Foundations: Networking, restrict admin ports",
                )
            )
    return findings


# --------------------------------------------------------------------------
# S3: public access block
# --------------------------------------------------------------------------
def check_s3_public_access(session) -> List[Finding]:
    s3 = session.client("s3")
    findings: List[Finding] = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            config = s3.get_public_access_block(Bucket=name)[
                "PublicAccessBlockConfiguration"
            ]
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                config = {}
            else:
                raise
        missing = [key for key in PUBLIC_ACCESS_KEYS if not config.get(key)]
        if missing:
            findings.append(
                Finding(
                    check_id="AWS-S3-001",
                    title="S3 bucket does not fully block public access",
                    severity="HIGH",
                    provider="aws",
                    resource=name,
                    region="global",
                    detail="Public access block settings not enabled: "
                    + ", ".join(missing),
                    remediation=(
                        "Enable all four Block Public Access settings on the "
                        "bucket (or on the whole account) unless the bucket is "
                        "intentionally a public website."
                    ),
                    reference="CIS AWS Foundations: Storage, S3 public access",
                )
            )
    return findings


# --------------------------------------------------------------------------
# IAM: MFA, old access keys, root keys
# --------------------------------------------------------------------------
def check_iam_mfa(session) -> List[Finding]:
    iam = session.client("iam")
    findings: List[Finding] = []
    for user in _paginate(iam, "list_users", "Users"):
        name = user["UserName"]
        try:
            iam.get_login_profile(UserName=name)  # has console access
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                continue  # no console password, so MFA for console not needed
            raise
        if not iam.list_mfa_devices(UserName=name).get("MFADevices"):
            findings.append(
                Finding(
                    check_id="AWS-IAM-001",
                    title="IAM user with console access has no MFA",
                    severity="HIGH",
                    provider="aws",
                    resource=name,
                    region="global",
                    detail="User can sign in to the console with a password only.",
                    remediation="Enable an MFA device for this user, or remove "
                    "console access if it is not needed.",
                    reference="CIS AWS Foundations: IAM, MFA for console users",
                )
            )
    return findings


def check_iam_access_keys(
    session, max_age_days: int = 90, now: Optional[datetime] = None
) -> List[Finding]:
    iam = session.client("iam")
    now = now or datetime.now(timezone.utc)
    findings: List[Finding] = []
    for user in _paginate(iam, "list_users", "Users"):
        name = user["UserName"]
        for key in iam.list_access_keys(UserName=name).get("AccessKeyMetadata", []):
            if key.get("Status") != "Active":
                continue
            age = (now - key["CreateDate"]).days
            if age > max_age_days:
                findings.append(
                    Finding(
                        check_id="AWS-IAM-002",
                        title=f"Access key older than {max_age_days} days",
                        severity="MEDIUM",
                        provider="aws",
                        resource=f"{name} / {key['AccessKeyId']}",
                        region="global",
                        detail=f"Active key is {age} days old.",
                        remediation="Create a new key, update the application, "
                        "then deactivate and delete the old key. Prefer IAM "
                        "roles over long-lived keys.",
                        reference="CIS AWS Foundations: IAM, rotate access keys",
                    )
                )
    return findings


def check_root_access_keys(session) -> List[Finding]:
    iam = session.client("iam")
    summary = iam.get_account_summary().get("SummaryMap", {})
    if summary.get("AccountAccessKeysPresent", 0) > 0:
        return [
            Finding(
                check_id="AWS-IAM-003",
                title="Root account has access keys",
                severity="CRITICAL",
                provider="aws",
                resource="root account",
                region="global",
                detail="The root user has at least one access key.",
                remediation="Delete the root access keys and use IAM roles or "
                "users with least privilege instead.",
                reference="CIS AWS Foundations: IAM, no root access keys",
            )
        ]
    return []


# --------------------------------------------------------------------------
# EC2/VPC: unencrypted volumes, missing flow logs
# --------------------------------------------------------------------------
def check_ebs_encryption(session, region: str) -> List[Finding]:
    ec2 = session.client("ec2", region_name=region)
    findings: List[Finding] = []
    for volume in _paginate(ec2, "describe_volumes", "Volumes"):
        if not volume.get("Encrypted"):
            findings.append(
                Finding(
                    check_id="AWS-EC2-002",
                    title="EBS volume is not encrypted",
                    severity="MEDIUM",
                    provider="aws",
                    resource=volume["VolumeId"],
                    region=region,
                    detail=f"{volume.get('Size', '?')} GiB volume without encryption.",
                    remediation="Enable EBS encryption by default for the region, "
                    "and migrate this volume via an encrypted snapshot copy.",
                    reference="CIS AWS Foundations: Storage, EBS encryption",
                )
            )
    return findings


def check_vpc_flow_logs(session, region: str) -> List[Finding]:
    ec2 = session.client("ec2", region_name=region)
    covered = {
        flow["ResourceId"] for flow in _paginate(ec2, "describe_flow_logs", "FlowLogs")
    }
    findings: List[Finding] = []
    for vpc in _paginate(ec2, "describe_vpcs", "Vpcs"):
        if vpc["VpcId"] not in covered:
            findings.append(
                Finding(
                    check_id="AWS-VPC-001",
                    title="VPC has no flow logs",
                    severity="MEDIUM",
                    provider="aws",
                    resource=vpc["VpcId"],
                    region=region,
                    detail="No VPC-level flow log is configured, so network "
                    "traffic cannot be investigated after an incident.",
                    remediation="Create a flow log for the VPC that delivers to "
                    "CloudWatch Logs or S3.",
                    reference="CIS AWS Foundations: Logging, VPC flow logs",
                )
            )
    return findings


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------
GLOBAL_CHECKS: List[Callable] = [
    check_s3_public_access,
    check_iam_mfa,
    check_iam_access_keys,
    check_root_access_keys,
]
REGIONAL_CHECKS: List[Callable] = [
    check_security_groups,
    check_ebs_encryption,
    check_vpc_flow_logs,
]


def run_all(session, regions: Optional[List[str]] = None) -> ScanResult:
    """Run every AWS check. A failing check is recorded, not fatal."""
    regions = regions or [session.region_name or "us-east-1"]
    result = ScanResult()
    for check in GLOBAL_CHECKS:
        try:
            result.findings.extend(check(session))
        except Exception as err:  # keep scanning even if one check is denied
            result.errors.append(f"aws {check.__name__}: {err}")
    for region in regions:
        for check in REGIONAL_CHECKS:
            try:
                result.findings.extend(check(session, region))
            except Exception as err:
                result.errors.append(f"aws {check.__name__} ({region}): {err}")
    return result

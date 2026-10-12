"""Azure checks.

Checks receive an already-built Azure management client, so they can be tested
with simple fake objects. The Azure SDK is only imported inside ``run_all``.
"""

from __future__ import annotations

from typing import List, Optional

from .models import Finding, ScanResult

ADMIN_PORTS = (22, 3389)
INTERNET_SOURCES = {"*", "0.0.0.0/0", "0.0.0.0", "internet", "any"}


def _val(value) -> str:
    """Normalise an Azure enum or plain string to lowercase text."""
    return str(getattr(value, "value", value) or "").lower()


def _port_in_spec(spec: str, port: int) -> bool:
    spec = str(spec).strip()
    if spec == "*":
        return True
    if "-" in spec:
        low, _, high = spec.partition("-")
        return low.isdigit() and high.isdigit() and int(low) <= port <= int(high)
    return spec.isdigit() and int(spec) == port


def _sources(rule) -> List[str]:
    sources = list(getattr(rule, "source_address_prefixes", None) or [])
    if getattr(rule, "source_address_prefix", None):
        sources.append(rule.source_address_prefix)
    return sources


def _dest_ports(rule) -> List[str]:
    ports = list(getattr(rule, "destination_port_ranges", None) or [])
    if getattr(rule, "destination_port_range", None):
        ports.append(rule.destination_port_range)
    return ports


def check_nsg_admin_ports(network_client) -> List[Finding]:
    findings: List[Finding] = []
    for nsg in network_client.network_security_groups.list_all():
        for rule in nsg.security_rules or []:
            if _val(rule.direction) != "inbound" or _val(rule.access) != "allow":
                continue
            if _val(rule.protocol) not in ("tcp", "*"):
                continue
            if not any(src.lower() in INTERNET_SOURCES for src in _sources(rule)):
                continue
            exposed = [
                port
                for port in ADMIN_PORTS
                if any(_port_in_spec(spec, port) for spec in _dest_ports(rule))
            ]
            if exposed:
                findings.append(
                    Finding(
                        check_id="AZ-NSG-001",
                        title="NSG rule allows admin access from the internet",
                        severity="HIGH",
                        provider="azure",
                        resource=f"{nsg.name}/{rule.name}",
                        region=getattr(nsg, "location", "") or "",
                        detail="Inbound allow rule from the internet reaches "
                        "port(s) " + ", ".join(str(p) for p in exposed),
                        remediation="Limit the source to your IP or VPN range, "
                        "or use Azure Bastion instead of exposing SSH/RDP.",
                        reference="CIS Azure Foundations: Networking, restrict RDP/SSH",
                    )
                )
    return findings


def check_storage_accounts(storage_client) -> List[Finding]:
    findings: List[Finding] = []
    for account in storage_client.storage_accounts.list():
        name = account.name
        region = getattr(account, "location", "") or ""

        public_blob = getattr(account, "allow_blob_public_access", None)
        if public_blob is not False:
            findings.append(
                Finding(
                    check_id="AZ-STOR-001",
                    title="Storage account may allow public blob access",
                    severity="HIGH" if public_blob else "MEDIUM",
                    provider="azure",
                    resource=name,
                    region=region,
                    detail="Public blob access is enabled."
                    if public_blob
                    else "Public blob access is not explicitly disabled.",
                    remediation="Set 'Allow Blob anonymous access' to Disabled "
                    "on the storage account.",
                    reference="CIS Azure Foundations: Storage, public access",
                )
            )

        if getattr(account, "enable_https_traffic_only", True) is False:
            findings.append(
                Finding(
                    check_id="AZ-STOR-002",
                    title="Storage account does not require HTTPS",
                    severity="MEDIUM",
                    provider="azure",
                    resource=name,
                    region=region,
                    detail="'Secure transfer required' is turned off.",
                    remediation="Enable 'Secure transfer required'.",
                    reference="CIS Azure Foundations: Storage, secure transfer",
                )
            )

        tls = _val(getattr(account, "minimum_tls_version", None))
        if tls not in ("tls1_2", "tls1_3"):
            findings.append(
                Finding(
                    check_id="AZ-STOR-003",
                    title="Storage account allows old TLS versions",
                    severity="MEDIUM",
                    provider="azure",
                    resource=name,
                    region=region,
                    detail=f"Minimum TLS version is '{tls or 'not set'}'.",
                    remediation="Set the minimum TLS version to 1.2.",
                    reference="CIS Azure Foundations: Storage, minimum TLS",
                )
            )
    return findings


def run_all(subscription_id: str, credential=None) -> ScanResult:
    """Run every Azure check. Missing SDK or denied calls are recorded, not fatal."""
    result = ScanResult()
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.storage import StorageManagementClient
    except ImportError:
        result.errors.append(
            "azure: SDK not installed. Run: pip install 'cloudwarden[azure]'"
        )
        return result

    credential = credential or DefaultAzureCredential()
    clients = (
        (check_nsg_admin_ports, NetworkManagementClient(credential, subscription_id)),
        (check_storage_accounts, StorageManagementClient(credential, subscription_id)),
    )
    for check, client in clients:
        try:
            result.findings.extend(check(client))
        except Exception as err:
            result.errors.append(f"azure {check.__name__}: {err}")
    return result

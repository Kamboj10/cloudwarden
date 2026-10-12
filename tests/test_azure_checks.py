from types import SimpleNamespace as NS

from cloudwarden import azure_checks as az


def rule(**kw):
    base = dict(
        name="r1",
        direction="Inbound",
        access="Allow",
        protocol="Tcp",
        source_address_prefix="*",
        source_address_prefixes=[],
        destination_port_range="22",
        destination_port_ranges=[],
    )
    base.update(kw)
    return NS(**base)


def network_client(*nsgs):
    return NS(network_security_groups=NS(list_all=lambda: list(nsgs)))


def nsg(*rules):
    return NS(name="nsg1", location="centralindia", security_rules=list(rules))


def test_ssh_open_to_internet_is_flagged():
    findings = az.check_nsg_admin_ports(network_client(nsg(rule())))
    assert len(findings) == 1
    assert findings[0].check_id == "AZ-NSG-001"
    assert findings[0].resource == "nsg1/r1"


def test_wildcard_port_range_is_flagged():
    r = rule(destination_port_range="*")
    assert az.check_nsg_admin_ports(network_client(nsg(r)))


def test_port_range_containing_rdp_is_flagged():
    r = rule(destination_port_range="3000-4000")
    assert az.check_nsg_admin_ports(network_client(nsg(r)))


def test_deny_rule_is_not_flagged():
    r = rule(access="Deny")
    assert az.check_nsg_admin_ports(network_client(nsg(r))) == []


def test_private_source_is_not_flagged():
    r = rule(source_address_prefix="10.0.0.0/8")
    assert az.check_nsg_admin_ports(network_client(nsg(r))) == []


def test_https_only_is_not_flagged():
    r = rule(destination_port_range="443")
    assert az.check_nsg_admin_ports(network_client(nsg(r))) == []


def test_enum_like_values_are_handled():
    inbound = NS(value="Inbound")
    allow = NS(value="Allow")
    r = rule(direction=inbound, access=allow)
    assert az.check_nsg_admin_ports(network_client(nsg(r)))


def storage_client(*accounts):
    return NS(storage_accounts=NS(list=lambda: list(accounts)))


def account(**kw):
    base = dict(
        name="stor1",
        location="centralindia",
        allow_blob_public_access=False,
        enable_https_traffic_only=True,
        minimum_tls_version="TLS1_2",
    )
    base.update(kw)
    return NS(**base)


def test_secure_storage_account_is_clean():
    assert az.check_storage_accounts(storage_client(account())) == []


def test_public_blob_access_is_high():
    findings = az.check_storage_accounts(
        storage_client(account(allow_blob_public_access=True))
    )
    assert [f.check_id for f in findings] == ["AZ-STOR-001"]
    assert findings[0].severity == "HIGH"


def test_unset_public_blob_access_is_medium():
    findings = az.check_storage_accounts(
        storage_client(account(allow_blob_public_access=None))
    )
    assert findings[0].severity == "MEDIUM"


def test_http_allowed_and_old_tls_are_flagged():
    findings = az.check_storage_accounts(
        storage_client(account(enable_https_traffic_only=False, minimum_tls_version="TLS1_0"))
    )
    assert sorted(f.check_id for f in findings) == ["AZ-STOR-002", "AZ-STOR-003"]

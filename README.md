![Python](https://img.shields.io/badge/Python-3.14.7-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)
![Tests](https://img.shields.io/badge/tests-passing-green.svg)

# CloudWarden

A read-only security watchdog for small AWS and Azure accounts. It scans for the mistakes that most often get small teams breached, and tells you how to fix each one in plain language.

> **Authorised use only.** Run CloudWarden only on accounts you own or have written permission to scan. It uses read-only permissions and never changes anything.

## Why this exists

Startups, student clubs and freelancers often run cloud accounts with nobody checking security. Typical results: a storage bucket open to the internet, SSH open to the whole world, users with no MFA, access keys nobody ever rotated. Big scanners exist, but their first report can be hundreds of lines long. CloudWarden starts with a short list of high-impact checks, an explanation for every finding, and an exit code you can use to fail a pipeline.

## What it checks (v0.1)

| ID | Provider | Severity | Check |
|----|----------|----------|-------|
| AWS-EC2-001 | AWS | High / Critical | Security group allows SSH, RDP or all traffic from the internet |
| AWS-EC2-002 | AWS | Medium | EBS volume is not encrypted |
| AWS-VPC-001 | AWS | Medium | VPC has no flow logs |
| AWS-S3-001 | AWS | High | S3 bucket does not fully block public access |
| AWS-IAM-001 | AWS | High | Console user has no MFA |
| AWS-IAM-002 | AWS | Medium | Active access key older than 90 days |
| AWS-IAM-003 | AWS | Critical | Root account has access keys |
| AZ-NSG-001 | Azure | High | NSG rule allows SSH or RDP from the internet |
| AZ-STOR-001 | Azure | High / Medium | Storage account allows (or does not forbid) public blob access |
| AZ-STOR-002 | Azure | Medium | Storage account does not require HTTPS |
| AZ-STOR-003 | Azure | Medium | Storage account allows TLS older than 1.2 |

Each finding carries a reference to the matching area of the CIS Foundations Benchmarks. Control numbers differ between benchmark versions, so check the exact ID against the version you follow.

## Quick start

```bash
git clone https://github.com/Kamboj10/cloudwarden.git
cd cloudwarden
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[azure]"        # drop [azure] if you only scan AWS

# AWS (uses your normal AWS credentials or --profile)
cloudwarden --aws --region ap-south-1 --format html --output report.html

# Azure
export AZURE_SUBSCRIPTION_ID=<id>
cloudwarden --azure --format text

# Both, failing with exit code 1 on any high or critical finding
cloudwarden --aws --azure --region ap-south-1 --fail-on high
```

Set up the read-only access first: [docs/SETUP.md](docs/SETUP.md). New here? Follow [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) from unzip to finished project.

## Using it in a pipeline

`--fail-on` controls the exit code: `0` means nothing at or above the level, `1` means findings reached it, `2` means bad usage. `.github/workflows/scheduled-scan.yml` shows a weekly scan that signs in to AWS with OIDC, so no access key is ever stored in GitHub.

## How it works

```
 cli.py ──► aws_checks.run_all(session, regions) ─┐
        └─► azure_checks.run_all(subscription)  ──┼─► ScanResult(findings, errors)
                                                  │            │
                                                  │            ▼
                                                  │      report.py → text | json | html
                                                  └─ a denied or failing check is recorded
                                                     in `errors`, the scan keeps going
```

Design decisions worth knowing:

- **Read-only by construction.** Every call is a List, Get or Describe. The recommended IAM role is the AWS-managed `SecurityAudit` policy; for Azure it is the `Reader` role.
- **Checks are small functions that return findings.** AWS checks take a boto3 session. Azure checks take an already-built client, so tests pass in simple fake objects.
- **One failing check never stops the scan.** A missing permission is listed under "checks that could not run" instead of crashing.
- **HTML output is escaped**, so a resource name containing markup cannot inject script into the report.

## Tests

```bash
pip install -e ".[azure,dev]"
pytest
```

AWS tests run against [moto](https://github.com/getmoto/moto), an in-memory fake of AWS, so they never touch a real account. Each check has a passing and a failing case.

## Try it safely

`lab/main.tf` creates a few deliberately weak resources in a **sandbox** AWS account (an open security group, an unencrypted volume, a bucket with no public access block). Run CloudWarden, save the report as your **before** evidence, fix the issues, run again for the **after** evidence, then `terraform destroy`.

## Comparison with other tools

Prowler, ScoutSuite and cloud-audit are broader and more mature. Prowler covers hundreds of checks and many compliance frameworks; use it when you need full coverage. CloudWarden is deliberately small: a short, explained list for people who have never run a cloud security scan, with CI-friendly exit codes and both AWS and Azure in one command.

## Limitations

- 11 checks. This is a starting point, not a full benchmark.
- No attack-path analysis, drift tracking or automatic fixing.
- Only the regions you pass with `--region` are scanned for regional checks.
- Azure checks cover network security groups and storage accounts only.

## Roadmap

- [ ] Compliance module: map checks to specific legal or framework requirements (for example India's CERT-In log-retention rules) with evidence in the report
- [ ] Diff mode: show only new findings since the last scan
- [ ] More checks: RDS public access, CloudTrail enabled, Azure VM disk encryption
- [ ] Slack and Telegram alerts

## License

MIT

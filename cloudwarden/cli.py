"""Command line interface.

Exit codes: 0 = scan finished and nothing at/above --fail-on,
            1 = findings at or above --fail-on, 2 = bad usage.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__, aws_checks, azure_checks
from .models import ScanResult
from .report import RENDERERS, should_fail


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudwarden",
        description="Read-only security checks for AWS and Azure accounts.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--aws", action="store_true", help="scan AWS")
    parser.add_argument("--profile", help="AWS profile name (default: environment)")
    parser.add_argument(
        "--region",
        action="append",
        help="AWS region to scan; repeat for several (default: session region)",
    )
    parser.add_argument("--azure", action="store_true", help="scan Azure")
    parser.add_argument(
        "--subscription-id",
        help="Azure subscription ID (or set AZURE_SUBSCRIPTION_ID)",
    )
    parser.add_argument(
        "--format", choices=sorted(RENDERERS), default="text", help="report format"
    )
    parser.add_argument("--output", help="write the report to this file")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
        help="exit with code 1 if a finding is at or above this severity",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not (args.aws or args.azure):
        print("error: choose at least one provider: --aws and/or --azure", file=sys.stderr)
        return 2

    result = ScanResult()

    if args.aws:
        import boto3

        session = (
            boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
        )
        result.merge(aws_checks.run_all(session, args.region))

    if args.azure:
        subscription = args.subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID")
        if not subscription:
            print(
                "error: Azure needs --subscription-id or AZURE_SUBSCRIPTION_ID",
                file=sys.stderr,
            )
            return 2
        result.merge(azure_checks.run_all(subscription))

    report = RENDERERS[args.format](result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(report)
        print(
            f"Report written to {args.output} "
            f"({len(result.findings)} findings, {len(result.errors)} checks could not run)",
            file=sys.stderr,
        )
    else:
        print(report)

    return 1 if should_fail(result.findings, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())

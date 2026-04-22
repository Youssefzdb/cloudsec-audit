#!/usr/bin/env python3
"""
cloudsec-audit - Cloud Infrastructure Security Auditing Framework
Audits AWS, GCP, Azure configurations for misconfigurations and risks
"""
import argparse
from modules.aws_auditor import AWSAuditor
from modules.config_checker import ConfigChecker
from modules.iam_analyzer import IAMAnalyzer
from modules.report import CloudReport

def main():
    parser = argparse.ArgumentParser(description="CloudSec Audit Framework")
    parser.add_argument("--provider", choices=["aws", "gcp", "azure", "config"], default="config")
    parser.add_argument("--config", help="Path to cloud config JSON/YAML file")
    parser.add_argument("--profile", default="default", help="AWS profile name")
    parser.add_argument("--output", default="cloudsec_report.html")
    args = parser.parse_args()

    print(f"[*] CloudSec Audit starting | Provider: {args.provider}")
    results = {}

    if args.provider == "aws":
        auditor = AWSAuditor(args.profile)
        results["aws"] = auditor.audit()
    elif args.config:
        checker = ConfigChecker(args.config)
        results["config"] = checker.check()

    iam = IAMAnalyzer(args.config or "")
    results["iam"] = iam.analyze()

    report = CloudReport(args.provider, results)
    report.save(args.output)
    print(f"[+] Audit complete. Report: {args.output}")

if __name__ == "__main__":
    main()

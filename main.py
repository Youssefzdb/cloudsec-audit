#!/usr/bin/env python3
"""
cloudsec-audit - Cloud Infrastructure Security Auditing Framework
Audits AWS/GCP/Azure configurations for misconfigurations and vulnerabilities
"""
import argparse
from modules.aws_auditor import AWSAuditor
from modules.s3_checker import S3Checker
from modules.iam_analyzer import IAMAnalyzer
from modules.report import CloudReport

def main():
    parser = argparse.ArgumentParser(description="CloudSec Audit Framework")
    parser.add_argument("--provider", choices=["aws", "gcp", "azure", "all"], default="aws")
    parser.add_argument("--profile", default="default", help="AWS profile name")
    parser.add_argument("--output", default="cloudsec_report.html")
    args = parser.parse_args()

    print(f"[*] CloudSec Auditor starting - Provider: {args.provider}")
    results = {}

    if args.provider in ["aws", "all"]:
        auditor = AWSAuditor(args.profile)
        results["aws"] = auditor.audit()

        s3 = S3Checker(args.profile)
        results["s3"] = s3.check()

        iam = IAMAnalyzer(args.profile)
        results["iam"] = iam.analyze()

    report = CloudReport(results)
    report.save(args.output)
    print(f"[+] Audit complete. Report: {args.output}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
cloudsec-audit - Cloud Infrastructure Security Auditing Framework
Audits AWS/GCP/Azure misconfigurations and exposed resources
"""
import argparse
from modules.aws_auditor import AWSAuditor
from modules.s3_checker import S3Checker
from modules.iam_analyzer import IAMAnalyzer
from modules.report import CloudReport

def main():
    parser = argparse.ArgumentParser(description="CloudSec Audit Tool")
    parser.add_argument("--provider", choices=["aws", "gcp", "azure"], default="aws")
    parser.add_argument("--s3-bucket", help="Check specific S3 bucket")
    parser.add_argument("--check-public", action="store_true", help="Check for public resources")
    parser.add_argument("--output", default="cloudsec_report.html")
    args = parser.parse_args()

    results = {}
    print(f"[*] Starting cloud security audit ({args.provider.upper()})")

    if args.provider == "aws":
        auditor = AWSAuditor()
        results["aws"] = auditor.audit()

    if args.s3_bucket:
        s3 = S3Checker(args.s3_bucket)
        results["s3"] = s3.check()

    if args.check_public:
        iam = IAMAnalyzer()
        results["iam"] = iam.analyze()

    report = CloudReport(results)
    report.save(args.output)
    print(f"[+] Audit complete. Report: {args.output}")

if __name__ == "__main__":
    main()

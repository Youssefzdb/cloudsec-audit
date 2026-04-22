#!/usr/bin/env python3
"""cloudsec-audit - Cloud Infrastructure Security Auditing Framework"""
import argparse
from modules.aws_audit import AWSAuditor
from modules.s3_checker import S3Checker
from modules.iam_audit import IAMAuditor
from modules.report import Report

def main():
    parser = argparse.ArgumentParser(description="cloudsec-audit")
    parser.add_argument("--provider", choices=["aws", "all"], default="aws")
    parser.add_argument("--output", default="cloud_report.html")
    parser.add_argument("--profile", default="default", help="AWS profile name")
    args = parser.parse_args()

    print(f"[*] Cloud Security Audit - Provider: {args.provider}")
    results = {}

    if args.provider in ["aws", "all"]:
        results["s3"]  = S3Checker(args.profile).check()
        results["iam"] = IAMAuditor(args.profile).audit()
        results["aws"] = AWSAuditor(args.profile).audit()

    Report(results).save(args.output)
    print(f"[+] Report: {args.output}")

if __name__ == "__main__":
    main()

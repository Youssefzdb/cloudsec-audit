#!/usr/bin/env python3
"""cloudsec-audit - Cloud Infrastructure Security Auditing Framework"""
import argparse
from modules.aws_auditor import AWSAuditor
from modules.config_checker import ConfigChecker
from modules.iam_analyzer import IAMAnalyzer
from modules.reporter import CloudSecReporter

def main():
    parser = argparse.ArgumentParser(description="cloudsec-audit - Cloud Security Audit")
    parser.add_argument("--provider", choices=["aws", "config"], default="config")
    parser.add_argument("--config", help="Path to cloud config JSON")
    parser.add_argument("--output", default="cloudsec_report.json")
    args = parser.parse_args()

    print(f"[*] cloudsec-audit | provider: {args.provider}")
    results = {}

    if args.provider == "aws":
        auditor = AWSAuditor()
        results["aws"] = auditor.audit()
    
    if args.config:
        checker = ConfigChecker(args.config)
        results["config"] = checker.check()
        iam = IAMAnalyzer(args.config)
        results["iam"] = iam.analyze()

    reporter = CloudSecReporter(results)
    reporter.save(args.output)
    print(f"[+] Audit complete. Report: {args.output}")

if __name__ == "__main__":
    main()

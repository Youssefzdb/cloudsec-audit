#!/usr/bin/env python3
"""cloudsec-audit - Cloud Security Posture Auditor (AWS/GCP/Azure)"""
import argparse
from modules.aws_auditor import AWSAuditor
from modules.azure_auditor import AzureAuditor
from modules.report import CloudReport

def main():
    parser = argparse.ArgumentParser(description="Cloud Security Posture Auditor")
    parser.add_argument("--provider", choices=["aws", "azure", "gcp"], required=True)
    parser.add_argument("--profile", default="default", help="AWS profile name")
    parser.add_argument("--output", default="cloud_audit.html")
    args = parser.parse_args()

    print(f"[*] Auditing {args.provider.upper()} cloud environment...")
    findings = []

    if args.provider == "aws":
        auditor = AWSAuditor(args.profile)
        findings = auditor.audit()
    elif args.provider == "azure":
        auditor = AzureAuditor()
        findings = auditor.audit()
    else:
        print("[-] GCP support coming soon")

    report = CloudReport(args.provider, findings)
    report.save(args.output)
    print(f"[+] {len(findings)} findings. Report: {args.output}")

if __name__ == "__main__":
    main()

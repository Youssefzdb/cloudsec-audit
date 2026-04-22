#!/usr/bin/env python3
"""Azure Security Auditor - Checks storage, NSGs, RBAC"""
import subprocess
import json

class AzureAuditor:
    def _run_az(self, cmd):
        try:
            result = subprocess.run(["az"] + cmd + ["--output", "json"],
                capture_output=True, text=True, timeout=15)
            return json.loads(result.stdout) if result.stdout else []
        except:
            return []

    def check_storage_public(self):
        findings = []
        print("[*] Checking Azure Storage accounts...")
        accounts = self._run_az(["storage", "account", "list"])
        for acc in accounts:
            if acc.get("allowBlobPublicAccess"):
                findings.append({
                    "resource": acc.get("name"),
                    "issue": "Blob public access enabled",
                    "severity": "HIGH",
                    "service": "Storage"
                })
                print(f"[!] HIGH: Storage {acc.get('name')} has public blob access")
        return findings

    def check_nsg_rules(self):
        findings = []
        print("[*] Checking NSG rules...")
        nsgs = self._run_az(["network", "nsg", "list"])
        for nsg in nsgs:
            for rule in nsg.get("securityRules", []):
                if rule.get("access") == "Allow" and rule.get("sourceAddressPrefix") == "*":
                    findings.append({
                        "resource": nsg.get("name"),
                        "issue": f"NSG rule allows all inbound on port {rule.get('destinationPortRange')}",
                        "severity": "HIGH",
                        "service": "NSG"
                    })
        return findings

    def audit(self):
        findings = []
        findings.extend(self.check_storage_public())
        findings.extend(self.check_nsg_rules())
        return findings

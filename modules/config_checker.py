import json
import yaml
import os

RISKY_PATTERNS = {
    "password_in_config": ["password", "passwd", "secret", "api_key", "token"],
    "debug_mode": ["debug: true", "debug=true", "DEBUG=1"],
    "open_ports": ["0.0.0.0", ":::"],
}

class ConfigChecker:
    def __init__(self, filepath):
        self.filepath = filepath
        self.findings = []

    def load_config(self):
        try:
            with open(self.filepath, "r") as f:
                if self.filepath.endswith(".json"):
                    return json.load(f)
                elif self.filepath.endswith((".yaml", ".yml")):
                    return yaml.safe_load(f)
                else:
                    return f.read()
        except Exception as e:
            print(f"[-] Config load error: {e}")
            return {}

    def check(self):
        config_str = str(self.load_config()).lower()
        for issue_type, keywords in RISKY_PATTERNS.items():
            for kw in keywords:
                if kw.lower() in config_str:
                    self.findings.append({
                        "issue": issue_type,
                        "keyword": kw,
                        "severity": "HIGH" if "password" in kw or "secret" in kw else "MEDIUM"
                    })
                    print(f"[!] Found {issue_type}: keyword '{kw}'")
        return self.findings

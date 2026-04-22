#!/usr/bin/env python3
"""Cloud Security Report Generator"""
from datetime import datetime

class CloudReport:
    def __init__(self, results):
        self.results = results

    def save(self, filename):
        all_findings = []
        for category, items in self.results.items():
            for item in items:
                item["category"] = category.upper()
                all_findings.append(item)

        critical = [f for f in all_findings if f.get("severity") == "CRITICAL"]
        high = [f for f in all_findings if f.get("severity") == "HIGH"]
        medium = [f for f in all_findings if f.get("severity") == "MEDIUM"]

        findings_html = "".join(
            f"<tr class='{f.get('severity','').lower()}'><td>{f.get('category','')}</td><td>{f.get('type','')}</td><td>{f.get('resource','')}</td><td>{f.get('detail','')}</td><td><b>{f.get('severity','')}</b></td></tr>"
            for f in all_findings
        )

        html = f"""<!DOCTYPE html>
<html><head><title>CloudSec Audit Report</title>
<style>
body{{font-family:Arial;background:#0f1117;color:#e0e0e0;padding:20px}}
h1{{color:#38bdf8}} h2{{color:#7dd3fc}}
.card{{background:#1e2030;border-radius:8px;padding:15px;margin:10px 0}}
table{{width:100%;border-collapse:collapse}} td,th{{padding:8px;border:1px solid #2a2a3a}}
th{{background:#1a2035}} .critical td:last-child{{color:#ef4444}}
.high td:last-child{{color:#f97316}} .medium td:last-child{{color:#facc15}}
.stats{{display:flex;gap:20px}} .stat{{background:#1e2030;padding:15px;border-radius:8px;text-align:center}}
.stat .num{{font-size:2em;font-weight:bold}}
</style></head>
<body>
<h1>CloudSec Audit Report</h1>
<p>{datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<div class="stats">
  <div class="stat"><div class="num" style="color:#ef4444">{len(critical)}</div><div>CRITICAL</div></div>
  <div class="stat"><div class="num" style="color:#f97316">{len(high)}</div><div>HIGH</div></div>
  <div class="stat"><div class="num" style="color:#facc15">{len(medium)}</div><div>MEDIUM</div></div>
</div>
<div class="card">
  <h2>All Findings ({len(all_findings)})</h2>
  <table><tr><th>Category</th><th>Type</th><th>Resource</th><th>Detail</th><th>Severity</th></tr>
  {findings_html}</table>
</div>
</body></html>"""
        with open(filename, "w") as f:
            f.write(html)
        print(f"[+] Report saved: {filename}")

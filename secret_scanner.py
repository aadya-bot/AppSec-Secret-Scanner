# -*- coding: utf-8 -*-
"""
Created on Mon Jun 29 09:11:31 2026

@author: NDTES_YOG"""

import os
from datetime import datetime

# Mock Source Code Files (Our simulated developer workspace)
mock_workspace = {
    "src/auth.py": [
        "import os",
        "def login(user, pwd):",
        "    # SAFE: Using environment variables instead of hardcoding",
        "    db_pass = os.environ.get('DB_PASSWORD')",
        "    print('Attempting login for user: ' + user)"
    ],
    "config/settings.json": [
        "{",
        '    "environment": "production",',
        '    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",',  # CRITICAL LEAK
        '    "port": 8080',
        "}"
    ],
    "src/database.sql": [
        "CREATE USER 'admin'@'localhost' IDENTIFIED BY 'SuperSecretPassword123!';", # HIGH LEAK
        "GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost';"
    ],
    "deploy/script.sh": [
        "#!/bin/bash",
        "echo 'Starting deployment...'",
        "curl -H 'Authorization: Token sb_secret_token_987654321' https://api.service.com/deploy" # HIGH LEAK
    ]
}

class SecretScanner:
    """
    Static Application Security Testing (SAST) Scanner
    Scans mock workspace source code files for hardcoded secrets, keys, and tokens.
    """
    def __init__(self):
        self.findings = []
        self.total_files_scanned = 0
        self.total_leaks_found = 0
        self.workspace_risk_score = 0

    def scan_workspace(self):
        """Iterate through the mock repository code files line by line"""
        print("\n" + "="*60)
        print("🚀 APPSEC STATIC CODE SCAN STARTING")
        print("="*60)

        # High-risk target phrases to catch in strings
        critical_keywords = ['aws_access_key', 'aws_secret', 'private_key']
        high_keywords = ['password', 'identified by', 'secret_token', 'api_key']

        for filepath, lines in mock_workspace.items():
            self.total_files_scanned += 1
            print(f"🔍 Analyzing: {filepath} ({len(lines)} lines)")
            
            for line_num, line_content in enumerate(lines, 1):
                clean_line = line_content.lower()
                
                # Check for Critical Vulnerabilities
                for keyword in critical_keywords:
                    if keyword in clean_line:
                        self.findings.append({
                            'file': filepath,
                            'line': line_num,
                            'code_snippet': line_content.strip(),
                            'severity': 'critical',
                            'icon': '🚨',
                            'type': 'Hardcoded Cloud Credential',
                            'description': f"Exposed cloud configuration key '{keyword}' found in source code.",
                            'fix': 'Migrate credential to an external safe configuration manager or AWS Secrets Manager.'
                        })
                        self.total_leaks_found += 1
                        self.workspace_risk_score += 35

                # Check for High Vulnerabilities
                for keyword in high_keywords:
                    # Ignore lines that are clearly code comments
                    if keyword in clean_line and not clean_line.strip().startswith('#') and not clean_line.strip().startswith('//'):
                        # Ensure we don't double-flag a line if it matched a critical check already
                        if not any(f['file'] == filepath and f['line'] == line_num for f in self.findings):
                            self.findings.append({
                                'file': filepath,
                                'line': line_num,
                                'code_snippet': line_content.strip(),
                                'severity': 'high',
                                'icon': '🔓',
                                'type': 'Hardcoded Secret / Password',
                                'description': f"Hardcoded text plain variable assignment tracking '{keyword}' pattern.",
                                'fix': 'Inject credential runtime token via environmental variables configuration.'
                            })
                            self.total_leaks_found += 1
                            self.workspace_risk_score += 20

        # Cap max workspace risk score at 100
        self.workspace_risk_score = min(self.workspace_risk_score, 100)

    def generate_html_dashboard(self):
        """Compile findings matrix directly into a frontend dashboard report file"""
        os.makedirs('reports', exist_ok=True)
        
        status_profile = "SECURE"
        status_class = "low"
        if self.workspace_risk_score >= 70:
            status_profile = "FAILING / CRITICAL RISK"
            status_class = "critical"
        elif self.workspace_risk_score >= 35:
            status_profile = "WARNING / HIGH RISK"
            status_class = "medium"

        # Build dynamic rows for findings
        findings_table_rows = ""
        if not self.findings:
            findings_table_rows = """
            <tr>
                <td colspan="5" style="text-align: center; color: #28a745; font-weight: bold; padding: 30px;">
                    🎉 Excellent! No hardcoded credentials or passwords detected in this codebase.
                </td>
            </tr>
            """
        else:
            for f in self.findings:
                findings_table_rows += f"""
                <tr class="finding-row {f['severity']}">
                    <td><strong>{f['file']}</strong><br><small style="color: #666;">Line {f['line']}</small></td>
                    <td><span class="badge {f['severity']}">{f['severity'].upper()}</span></td>
                    <td><strong>{f['type']}</strong></td>
                    <td><code class="snippet-box">{f['code_snippet']}</code></td>
                    <td><small>🔧 {f['fix']}</small></td>
                </tr>
                """

        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AppSec Static Analysis Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background: #0f172a; margin: 0; padding: 30px; color: #cbd5e1; }
        .wrapper { max-width: 1100px; margin: 0 auto; background: #1e293b; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
        .banner { background: linear-gradient(135deg, #020617 0%, #0f172a 100%); color: #38bdf8; padding: 30px; border-radius: 8px; text-align: center; margin-bottom: 35px; border: 1px solid #334155; }
        .metrics-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; margin-bottom: 40px; }
        .metric-card { background: #0f172a; border-radius: 8px; padding: 20px; text-align: center; border-top: 4px solid #38bdf8; border: 1px solid #334155; }
        .metric-card.status-box.critical { border-top-color: #f43f5e; background: #271625; }
        .metric-card.status-box.medium { border-top-color: #eab308; background: #2a2415; }
        .metric-card.status-box.low { border-top-color: #22c55e; background: #14281a; }
        .metric-num { font-size: 32px; font-weight: bold; color: #f8fafc; margin-top: 5px; }
        .metric-num.critical { color: #f43f5e; }
        .metric-num.medium { color: #eab308; }
        .metric-num.low { color: #22c55e; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid #334155; vertical-align: top; }
        th { background-color: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 12px; }
        .badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; display: inline-block; }
        .badge.critical { background: #f43f5e; color: #ffffff; }
        .badge.high { background: #eab308; color: #000000; }
        .snippet-box { display: block; background: #020617; color: #a7f3d0; padding: 8px; border-radius: 4px; font-family: 'Courier New', Courier, monospace; overflow-x: auto; font-size: 12px; white-space: pre-wrap; border: 1px solid #334155; }
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="banner">
            <h1>🛡️ Static Application Security Testing (SAST)</h1>
            <p>Automated Code Repository Secret Leakage Report</p>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div style="color: #6b7280; font-weight: 600;">Files Audited</div>
                <div class="metric-num">[FILES_COUNT]</div>
            </div>
            <div class="metric-card">
                <div style="color: #6b7280; font-weight: 600;">Vulnerabilities Found</div>
                <div class="metric-num [STATUS_CLASS]">[LEAKS_COUNT]</div>
            </div>
            <div class="metric-card status-box [STATUS_CLASS]">
                <div style="color: #6b7280; font-weight: 600;">Workspace Security Score</div>
                <div class="metric-num [STATUS_CLASS]">[SCORE]/100</div>
                <div style="font-size: 12px; font-weight: bold; margin-top: 5px;">[PROFILE]</div>
            </div>
        </div>

        <h2>📝 Identified Vulnerability Catalog</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 20%;">Target Location</th>
                    <th style="width: 10%;">Severity</th>
                    <th style="width: 20%;">Vulnerability Type</th>
                    <th style="width: 30%;">Offending Line Snippet</th>
                    <th style="width: 20%;">Remediation Path</th>
                </tr>
            </thead>
            <tbody>
                [TABLE_ROWS]
            </tbody>
        </table>
    </div>
</body>
</html>"""

        # Map execution outcomes safely to string layout
        final_html = html_template\
            .replace("[FILES_COUNT]", str(self.total_files_scanned))\
            .replace("[LEAKS_COUNT]", str(self.total_leaks_found))\
            .replace("[SCORE]", str(self.workspace_risk_score))\
            .replace("[PROFILE]", status_profile)\
            .replace("[STATUS_CLASS]", status_class)\
            .replace("[TABLE_ROWS]", findings_table_rows)

        filepath = 'reports/sast_secret_report.html'
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(final_html)
        
        print("\n" + "="*60)
        print(f"✅ Dashboard generated cleanly: {filepath}")
        print("="*60 + "\n")


if __name__ == "__main__":
    scanner = SecretScanner()
    scanner.scan_workspace()
    scanner.generate_html_dashboard()
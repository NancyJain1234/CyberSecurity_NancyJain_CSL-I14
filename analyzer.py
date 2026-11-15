#!/usr/bin/env python3
"""
IoT Telnet Honeypot - Log Analyzer and Threat Intelligence Reporter
Parses captured session logs, authentication attempts, and command chains.
Generates CLI statistics and an interactive HTML dashboard report.
"""

import os
import sys
import sqlite3
import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from honeypot.config import DB_FILE, REPORTS_DIR

def format_table(headers, rows):
    """Generates a clean ASCII table without external dependencies."""
    if not rows:
        return "  (No records found)\n"
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(val)))
    
    header_line = " | ".join(f"{h:<{col_widths[i]}}" for i, h in enumerate(headers))
    sep_line = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    row_lines = [
        " | ".join(f"{str(val):<{col_widths[i]}}" for i, val in enumerate(row))
        for row in rows
    ]
    return f"{header_line}\n{sep_line}\n" + "\n".join(row_lines) + "\n"

class LogAnalyzer:
    def __init__(self, db_path=DB_FILE):
        self.db_path = str(db_path)
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"Database not found at {self.db_path}. Please run the honeypot or simulator first.")

    def _query(self, sql, params=()):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(sql, params)
            return cursor.fetchall()

    def get_summary_statistics(self):
        """Calculates global honeypot metrics."""
        total_sessions = self._query("SELECT COUNT(*) as cnt FROM sessions")[0]["cnt"]
        unique_ips = self._query("SELECT COUNT(DISTINCT client_ip) as cnt FROM sessions")[0]["cnt"]
        total_auth = self._query("SELECT COUNT(*) as cnt FROM auth_attempts")[0]["cnt"]
        accepted_auth = self._query("SELECT COUNT(*) as cnt FROM auth_attempts WHERE success = 1")[0]["cnt"]
        total_commands = self._query("SELECT COUNT(*) as cnt FROM commands")[0]["cnt"]
        
        # Threat severity breakdown
        severity_counts = self._query("""
            SELECT severity, COUNT(*) as cnt 
            FROM commands 
            WHERE severity != 'NONE' 
            GROUP BY severity 
            ORDER BY cnt DESC
        """)
        
        # Botnet signatures breakdown
        botnets = self._query("""
            SELECT botnet_family, COUNT(*) as cnt 
            FROM commands 
            WHERE botnet_family != 'Unclassified' AND botnet_family != '' 
            GROUP BY botnet_family 
            ORDER BY cnt DESC
        """)

        return {
            "total_sessions": total_sessions,
            "unique_ips": unique_ips,
            "total_auth": total_auth,
            "accepted_auth": accepted_auth,
            "rejected_auth": total_auth - accepted_auth,
            "total_commands": total_commands,
            "severities": [(r["severity"], r["cnt"]) for r in severity_counts],
            "botnets": [(r["botnet_family"], r["cnt"]) for r in botnets],
        }

    def get_top_attackers(self, limit=10):
        rows = self._query(f"""
            SELECT client_ip, COUNT(*) as sessions_count, MAX(started_at) as last_seen
            FROM sessions
            GROUP BY client_ip
            ORDER BY sessions_count DESC
            LIMIT {limit}
        """)
        return [(r["client_ip"], r["sessions_count"], r["last_seen"]) for r in rows]

    def get_top_usernames(self, limit=10):
        rows = self._query(f"""
            SELECT username, COUNT(*) as cnt
            FROM auth_attempts
            GROUP BY username
            ORDER BY cnt DESC
            LIMIT {limit}
        """)
        return [(r["username"], r["cnt"]) for r in rows]

    def get_top_passwords(self, limit=10):
        rows = self._query(f"""
            SELECT password, COUNT(*) as cnt
            FROM auth_attempts
            GROUP BY password
            ORDER BY cnt DESC
            LIMIT {limit}
        """)
        return [(r["password"], r["cnt"]) for r in rows]

    def get_top_combos(self, limit=10):
        rows = self._query(f"""
            SELECT username, password, known_iot_signature, COUNT(*) as cnt
            FROM auth_attempts
            GROUP BY username, password
            ORDER BY cnt DESC
            LIMIT {limit}
        """)
        return [(f"{r['username']} : {r['password']}", r["known_iot_signature"], r["cnt"]) for r in rows]

    def get_top_commands(self, limit=15):
        rows = self._query(f"""
            SELECT raw_command, matched_signature, botnet_family, severity, COUNT(*) as cnt
            FROM commands
            GROUP BY raw_command
            ORDER BY cnt DESC
            LIMIT {limit}
        """)
        return [
            (r["raw_command"], r["matched_signature"] or "None", r["botnet_family"] or "Unknown", r["severity"], r["cnt"])
            for r in rows
        ]

    def get_extracted_urls(self):
        rows = self._query("SELECT extracted_urls FROM commands WHERE extracted_urls != ''")
        urls = []
        for r in rows:
            for u in r["extracted_urls"].split(","):
                u = u.strip()
                if u:
                    urls.append(u)
        return Counter(urls).most_common()

    def print_cli_summary(self):
        """Displays rich terminal summary."""
        stats = self.get_summary_statistics()

        print("\n" + "=" * 80)
        print("          IoT TELNET HONEYPOT - FORENSIC LOG ANALYSIS REPORT")
        print("=" * 80)
        print(f" Total Attack Sessions      : {stats['total_sessions']}")
        print(f" Unique Attacking IP Addrs  : {stats['unique_ips']}")
        print(f" Total Brute-Force Logins   : {stats['total_auth']} (Accepted: {stats['accepted_auth']}, Rejected: {stats['rejected_auth']})")
        print(f" Total Injected Commands    : {stats['total_commands']}")
        print("=" * 80 + "\n")

        # Top Attackers
        print("[+] TOP ATTACKING IP ADDRESSES")
        attackers = self.get_top_attackers(5)
        print(format_table(["Attacker IP", "Sessions", "Last Seen Timestamp"], attackers))

        # Top Credentials
        print("[+] TOP TARGETED CREDENTIAL COMBINATIONS")
        combos = self.get_top_combos(8)
        print(format_table(["Credential (User:Pass)", "Identified Signature", "Attempts"], combos))

        # Top Injected Commands
        print("[+] TOP INJECTED SHELL COMMANDS")
        cmds = self.get_top_commands(8)
        print(format_table(["Command", "Detected Signature", "Family", "Severity", "Count"], cmds))

        # Malware URLs
        urls = self.get_extracted_urls()
        if urls:
            print("[+] IDENTIFIED MALWARE DOWNLOAD URLs")
            print(format_table(["Malicious URL / Dropper Location", "Attempt Count"], urls))

        # Botnet Signature Detection
        if stats["botnets"]:
            print("[+] ATTRIBUTED BOTNET FAMILIES / SIGNATURES")
            print(format_table(["Botnet Family / Behavior", "Matched Commands"], stats["botnets"]))

    def generate_html_report(self, output_path=None):
        """Generates an interactive, standalone HTML cybersecurity report with Chart.js."""
        if output_path is None:
            output_path = REPORTS_DIR / "honeypot_report.html"
        else:
            output_path = Path(output_path)

        stats = self.get_summary_statistics()
        top_combos = self.get_top_combos(10)
        top_cmds = self.get_top_commands(15)
        top_ips = self.get_top_attackers(10)
        top_users = self.get_top_usernames(6)
        urls = self.get_extracted_urls()

        # Prepare chart data
        user_labels = json.dumps([u[0] for u in top_users])
        user_data = json.dumps([u[1] for u in top_users])

        sev_labels = json.dumps([s[0] for s in stats["severities"]])
        sev_data = json.dumps([s[1] for s in stats["severities"]])

        botnet_labels = json.dumps([b[0] for b in stats["botnets"]])
        botnet_data = json.dumps([b[1] for b in stats["botnets"]])

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Telnet Honeypot - Threat Intelligence Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-main: #0d1117;
            --bg-card: #161b22;
            --border: #30363d;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --accent-blue: #58a6ff;
            --accent-red: #f85149;
            --accent-green: #3fb950;
            --accent-orange: #d29922;
            --accent-purple: #bc8cff;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-main);
            margin: 0;
            padding: 24px;
        }}
        .header {{
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}
        h1 {{
            color: #ffffff;
            margin: 0 0 8px 0;
            font-size: 1.8rem;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .badge {{
            font-size: 0.75rem;
            padding: 4px 8px;
            border-radius: 12px;
            background-color: rgba(248, 81, 73, 0.2);
            color: var(--accent-red);
            border: 1px solid var(--accent-red);
            font-weight: 600;
        }}
        .subtitle {{
            color: var(--text-muted);
            font-size: 0.95rem;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }}
        .kpi-title {{
            color: var(--text-muted);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
        }}
        .kpi-value {{
            font-size: 1.8rem;
            font-weight: 700;
            color: #ffffff;
        }}
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .card-title {{
            font-size: 1.1rem;
            font-weight: 600;
            margin-top: 0;
            margin-bottom: 16px;
            color: #ffffff;
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        th, td {{
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            color: var(--text-muted);
            font-weight: 600;
            background-color: rgba(255, 255, 255, 0.02);
        }}
        tr:hover {{
            background-color: rgba(255, 255, 255, 0.04);
        }}
        code {{
            background-color: rgba(110, 118, 129, 0.2);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
            font-size: 0.85em;
            color: #e6edf3;
        }}
        .sev-tag {{
            font-size: 0.75rem;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 600;
        }}
        .sev-CRITICAL {{ background-color: rgba(248, 81, 73, 0.2); color: #f85149; }}
        .sev-HIGH {{ background-color: rgba(210, 153, 34, 0.2); color: #d29922; }}
        .sev-MEDIUM {{ background-color: rgba(88, 166, 255, 0.2); color: #58a6ff; }}
        .sev-LOW {{ background-color: rgba(63, 185, 80, 0.2); color: #3fb950; }}
        .footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
        }}
    </style>
</head>
<body>

    <div class="header">
        <h1>
            <span>🛡️ IoT Telnet Honeypot Threat Intelligence</span>
            <span class="badge">LIVE CAPTURE</span>
        </h1>
        <div class="subtitle">Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Analysis of Mirai, Bashlite & IoT Scanning Campaigns</div>
    </div>

    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Total Sessions</div>
            <div class="kpi-value" style="color: var(--accent-blue);">{stats['total_sessions']}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Attacking IPs</div>
            <div class="kpi-value" style="color: var(--accent-purple);">{stats['unique_ips']}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Auth Attempts</div>
            <div class="kpi-value" style="color: var(--accent-orange);">{stats['total_auth']}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Captured Commands</div>
            <div class="kpi-value" style="color: var(--accent-red);">{stats['total_commands']}</div>
        </div>
    </div>

    <div class="charts-grid">
        <div class="card">
            <h3 class="card-title">Top Targeted Usernames</h3>
            <canvas id="userChart" height="200"></canvas>
        </div>
        <div class="card">
            <h3 class="card-title">Threat Severity Distribution</h3>
            <canvas id="sevChart" height="200"></canvas>
        </div>
    </div>

    <div class="card">
        <h3 class="card-title">Top Injected IoT Botnet Commands</h3>
        <table>
            <thead>
                <tr>
                    <th>Command</th>
                    <th>Detected Signature</th>
                    <th>Botnet Family</th>
                    <th>Severity</th>
                    <th>Frequency</th>
                </tr>
            </thead>
            <tbody>
                {''.join(f'''<tr>
                    <td><code>{c[0]}</code></td>
                    <td>{c[1]}</td>
                    <td>{c[2]}</td>
                    <td><span class="sev-tag sev-{c[3]}">{c[3]}</span></td>
                    <td><b>{c[4]}</b></td>
                </tr>''' for c in top_cmds)}
            </tbody>
        </table>
    </div>

    <div class="charts-grid">
        <div class="card">
            <h3 class="card-title">Top Credential Combinations (Brute-Force)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Credential (User:Pass)</th>
                        <th>Device Signature</th>
                        <th>Attempts</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(f'''<tr>
                        <td><code>{cb[0]}</code></td>
                        <td>{cb[1]}</td>
                        <td><b>{cb[2]}</b></td>
                    </tr>''' for cb in top_combos)}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h3 class="card-title">Top Attacking IP Addresses</h3>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Sessions</th>
                        <th>Last Seen</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(f'''<tr>
                        <td><code>{ip[0]}</code></td>
                        <td><b>{ip[1]}</b></td>
                        <td>{ip[2]}</td>
                    </tr>''' for ip in top_ips)}
                </tbody>
            </table>
        </div>
    </div>

    {'<div class="card"><h3 class="card-title">Identified Malware Dropper URLs</h3><table><thead><tr><th>Extracted Payload URL</th><th>Hits</th></tr></thead><tbody>' + ''.join(f'<tr><td><code>{u[0]}</code></td><td><b>{u[1]}</b></td></tr>' for u in urls) + '</tbody></table></div>' if urls else ''}

    <div class="footer">
        IoT Telnet Honeypot System &bull; Cybersecurity Project &bull; Auto-generated Report
    </div>

    <script>
        const ctxUser = document.getElementById('userChart').getContext('2d');
        new Chart(ctxUser, {{
            type: 'bar',
            data: {{
                labels: {user_labels},
                datasets: [{{
                    label: 'Attempts',
                    data: {user_data},
                    backgroundColor: '#58a6ff',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{ beginAtZero: true, grid: {{ color: '#30363d' }} }},
                    x: {{ grid: {{ display: false }} }}
                }},
                plugins: {{ legend: {{ display: false }} }}
            }}
        }});

        const ctxSev = document.getElementById('sevChart').getContext('2d');
        new Chart(ctxSev, {{
            type: 'doughnut',
            data: {{
                labels: {sev_labels},
                datasets: [{{
                    data: {sev_data},
                    backgroundColor: ['#f85149', '#d29922', '#58a6ff', '#3fb950', '#8b949e']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom', labels: {{ color: '#c9d1d9' }} }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print(f"\n[+] Interactive HTML Forensic Report generated successfully:")
        print(f"    --> {output_path.resolve()}")
        return output_path

def main():
    parser = argparse.ArgumentParser(description="Analyze IoT Telnet Honeypot Logs")
    parser.add_argument("--db", default=DB_FILE, help=f"Path to SQLite database (default: {DB_FILE})")
    parser.add_argument("--html", action="store_true", help="Generate standalone interactive HTML report")
    parser.add_argument("--out", default=None, help="Custom output path for the HTML report")
    args = parser.parse_args()

    try:
        analyzer = LogAnalyzer(db_path=args.db)
        analyzer.print_cli_summary()
        # Always generate HTML report or if flagged
        analyzer.generate_html_report(output_path=args.out)
    except FileNotFoundError as e:
        print(f"[!] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()


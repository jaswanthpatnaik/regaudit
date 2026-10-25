"""RegAudit Self-Contained HTML Report Generator.

Generates an offline, inline-CSS dark-themed cybersecurity audit report (Module 4).
Zero CDN dependencies, zero external fonts, zero JavaScript. Conforms to blue-team
investigation standards for internship submission and forensics archiving.
"""

from __future__ import annotations

import html
import logging
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.registry_keys import AUTORUN_KEYS
from database.db_manager import DatabaseManager
from utils.registry_helpers import read_key_values

LOGGER = logging.getLogger("RegAudit.Reporter")


def sanitize(val: Any) -> str:
    """Escape arbitrary strings for safe HTML rendering."""
    if val is None:
        return '<span class="dim">—</span>'
    text = str(val)
    if not text.strip():
        return '<span class="dim">(empty)</span>'
    return html.escape(text)


class HtmlExporter:
    """Compiles and exports self-contained HTML reports from SQLite records and baseline files."""

    def __init__(self, db_manager: DatabaseManager, baseline_data: Optional[Dict[str, Any]] = None) -> None:
        """Initialize HtmlExporter.

        Args:
            db_manager: DatabaseManager to extract change logs and session stats.
            baseline_data: Optional pre-loaded baseline snapshot dictionary.
        """
        self.db_manager = db_manager
        self.baseline_data = baseline_data or {}

    def _collect_live_autoruns(self) -> List[Dict[str, Any]]:
        """Collect current autorun values directly from registry if on Windows."""
        autorun_items: List[Dict[str, Any]] = []
        for hive, subkey in AUTORUN_KEYS:
            try:
                vals = read_key_values(hive, subkey)
                for val_name, val_info in vals.items():
                    data_str = str(val_info.get("data", ""))
                    norm_data = data_str.replace("/", "\\").lower()
                    is_flagged = any(
                        p in norm_data
                        for p in ["\\temp\\", "\\appdata\\roaming\\", "\\downloads\\", "\\public\\", "\\programdata\\"]
                    )
                    autorun_items.append(
                        {
                            "key": subkey,
                            "value_name": val_name,
                            "data": data_str,
                            "type": val_info.get("type", "REG_SZ"),
                            "flagged": is_flagged,
                        }
                    )
            except Exception:
                continue
        return autorun_items

    def generate_html(self, output_path: Path, last_n_changes: Optional[int] = None) -> Path:
        """Render and save the self-contained HTML audit report.

        Args:
            output_path: File path to save the HTML document.
            last_n_changes: Optional limit on number of recent changes to include.

        Returns:
            The resolved Path of the written report.
        """
        output_path = Path(output_path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # 1. Fetch data from SQLite
        changes = self.db_manager.get_changes(limit=last_n_changes)
        counts = self.db_manager.get_total_change_counts()
        snapshots = self.db_manager.get_snapshots(limit=5)

        hostname = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or platform.node()
        os_info = f"{platform.system()} {platform.release()}"
        report_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Baseline info
        meta = self.baseline_data.get("metadata", {})
        baseline_time = meta.get("captured_at", "Not Available")
        baseline_keys = meta.get("total_keys_monitored", len(snapshots))
        baseline_values = meta.get("total_values_captured", 0)

        # Determine Integrity Status
        if counts["critical"] > 0:
            status_text = "CRITICAL THREAT DETECTED"
            status_class = "badge-critical"
            summary_desc = f"Integrity check failed with {counts['critical']} critical malware indicators."
        elif counts["high"] > 0:
            status_text = "SECURITY WARNING"
            status_class = "badge-high"
            summary_desc = f"Integrity check flagged {counts['high']} high-severity policy modifications."
        elif counts["total"] > 0:
            status_text = "MODIFIED / BENIGN"
            status_class = "badge-medium"
            summary_desc = f"Monitored keys modified ({counts['total']} total), no known malware patterns."
        else:
            status_text = "SYSTEM INTEGRITY VERIFIED (PASS)"
            status_class = "badge-clean"
            summary_desc = "All monitored registry keys match baseline. Zero integrity anomalies."

        # Collect Autoruns
        autoruns = self._collect_live_autoruns()

        # Build Autorun Rows
        autorun_rows_html = ""
        if not autoruns:
            autorun_rows_html = '<tr><td colspan="4" class="text-center dim">No active autorun keys read on this host platform.</td></tr>'
        else:
            for item in autoruns:
                flag_class = "row-flagged" if item["flagged"] else ""
                flag_badge = '<span class="badge badge-critical">SUSPICIOUS PATH</span>' if item["flagged"] else '<span class="badge badge-clean">STANDARD</span>'
                autorun_rows_html += f"""
                <tr class="{flag_class}">
                    <td><code>{sanitize(item['key'])}</code></td>
                    <td><strong>{sanitize(item['value_name'])}</strong></td>
                    <td class="code-wrap">{sanitize(item['data'])}</td>
                    <td>{flag_badge}</td>
                </tr>
                """

        # Build Change Rows
        change_rows_html = ""
        malware_hits_html = ""
        seen_patterns = set()

        if not changes:
            change_rows_html = '<tr><td colspan="8" class="text-center dim">No change events recorded in current database.</td></tr>'
            malware_hits_html = '<div class="alert-box alert-clean">No malware-like registry tampering signatures detected.</div>'
        else:
            for c in changes:
                sev = c.get("severity", "LOW")
                ctype = c.get("change_type", "MODIFIED")
                pattern = c.get("pattern_matched", "")

                sev_badge_class = {
                    "CRITICAL": "badge-critical",
                    "HIGH": "badge-high",
                    "MEDIUM": "badge-medium",
                    "LOW": "badge-low",
                }.get(sev, "badge-low")

                type_badge_class = {
                    "ADDED": "type-added",
                    "MODIFIED": "type-modified",
                    "DELETED": "type-deleted",
                }.get(ctype, "")

                change_rows_html += f"""
                <tr>
                    <td>{sanitize(c.get('timestamp'))}</td>
                    <td><span class="badge {sev_badge_class}">{sev}</span></td>
                    <td><span class="badge {type_badge_class}">{ctype}</span></td>
                    <td><strong>{sanitize(c.get('hive'))}</strong></td>
                    <td><code>{sanitize(c.get('key_path'))}</code></td>
                    <td>{sanitize(c.get('value_name'))}</td>
                    <td class="code-wrap"><span class="old-val">{sanitize(c.get('old_data'))}</span> &rarr; <span class="new-val">{sanitize(c.get('new_data'))}</span></td>
                    <td>{sanitize(pattern)}</td>
                </tr>
                """

                # Extract malware pattern hits
                if pattern and sev in ("CRITICAL", "HIGH") and pattern not in seen_patterns:
                    seen_patterns.add(pattern)
                    box_class = "alert-critical" if sev == "CRITICAL" else "alert-high"
                    malware_hits_html += f"""
                    <div class="alert-box {box_class}">
                        <h4>[{sev}] {sanitize(pattern)}</h4>
                        <p><strong>Registry Target:</strong> {sanitize(c.get('hive'))}\\{sanitize(c.get('key_path'))}\\{sanitize(c.get('value_name'))}</p>
                        <p><strong>Observed Change:</strong> Old: <code>{sanitize(c.get('old_data'))}</code> &rarr; New: <code>{sanitize(c.get('new_data'))}</code></p>
                        <p><strong>Forensic Detail:</strong> {sanitize(c.get('detail'))}</p>
                    </div>
                    """

            if not malware_hits_html:
                malware_hits_html = '<div class="alert-box alert-clean">No critical or high-severity malware patterns detected in change logs.</div>'

        # Build Snapshot Rows
        snapshot_rows_html = ""
        if not snapshots:
            snapshot_rows_html = f'<tr><td>{sanitize(baseline_time)}</td><td>{baseline_keys}</td><td>{baseline_values}</td><td>{sanitize(meta.get("notes", "Baseline snapshot loaded from JSON file"))}</td></tr>'
        else:
            for s in snapshots:
                snapshot_rows_html += f"""
                <tr>
                    <td>{sanitize(s.get('captured_at'))}</td>
                    <td>{s.get('total_keys_monitored')}</td>
                    <td>{s.get('total_values_captured')}</td>
                    <td>{sanitize(s.get('notes'))}</td>
                </tr>
                """

        # Generate Actionable Blue-Team Recommendations
        recommendations: List[str] = []
        if counts["critical"] > 0:
            recommendations.append(
                "<strong>Host Containment:</strong> Immediately isolate host from corporate network. "
                "Active persistence or Winlogon / command hijacking detected."
            )
            recommendations.append(
                "<strong>Triage Volatile Autoruns:</strong> Inspect suspicious binaries found in Temp/AppData directories; "
                "capture file hashes for VirusTotal and threat intelligence query."
            )
        if counts["high"] > 0:
            recommendations.append(
                "<strong>Restore Antivirus & Firewall:</strong> Re-enable Windows Defender (DisableAntiSpyware=0, "
                "DisableRealtimeMonitoring=0) and ensure UAC is active (EnableLUA=1)."
            )
            recommendations.append(
                "<strong>Audit Windows Services:</strong> Verify newly created service entries against baseline authorization list."
            )
        if not recommendations:
            recommendations.append(
                "<strong>Maintain Baseline Cadence:</strong> Capture periodic baseline snapshots prior to scheduled software deployments."
            )
            recommendations.append(
                "<strong>Principle of Least Privilege:</strong> Ensure standard user accounts do not possess administrative write rights to HKLM hives."
            )

        recs_html = "".join(f"<li>{r}</li>" for r in recommendations)

        # Assemble Full Document
        full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RegAudit — Registry Audit Report</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b2d;
            --header-bg: #1a1f2e;
            --border-color: #30363d;
            --text-main: #c9d1d9;
            --text-heading: #f0f6fc;
            --text-muted: #8b949e;
            --accent-blue: #58a6ff;
            --color-critical: #f85149;
            --color-high: #f0883e;
            --color-medium: #d29922;
            --color-low: #3fb950;
            --color-added: #238636;
            --color-modified: #9e6a03;
            --color-deleted: #da3633;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            font-size: 14px;
            line-height: 1.6;
            padding: 24px;
        }}
        .container {{
            max-width: 1280px;
            margin: 0 auto;
        }}
        header {{
            background-color: var(--header-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        header h1 {{
            color: var(--text-heading);
            font-size: 26px;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            margin-top: 16px;
            font-size: 13px;
        }}
        .meta-item {{
            background-color: rgba(255,255,255,0.03);
            padding: 10px 14px;
            border-radius: 6px;
            border: 1px solid rgba(255,255,255,0.05);
        }}
        .meta-item span {{
            display: block;
            color: var(--text-muted);
            font-size: 11px;
            text-transform: uppercase;
        }}
        .meta-item strong {{
            color: var(--text-heading);
            font-size: 14px;
        }}
        .card-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }}
        .card .card-title {{
            color: var(--text-muted);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 8px;
        }}
        .card .card-value {{
            font-size: 32px;
            font-weight: 700;
            color: var(--text-heading);
            line-height: 1;
        }}
        .card .card-subtext {{
            color: var(--text-muted);
            font-size: 12px;
            margin-top: 8px;
        }}
        .section {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        .section h2 {{
            color: var(--text-heading);
            font-size: 18px;
            margin-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 8px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }}
        th {{
            background-color: rgba(255,255,255,0.04);
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
        }}
        tr:hover td {{
            background-color: rgba(255,255,255,0.02);
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-critical {{ background-color: rgba(248, 81, 73, 0.2); color: var(--color-critical); border: 1px solid var(--color-critical); }}
        .badge-high {{ background-color: rgba(240, 136, 62, 0.2); color: var(--color-high); border: 1px solid var(--color-high); }}
        .badge-medium {{ background-color: rgba(210, 153, 34, 0.2); color: var(--color-medium); border: 1px solid var(--color-medium); }}
        .badge-low {{ background-color: rgba(63, 185, 80, 0.2); color: var(--color-low); border: 1px solid var(--color-low); }}
        .badge-clean {{ background-color: rgba(63, 185, 80, 0.2); color: var(--color-low); border: 1px solid var(--color-low); }}

        .type-added {{ background-color: rgba(35, 134, 54, 0.2); color: #3fb950; }}
        .type-modified {{ background-color: rgba(158, 106, 3, 0.2); color: #d29922; }}
        .type-deleted {{ background-color: rgba(218, 54, 51, 0.2); color: #f85149; text-decoration: line-through; }}

        code {{
            background-color: rgba(255,255,255,0.06);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: Consolas, Monaco, "Courier New", monospace;
            font-size: 12px;
            color: var(--accent-blue);
        }}
        .code-wrap {{
            word-break: break-all;
            max-width: 320px;
        }}
        .dim {{ color: var(--text-muted); }}
        .old-val {{ color: #f0883e; }}
        .new-val {{ color: #3fb950; font-weight: 600; }}
        .row-flagged td {{ background-color: rgba(248, 81, 73, 0.08); }}

        .alert-box {{
            padding: 16px;
            border-radius: 6px;
            margin-bottom: 12px;
        }}
        .alert-critical {{
            background-color: rgba(248, 81, 73, 0.1);
            border-left: 4px solid var(--color-critical);
        }}
        .alert-critical h4 {{ color: var(--color-critical); margin-bottom: 6px; }}
        .alert-high {{
            background-color: rgba(240, 136, 62, 0.1);
            border-left: 4px solid var(--color-high);
        }}
        .alert-high h4 {{ color: var(--color-high); margin-bottom: 6px; }}
        .alert-clean {{
            background-color: rgba(63, 185, 80, 0.1);
            border-left: 4px solid var(--color-low);
            color: var(--color-low);
        }}
        .rec-list {{
            list-style: none;
            padding-left: 0;
        }}
        .rec-list li {{
            padding: 10px 14px;
            margin-bottom: 8px;
            background-color: rgba(255,255,255,0.02);
            border-left: 3px solid var(--accent-blue);
            border-radius: 0 6px 6px 0;
        }}
        footer {{
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 32px;
            padding-top: 16px;
            border-top: 1px solid var(--border-color);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>RegAudit &mdash; Registry Audit Report</h1>
            <p>Unified Mentor Cybersecurity Internship &bull; Windows Registry Change Monitoring System</p>
            <div class="meta-grid">
                <div class="meta-item">
                    <span>Host Endpoint</span>
                    <strong>{sanitize(hostname)}</strong>
                </div>
                <div class="meta-item">
                    <span>Operating System</span>
                    <strong>{sanitize(os_info)}</strong>
                </div>
                <div class="meta-item">
                    <span>Generated Timestamp</span>
                    <strong>{report_time}</strong>
                </div>
                <div class="meta-item">
                    <span>Baseline Reference</span>
                    <strong>{sanitize(baseline_time[:19] if len(baseline_time)>=19 else baseline_time)}</strong>
                </div>
            </div>
        </header>

        <!-- Executive Summary Cards -->
        <div class="card-grid">
            <div class="card">
                <div class="card-title">Total Modifications</div>
                <div class="card-value">{counts['total']}</div>
                <div class="card-subtext">Events across monitored keys</div>
            </div>
            <div class="card">
                <div class="card-title">Critical Threats</div>
                <div class="card-value" style="color: var(--color-critical);">{counts['critical']}</div>
                <div class="card-subtext">Winlogon/Tooling/Untrusted run</div>
            </div>
            <div class="card">
                <div class="card-title">High Policy Alerts</div>
                <div class="card-value" style="color: var(--color-high);">{counts['high']}</div>
                <div class="card-subtext">Defender/UAC/Firewall tampering</div>
            </div>
            <div class="card">
                <div class="card-title">Integrity Verification</div>
                <div style="margin-top: 8px;"><span class="badge {status_class}">{status_text}</span></div>
                <div class="card-subtext">{summary_desc}</div>
            </div>
        </div>

        <!-- Section 3: Autorun Analysis -->
        <div class="section">
            <h2>Module 1 &bull; Active Autorun &amp; Startup Inventory</h2>
            <p class="dim" style="margin-bottom: 16px;">Direct audit of HKCU and HKLM Run / RunOnce startup registration entries.</p>
            <table>
                <thead>
                    <tr>
                        <th>Registry Key</th>
                        <th>Value Name</th>
                        <th>Target Executable / Path</th>
                        <th>Analysis Flag</th>
                    </tr>
                </thead>
                <tbody>
                    {autorun_rows_html}
                </tbody>
            </table>
        </div>

        <!-- Section 5: Malware Pattern Matches -->
        <div class="section">
            <h2>Module 2 &bull; Malware-Like Signature Detections</h2>
            <p class="dim" style="margin-bottom: 16px;">Heuristic matching against known defense impairment, UAC bypasses, and persistence mechanics.</p>
            {malware_hits_html}
        </div>

        <!-- Section 4: Full Registry Change Log -->
        <div class="section">
            <h2>Module 3 &bull; Registry Integrity Change Audit Log</h2>
            <p class="dim" style="margin-bottom: 16px;">Chronological record of all cryptographic baseline deviations.</p>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Hive</th>
                        <th>Key Path</th>
                        <th>Value</th>
                        <th>Delta (Old &rarr; New)</th>
                        <th>Rule Matched</th>
                    </tr>
                </thead>
                <tbody>
                    {change_rows_html}
                </tbody>
            </table>
        </div>

        <!-- Section 7: Baseline Snapshots -->
        <div class="section">
            <h2>Integrity Baseline Provenance</h2>
            <table>
                <thead>
                    <tr>
                        <th>Capture Timestamp</th>
                        <th>Keys Monitored</th>
                        <th>Values Hashed</th>
                        <th>Snapshot Notes</th>
                    </tr>
                </thead>
                <tbody>
                    {snapshot_rows_html}
                </tbody>
            </table>
        </div>

        <!-- Section 8: Recommendations -->
        <div class="section">
            <h2>Blue-Team Remediation Recommendations</h2>
            <ul class="rec-list">
                {recs_html}
            </ul>
        </div>

        <footer>
            RegAudit v1.0 &bull; Automated Windows Registry Change Monitoring System &bull; Strictly Defensive &bull; Unified Mentor
        </footer>
    </div>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_html)

        LOGGER.info("HTML Audit Report successfully exported to %s", output_path)
        return output_path

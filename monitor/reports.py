from __future__ import annotations

from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path

from django.conf import settings
from django.db.models import Count
from django.utils import timezone

from .models import Alert, BulkTransferIncident, FileEvent, IntegrityCheckHistory, MonitoringPolicy, SimulatedEmailAlert


def _row(value: str, limit: int = 220) -> str:
    return f"<td>{escape(str(value))[:limit]}</td>"


def _events_table(events) -> str:
    if not events:
        return "<p>No records found.</p>"
    rows = []
    for event in events:
        rows.append(
            "<tr>"
            + _row(timezone.localtime(event.timestamp).strftime("%Y-%m-%d %H:%M:%S"))
            + _row(event.event_type)
            + _row(event.severity)
            + _row(event.risk_score)
            + _row("Yes" if event.is_sensitive else "No")
            + _row("Yes" if event.is_authorized else "No")
            + _row(event.sensitivity_category)
            + _row(event.reason)
            + _row(event.source_path)
            + _row(event.destination_path)
            + _row(event.integrity_status)
            + "</tr>"
        )
    return """
<table>
<thead><tr><th>Timestamp</th><th>Event</th><th>Severity</th><th>Risk</th><th>Sensitive</th><th>Authorized</th><th>Category</th><th>Reason</th><th>Source</th><th>Destination</th><th>Integrity</th></tr></thead>
<tbody>{}</tbody>
</table>
""".format("".join(rows))


def _alerts_table(alerts) -> str:
    if not alerts:
        return "<p>No alerts found.</p>"
    rows = []
    for alert in alerts:
        event = alert.event
        rows.append(
            "<tr>"
            + _row(timezone.localtime(alert.created_at).strftime("%Y-%m-%d %H:%M:%S"))
            + _row(alert.status)
            + _row(event.severity)
            + _row(event.risk_score)
            + _row(alert.assigned_to or "Unassigned")
            + _row(event.reason)
            + _row(alert.recommended_action)
            + "</tr>"
        )
    return """
<table>
<thead><tr><th>Created</th><th>Status</th><th>Severity</th><th>Risk</th><th>Assigned To</th><th>Reason</th><th>Recommended Action</th></tr></thead>
<tbody>{}</tbody>
</table>
""".format("".join(rows))


def _integrity_table(items) -> str:
    if not items:
        return "<p>No integrity history found.</p>"
    rows = []
    for item in items:
        rows.append(
            "<tr>"
            + _row(timezone.localtime(item.checked_at).strftime("%Y-%m-%d %H:%M:%S"))
            + _row(item.status)
            + _row(item.path)
            + _row(item.baseline_hash, 90)
            + _row(item.current_hash, 90)
            + _row(item.reason)
            + "</tr>"
        )
    return """
<table>
<thead><tr><th>Checked</th><th>Status</th><th>Path</th><th>Baseline Hash</th><th>Current Hash</th><th>Reason</th></tr></thead>
<tbody>{}</tbody>
</table>
""".format("".join(rows))


def _summary_list(rows, key: str) -> str:
    if not rows:
        return "<p>No data.</p>"
    return "<ul>" + "".join(f"<li><strong>{escape(str(row[key] or 'Unknown'))}</strong>: {row['total']}</li>" for row in rows) + "</ul>"


def generate_html_report() -> Path:
    reports_dir = Path(settings.BASE_DIR) / "reports"
    reports_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = reports_dir / f"secure_file_transfer_audit_{timestamp}.html"

    total_events = FileEvent.objects.count()
    total_alerts = Alert.objects.count()
    unauthorized = FileEvent.objects.filter(is_authorized=False).count()
    sensitive = FileEvent.objects.filter(is_sensitive=True).count()
    critical = FileEvent.objects.filter(severity="Critical").count()
    high = FileEvent.objects.filter(severity="High").count()
    bulk_count = BulkTransferIncident.objects.count()
    email_count = SimulatedEmailAlert.objects.count()
    policy = MonitoringPolicy.objects.filter(is_active=True).first()

    recent_events = list(FileEvent.objects.all()[:50])
    recent_alerts = list(Alert.objects.select_related("event")[:30])
    integrity_history = list(IntegrityCheckHistory.objects.all()[:30])
    severity_rows = list(FileEvent.objects.values("severity").annotate(total=Count("id")).order_by("-total"))
    user_rows = list(FileEvent.objects.values("username").annotate(total=Count("id")).order_by("-total")[:10])
    category_rows = list(FileEvent.objects.values("sensitivity_category").annotate(total=Count("id")).order_by("-total")[:10])

    html = f"""
<!doctype html>
<html><head><meta charset="utf-8"><title>Secure File Transfer Audit Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 28px; background: #f8fafc; color: #111827; }}
.report {{ max-width: 1180px; margin: auto; background: white; padding: 28px; border-radius: 18px; box-shadow: 0 15px 40px rgba(15,23,42,.12); }}
h1 {{ margin-bottom: 4px; }} h2 {{ margin-top: 30px; }} .muted {{ color: #64748b; }}
.grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }}
.card {{ border: 1px solid #e5e7eb; border-radius: 14px; padding: 14px; background: #f8fafc; }}
.card span {{ display:block; color:#64748b; font-size:12px; text-transform:uppercase; font-weight:bold; }} .card strong {{ font-size:28px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }} th, td {{ border: 1px solid #e5e7eb; padding: 8px; vertical-align: top; }} th {{ background: #eef2ff; text-align: left; }}
.badge {{ display:inline-block; padding:4px 8px; border-radius:999px; background:#eef2ff; color:#3730a3; font-weight:bold; }}
ul {{ line-height: 1.7; }} .policy {{ white-space: pre-wrap; background:#f8fafc; border:1px solid #e5e7eb; border-radius:12px; padding:12px; }}
@media print {{ body {{ background: white; }} .report {{ box-shadow: none; }} }}
</style></head><body><div class="report">
<h1>Secure File Transfer Monitoring System - Audit Report</h1>
<p class="muted">Generated: {escape(timezone.localtime(timezone.now()).strftime('%Y-%m-%d %H:%M:%S'))}</p>
<div class="grid">
<div class="card"><span>Total Events</span><strong>{total_events}</strong></div>
<div class="card"><span>Total Alerts</span><strong>{total_alerts}</strong></div>
<div class="card"><span>Unauthorized</span><strong>{unauthorized}</strong></div>
<div class="card"><span>Sensitive Events</span><strong>{sensitive}</strong></div>
<div class="card"><span>Critical Events</span><strong>{critical}</strong></div>
<div class="card"><span>High Events</span><strong>{high}</strong></div>
<div class="card"><span>Bulk Incidents</span><strong>{bulk_count}</strong></div>
<div class="card"><span>Email Alerts</span><strong>{email_count}</strong></div>
</div>
<h2>Executive Summary</h2>
<p>This report summarizes monitored file movement, sensitive data classification, unauthorized transfers, integrity checks, simulated email alerts, and analyst investigation evidence.</p>
<h2>Active Policy</h2>
<div class="policy">{escape(policy.name if policy else 'No active policy')}

Monitored directories:
{escape(policy.monitored_directories if policy else '')}

Sensitive directories:
{escape(policy.sensitive_directories if policy else '')}

Allowed destinations:
{escape(policy.allowed_destinations if policy else '')}

Blocked destination keywords:
{escape(policy.blocked_destination_keywords if policy else '')}</div>
<h2>Severity Breakdown</h2>{_summary_list(severity_rows, 'severity')}
<h2>Top Users by File Activity</h2>{_summary_list(user_rows, 'username')}
<h2>Sensitivity Classification Breakdown</h2>{_summary_list(category_rows, 'sensitivity_category')}
<h2>Recent Alerts</h2>{_alerts_table(recent_alerts)}
<h2>Recent File Activity</h2>{_events_table(recent_events)}
<h2>Integrity Check History</h2>{_integrity_table(integrity_history)}
<h2>Conclusion</h2>
<p>The evidence above demonstrates file transfer logging, DLP-style policy checks, unauthorized movement detection, hash-based integrity verification, bulk transfer detection, alert lifecycle tracking, and audit reporting.</p>
</div></body></html>
"""
    path.write_text(html, encoding="utf-8")
    return path

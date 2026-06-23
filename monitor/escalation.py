from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.contrib.auth.models import User
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.html import strip_tags

from .models import Alert, MonitoringPolicy, SimulatedEmailAlert

SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _unique_emails(values) -> list[str]:
    seen = set()
    cleaned = []
    for value in values:
        email = (value or "").strip().lower()
        if email and "@" in email and email not in seen:
            cleaned.append(email)
            seen.add(email)
    return cleaned


def _split_policy_lines(value: str) -> list[str]:
    return [line.strip() for line in (value or "").splitlines() if line.strip()]


def _path_inside(path: str, roots: list[str]) -> bool:
    if not path:
        return False
    try:
        candidate = Path(path).expanduser().resolve()
    except Exception:
        return False
    for root in roots:
        try:
            candidate.relative_to(Path(root).expanduser().resolve())
            return True
        except Exception:
            continue
    return False


def _matched_keywords(path: str, keywords: list[str]) -> list[str]:
    lowered = (path or "").lower()
    return [kw for kw in keywords if kw and kw.lower() in lowered]


def policy_team_users(policy: MonitoringPolicy, roles: list[str] | None = None, available_only: bool = False):
    qs = User.objects.filter(policy_memberships__policy=policy, policy_memberships__is_active=True)
    if roles:
        qs = qs.filter(policy_memberships__role__in=roles)
    if available_only:
        qs = qs.filter(sftm_profile__availability_status="available")
    return qs.distinct().order_by("username")


def policy_team_emails(policy: MonitoringPolicy, roles: list[str] | None = None, available_only: bool = False) -> list[str]:
    return _unique_emails(policy_team_users(policy, roles=roles, available_only=available_only).values_list("email", flat=True))


def severity_explanation(severity: str) -> str:
    return {
        "Critical": "Critical means the event matched strong data-loss indicators, such as a sensitive file appearing in an unapproved or blocked destination. Immediate review is required.",
        "High": "High means the event involves sensitive data or an unsafe movement pattern and should be investigated promptly.",
        "Medium": "Medium means the activity matched a sensitivity rule, but the destination or context needs review before escalation.",
        "Low": "Low means the event is useful for evidence and monitoring, but it does not currently show strong exfiltration indicators.",
        "Info": "Info means the event was recorded for visibility and audit evidence.",
    }.get(severity, "The event was categorized using the configured monitoring policy and risk score.")


def risk_band(score: int) -> str:
    if score >= 90:
        return "Critical Risk"
    if score >= 65:
        return "High Risk"
    if score >= 35:
        return "Medium Risk"
    if score >= 10:
        return "Low Risk"
    return "Informational"


def observed_file_name(alert: Alert) -> str:
    event = alert.event
    return Path(event.destination_path or event.source_path or "Unknown file").name or "Unknown file"


def _short_path(path: str) -> str:
    if not path:
        return "N/A"
    try:
        parts = Path(path).parts
        if len(parts) > 4:
            return "/".join(parts[-4:])
    except Exception:
        pass
    return path


def alert_path_details(alert: Alert) -> dict:
    """Return plain-language path details without inventing a source path.

    Copy operations are usually reported by the operating system as a "created"
    event at the new location. In that case the monitor knows where the copied
    file appeared, but not the original file path. The UI/email should say that
    clearly instead of displaying an incorrect source.
    """
    event = alert.event
    event_type = event.event_type or "unknown"
    observed = event.destination_path or event.source_path or "N/A"
    file_name = Path(observed).name if observed and observed != "N/A" else "Unknown file"

    if event_type == "copied":
        destination = event.destination_path or "N/A"
        return {
            "movement_label": "File copied",
            "plain_action": "A sensitive file was copied",
            "file_name": file_name,
            "detected_location_label": "Destination",
            "detected_location": destination,
            "detected_location_short": _short_path(destination),
            "source_display": event.source_path or "N/A",
            "destination_display": destination,
            "observed_display": destination,
            "summary_path_label": "Destination",
            "explanation": "The monitor detected a newly created destination file and matched it to a source file with the same filename and hash in a sensitive folder.",
            "show_source": bool(event.source_path),
            "show_destination": True,
        }
    if event_type == "created" and not event.destination_path:
        location = event.source_path or "N/A"
        return {
            "movement_label": "File created",
            "plain_action": "A new file was created",
            "file_name": file_name,
            "detected_location_label": "Created file",
            "detected_location": location,
            "detected_location_short": _short_path(location),
            "source_display": "N/A",
            "destination_display": location,
            "observed_display": location,
            "summary_path_label": "Created file",
            "explanation": "The monitor detected a new file at this location. No separate source path is available for a normal created-file event.",
            "show_source": False,
            "show_destination": True,
        }
    if event_type == "moved":
        destination = event.destination_path or "N/A"
        return {
            "movement_label": "File moved or renamed",
            "plain_action": "A file was moved",
            "file_name": file_name,
            "detected_location_label": "New location",
            "detected_location": destination,
            "detected_location_short": _short_path(destination),
            "source_display": event.source_path or "N/A",
            "destination_display": destination,
            "observed_display": destination,
            "summary_path_label": "New location",
            "explanation": "The monitor captured the previous path and the new path for this movement.",
            "show_source": True,
            "show_destination": True,
        }
    if event_type == "modified":
        location = event.source_path or event.destination_path or "N/A"
        return {
            "movement_label": "File modified",
            "plain_action": "A monitored file was modified",
            "file_name": file_name,
            "detected_location_label": "Modified file",
            "detected_location": location,
            "detected_location_short": _short_path(location),
            "source_display": location,
            "destination_display": "N/A",
            "observed_display": location,
            "summary_path_label": "Modified file",
            "explanation": "The file content or metadata changed inside a monitored location.",
            "show_source": True,
            "show_destination": False,
        }
    if event_type == "deleted":
        location = event.source_path or event.destination_path or "N/A"
        return {
            "movement_label": "File deleted",
            "plain_action": "A monitored file was deleted",
            "file_name": file_name,
            "detected_location_label": "Deleted file",
            "detected_location": location,
            "detected_location_short": _short_path(location),
            "source_display": location,
            "destination_display": "N/A",
            "observed_display": location,
            "summary_path_label": "Deleted file",
            "explanation": "The monitored file was removed from the filesystem.",
            "show_source": True,
            "show_destination": False,
        }
    return {
        "movement_label": event_type.replace("_", " ").title(),
        "plain_action": "A monitored file event was detected",
        "file_name": file_name,
        "detected_location_label": "Observed path",
        "detected_location": observed,
        "detected_location_short": _short_path(observed),
        "source_display": event.source_path or "N/A",
        "destination_display": event.destination_path or "N/A",
        "observed_display": observed,
        "summary_path_label": "Observed path",
        "explanation": "The event was recorded by the monitoring engine for policy evaluation.",
        "show_source": bool(event.source_path),
        "show_destination": bool(event.destination_path),
    }


def destination_assessment(alert: Alert) -> str:
    event = alert.event
    policy = event.policy
    details = alert_path_details(alert)
    destination = details.get("detected_location") or details.get("observed_display")
    if not policy or not destination or destination.startswith("N/A") or destination.startswith("Not available"):
        return "Location context is not available for this event."
    allowed = _path_inside(destination, policy.allowed_list())
    sensitive = _path_inside(destination, policy.sensitive_list())
    blocked = _matched_keywords(destination, policy.blocked_keyword_list())
    if allowed:
        return "Destination is inside an approved destination folder."
    if sensitive:
        return "Destination is inside the sensitive monitored folder."
    if blocked:
        return f"Destination matched blocked keyword(s): {', '.join(blocked[:5])}."
    if not event.is_authorized:
        return "Destination is outside approved destinations."
    return "No blocked destination keyword was matched."


def categorized_reason_items(alert: Alert) -> list[str]:
    event = alert.event
    policy = event.policy
    text = f"{event.reason or ''}; {event.classification_reason or ''}".lower()
    details = alert_path_details(alert)
    observed = details.get("detected_location") or details.get("observed_display")
    items: list[str] = []

    if "restricted filename" in text:
        items.append("Restricted filename matched")
    if "sensitive filename keyword" in text or "keyword" in text:
        items.append("Sensitive keyword matched")
    if "sensitive extension" in text:
        items.append("Sensitive file extension")
    if "sensitive directory" in text or "inside sensitive directory" in text or "located inside sensitive directory" in text:
        items.append("Sensitive directory rule")
    if policy:
        blocked = _matched_keywords(observed, policy.blocked_keyword_list())
        if blocked:
            items.append(f"Blocked destination: {', '.join(blocked[:3])}")
    if "outside approved" in text or "unapproved" in text or not event.is_authorized:
        items.append("Outside approved destination")
    if "bulk transfer" in text:
        items.append("Bulk movement pattern")
    if "integrity" in text or "hash mismatch" in text:
        items.append("Hash/integrity concern")
    if event.sensitivity_category and event.sensitivity_category != "Normal" and not items:
        items.append(event.sensitivity_category)
    if not items:
        items.append("Matched monitoring policy")
    return list(dict.fromkeys(items))[:5]


def incident_summary(alert: Alert) -> str:
    event = alert.event
    details = alert_path_details(alert)
    file_name = details.get("file_name") or observed_file_name(alert)
    location = details.get("detected_location_short") or details.get("detected_location") or "the monitored workspace"
    assessment = destination_assessment(alert)

    if event.event_type == "copied":
        return f"{file_name} was copied from {_short_path(details['source_display'])} to {_short_path(details['destination_display'])}. {assessment}"
    if event.event_type == "created":
        return f"{file_name} was created at {location}. {assessment}"
    if event.event_type == "moved":
        return f"{file_name} moved from {_short_path(details['source_display'])} to {_short_path(details['destination_display'])}. {assessment}"
    if event.event_type == "modified":
        return f"{file_name} was modified at {location}."
    if event.event_type == "deleted":
        return f"{file_name} was deleted from {location}."
    if event.event_type == "bulk_transfer":
        return f"A high number of file events was detected near {location}."
    return f"{file_name} generated a monitored {event.event_type} event at {location}."


def simple_reason(alert: Alert) -> str:
    rules = categorized_reason_items(alert)
    if not rules:
        return "The activity matched the configured monitoring policy."
    if len(rules) == 1:
        return f"Matched rule: {rules[0]}."
    return "Matched rules: " + "; ".join(rules[:3]) + "."


def primary_action(alert: Alert, escalation_reason: str = "") -> str:
    event = alert.event
    if escalation_reason:
        return "This alert was not claimed in time. Assign it to an admin or analyst and review the file movement now."
    if not event.is_authorized:
        return "Confirm whether this file movement was approved. If not approved, remove the file from the risky location and document the incident."
    if event.event_type == "deleted":
        return "Confirm whether the deletion was approved. Restore the file if required and document the result."
    if event.event_type == "modified":
        return "Confirm whether the change was expected. Review hash evidence if needed and document the result."
    return "Review the activity with the user or data owner, document the outcome, and close the alert only after validation."


def recommended_steps(alert: Alert, escalation_reason: str = "") -> list[str]:
    event = alert.event
    steps = []
    if escalation_reason or alert.owner_name == "Unassigned":
        steps.append("Claim or assign the alert.")
    steps.append("Check whether the file activity was approved.")
    if not event.is_authorized:
        steps.append("If not approved, remove the file from the risky destination.")
    steps.append("Add investigation notes and close the alert as resolved or false positive.")
    return steps[:4]


def alert_email_context(alert: Alert, title: str, escalation_reason: str = "") -> dict:
    event = alert.event
    policy = event.policy
    details = alert_path_details(alert)
    dashboard_url = getattr(settings, "SFTM_DASHBOARD_URL", "").rstrip("/")
    alert_url = f"{dashboard_url}/alerts/{alert.pk}/" if dashboard_url else ""
    return {
        "title": title,
        "alert": alert,
        "event": event,
        "policy": policy,
        "policy_name": policy.name if policy else "No Policy",
        "file_name": observed_file_name(alert),
        "owner": alert.owner_name,
        "risk_band": risk_band(event.risk_score),
        "severity_explanation": severity_explanation(event.severity),
        "category_items": categorized_reason_items(alert),
        "escalation_reason": escalation_reason,
        "logo_url": getattr(settings, "PROJECT_LOGO_URL", ""),
        "dashboard_url": dashboard_url,
        "alert_url": alert_url,
        "created_at": timezone.localtime(alert.created_at).strftime("%Y-%m-%d %H:%M:%S"),
        "recommended_action": primary_action(alert, escalation_reason),
        "recommended_steps": recommended_steps(alert, escalation_reason),
        "incident_summary": incident_summary(alert),
        "simple_reason": simple_reason(alert),
        "path_details": details,
        "destination_assessment": destination_assessment(alert),
    }


def build_alert_email(alert: Alert, title: str, escalation_reason: str = "") -> tuple[str, str, str]:
    event = alert.event
    context = alert_email_context(alert, title, escalation_reason)
    subject_prefix = "ACTION REQUIRED" if escalation_reason else "SFTM ALERT"
    subject = f"[{subject_prefix}] {event.severity} - {context['file_name']}"
    html_body = render_to_string("monitor/emails/alert_email.html", context)
    lines = [
        title,
        "",
        "What happened",
        context["incident_summary"],
        "",
        "Why the system flagged it",
        context["simple_reason"],
        "",
        "Key details",
        f"Policy: {context['policy_name']}",
        f"Alert ID: {alert.id}",
        f"Severity: {event.severity}",
        f"Risk score: {event.risk_score}/100 ({context['risk_band']})",
        f"Status: {alert.get_status_display()}",
        f"Owner: {context['owner']}",
        f"Event type: {context['path_details']['movement_label']}",
        f"{context['path_details']['detected_location_label']}: {context['path_details']['detected_location']}",
    ]
    if context['path_details'].get('show_source'):
        lines.append(f"Source: {context['path_details']['source_display']}")
    if context['path_details'].get('show_destination') and context['path_details']['destination_display'] != context['path_details']['detected_location']:
        lines.append(f"Destination: {context['path_details']['destination_display']}")
    if escalation_reason:
        lines += ["", "Escalation reason", escalation_reason]
    lines += [
        "",
        "Required action",
        context["recommended_action"],
    ]
    if context["alert_url"]:
        lines += ["", f"Open alert: {context['alert_url']}"]
    body = "\n".join(lines)
    return subject, body, html_body


def send_and_record_email(
    recipients: list[str],
    subject: str,
    body: str,
    alert: Alert | None = None,
    purpose: str = "system",
    html_body: str = "",
) -> int:
    recipients = _unique_emails(recipients)
    if not recipients:
        return 0
    sent = 0
    status = "Queued"
    error = ""
    try:
        message = EmailMultiAlternatives(
            subject=subject,
            body=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=recipients,
        )
        if html_body:
            message.attach_alternative(html_body, "text/html")
        message.send(fail_silently=False)
        status = "Sent"
        sent = len(recipients)
    except Exception as exc:
        status = "Failed - check SMTP settings"
        error = str(exc)
    for recipient in recipients:
        SimulatedEmailAlert.objects.create(
            alert=alert,
            recipient=recipient,
            subject=subject,
            body=body,
            purpose=purpose,
            delivery_status=status,
            error_message=error,
        )
    return sent


def should_email_policy(policy: MonitoringPolicy, severity: str) -> bool:
    threshold = policy.email_alert_min_severity
    if threshold == "Disabled":
        return False
    if threshold == "Critical":
        return severity == "Critical"
    return severity in {"High", "Critical"}


def notify_alert_created(alert: Alert) -> None:
    policy = alert.event.policy
    if not policy or alert.initial_notification_sent:
        return
    if not should_email_policy(policy, alert.event.severity):
        return
    recipients = []
    recipients += policy.email_recipient_list()
    if policy.notify_policy_team:
        recipients += policy_team_emails(policy, roles=["policy_admin", "analyst"], available_only=False)
    if not recipients:
        return
    subject, body, html_body = build_alert_email(alert, "New File Transfer Alert")
    send_and_record_email(recipients, subject, body, alert=alert, purpose="alert", html_body=html_body)
    alert.initial_notification_sent = True
    alert.save(update_fields=["initial_notification_sent", "updated_at"])


def due_for_escalation(alert: Alert, now=None) -> tuple[bool, str]:
    now = now or timezone.now()
    policy = alert.event.policy
    if not policy or not policy.escalation_enabled or alert.escalated:
        return False, ""
    if alert.status not in {"open"}:
        return False, ""
    if alert.claimed_by_id or alert.assigned_user_id:
        return False, ""
    available_team = policy_team_users(policy, roles=["policy_admin", "analyst"], available_only=True).count()
    if available_team == 0:
        return True, "No assigned policy admin or analyst is marked Available."
    age_minutes = (now - alert.created_at).total_seconds() / 60
    if age_minutes >= policy.escalation_after_minutes:
        return True, f"Alert has not been claimed within {policy.escalation_after_minutes} minutes."
    return False, ""


def escalate_alert(alert: Alert, reason: str = "") -> bool:
    policy = alert.event.policy
    if not policy or alert.escalated:
        return False
    recipients = []
    recipients += policy.escalation_recipient_list()
    recipients += policy_team_emails(policy, roles=["policy_admin"], available_only=False)
    recipients = _unique_emails(recipients)
    if not recipients:
        return False
    subject, body, html_body = build_alert_email(alert, "Unclaimed Alert Escalation", reason)
    send_and_record_email(recipients, subject, body, alert=alert, purpose="escalation", html_body=html_body)
    alert.escalated = True
    alert.escalated_at = timezone.now()
    alert.escalation_recipients = "\n".join(recipients)
    alert.escalation_reason = reason
    alert.save(update_fields=["escalated", "escalated_at", "escalation_recipients", "escalation_reason", "updated_at"])
    return True


def process_due_escalations() -> int:
    count = 0
    for alert in Alert.objects.select_related("event", "event__policy").filter(status="open", escalated=False):
        due, reason = due_for_escalation(alert)
        if due and escalate_alert(alert, reason):
            count += 1
    return count

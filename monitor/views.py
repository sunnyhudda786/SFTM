from __future__ import annotations

import csv
import random
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group, User
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.html import strip_tags

from .escalation import (
    alert_path_details,
    categorized_reason_items,
    destination_assessment,
    incident_summary,
    primary_action,
    process_due_escalations,
    recommended_steps,
    risk_band,
    send_and_record_email,
    severity_explanation,
    simple_reason,
)
from .forms import (
    AlertAssignForm,
    AlertUpdateForm,
    AvailabilityForm,
    MonitoringPolicyForm,
    OTPRequestForm,
    OTPVerifyForm,
    TeamUserCreationForm,
)
from .models import (
    Alert,
    BulkTransferIncident,
    FileEvent,
    IntegrityBaseline,
    IntegrityCheckHistory,
    MonitoringPolicy,
    PasswordResetOTP,
    PolicyMembership,
    SimulatedEmailAlert,
    UserProfile,
)
from .reports import generate_html_report
from .roles import (
    ROLE_NAMES,
    admin_required,
    allowed_policy_ids,
    can_view_policy,
    ensure_roles,
    is_admin,
    is_analyst,
    is_auditor,
    is_policy_admin,
    is_policy_analyst,
)


SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]


def _get_policy() -> MonitoringPolicy | None:
    return MonitoringPolicy.objects.filter(is_active=True).order_by("-updated_at").first()


def _percent(value: int, max_value: int) -> int:
    if max_value <= 0:
        return 0
    return max(4 if value else 0, round((value / max_value) * 100))


def _ensure_profile(user) -> UserProfile | None:
    if user and user.is_authenticated:
        profile, _ = UserProfile.objects.get_or_create(user=user)
        return profile
    return None


def _policy_filter_kwargs(user):
    ids = allowed_policy_ids(user)
    if ids is None:
        return {}
    return {"policy_id__in": ids}


def _scope_events(qs, user):
    ids = allowed_policy_ids(user)
    if ids is None:
        return qs
    return qs.filter(policy_id__in=ids)


def _scope_alerts(qs, user):
    ids = allowed_policy_ids(user)
    if ids is None:
        return qs
    return qs.filter(event__policy_id__in=ids)


def _scope_policies(qs, user):
    ids = allowed_policy_ids(user)
    if ids is None:
        return qs
    return qs.filter(id__in=ids)


def _can_update_alert(user, alert: Alert) -> bool:
    policy = alert.event.policy
    if not policy:
        return bool(user.is_superuser)
    if is_policy_admin(user, policy):
        return True
    return bool(alert.claimed_by_id == user.id or alert.assigned_user_id == user.id)


def _can_claim_alert(user, alert: Alert) -> bool:
    policy = alert.event.policy
    return bool(policy and is_policy_analyst(user, policy) and not alert.is_claimed and alert.status == "open")


def _policy_or_404_for_user(request, pk: int) -> MonitoringPolicy:
    policy = get_object_or_404(MonitoringPolicy, pk=pk)
    if not can_view_policy(request.user, policy):
        messages.error(request, "You are not assigned to this policy.")
        raise Http404("Policy not found")
    return policy


@login_required
def dashboard(request):
    profile = _ensure_profile(request.user)
    policy = _get_policy()
    event_qs = _scope_events(FileEvent.objects.all(), request.user)
    alert_qs = _scope_alerts(Alert.objects.select_related("event", "event__policy", "assigned_user", "claimed_by"), request.user)
    policy_qs = _scope_policies(MonitoringPolicy.objects.prefetch_related("memberships", "memberships__user"), request.user)

    is_admin_view = is_admin(request.user)
    is_analyst_view = is_analyst(request.user)
    is_auditor_view = is_auditor(request.user)

    total_events = event_qs.count()
    all_alerts = alert_qs.count()
    active_alert_qs = alert_qs.exclude(status__in=["closed", "false_positive"])
    total_alerts = active_alert_qs.count()
    sensitive_events = event_qs.filter(is_sensitive=True).count()
    unauthorized_events = event_qs.filter(is_authorized=False).count()
    critical_alerts = active_alert_qs.filter(event__severity="Critical").count()
    high_alerts = active_alert_qs.filter(event__severity="High").count()
    latest_events = event_qs.select_related("policy")[:10]
    latest_alerts = active_alert_qs[:8]
    open_alerts = active_alert_qs.filter(status="open").count()
    investigating_alerts = active_alert_qs.filter(status="investigating").count()
    resolved_alerts = alert_qs.filter(status__in=["closed", "false_positive"]).count()
    false_positive_alerts = alert_qs.filter(status="false_positive").count()
    unassigned_alerts_qs = active_alert_qs.filter(status="open", assigned_user__isnull=True, claimed_by__isnull=True)
    unassigned_alerts = unassigned_alerts_qs.count()
    assigned_active_alerts = active_alert_qs.exclude(Q(assigned_user__isnull=True) & Q(claimed_by__isnull=True)).count()
    my_alerts_qs = active_alert_qs.filter(Q(assigned_user=request.user) | Q(claimed_by=request.user))
    my_alerts = my_alerts_qs.count()
    closed_today = alert_qs.filter(status__in=["closed", "false_positive"], closed_at__date=timezone.now().date()).count()
    escalated_alerts = active_alert_qs.filter(escalated=True).count()

    bulk_qs = BulkTransferIncident.objects.select_related("policy")
    ids = allowed_policy_ids(request.user)
    if ids is not None:
        bulk_qs = bulk_qs.filter(policy_id__in=ids)
    bulk_incidents = bulk_qs.count()
    simulated_emails = SimulatedEmailAlert.objects.filter(alert__in=alert_qs).count()

    severity_raw = {row["event__severity"]: row["total"] for row in active_alert_qs.values("event__severity").annotate(total=Count("id"))}
    severity_counts = [{"label": item, "total": severity_raw.get(item, 0)} for item in SEVERITY_ORDER]
    max_severity = max([row["total"] for row in severity_counts], default=0)
    severity_counts = [{**row, "percent": _percent(row["total"], max_severity)} for row in severity_counts]

    alert_status_counts = [
        {"label": "Open", "value": "open", "total": open_alerts, "percent": _percent(open_alerts, max(all_alerts, 1))},
        {"label": "Investigating", "value": "investigating", "total": investigating_alerts, "percent": _percent(investigating_alerts, max(all_alerts, 1))},
        {"label": "Resolved", "value": "closed", "total": resolved_alerts, "percent": _percent(resolved_alerts, max(all_alerts, 1))},
    ]
    active_alert_percent = round((total_alerts / all_alerts) * 100) if all_alerts else 0
    resolved_alert_percent = round((resolved_alerts / all_alerts) * 100) if all_alerts else 0
    claim_rate_percent = round((assigned_active_alerts / total_alerts) * 100) if total_alerts else 0

    event_counts = []
    for value, label in FileEvent.EVENT_CHOICES:
        count = event_qs.filter(event_type=value).count()
        event_counts.append({"label": label, "total": count})
    max_event = max([row["total"] for row in event_counts], default=0)
    event_counts = [{**row, "percent": _percent(row["total"], max_event)} for row in event_counts]

    start_date = timezone.now().date() - timedelta(days=6)
    daily_counts = []
    for i in range(7):
        day = start_date + timedelta(days=i)
        count = event_qs.filter(timestamp__date=day).count()
        daily_counts.append({"label": day.strftime("%b %d"), "total": count})
    max_daily = max([row["total"] for row in daily_counts], default=0)
    daily_counts = [{**row, "percent": _percent(row["total"], max_daily)} for row in daily_counts]

    top_users = list(event_qs.values("username").annotate(total=Count("id")).order_by("-total")[:5])
    max_user = max([row["total"] for row in top_users], default=0)
    top_users = [{"label": row["username"] or "Unknown", "total": row["total"], "percent": _percent(row["total"], max_user)} for row in top_users]

    integrity_raw = list(IntegrityCheckHistory.objects.values("status").annotate(total=Count("id")).order_by("-total")[:6])
    max_integrity = max([row["total"] for row in integrity_raw], default=0)
    integrity_counts = [{"label": row["status"], "total": row["total"], "percent": _percent(row["total"], max_integrity)} for row in integrity_raw]

    scoped_policy_ids = list(policy_qs.values_list("id", flat=True))
    if ids is None:
        visible_users = User.objects.all().order_by("username")
    elif scoped_policy_ids:
        visible_users = User.objects.filter(policy_memberships__policy_id__in=scoped_policy_ids, policy_memberships__is_active=True).distinct().order_by("username")
    else:
        visible_users = User.objects.none()
    for u in visible_users:
        UserProfile.objects.get_or_create(user=u)
    team_profiles = UserProfile.objects.select_related("user").filter(user__in=visible_users).order_by("availability_status", "user__username")
    availability_raw = {row["availability_status"]: row["total"] for row in team_profiles.values("availability_status").annotate(total=Count("id"))}
    availability_counts = [
        {"label": label, "value": value, "total": availability_raw.get(value, 0)}
        for value, label in UserProfile.AVAILABILITY_CHOICES
    ]
    available_team = availability_raw.get("available", 0)

    policy_rows = []
    for pol in policy_qs[:8]:
        admins = [m.user for m in pol.memberships.all() if m.is_active and m.role == "policy_admin"]
        analysts = [m.user for m in pol.memberships.all() if m.is_active and m.role == "analyst"]
        auditors = [m.user for m in pol.memberships.all() if m.is_active and m.role == "auditor"]
        policy_alerts = alert_qs.filter(event__policy=pol)
        policy_rows.append({
            "policy": pol,
            "admins": admins,
            "analysts": analysts,
            "auditors": auditors,
            "open_alerts": policy_alerts.exclude(status__in=["closed", "false_positive"]).count(),
            "unassigned_alerts": policy_alerts.exclude(status__in=["closed", "false_positive"]).filter(status="open", assigned_user__isnull=True, claimed_by__isnull=True).count(),
            "critical_high": policy_alerts.filter(event__severity__in=["Critical", "High"]).exclude(status__in=["closed", "false_positive"]).count(),
            "escalated": policy_alerts.exclude(status__in=["closed", "false_positive"]).filter(escalated=True).count(),
        })

    analyst_memberships = PolicyMembership.objects.select_related("policy").filter(user=request.user, is_active=True, role__in=["analyst", "policy_admin"])
    analyst_policy_ids = list(analyst_memberships.values_list("policy_id", flat=True))
    claimable_alerts = unassigned_alerts_qs.filter(event__policy_id__in=analyst_policy_ids) if analyst_policy_ids else unassigned_alerts_qs if is_admin_view else Alert.objects.none()

    context = {
        "policy": policy,
        "policy_count": policy_qs.count(),
        "total_events": total_events,
        "total_alerts": total_alerts,
        "all_alerts": all_alerts,
        "resolved_alerts": resolved_alerts,
        "false_positive_alerts": false_positive_alerts,
        "investigating_alerts": investigating_alerts,
        "assigned_active_alerts": assigned_active_alerts,
        "alert_status_counts": alert_status_counts,
        "active_alert_percent": active_alert_percent,
        "resolved_alert_percent": resolved_alert_percent,
        "claim_rate_percent": claim_rate_percent,
        "sensitive_events": sensitive_events,
        "unauthorized_events": unauthorized_events,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "latest_events": latest_events,
        "latest_alerts": latest_alerts,
        "severity_counts": severity_counts,
        "event_counts": event_counts,
        "daily_counts": daily_counts,
        "top_users": top_users,
        "integrity_counts": integrity_counts,
        "open_alerts": open_alerts,
        "unassigned_alerts": unassigned_alerts,
        "my_alerts": my_alerts,
        "closed_today": closed_today,
        "escalated_alerts": escalated_alerts,
        "bulk_incidents": bulk_incidents,
        "simulated_emails": simulated_emails,
        "team_profiles": team_profiles[:8],
        "availability_counts": availability_counts,
        "available_team": available_team,
        "policy_rows": policy_rows,
        "my_queue": my_alerts_qs[:8],
        "claimable_alerts": claimable_alerts[:8],
        "assigned_policies": analyst_memberships,
        "is_admin_dashboard": is_admin_view,
        "is_analyst_dashboard": is_analyst_view,
        "is_auditor_dashboard": is_auditor_view,
        "user_profile": profile,
    }
    return render(request, "monitor/dashboard.html", context)


@login_required
def events(request):
    qs = _scope_events(FileEvent.objects.select_related("policy"), request.user)
    query = request.GET.get("q", "").strip()
    severity = request.GET.get("severity", "").strip()
    event_type = request.GET.get("event_type", "").strip()
    authorized = request.GET.get("authorized", "").strip()
    sensitive = request.GET.get("sensitive", "").strip()
    policy_id = request.GET.get("policy", "").strip()

    if query:
        qs = qs.filter(
            Q(source_path__icontains=query)
            | Q(destination_path__icontains=query)
            | Q(reason__icontains=query)
            | Q(username__icontains=query)
            | Q(process_name__icontains=query)
            | Q(sensitivity_category__icontains=query)
            | Q(classification_reason__icontains=query)
        )
    if severity:
        qs = qs.filter(severity=severity)
    if event_type:
        qs = qs.filter(event_type=event_type)
    if policy_id:
        qs = qs.filter(policy_id=policy_id)
    if authorized == "yes":
        qs = qs.filter(is_authorized=True)
    elif authorized == "no":
        qs = qs.filter(is_authorized=False)
    if sensitive == "yes":
        qs = qs.filter(is_sensitive=True)
    elif sensitive == "no":
        qs = qs.filter(is_sensitive=False)

    paginator = Paginator(qs, 25)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(
        request,
        "monitor/events.html",
        {
            "page_obj": page_obj,
            "severity_choices": FileEvent.SEVERITY_CHOICES,
            "event_choices": FileEvent.EVENT_CHOICES,
            "policies": _scope_policies(MonitoringPolicy.objects.all(), request.user),
            "filters": {"q": query, "severity": severity, "event_type": event_type, "authorized": authorized, "sensitive": sensitive, "policy": policy_id},
        },
    )


@login_required
def event_detail(request, pk: int):
    event = get_object_or_404(FileEvent.objects.select_related("policy"), pk=pk)
    if event.policy and not can_view_policy(request.user, event.policy):
        raise Http404("Event not found")
    alert = getattr(event, "alert", None)
    return render(request, "monitor/event_detail.html", {"event": event, "alert": alert})


@login_required
def alerts(request):
    qs = _scope_alerts(Alert.objects.select_related("event", "event__policy", "assigned_user", "claimed_by"), request.user)
    status = request.GET.get("status", "").strip()
    severity = request.GET.get("severity", "").strip()
    query = request.GET.get("q", "").strip()
    policy_id = request.GET.get("policy", "").strip()
    assigned = request.GET.get("assigned", "").strip()
    if status:
        qs = qs.filter(status=status)
    if severity:
        qs = qs.filter(event__severity=severity)
    if policy_id:
        qs = qs.filter(event__policy_id=policy_id)
    if assigned == "me":
        qs = qs.filter(Q(assigned_user=request.user) | Q(claimed_by=request.user))
    elif assigned == "unassigned":
        qs = qs.filter(assigned_user__isnull=True, claimed_by__isnull=True)
    if query:
        qs = qs.filter(Q(event__reason__icontains=query) | Q(event__source_path__icontains=query) | Q(event__destination_path__icontains=query))
    paginator = Paginator(qs, 20)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(
        request,
        "monitor/alerts.html",
        {
            "page_obj": page_obj,
            "status": status,
            "severity": severity,
            "query": query,
            "assigned": assigned,
            "policies": _scope_policies(MonitoringPolicy.objects.all(), request.user),
            "status_choices": Alert.STATUS_CHOICES,
            "severity_choices": FileEvent.SEVERITY_CHOICES,
        },
    )


@login_required
def alert_detail(request, pk: int):
    alert = get_object_or_404(Alert.objects.select_related("event", "event__policy", "assigned_user", "claimed_by"), pk=pk)
    policy = alert.event.policy
    if policy and not can_view_policy(request.user, policy):
        raise Http404("Alert not found")

    emails = alert.email_notifications.all()
    can_claim = _can_claim_alert(request.user, alert)
    can_update = _can_update_alert(request.user, alert)
    can_assign = bool(policy and is_policy_admin(request.user, policy))
    form = AlertUpdateForm(instance=alert)
    assign_form = AlertAssignForm(instance=alert, policy=policy)

    if request.method == "POST":
        action = request.POST.get("action", "update")
        if action == "claim":
            if not can_claim:
                messages.error(request, "This alert is already assigned or you are not assigned to this policy.")
            else:
                alert.claimed_by = request.user
                alert.assigned_user = request.user
                alert.assigned_to = request.user.username
                alert.claimed_at = timezone.now()
                alert.status = "investigating"
                alert.last_updated_by = request.user
                alert.save(update_fields=["claimed_by", "assigned_user", "assigned_to", "claimed_at", "status", "last_updated_by", "updated_at"])
                messages.success(request, "Alert claimed. You are now the alert owner.")
            return redirect("alert_detail", pk=alert.pk)

        if action == "release":
            if not can_update:
                messages.error(request, "Only the owner or policy admin can release this alert.")
            else:
                alert.claimed_by = None
                alert.assigned_user = None
                alert.assigned_to = ""
                alert.claimed_at = None
                if alert.status == "investigating":
                    alert.status = "open"
                alert.last_updated_by = request.user
                alert.save(update_fields=["claimed_by", "assigned_user", "assigned_to", "claimed_at", "status", "last_updated_by", "updated_at"])
                messages.success(request, "Alert released back to the open queue.")
            return redirect("alert_detail", pk=alert.pk)

        if action == "assign":
            if not can_assign:
                messages.error(request, "Only a policy admin can assign or reassign this alert.")
            else:
                assign_form = AlertAssignForm(request.POST, instance=alert, policy=policy)
                if assign_form.is_valid():
                    updated = assign_form.save(commit=False)
                    updated.claimed_by = updated.assigned_user
                    updated.assigned_to = updated.assigned_user.username if updated.assigned_user else ""
                    updated.claimed_at = timezone.now() if updated.assigned_user else None
                    updated.status = "investigating" if updated.assigned_user else "open"
                    updated.last_updated_by = request.user
                    updated.save()
                    messages.success(request, "Alert assignment updated.")
            return redirect("alert_detail", pk=alert.pk)

        if not can_update:
            messages.error(request, "Only the assigned owner or policy admin can update this investigation.")
            return redirect("alert_detail", pk=alert.pk)
        form = AlertUpdateForm(request.POST, instance=alert)
        if form.is_valid():
            updated = form.save(commit=False)
            if updated.status in {"closed", "false_positive"} and not updated.closed_at:
                updated.closed_at = timezone.now()
            if updated.status not in {"closed", "false_positive"}:
                updated.closed_at = None
            updated.last_updated_by = request.user
            updated.save()
            messages.success(request, "Alert investigation updated.")
            return redirect("alert_detail", pk=alert.pk)

    category_items = categorized_reason_items(alert)
    severity_text = severity_explanation(alert.event.severity)
    risk_label = risk_band(alert.event.risk_score)
    path_details = alert_path_details(alert)
    return render(request, "monitor/alert_detail.html", {
        "alert": alert,
        "form": form,
        "assign_form": assign_form,
        "emails": emails,
        "can_claim": can_claim,
        "can_update": can_update,
        "can_assign": can_assign,
        "category_items": category_items,
        "severity_text": severity_text,
        "risk_label": risk_label,
        "path_details": path_details,
        "incident_summary": incident_summary(alert),
        "simple_reason": simple_reason(alert),
        "primary_action": primary_action(alert, alert.escalation_reason or ""),
        "recommended_steps": recommended_steps(alert, alert.escalation_reason or ""),
        "destination_assessment": destination_assessment(alert),
    })


@admin_required
def policies(request):
    ensure_roles()
    policy_list = _scope_policies(MonitoringPolicy.objects.prefetch_related("memberships", "memberships__user"), request.user).order_by("-is_active", "-updated_at")
    return render(request, "monitor/policies.html", {"policies": policy_list})


@admin_required
def policy_create(request):
    if request.method == "POST":
        form = MonitoringPolicyForm(request.POST)
        if form.is_valid():
            policy = form.save(commit=False)
            policy.created_by = request.user
            policy.save()
            form.save_memberships(policy, assigned_by=request.user)
            if request.user.is_authenticated and not request.user.is_superuser:
                PolicyMembership.objects.get_or_create(policy=policy, user=request.user, role="policy_admin", defaults={"assigned_by": request.user, "is_active": True})
            messages.success(request, "Policy created successfully.")
            return redirect("policies")
    else:
        form = MonitoringPolicyForm(initial={
            "hash_algorithm": "sha256",
            "burst_threshold_file_count": 20,
            "burst_threshold_seconds": 60,
            "email_alert_min_severity": "High",
            "escalation_enabled": True,
            "escalation_after_minutes": 5,
            "notify_policy_team": True,
        })
    return render(request, "monitor/policy_form.html", {"form": form, "mode": "Create"})


@admin_required
def policy_edit(request, pk: int):
    policy = _policy_or_404_for_user(request, pk)
    if not is_policy_admin(request.user, policy):
        messages.error(request, "Only the assigned policy admin can edit this policy.")
        return redirect("policies")
    if request.method == "POST":
        form = MonitoringPolicyForm(request.POST, instance=policy)
        if form.is_valid():
            saved = form.save(commit=False)
            saved.save()
            form.save_memberships(saved, assigned_by=request.user)
            messages.success(request, "Policy updated successfully.")
            return redirect("policies")
    else:
        form = MonitoringPolicyForm(instance=policy)
    return render(request, "monitor/policy_form.html", {"form": form, "policy": policy, "mode": "Edit"})


@admin_required
def policy_activate(request, pk: int):
    policy = _policy_or_404_for_user(request, pk)
    if request.method == "POST":
        if not is_policy_admin(request.user, policy):
            messages.error(request, "Only the assigned policy admin can activate this policy.")
        elif not policy.monitored_directories.strip() and not policy.is_active:
            messages.error(request, "Add at least one monitored directory before activating this policy.")
        else:
            policy.is_active = not policy.is_active
            policy.save(update_fields=["is_active", "updated_at"])
            state = "activated" if policy.is_active else "deactivated"
            messages.success(request, f"Policy {state}: {policy.name}.")
    return redirect("policies")


@admin_required
def policy_delete(request, pk: int):
    policy = _policy_or_404_for_user(request, pk)
    if request.method == "POST":
        if not is_policy_admin(request.user, policy):
            messages.error(request, "Only the assigned policy admin can delete this policy.")
        else:
            name = policy.name
            policy.delete()
            messages.success(request, f"Policy deleted: {name}")
    return redirect("policies")


@login_required
def integrity(request):
    status = request.GET.get("status", "").strip()
    baselines = IntegrityBaseline.objects.all().order_by("path")
    history = IntegrityCheckHistory.objects.all()
    if status:
        history = history.filter(status=status)
    history_page = Paginator(history, 25).get_page(request.GET.get("page"))
    return render(request, "monitor/integrity.html", {"baselines": baselines, "history_page": history_page, "status": status, "status_choices": IntegrityCheckHistory.STATUS_CHOICES})


@login_required
def reports(request):
    reports_dir = Path(settings.BASE_DIR) / "reports"
    reports_dir.mkdir(exist_ok=True)
    report_files = sorted(reports_dir.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
    return render(request, "monitor/reports.html", {"report_files": report_files})


@login_required
def generate_report(request):
    path = generate_html_report()
    messages.success(request, f"Audit report generated: {path.name}")
    return redirect("reports")


@login_required
def download_report(request, filename: str):
    reports_dir = Path(settings.BASE_DIR) / "reports"
    path = reports_dir / filename
    if not path.exists() or path.suffix.lower() != ".html":
        raise Http404("Report not found")
    return FileResponse(path.open("rb"), as_attachment=True, filename=path.name)


@login_required
def email_alerts(request):
    qs = SimulatedEmailAlert.objects.select_related("alert", "alert__event", "alert__event__policy")
    ids = allowed_policy_ids(request.user)
    if ids is not None:
        qs = qs.filter(Q(alert__event__policy_id__in=ids) | Q(alert__isnull=True))
    paginator = Paginator(qs, 20)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(request, "monitor/email_alerts.html", {"page_obj": page_obj})


@login_required
def bulk_incidents(request):
    qs = BulkTransferIncident.objects.select_related("policy").all()
    ids = allowed_policy_ids(request.user)
    if ids is not None:
        qs = qs.filter(policy_id__in=ids)
    paginator = Paginator(qs, 20)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(request, "monitor/bulk_incidents.html", {"page_obj": page_obj})


@admin_required
def team_users(request):
    ensure_roles()
    if request.method == "POST" and request.POST.get("action") == "set_availability":
        target = get_object_or_404(User, pk=request.POST.get("user_id"))
        status = request.POST.get("availability_status", "available")
        valid_values = [value for value, _label in UserProfile.AVAILABILITY_CHOICES]
        if status not in valid_values:
            messages.error(request, "Invalid availability status.")
        else:
            profile, _ = UserProfile.objects.get_or_create(user=target)
            profile.availability_status = status
            profile.save(update_fields=["availability_status", "updated_at"])
            messages.success(request, f"Availability updated for {target.username}.")
        return redirect("team_users")

    if request.method == "POST":
        form = TeamUserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "User created and role assigned.")
            return redirect("team_users")
    else:
        form = TeamUserCreationForm()
    users = User.objects.all().order_by("username")
    for user in users:
        UserProfile.objects.get_or_create(user=user)
    groups = Group.objects.filter(name__in=ROLE_NAMES)
    memberships = PolicyMembership.objects.select_related("user", "policy").filter(is_active=True)
    return render(request, "monitor/team_users.html", {"form": form, "users": users, "groups": groups, "memberships": memberships, "availability_choices": UserProfile.AVAILABILITY_CHOICES})


@login_required
def update_availability(request):
    profile = _ensure_profile(request.user)
    if request.method == "POST":
        form = AvailabilityForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, "Availability updated.")
    return redirect(request.META.get("HTTP_REFERER", "dashboard"))


@login_required
def run_escalation_check(request):
    if not is_admin(request.user):
        messages.error(request, "Only Admin can run manual escalation checks.")
        return redirect("dashboard")
    count = process_due_escalations()
    messages.success(request, f"Escalation check complete. {count} alert(s) escalated.")
    return redirect("alerts")


def otp_password_reset_request(request):
    form = OTPRequestForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        email = form.cleaned_data["email"].strip().lower()
        users = User.objects.filter(email__iexact=email, is_active=True)
        if users.exists():
            user = users.first()
            code = f"{random.randint(0, 999999):06d}"
            PasswordResetOTP.objects.filter(user=user, used_at__isnull=True).update(used_at=timezone.now())
            otp = PasswordResetOTP.objects.create(
                user=user,
                email=email,
                code_hash=PasswordResetOTP.hash_code(code),
                expires_at=timezone.now() + timedelta(minutes=getattr(settings, "OTP_EXPIRY_MINUTES", 10)),
            )
            subject = "SFTM Password Reset OTP"
            expiry_minutes = getattr(settings, "OTP_EXPIRY_MINUTES", 10)
            html_body = render_to_string(
                "monitor/emails/otp_email.html",
                {
                    "username": user.username,
                    "otp_code": code,
                    "expiry_minutes": expiry_minutes,
                    "logo_url": getattr(settings, "PROJECT_LOGO_URL", ""),
                },
            )
            body = (
                "Secure File Transfer Monitor password reset OTP\n\n"
                f"Hello {user.username},\n"
                f"Your OTP code is: {code}\n\n"
                f"This OTP expires in {expiry_minutes} minutes. Do not share it with anyone.\n"
                "If you did not request this reset, ignore this email."
            )
            send_and_record_email([email], subject, body, alert=None, purpose="otp", html_body=html_body)
        messages.success(request, "If the email matches an active account, an OTP has been sent.")
        return redirect(f"/password-reset/verify/?email={email}")
    return render(request, "monitor/otp_request.html", {"form": form})


def otp_password_reset_verify(request):
    email = request.GET.get("email") or request.POST.get("email") or ""
    if request.method == "POST":
        form = OTPVerifyForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"].strip().lower()
            code = form.cleaned_data["otp"].strip()
            otp = PasswordResetOTP.objects.filter(email__iexact=email, used_at__isnull=True).select_related("user").first()
            if not otp:
                form.add_error("otp", "OTP is invalid or expired.")
            else:
                otp.attempts += 1
                otp.save(update_fields=["attempts"])
                if otp.attempts > 5:
                    otp.used_at = timezone.now()
                    otp.save(update_fields=["used_at"])
                    form.add_error("otp", "Too many attempts. Request a new OTP.")
                elif not otp.is_valid(code):
                    form.add_error("otp", "OTP is invalid or expired.")
                else:
                    user = otp.user
                    user.set_password(form.cleaned_data["new_password1"])
                    user.save()
                    otp.used_at = timezone.now()
                    otp.save(update_fields=["used_at"])
                    messages.success(request, "Password reset successfully. Please sign in with your new password.")
                    return redirect("login")
    else:
        form = OTPVerifyForm(initial={"email": email})
    return render(request, "monitor/otp_verify.html", {"form": form, "email": email})


@login_required
def export_events_csv(request):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="secure_file_transfer_events.csv"'
    writer = csv.writer(response)
    writer.writerow(["timestamp", "policy", "event_type", "severity", "risk_score", "sensitive", "sensitivity_category", "classification_reason", "authorized", "username", "process_name", "source_path", "destination_path", "hash_before", "hash_after", "integrity_status", "reason"])
    for event in _scope_events(FileEvent.objects.select_related("policy"), request.user).order_by("-timestamp"):
        writer.writerow([event.timestamp, event.policy.name if event.policy else "", event.event_type, event.severity, event.risk_score, event.is_sensitive, event.sensitivity_category, event.classification_reason, event.is_authorized, event.username, event.process_name, event.source_path, event.destination_path, event.hash_before, event.hash_after, event.integrity_status, event.reason])
    return response


@login_required
def export_alerts_csv(request):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="secure_file_transfer_alerts.csv"'
    writer = csv.writer(response)
    writer.writerow(["created_at", "policy", "status", "severity", "risk_score", "owner", "escalated", "escalated_at", "reason", "recommended_action", "path"])
    for alert in _scope_alerts(Alert.objects.select_related("event", "event__policy", "assigned_user", "claimed_by"), request.user).order_by("-created_at"):
        event = alert.event
        writer.writerow([alert.created_at, event.policy.name if event.policy else "", alert.status, event.severity, event.risk_score, alert.owner_name, alert.escalated, alert.escalated_at, event.reason, alert.recommended_action, event.destination_path or event.source_path])
    return response

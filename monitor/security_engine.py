from __future__ import annotations

import getpass
import hashlib
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import psutil
except Exception:  # pragma: no cover - optional dependency safety
    psutil = None

from django.db import transaction
from django.utils import timezone

from .models import (
    Alert,
    BulkTransferIncident,
    FileEvent,
    IntegrityBaseline,
    IntegrityCheckHistory,
    MonitoringPolicy,
    SimulatedEmailAlert,
)
from .escalation import notify_alert_created


_recent_events: deque[tuple[float, str]] = deque()
_last_bulk_alert_time: float = 0


SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


@dataclass
class SensitivityResult:
    is_sensitive: bool
    category: str
    reason: str


def normalize_path(path: Optional[str]) -> str:
    if not path:
        return ""
    try:
        return str(Path(path).expanduser().resolve())
    except Exception:
        return str(path)


def file_hash(path: str | Path, algorithm: str = "sha256", chunk_size: int = 1024 * 1024) -> str:
    """Return file hash. Empty string means missing, directory, or unreadable file."""
    path = Path(path)
    if not path.exists() or not path.is_file():
        return ""
    try:
        hasher = hashlib.new((algorithm or "sha256").lower())
    except ValueError:
        hasher = hashlib.sha256()
    try:
        with path.open("rb") as file_object:
            while chunk := file_object.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, OSError):
        return ""


def inside_any(path: str, roots: list[str]) -> bool:
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


def process_using_file(path: str) -> str:
    """Best-effort process attribution. Some OS permissions prevent exact process mapping."""
    if not path or not psutil:
        return "Unknown"
    target = normalize_path(path)
    try:
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                for opened in proc.open_files() or []:
                    if normalize_path(opened.path) == target:
                        return proc.info.get("name") or "Unknown"
            except Exception:
                continue
    except Exception:
        return "Unknown"
    return "Unknown"


def file_size(path: str) -> int:
    try:
        candidate = Path(path)
        return candidate.stat().st_size if candidate.exists() and candidate.is_file() else 0
    except OSError:
        return 0


def destination_blocked(policy: MonitoringPolicy, path: str) -> bool:
    lowered = path.lower()
    return any(keyword.lower() in lowered for keyword in policy.blocked_keyword_list())


def trusted_process(policy: MonitoringPolicy, process_name: str) -> bool:
    lowered = (process_name or "").lower()
    return bool(lowered and any(keyword.lower() in lowered for keyword in policy.trusted_process_list()))


def classify_sensitivity(policy: MonitoringPolicy, source: str, destination: str) -> SensitivityResult:
    """Classify a file by folder, exact name, filename keywords, and extension."""
    restricted = {name.lower() for name in policy.restricted_file_list()}
    keywords = [kw.lower() for kw in policy.sensitive_keyword_list()]
    extensions = set(policy.sensitive_extension_list())
    reasons: list[str] = []
    category = "Normal"

    for candidate in [source, destination]:
        if not candidate:
            continue
        name = Path(candidate).name.lower()
        suffix = Path(candidate).suffix.lower()

        if inside_any(candidate, policy.sensitive_list()):
            reasons.append("located inside sensitive directory")
            category = "Sensitive Directory Data"
        if name in restricted:
            reasons.append("matched restricted filename")
            category = "Restricted File"
        matched_keywords = [kw for kw in keywords if kw and kw in name]
        if matched_keywords:
            reasons.append(f"matched sensitive filename keyword: {', '.join(matched_keywords[:3])}")
            category = "Keyword Classified Sensitive Data"
        if suffix in extensions and (matched_keywords or name in restricted or inside_any(candidate, policy.sensitive_list())):
            reasons.append(f"sensitive extension observed: {suffix}")
            if category == "Normal":
                category = "Sensitive Extension"

    if reasons:
        return SensitivityResult(True, category, "; ".join(dict.fromkeys(reasons)))
    return SensitivityResult(False, "Normal", "No sensitive policy match")


def update_baseline(path: str, hash_value: str, algorithm: str) -> None:
    if not path or not hash_value:
        return
    IntegrityBaseline.objects.update_or_create(
        path=path,
        defaults={
            "hash_value": hash_value,
            "algorithm": algorithm,
            "file_size": file_size(path),
            "last_seen": timezone.now(),
        },
    )


def previous_hash(path: str) -> str:
    if not path:
        return ""
    baseline = IntegrityBaseline.objects.filter(path=path).first()
    return baseline.hash_value if baseline else ""


def infer_copy_source(policy: MonitoringPolicy, destination: str, hash_value: str, algorithm: str) -> str:
    """Best-effort source inference for copy events.

    Watchdog/macOS reports a file copy as a CREATED event at the destination.
    It does not provide the original source path. To make the alert useful and
    accurate, we search configured sensitive folders for a file with the same
    filename and same hash. When found, the event is stored as COPIED with that
    source path and the created path as destination.
    """
    if not destination or not hash_value:
        return ""
    try:
        dest_path = Path(destination).expanduser().resolve()
        filename = dest_path.name
    except Exception:
        return ""
    for root in policy.sensitive_list():
        try:
            root_path = Path(root).expanduser().resolve()
            if not root_path.exists() or not root_path.is_dir():
                continue
            for candidate in root_path.rglob(filename):
                try:
                    candidate = candidate.resolve()
                    if candidate == dest_path:
                        continue
                    if candidate.is_file() and file_hash(candidate, algorithm) == hash_value:
                        return str(candidate)
                except Exception:
                    continue
        except Exception:
            continue
    return ""


def recent_duplicate_event(event_type: str, source: str, destination: str, hash_after: str, policy: MonitoringPolicy) -> FileEvent | None:
    """Prevent duplicate activity rows/alerts caused by OS filesystem noise.

    A single user action can trigger created + modified events, or multiple
    modified events. We suppress repeated events with the same path/hash inside
    a short window so one real change creates one activity row and at most one
    alert.
    """
    target = destination or source
    window_start = timezone.now() - timezone.timedelta(seconds=4)
    qs = FileEvent.objects.filter(policy=policy, timestamp__gte=window_start)

    # Exact duplicate from watchdog.
    exact = qs.filter(event_type=event_type, source_path=source, destination_path=destination).first()
    if exact:
        return exact

    # Created/copied/modified noise for same observed file and same hash.
    if event_type in {"created", "copied", "modified"} and target:
        path_q = qs.filter(event_type__in=["created", "copied", "modified"]).filter(
            source_path=target
        ) | qs.filter(event_type__in=["created", "copied", "modified"]).filter(
            destination_path=target
        )
        if hash_after:
            dup = path_q.filter(hash_after=hash_after).first()
            if dup:
                return dup
        dup = path_q.first()
        if dup and not hash_after:
            return dup

    # Duplicate delete events for the same missing file.
    if event_type == "deleted" and source:
        dup = qs.filter(event_type="deleted", source_path=source).first()
        if dup:
            return dup

    return None


def severity_from_score(score: int) -> str:
    if score >= 90:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 35:
        return "Medium"
    if score >= 10:
        return "Low"
    return "Info"


def recommended_action_for(event: FileEvent) -> str:
    if event.severity == "Critical":
        return (
            "Immediately review the file transfer, validate the destination, preserve evidence, "
            "contact the user/owner, and isolate the endpoint if exfiltration is suspected."
        )
    if event.severity == "High":
        return (
            "Investigate the user, destination, and business justification. Confirm whether the transfer was approved, "
            "review hash evidence, and update policy or escalate to incident response."
        )
    if event.severity == "Medium":
        return "Review the activity for business context, check file ownership, and confirm whether the file was changed legitimately."
    return "Document the event and continue monitoring."


def should_simulate_email(policy: MonitoringPolicy, severity: str) -> bool:
    threshold = policy.email_alert_min_severity
    if threshold == "Disabled":
        return False
    if threshold == "Critical":
        return severity == "Critical"
    return severity in {"High", "Critical"}


def create_simulated_emails(policy: MonitoringPolicy, alert: Alert) -> None:
    recipients = policy.email_recipient_list()
    if not recipients:
        return
    event = alert.event
    subject = f"{event.severity} File Transfer Alert - {Path(event.destination_path or event.source_path).name or 'Unknown file'}"
    body = (
        f"Severity: {event.severity}\n"
        f"Risk Score: {event.risk_score}\n"
        f"User: {event.username}\n"
        f"Process: {event.process_name}\n"
        f"Event Type: {event.event_type}\n"
        f"Sensitive: {event.is_sensitive}\n"
        f"Category: {event.sensitivity_category}\n"
        f"Source: {event.source_path}\n"
        f"Destination: {event.destination_path}\n"
        f"Hash Before: {event.hash_before}\n"
        f"Hash After: {event.hash_after}\n"
        f"Integrity Status: {event.integrity_status}\n"
        f"Reason: {event.reason}\n"
        f"Recommended Action: {alert.recommended_action}\n"
    )
    for recipient in recipients:
        SimulatedEmailAlert.objects.get_or_create(
            alert=alert,
            recipient=recipient,
            defaults={"subject": subject, "body": body},
        )


def record_integrity_history(path: str, baseline_hash: str, current_hash: str, algorithm: str, status: str, reason: str = "") -> None:
    IntegrityCheckHistory.objects.create(
        path=path,
        baseline_hash=baseline_hash or "",
        current_hash=current_hash or "",
        algorithm=algorithm,
        file_size=file_size(path),
        status=status,
        reason=reason,
    )


def burst_status(policy: MonitoringPolicy, destination_hint: str = "") -> tuple[bool, int, bool]:
    """Return (burst_detected, count, new_incident_created)."""
    global _last_bulk_alert_time
    now = time.time()
    _recent_events.append((now, destination_hint))
    while _recent_events and now - _recent_events[0][0] > policy.burst_threshold_seconds:
        _recent_events.popleft()

    count = len(_recent_events)
    detected = count >= policy.burst_threshold_file_count
    created = False
    if detected and (now - _last_bulk_alert_time) > max(10, policy.burst_threshold_seconds / 2):
        _last_bulk_alert_time = now
        paths = [item[1] for item in _recent_events if item[1]]
        BulkTransferIncident.objects.create(
            window_start=timezone.now() - timezone.timedelta(seconds=policy.burst_threshold_seconds),
            window_end=timezone.now(),
            file_count=count,
            username=getpass.getuser(),
            destination_hint=paths[-1] if paths else destination_hint,
            severity="High",
            reason=f"{count} file events occurred within {policy.burst_threshold_seconds} seconds.",
            policy=policy,
        )
        created = True
    return detected, count, created


@transaction.atomic
def analyze_and_record_event(
    event_type: str,
    source_path: str = "",
    destination_path: str = "",
    policy: Optional[MonitoringPolicy] = None,
) -> FileEvent:
    """Classify one file event and save evidence to SQLite."""
    policy = policy or MonitoringPolicy.objects.filter(is_active=True).first()
    if not policy:
        raise ValueError("No active monitoring policy configured. Create one from the Policy page before starting monitoring.")
    source = normalize_path(source_path)
    destination = normalize_path(destination_path)
    target_path = destination or source
    algorithm = policy.hash_algorithm or "sha256"

    hash_before = previous_hash(source)
    if event_type == "moved" and source and not hash_before:
        # If watchdog reports a move after the source disappears, use any known baseline if available.
        hash_before = previous_hash(destination)
    hash_after = file_hash(target_path, algorithm)

    # macOS/watchdog reports a copy as CREATED at the new file location.
    # When a matching source file is found in sensitive folders, store it as a copied event with source and destination.
    if event_type == "created" and source and not destination:
        inferred_source = infer_copy_source(policy, source, hash_after, algorithm)
        if inferred_source:
            destination = source
            source = inferred_source
            target_path = destination
            event_type = "copied"
            hash_before = previous_hash(source) or hash_after

    duplicate = recent_duplicate_event(event_type, source, destination, hash_after, policy)
    if duplicate:
        return duplicate

    proc = process_using_file(target_path)

    classification = classify_sensitivity(policy, source, destination)
    effective_destination = destination or source
    allowed_destination = inside_any(effective_destination, policy.allowed_list()) if effective_destination else False
    inside_sensitive_area = inside_any(effective_destination, policy.sensitive_list()) if effective_destination else False
    blocked_destination = destination_blocked(policy, effective_destination)
    burst, burst_count, new_bulk_incident = burst_status(policy, effective_destination)

    authorized = True
    risk_score = 0
    reasons: list[str] = []

    if classification.is_sensitive:
        risk_score += 25
        reasons.append(classification.reason)

    # Copy events are often reported as created at the destination without original source.
    if classification.is_sensitive and event_type in {"created", "copied", "moved"} and not allowed_destination and not inside_sensitive_area:
        authorized = False
        risk_score += 45
        reasons.append("Sensitive or restricted file appeared outside approved destination")

    if classification.is_sensitive and destination and not allowed_destination:
        authorized = False
        risk_score += 35
        reasons.append("Sensitive file moved outside approved destination")

    if classification.is_sensitive and blocked_destination:
        authorized = False
        risk_score += 55
        reasons.append("Sensitive file movement matched USB/cloud/network blocked keyword")

    if burst:
        authorized = False
        risk_score += 40
        reasons.append(f"Bulk transfer behavior: {burst_count} file events inside {policy.burst_threshold_seconds} seconds")
        if new_bulk_incident:
            reasons.append("Bulk transfer incident record created")

    if event_type in {"modified", "deleted"} and classification.is_sensitive:
        risk_score += 25
        reasons.append(f"Sensitive file was {event_type}")

    if trusted_process(policy, proc):
        risk_score = max(0, risk_score - 20)
        reasons.append("Trusted process keyword matched; risk score reduced")

    integrity_status = "Not checked"
    if event_type in {"created", "copied", "modified", "moved", "manual_scan"}:
        if hash_before and hash_after and hash_before != hash_after:
            integrity_status = "Hash mismatch detected"
            risk_score += 45
            reasons.append("Integrity violation: current hash does not match stored baseline")
            record_integrity_history(target_path, hash_before, hash_after, algorithm, "Hash Mismatch", integrity_status)
        elif hash_after and not hash_before:
            integrity_status = "Hash calculated"
            record_integrity_history(target_path, "", hash_after, algorithm, "Baseline Created", "New integrity baseline observed")
        elif hash_after:
            integrity_status = "Hash unchanged"
            record_integrity_history(target_path, hash_before, hash_after, algorithm, "Unchanged", "Current hash matches baseline")
        else:
            integrity_status = "Unreadable or missing"
            record_integrity_history(target_path, hash_before, "", algorithm, "Unreadable", "Could not calculate current file hash")

    severity = severity_from_score(risk_score)
    extension = Path(target_path).suffix.lower()[:32] if target_path else ""
    event = FileEvent.objects.create(
        event_type=event_type,
        source_path=source,
        destination_path=destination,
        username=getpass.getuser(),
        process_name=proc,
        is_sensitive=classification.is_sensitive,
        sensitivity_category=classification.category,
        classification_reason=classification.reason,
        is_authorized=authorized,
        severity=severity,
        risk_score=min(risk_score, 100),
        reason="; ".join(dict.fromkeys(reasons)) if reasons else "Normal monitored event",
        hash_before=hash_before,
        hash_after=hash_after,
        integrity_status=integrity_status,
        file_size=file_size(target_path),
        file_extension=extension,
        policy=policy,
    )

    if hash_after and event_type != "deleted":
        update_baseline(target_path, hash_after, algorithm)

    if event.alert_required:
        alert, _ = Alert.objects.get_or_create(
            event=event,
            defaults={"recommended_action": recommended_action_for(event)},
        )
        notify_alert_created(alert)

    return event

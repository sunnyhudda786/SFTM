from __future__ import annotations

import hashlib

from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class UserProfile(models.Model):
    AVAILABILITY_CHOICES = [
        ("available", "Available"),
        ("away", "Away"),
        ("off_duty", "Off Duty"),
        ("on_leave", "On Leave"),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="sftm_profile")
    availability_status = models.CharField(max_length=20, choices=AVAILABILITY_CHOICES, default="available")
    phone = models.CharField(max_length=40, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["user__username"]

    def __str__(self) -> str:
        return f"{self.user.username} - {self.get_availability_status_display()}"


class MonitoringPolicy(models.Model):
    """Editable monitoring and DLP-style policy used by the watchdog agent."""

    HASH_CHOICES = [("sha256", "SHA256"), ("md5", "MD5")]
    EMAIL_SEVERITY_CHOICES = [
        ("High", "High and Critical"),
        ("Critical", "Critical only"),
        ("Disabled", "Disabled"),
    ]

    name = models.CharField(max_length=120, default="My File Transfer Monitoring Policy")
    description = models.TextField(blank=True, default="")
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="created_policies")
    monitored_directories = models.TextField(
        blank=True,
        default="",
        help_text="One real folder path per line. These folders are watched recursively by the monitor command.",
    )
    sensitive_directories = models.TextField(
        blank=True,
        default="",
        help_text="One real folder path per line. Files inside these folders are treated as sensitive.",
    )
    allowed_destinations = models.TextField(
        blank=True,
        default="",
        help_text="One real folder path per line. Sensitive files moved here are considered approved.",
    )
    restricted_files = models.TextField(
        blank=True,
        default="",
        help_text="Optional. One exact filename per line, for example payroll.xlsx or client_data.csv.",
    )
    sensitive_filename_keywords = models.TextField(
        blank=True,
        default="",
        help_text="Optional. One keyword per line, for example salary, passport, confidential, client, contract.",
    )
    sensitive_extensions = models.TextField(
        blank=True,
        default="",
        help_text="Optional. One extension per line, for example .xlsx, .csv, .pdf, .sql, .zip.",
    )
    blocked_destination_keywords = models.TextField(
        blank=True,
        default="",
        help_text="Optional. One destination keyword per line, for example USB, OneDrive, Dropbox, External, NetworkShare.",
    )
    trusted_process_keywords = models.TextField(
        blank=True,
        default="",
        help_text="Optional. Process keywords that reduce risk, for example backup or antivirus.",
    )
    hash_algorithm = models.CharField(max_length=20, choices=HASH_CHOICES, default="sha256")
    burst_threshold_file_count = models.PositiveIntegerField(default=20)
    burst_threshold_seconds = models.PositiveIntegerField(default=60)
    email_alert_min_severity = models.CharField(max_length=20, choices=EMAIL_SEVERITY_CHOICES, default="High")
    simulated_email_recipients = models.TextField(
        blank=True,
        default="",
        help_text="Optional. One recipient per line for direct alert notifications.",
    )
    escalation_enabled = models.BooleanField(default=True)
    escalation_after_minutes = models.PositiveIntegerField(default=5)
    escalation_group_recipients = models.TextField(
        blank=True,
        default="",
        help_text="One group email per line. Used when no assigned admin/analyst claims an alert in time.",
    )
    notify_policy_team = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Monitoring policies"
        ordering = ["-is_active", "name"]

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def _split_lines(value: str) -> list[str]:
        return [line.strip() for line in (value or "").replace(";", "\n").splitlines() if line.strip()]

    def monitored_list(self) -> list[str]:
        return self._split_lines(self.monitored_directories)

    def sensitive_list(self) -> list[str]:
        return self._split_lines(self.sensitive_directories)

    def allowed_list(self) -> list[str]:
        return self._split_lines(self.allowed_destinations)

    def restricted_file_list(self) -> list[str]:
        return self._split_lines(self.restricted_files)

    def sensitive_keyword_list(self) -> list[str]:
        return self._split_lines(self.sensitive_filename_keywords)

    def sensitive_extension_list(self) -> list[str]:
        return [item.lower() if item.startswith(".") else f".{item.lower()}" for item in self._split_lines(self.sensitive_extensions)]

    def blocked_keyword_list(self) -> list[str]:
        return self._split_lines(self.blocked_destination_keywords)

    def trusted_process_list(self) -> list[str]:
        return self._split_lines(self.trusted_process_keywords)

    def email_recipient_list(self) -> list[str]:
        return self._split_lines(self.simulated_email_recipients)

    def escalation_recipient_list(self) -> list[str]:
        return self._split_lines(self.escalation_group_recipients)


class PolicyMembership(models.Model):
    ROLE_CHOICES = [
        ("policy_admin", "Policy Admin"),
        ("analyst", "Security Analyst"),
        ("auditor", "Read-only Auditor"),
    ]
    policy = models.ForeignKey(MonitoringPolicy, on_delete=models.CASCADE, related_name="memberships")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="policy_memberships")
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    assigned_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="assigned_policy_memberships")
    is_active = models.BooleanField(default=True)
    assigned_at = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = [("policy", "user", "role")]
        ordering = ["policy__name", "role", "user__username"]

    def __str__(self) -> str:
        return f"{self.user.username} -> {self.policy.name} ({self.get_role_display()})"


class IntegrityBaseline(models.Model):
    """Stores last known hash for integrity comparison."""

    path = models.TextField(unique=True)
    hash_value = models.CharField(max_length=128)
    algorithm = models.CharField(max_length=20, default="sha256")
    file_size = models.BigIntegerField(default=0)
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["path"]

    def __str__(self) -> str:
        return self.path


class IntegrityCheckHistory(models.Model):
    STATUS_CHOICES = [
        ("Baseline Created", "Baseline Created"),
        ("Unchanged", "Unchanged"),
        ("Hash Mismatch", "Hash Mismatch"),
        ("Missing", "Missing"),
        ("Unreadable", "Unreadable"),
    ]

    path = models.TextField(db_index=True)
    baseline_hash = models.CharField(max_length=128, blank=True)
    current_hash = models.CharField(max_length=128, blank=True)
    algorithm = models.CharField(max_length=20, default="sha256")
    file_size = models.BigIntegerField(default=0)
    status = models.CharField(max_length=40, choices=STATUS_CHOICES, default="Unchanged", db_index=True)
    reason = models.TextField(blank=True)
    checked_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-checked_at"]
        verbose_name_plural = "Integrity check history"

    def __str__(self) -> str:
        return f"{self.status}: {self.path}"


class FileEvent(models.Model):
    EVENT_CHOICES = [
        ("created", "Created"),
        ("copied", "Copied"),
        ("modified", "Modified"),
        ("deleted", "Deleted"),
        ("moved", "Moved"),
        ("manual_scan", "Manual Scan"),
        ("bulk_transfer", "Bulk Transfer"),
    ]
    SEVERITY_CHOICES = [
        ("Info", "Info"),
        ("Low", "Low"),
        ("Medium", "Medium"),
        ("High", "High"),
        ("Critical", "Critical"),
    ]

    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    event_type = models.CharField(max_length=30, choices=EVENT_CHOICES)
    source_path = models.TextField(blank=True)
    destination_path = models.TextField(blank=True)
    username = models.CharField(max_length=120, blank=True)
    process_name = models.CharField(max_length=200, blank=True, default="Unknown")
    is_sensitive = models.BooleanField(default=False)
    sensitivity_category = models.CharField(max_length=120, blank=True, default="Normal")
    classification_reason = models.TextField(blank=True)
    is_authorized = models.BooleanField(default=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="Info", db_index=True)
    risk_score = models.PositiveIntegerField(default=0, db_index=True)
    reason = models.TextField(default="Normal monitored event")
    hash_before = models.CharField(max_length=128, blank=True)
    hash_after = models.CharField(max_length=128, blank=True)
    integrity_status = models.CharField(max_length=120, default="Not checked")
    file_size = models.BigIntegerField(default=0)
    file_extension = models.CharField(max_length=32, blank=True)
    policy = models.ForeignKey(MonitoringPolicy, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self) -> str:
        return f"{self.timestamp:%Y-%m-%d %H:%M:%S} {self.event_type} {self.severity}"

    @property
    def alert_required(self) -> bool:
        return (not self.is_authorized) or self.severity in {"High", "Critical"}


class Alert(models.Model):
    STATUS_CHOICES = [
        ("open", "Open"),
        ("investigating", "Investigating"),
        ("closed", "Closed"),
        ("false_positive", "False Positive"),
    ]

    event = models.OneToOneField(FileEvent, on_delete=models.CASCADE, related_name="alert")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="open", db_index=True)
    assigned_to = models.CharField(max_length=120, blank=True)  # kept for CSV/backward compatibility
    assigned_user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="assigned_alerts")
    claimed_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="claimed_alerts")
    claimed_at = models.DateTimeField(null=True, blank=True)
    last_updated_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="updated_alerts")
    analyst_notes = models.TextField(blank=True)
    recommended_action = models.TextField(blank=True)
    escalated = models.BooleanField(default=False)
    escalated_at = models.DateTimeField(null=True, blank=True)
    escalation_recipients = models.TextField(blank=True)
    escalation_reason = models.TextField(blank=True)
    initial_notification_sent = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.event.severity} alert - {self.status}"

    @property
    def owner_name(self) -> str:
        if self.claimed_by:
            return self.claimed_by.username
        if self.assigned_user:
            return self.assigned_user.username
        return self.assigned_to or "Unassigned"

    @property
    def is_claimed(self) -> bool:
        return bool(self.claimed_by_id or self.assigned_user_id)


class BulkTransferIncident(models.Model):
    window_start = models.DateTimeField()
    window_end = models.DateTimeField(default=timezone.now)
    file_count = models.PositiveIntegerField(default=0)
    username = models.CharField(max_length=120, blank=True)
    destination_hint = models.TextField(blank=True)
    severity = models.CharField(max_length=20, choices=FileEvent.SEVERITY_CHOICES, default="High")
    reason = models.TextField(default="Abnormal number of file events in a short time window")
    policy = models.ForeignKey(MonitoringPolicy, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Bulk transfer: {self.file_count} files"


class SimulatedEmailAlert(models.Model):
    PURPOSE_CHOICES = [
        ("alert", "Initial Alert Notification"),
        ("escalation", "Escalation Notification"),
        ("otp", "Password Reset OTP"),
        ("system", "System Email"),
    ]
    alert = models.ForeignKey(Alert, null=True, blank=True, on_delete=models.CASCADE, related_name="email_notifications")
    recipient = models.EmailField()
    subject = models.CharField(max_length=255)
    body = models.TextField()
    purpose = models.CharField(max_length=30, choices=PURPOSE_CHOICES, default="alert")
    delivery_status = models.CharField(max_length=80, default="Stored Locally")
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.subject} -> {self.recipient}"


class PasswordResetOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="password_reset_otps")
    email = models.EmailField()
    code_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    attempts = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-created_at"]

    @staticmethod
    def hash_code(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    def is_valid(self, code: str) -> bool:
        return not self.used_at and self.expires_at >= timezone.now() and self.code_hash == self.hash_code(code)

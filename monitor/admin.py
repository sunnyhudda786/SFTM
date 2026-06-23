from django.contrib import admin

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


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "availability_status", "updated_at")
    list_filter = ("availability_status",)


@admin.register(MonitoringPolicy)
class MonitoringPolicyAdmin(admin.ModelAdmin):
    list_display = ("name", "is_active", "hash_algorithm", "escalation_enabled", "escalation_after_minutes", "updated_at")
    list_filter = ("is_active", "hash_algorithm", "escalation_enabled")
    search_fields = ("name", "description")


@admin.register(PolicyMembership)
class PolicyMembershipAdmin(admin.ModelAdmin):
    list_display = ("policy", "user", "role", "is_active", "assigned_by", "assigned_at")
    list_filter = ("role", "is_active")
    search_fields = ("policy__name", "user__username", "user__email")


@admin.register(FileEvent)
class FileEventAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "policy", "event_type", "severity", "risk_score", "is_sensitive", "is_authorized", "username", "short_path")
    list_filter = ("severity", "event_type", "is_sensitive", "is_authorized", "sensitivity_category", "policy")
    search_fields = ("source_path", "destination_path", "reason", "username", "classification_reason")

    def short_path(self, obj):
        return (obj.destination_path or obj.source_path)[-80:]


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("created_at", "status", "owner_name", "escalated", "event_severity", "event_risk")
    list_filter = ("status", "escalated", "event__severity", "event__policy")
    search_fields = ("event__source_path", "event__destination_path", "event__reason", "analyst_notes", "assigned_user__username")

    def event_severity(self, obj):
        return obj.event.severity

    def event_risk(self, obj):
        return obj.event.risk_score


@admin.register(IntegrityBaseline)
class IntegrityBaselineAdmin(admin.ModelAdmin):
    list_display = ("path", "algorithm", "file_size", "last_seen")
    search_fields = ("path", "hash_value")


@admin.register(IntegrityCheckHistory)
class IntegrityCheckHistoryAdmin(admin.ModelAdmin):
    list_display = ("checked_at", "status", "path", "algorithm", "file_size")
    list_filter = ("status", "algorithm")
    search_fields = ("path", "baseline_hash", "current_hash", "reason")


@admin.register(BulkTransferIncident)
class BulkTransferIncidentAdmin(admin.ModelAdmin):
    list_display = ("created_at", "policy", "severity", "file_count", "username", "destination_hint")
    list_filter = ("severity", "policy")
    search_fields = ("destination_hint", "reason", "username")


@admin.register(SimulatedEmailAlert)
class SimulatedEmailAlertAdmin(admin.ModelAdmin):
    list_display = ("created_at", "purpose", "recipient", "subject", "delivery_status")
    list_filter = ("purpose", "delivery_status")
    search_fields = ("recipient", "subject", "body", "error_message")


@admin.register(PasswordResetOTP)
class PasswordResetOTPAdmin(admin.ModelAdmin):
    list_display = ("email", "user", "created_at", "expires_at", "used_at", "attempts")
    search_fields = ("email", "user__username")

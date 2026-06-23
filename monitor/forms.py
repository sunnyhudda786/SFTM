from django import forms
from django.contrib.auth.forms import UserCreationForm, SetPasswordForm
from django.contrib.auth.models import Group, User

from .models import Alert, MonitoringPolicy, PolicyMembership, UserProfile


REQUIREMENT_BASED_POLICY_INITIAL = {
    "name": "Requirement-Based Secure File Transfer Policy",
    "is_active": True,
    "monitored_directories": "",
    "sensitive_directories": "",
    "allowed_destinations": "",
    "restricted_files": "salary.xlsx\nclient_data.csv\ncustomer_database.csv\nemployee_records.xlsx\npassport_scan.pdf\npasswords.txt\nfinancial_report.xlsx\nconfidential_contract.pdf\nsource_code.zip\ndatabase_backup.sql",
    "sensitive_filename_keywords": "confidential\nrestricted\nsecret\nprivate\nsalary\npayroll\npassport\nidentity\nclient\ncustomer\ncontract\ninvoice\nfinancial\nfinance\nemployee\nhr\npassword\ncredential\nsource_code\nbackup\ndatabase",
    "sensitive_extensions": ".xlsx\n.csv\n.pdf\n.docx\n.sql\n.zip\n.7z\n.tar\n.gz\n.key\n.pem\n.pfx",
    "blocked_destination_keywords": "USB\nExternal\nRemovable\nPenDrive\nThumbDrive\nDropbox\nOneDrive\nGoogle Drive\niCloud\nMega\nBox\nNetworkShare\nUnknown\nTemp\nDownloads\nPublic\nDesktop/Exfiltration\nCloudSync",
    "trusted_process_keywords": "backup\ndefender\nantivirus\nedr\nmdm\nit-approved\nscheduled-backup",
    "hash_algorithm": "sha256",
    "burst_threshold_file_count": 20,
    "burst_threshold_seconds": 60,
    "email_alert_min_severity": "High",
    "notify_policy_team": True,
    "escalation_enabled": True,
    "escalation_after_minutes": 5,
}

POLICY_TEMPLATE_EXPLANATION = [
    ("File transfer logging", "Monitors create, modify, move, delete, copy-like creation, and suspicious destination activity."),
    ("Unauthorized movement detection", "Flags restricted file names, sensitive folders, sensitive keywords/extensions, blocked USB/cloud/network destinations, and unapproved movement."),
    ("Integrity verification", "Uses SHA256 by default to create baselines and compare hash changes after modification or transfer."),
    ("Bulk transfer detection", "Raises incidents when many files move within the configured time window."),
    ("Team separation", "Assigns admins, analysts, and auditors to specific policies so users only see relevant work."),
    ("Escalation workflow", "Emails policy team and escalation group if high-risk alerts are not claimed within the configured SLA."),
]


def _users_in_group(group_name: str):
    return User.objects.filter(groups__name=group_name).order_by("username").distinct()


class MonitoringPolicyForm(forms.ModelForm):
    policy_admins = forms.ModelMultipleChoiceField(
        queryset=User.objects.none(), required=False, widget=forms.CheckboxSelectMultiple,
        help_text="Admins assigned here can manage this policy and assign/handle its alerts."
    )
    analysts = forms.ModelMultipleChoiceField(
        queryset=User.objects.none(), required=False, widget=forms.CheckboxSelectMultiple,
        help_text="Security Analysts assigned here can claim and investigate alerts for this policy."
    )
    auditors = forms.ModelMultipleChoiceField(
        queryset=User.objects.none(), required=False, widget=forms.CheckboxSelectMultiple,
        help_text="Auditors assigned here can review evidence for this policy without editing."
    )

    class Meta:
        model = MonitoringPolicy
        fields = [
            "name", "description", "is_active",
            "monitored_directories", "sensitive_directories", "allowed_destinations",
            "restricted_files", "sensitive_filename_keywords", "sensitive_extensions",
            "blocked_destination_keywords", "trusted_process_keywords",
            "hash_algorithm", "burst_threshold_file_count", "burst_threshold_seconds",
            "email_alert_min_severity", "simulated_email_recipients", "notify_policy_team",
            "escalation_enabled", "escalation_after_minutes", "escalation_group_recipients",
        ]
        labels = {
            "name": "Policy name",
            "description": "Policy description",
            "is_active": "Make this the active monitoring policy",
            "monitored_directories": "Monitored directories",
            "sensitive_directories": "Sensitive directories",
            "allowed_destinations": "Allowed destinations",
            "restricted_files": "Restricted files",
            "sensitive_filename_keywords": "Sensitive filename keywords",
            "sensitive_extensions": "Sensitive extensions",
            "blocked_destination_keywords": "Blocked destination keywords",
            "trusted_process_keywords": "Trusted process keywords",
            "hash_algorithm": "Integrity hash algorithm",
            "burst_threshold_file_count": "Bulk transfer file count",
            "burst_threshold_seconds": "Bulk transfer time window",
            "email_alert_min_severity": "Email alert threshold",
            "simulated_email_recipients": "Direct alert recipients",
            "notify_policy_team": "Notify assigned policy team on alerts",
            "escalation_enabled": "Enable unclaimed alert escalation",
            "escalation_after_minutes": "Escalate if unclaimed after minutes",
            "escalation_group_recipients": "Escalation group recipients",
        }
        help_texts = {
            "monitored_directories": "One real folder path per line. The monitor watches these folders recursively.",
            "sensitive_directories": "One real sensitive folder path per line, such as HR, Finance, Legal, or Client Data folders.",
            "allowed_destinations": "Approved destinations for sensitive files, such as a secure backup or approved internal share.",
            "restricted_files": "Exact filenames that should be treated as restricted.",
            "sensitive_filename_keywords": "Keywords that identify sensitive content by filename.",
            "sensitive_extensions": "Extensions that need closer monitoring.",
            "blocked_destination_keywords": "Keywords that represent USB, cloud sync, public folders, or unknown network destinations.",
            "trusted_process_keywords": "Optional process keywords that may reduce risk for approved backup/security tools.",
            "burst_threshold_file_count": "Number of files moved within the time window before a bulk-transfer incident is created.",
            "burst_threshold_seconds": "Time window used for bulk-transfer detection.",
            "simulated_email_recipients": "One email per line for extra alert recipients.",
            "escalation_group_recipients": "One email per line for escalation group notification.",
        }
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "Example: Finance Sensitive Transfer Policy"}),
            "description": forms.Textarea(attrs={"rows": 3, "placeholder": "Example: Monitors finance folders and blocks unauthorized USB/cloud movement."}),
            "monitored_directories": forms.Textarea(attrs={"rows": 4, "placeholder": "/Users/yourname/SFTM/Workspace"}),
            "sensitive_directories": forms.Textarea(attrs={"rows": 4, "placeholder": "/Users/yourname/SFTM/Workspace/Sensitive\n/Users/yourname/SFTM/Workspace/Finance"}),
            "allowed_destinations": forms.Textarea(attrs={"rows": 4, "placeholder": "/Users/yourname/SFTM/Workspace/Approved\n/Users/yourname/SFTM/Workspace/SecureBackup"}),
            "restricted_files": forms.Textarea(attrs={"rows": 5, "placeholder": "salary.xlsx\nclient_data.csv\npasswords.txt\ndatabase_backup.sql"}),
            "sensitive_filename_keywords": forms.Textarea(attrs={"rows": 5, "placeholder": "confidential\nsalary\npayroll\npassport\nclient\ncontract\npassword"}),
            "sensitive_extensions": forms.Textarea(attrs={"rows": 4, "placeholder": ".xlsx\n.csv\n.pdf\n.sql\n.zip"}),
            "blocked_destination_keywords": forms.Textarea(attrs={"rows": 5, "placeholder": "USB\nExternal\nDropbox\nOneDrive\nGoogle Drive\nNetworkShare\nPublic"}),
            "trusted_process_keywords": forms.Textarea(attrs={"rows": 3, "placeholder": "backup\ndefender\nantivirus"}),
            "simulated_email_recipients": forms.Textarea(attrs={"rows": 3, "placeholder": "security-team@company.local\nsoc-analyst@company.local"}),
            "escalation_group_recipients": forms.Textarea(attrs={"rows": 3, "placeholder": "finance-security-team@company.com\nsoc-manager@company.com"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["policy_admins"].queryset = _users_in_group("Admin")
        self.fields["analysts"].queryset = _users_in_group("Security Analyst")
        self.fields["auditors"].queryset = _users_in_group("Read-only Auditor")
        if self.instance and self.instance.pk:
            self.fields["policy_admins"].initial = User.objects.filter(policy_memberships__policy=self.instance, policy_memberships__role="policy_admin", policy_memberships__is_active=True)
            self.fields["analysts"].initial = User.objects.filter(policy_memberships__policy=self.instance, policy_memberships__role="analyst", policy_memberships__is_active=True)
            self.fields["auditors"].initial = User.objects.filter(policy_memberships__policy=self.instance, policy_memberships__role="auditor", policy_memberships__is_active=True)

    def clean(self):
        cleaned = super().clean()
        monitored = cleaned.get("monitored_directories", "").strip()
        if cleaned.get("is_active") and not monitored:
            self.add_error("monitored_directories", "An active policy must include at least one monitored directory.")
        if cleaned.get("escalation_enabled") and not (cleaned.get("escalation_group_recipients") or "").strip():
            self.add_error("escalation_group_recipients", "Add at least one escalation group email or disable escalation.")
        return cleaned

    def save(self, commit=True, assigned_by=None):
        policy = super().save(commit=commit)
        if commit:
            self.save_memberships(policy, assigned_by=assigned_by)
        return policy

    def save_memberships(self, policy: MonitoringPolicy, assigned_by=None):
        role_map = {
            "policy_admins": "policy_admin",
            "analysts": "analyst",
            "auditors": "auditor",
        }
        for field, role in role_map.items():
            selected_users = list(self.cleaned_data.get(field) or [])
            PolicyMembership.objects.filter(policy=policy, role=role).exclude(user__in=selected_users).update(is_active=False)
            for user in selected_users:
                PolicyMembership.objects.update_or_create(
                    policy=policy, user=user, role=role,
                    defaults={"assigned_by": assigned_by, "is_active": True},
                )
                UserProfile.objects.get_or_create(user=user)


class AlertUpdateForm(forms.ModelForm):
    class Meta:
        model = Alert
        fields = ["status", "analyst_notes", "recommended_action"]
        widgets = {
            "analyst_notes": forms.Textarea(attrs={"rows": 5}),
            "recommended_action": forms.Textarea(attrs={"rows": 4}),
        }


class AlertAssignForm(forms.ModelForm):
    class Meta:
        model = Alert
        fields = ["assigned_user"]
        labels = {"assigned_user": "Assign to analyst"}

    def __init__(self, *args, policy=None, **kwargs):
        super().__init__(*args, **kwargs)
        qs = User.objects.filter(policy_memberships__policy=policy, policy_memberships__role="analyst", policy_memberships__is_active=True).distinct()
        self.fields["assigned_user"].queryset = qs
        self.fields["assigned_user"].required = False


class TeamUserCreationForm(UserCreationForm):
    role = forms.ChoiceField(
        choices=[
            ("Admin", "Admin"),
            ("Security Analyst", "Security Analyst"),
            ("Read-only Auditor", "Read-only Auditor"),
        ],
        help_text="Admin can manage policies/users. Analyst can investigate assigned-policy alerts. Auditor can view only.",
    )
    email = forms.EmailField(required=True, help_text="Required for OTP password reset and alert notifications.")
    availability_status = forms.ChoiceField(choices=UserProfile.AVAILABILITY_CHOICES, initial="available", required=True)

    class Meta:
        model = User
        fields = ["username", "email", "role", "availability_status", "password1", "password2"]

    def clean_email(self):
        email = self.cleaned_data.get("email", "").strip().lower()
        if not email:
            raise forms.ValidationError("Email is required because users reset passwords by email.")
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("This email is already assigned to another user.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data.get("email", "").strip().lower()
        if commit:
            user.save()
            group, _ = Group.objects.get_or_create(name=self.cleaned_data["role"])
            user.groups.set([group])
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.availability_status = self.cleaned_data.get("availability_status", "available")
            profile.save()
        return user


class AvailabilityForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ["availability_status"]
        labels = {"availability_status": "Availability"}


class OTPRequestForm(forms.Form):
    email = forms.EmailField(label="Account email")


class OTPVerifyForm(forms.Form):
    email = forms.EmailField(widget=forms.HiddenInput)
    otp = forms.CharField(label="OTP code", max_length=6, min_length=6)
    new_password1 = forms.CharField(label="New password", widget=forms.PasswordInput)
    new_password2 = forms.CharField(label="Confirm new password", widget=forms.PasswordInput)

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("new_password1") != cleaned.get("new_password2"):
            self.add_error("new_password2", "Passwords do not match.")
        return cleaned

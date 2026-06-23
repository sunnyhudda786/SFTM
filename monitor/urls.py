from django.contrib.auth import views as auth_views
from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("events/", views.events, name="events"),
    path("events/<int:pk>/", views.event_detail, name="event_detail"),
    path("alerts/", views.alerts, name="alerts"),
    path("alerts/<int:pk>/", views.alert_detail, name="alert_detail"),
    path("alerts/escalation-check/", views.run_escalation_check, name="run_escalation_check"),
    path("policies/", views.policies, name="policies"),
    path("policies/new/", views.policy_create, name="policy_create"),
    path("policies/<int:pk>/edit/", views.policy_edit, name="policy_edit"),
    path("policies/<int:pk>/activate/", views.policy_activate, name="policy_activate"),
    path("policies/<int:pk>/delete/", views.policy_delete, name="policy_delete"),
    path("integrity/", views.integrity, name="integrity"),
    path("bulk-incidents/", views.bulk_incidents, name="bulk_incidents"),
    path("email-alerts/", views.email_alerts, name="email_alerts"),
    path("reports/", views.reports, name="reports"),
    path("reports/generate/", views.generate_report, name="generate_report"),
    path("reports/download/<str:filename>/", views.download_report, name="download_report"),
    path("team-users/", views.team_users, name="team_users"),
    path("availability/", views.update_availability, name="update_availability"),
    path("export/events.csv", views.export_events_csv, name="export_events_csv"),
    path("export/alerts.csv", views.export_alerts_csv, name="export_alerts_csv"),
    path("login/", auth_views.LoginView.as_view(template_name="monitor/login.html"), name="login"),
    path("password-reset/", views.otp_password_reset_request, name="password_reset"),
    path("password-reset/verify/", views.otp_password_reset_verify, name="password_reset_verify"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
]

from __future__ import annotations

from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.shortcuts import redirect

ROLE_ADMIN = "Admin"
ROLE_ANALYST = "Security Analyst"
ROLE_AUDITOR = "Read-only Auditor"
ROLE_NAMES = [ROLE_ADMIN, ROLE_ANALYST, ROLE_AUDITOR]


def ensure_roles() -> None:
    for name in ROLE_NAMES:
        Group.objects.get_or_create(name=name)


def user_role(user) -> str:
    if not user or not user.is_authenticated:
        return ""
    if user.is_superuser or user.groups.filter(name=ROLE_ADMIN).exists():
        return ROLE_ADMIN
    for name in ROLE_NAMES:
        if user.groups.filter(name=name).exists():
            return name
    return "Unassigned"


def is_admin(user) -> bool:
    return bool(user and user.is_authenticated and (user.is_superuser or user.groups.filter(name=ROLE_ADMIN).exists()))


def is_analyst(user) -> bool:
    return bool(user and user.is_authenticated and user.groups.filter(name=ROLE_ANALYST).exists())


def is_auditor(user) -> bool:
    return bool(user and user.is_authenticated and user.groups.filter(name=ROLE_AUDITOR).exists())


def is_analyst_or_admin(user) -> bool:
    return bool(user and user.is_authenticated and (is_admin(user) or is_analyst(user)))


def allowed_policy_ids(user) -> list[int] | None:
    """None means unrestricted superuser/admin. List means scoped policy access."""
    if not user or not user.is_authenticated:
        return []
    if user.is_superuser:
        return None
    return list(
        user.policy_memberships.filter(is_active=True).values_list("policy_id", flat=True).distinct()
    )


def can_view_policy(user, policy) -> bool:
    if not policy:
        return False
    ids = allowed_policy_ids(user)
    return ids is None or policy.id in ids


def is_policy_admin(user, policy) -> bool:
    if not user or not user.is_authenticated or not policy:
        return False
    if user.is_superuser:
        return True
    return user.policy_memberships.filter(policy=policy, role="policy_admin", is_active=True).exists()


def is_policy_analyst(user, policy) -> bool:
    if not user or not user.is_authenticated or not policy:
        return False
    if user.is_superuser:
        return True
    return user.policy_memberships.filter(policy=policy, role__in=["policy_admin", "analyst"], is_active=True).exists()


def admin_required(view_func):
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not is_admin(request.user):
            messages.error(request, "Admin access is required for that page.")
            return redirect("dashboard")
        return view_func(request, *args, **kwargs)
    return wrapper


def analyst_required(view_func):
    @wraps(view_func)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not is_analyst_or_admin(request.user):
            messages.error(request, "Security Analyst or Admin access is required for that action.")
            return redirect("dashboard")
        return view_func(request, *args, **kwargs)
    return wrapper

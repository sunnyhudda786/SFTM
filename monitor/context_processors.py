from .roles import is_admin, is_analyst, is_analyst_or_admin, is_auditor, user_role


def role_context(request):
    user = getattr(request, "user", None)
    profile = None
    if user and user.is_authenticated:
        try:
            profile = user.sftm_profile
        except Exception:
            profile = None
    status_value = profile.availability_status if profile else "available"
    status_label = profile.get_availability_status_display() if profile else "Available"
    return {
        "current_role": user_role(user) if user and user.is_authenticated else "",
        "is_admin_user": is_admin(user) if user and user.is_authenticated else False,
        "is_analyst_user": is_analyst_or_admin(user) if user and user.is_authenticated else False,
        "is_analyst_only": is_analyst(user) if user and user.is_authenticated else False,
        "is_auditor_user": is_auditor(user) if user and user.is_authenticated else False,
        "availability_status": status_label,
        "availability_status_value": status_value,
    }

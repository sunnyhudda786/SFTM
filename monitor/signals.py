from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver

from .models import UserProfile


@receiver(user_logged_in)
def mark_user_available(sender, request, user, **kwargs):
    if not user:
        return
    profile, _ = UserProfile.objects.get_or_create(user=user)
    if profile.availability_status != "available":
        profile.availability_status = "available"
        profile.save(update_fields=["availability_status", "updated_at"])


@receiver(user_logged_out)
def mark_user_off_duty(sender, request, user, **kwargs):
    if not user:
        return
    profile, _ = UserProfile.objects.get_or_create(user=user)
    if profile.availability_status != "off_duty":
        profile.availability_status = "off_duty"
        profile.save(update_fields=["availability_status", "updated_at"])

from django.core.management.base import BaseCommand

from monitor.models import (
    Alert,
    BulkTransferIncident,
    FileEvent,
    IntegrityBaseline,
    IntegrityCheckHistory,
    PasswordResetOTP,
    SimulatedEmailAlert,
)


class Command(BaseCommand):
    help = "Clear runtime monitoring data while keeping users, roles, policies, and policy assignments."

    def add_arguments(self, parser):
        parser.add_argument(
            "--yes",
            action="store_true",
            help="Confirm deletion without interactive prompt.",
        )

    def handle(self, *args, **options):
        if not options["yes"]:
            self.stdout.write(self.style.WARNING("This will delete alerts, activity logs, email evidence, OTP records, integrity history, and baselines."))
            confirm = input("Type CLEAR to continue: ")
            if confirm != "CLEAR":
                self.stdout.write(self.style.ERROR("Cancelled."))
                return

        counts = {
            "email_records": SimulatedEmailAlert.objects.count(),
            "alerts": Alert.objects.count(),
            "file_events": FileEvent.objects.count(),
            "bulk_incidents": BulkTransferIncident.objects.count(),
            "integrity_history": IntegrityCheckHistory.objects.count(),
            "integrity_baselines": IntegrityBaseline.objects.count(),
            "otp_records": PasswordResetOTP.objects.count(),
        }
        SimulatedEmailAlert.objects.all().delete()
        Alert.objects.all().delete()
        FileEvent.objects.all().delete()
        BulkTransferIncident.objects.all().delete()
        IntegrityCheckHistory.objects.all().delete()
        IntegrityBaseline.objects.all().delete()
        PasswordResetOTP.objects.all().delete()
        self.stdout.write(self.style.SUCCESS("Runtime activity data cleared. Users and policies were kept."))
        for name, count in counts.items():
            self.stdout.write(f"{name}: {count}")

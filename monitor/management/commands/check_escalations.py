from django.core.management.base import BaseCommand

from monitor.escalation import process_due_escalations


class Command(BaseCommand):
    help = "Check open/unclaimed alerts and send escalation emails when SLA time is reached."

    def handle(self, *args, **options):
        count = process_due_escalations()
        self.stdout.write(self.style.SUCCESS(f"Escalation check complete. {count} alert(s) escalated."))

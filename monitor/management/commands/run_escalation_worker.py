import time

from django.core.management.base import BaseCommand

from monitor.escalation import process_due_escalations


class Command(BaseCommand):
    help = "Run an escalation worker that checks for unclaimed alerts repeatedly."

    def add_arguments(self, parser):
        parser.add_argument("--interval", type=int, default=60, help="Seconds between checks. Default: 60")

    def handle(self, *args, **options):
        interval = max(10, int(options["interval"]))
        self.stdout.write(self.style.SUCCESS(f"Escalation worker running. Checking every {interval} seconds. Press Ctrl+C to stop."))
        try:
            while True:
                count = process_due_escalations()
                if count:
                    self.stdout.write(self.style.WARNING(f"Escalated {count} alert(s)."))
                time.sleep(interval)
        except KeyboardInterrupt:
            self.stdout.write(self.style.SUCCESS("Escalation worker stopped."))

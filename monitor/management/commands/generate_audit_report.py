from django.core.management.base import BaseCommand

from monitor.reports import generate_html_report


class Command(BaseCommand):
    help = "Generate an HTML audit report from SQLite event and alert data."

    def handle(self, *args, **options):
        path = generate_html_report()
        self.stdout.write(self.style.SUCCESS(f"Report created: {path}"))

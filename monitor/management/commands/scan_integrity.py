from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from monitor.models import MonitoringPolicy
from monitor.security_engine import analyze_and_record_event


class Command(BaseCommand):
    help = "Hash every file in all active monitored policy directories and store integrity baselines/events."

    def add_arguments(self, parser):
        parser.add_argument("--policy", type=int, help="Optional policy ID to scan only one policy.")

    def handle(self, *args, **options):
        policies = MonitoringPolicy.objects.filter(is_active=True).order_by("name")
        if options.get("policy"):
            policies = policies.filter(pk=options["policy"])
        policies = list(policies)
        if not policies:
            raise CommandError("No active policy found. Create or activate a policy before scanning.")

        total = 0
        for policy in policies:
            roots = [Path(root).expanduser().resolve() for root in policy.monitored_list()]
            if not roots:
                self.stdout.write(self.style.WARNING(f"Skipping policy with no monitored directories: {policy.name}"))
                continue
            count = 0
            for root_path in roots:
                if not root_path.exists():
                    raise CommandError(f"Monitored directory does not exist for {policy.name}: {root_path}")
                for file_path in root_path.rglob("*"):
                    if file_path.is_file() and not file_path.name.startswith("."):
                        analyze_and_record_event("manual_scan", str(file_path), policy=policy)
                        count += 1
                        total += 1
            self.stdout.write(self.style.SUCCESS(f"{policy.name}: files checked {count}"))
        self.stdout.write(self.style.SUCCESS(f"Integrity scan completed. Total files checked: {total}"))

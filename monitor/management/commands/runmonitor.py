from pathlib import Path
import time

from django.core.management.base import BaseCommand, CommandError
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from monitor.models import MonitoringPolicy
from monitor.security_engine import analyze_and_record_event


class SecureTransferHandler(FileSystemEventHandler):
    def __init__(self, policy: MonitoringPolicy, stdout_write):
        super().__init__()
        self.policy = policy
        self.stdout_write = stdout_write
        self._last_modified: dict[str, float] = {}
        self._last_event: dict[tuple[str, str, str], float] = {}
        self._recent_created: dict[str, float] = {}

    def _ignore(self, path: str) -> bool:
        name = Path(path).name
        ignored_suffixes = ("~", ".tmp", ".swp", ".crdownload")
        return name.startswith(".") or name.endswith(ignored_suffixes) or "__pycache__" in path

    def _record(self, event_type: str, src: str, dest: str = "") -> None:
        if not src or self._ignore(src):
            return
        now = time.time()
        key = (event_type, src, dest or "")
        if now - self._last_event.get(key, 0) < 2.0:
            return
        self._last_event[key] = now
        try:
            event = analyze_and_record_event(event_type, src, dest, self.policy)
            marker = "ALERT" if event.alert_required else "OK"
            path = event.destination_path or event.source_path
            self.stdout_write(f"[{marker}] {self.policy.name} | {event.event_type.upper()} | {event.severity} | Risk {event.risk_score} | {Path(path).name} | {event.reason}")
        except Exception as exc:
            self.stdout_write(f"[ERROR] {self.policy.name} | Could not record event for {src}: {exc}")

    def on_created(self, event):
        if not event.is_directory:
            time.sleep(0.25)
            self._recent_created[event.src_path] = time.time()
            self._record("created", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        now = time.time()
        if now - self._recent_created.get(event.src_path, 0) < 3.0:
            return
        last = self._last_modified.get(event.src_path, 0)
        if now - last < 2.5:
            return
        self._last_modified[event.src_path] = now
        self._record("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._record("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._record("moved", event.src_path, event.dest_path)


class Command(BaseCommand):
    help = "Run the live file transfer watchdog monitor for all active policies. Keep this terminal open while testing transfers."

    def add_arguments(self, parser):
        parser.add_argument("--policy", type=int, help="Optional policy ID to monitor only one policy.")

    def handle(self, *args, **options):
        policies = MonitoringPolicy.objects.filter(is_active=True).order_by("name")
        if options.get("policy"):
            policies = policies.filter(pk=options["policy"])
        policies = list(policies)
        if not policies:
            raise CommandError("No active policy found. Create or activate a policy from the Policies page or run setup_company_workspace.")

        observer = Observer()
        watched_count = 0
        seen_pairs: set[tuple[int, str]] = set()

        for policy in policies:
            folders = [Path(folder).expanduser().resolve() for folder in policy.monitored_list()]
            if not folders:
                self.stdout.write(self.style.WARNING(f"Skipping policy with no monitored folders: {policy.name}"))
                continue
            handler = SecureTransferHandler(policy, self.stdout.write)
            for path in folders:
                if not path.exists():
                    raise CommandError(f"Monitored directory does not exist for {policy.name}: {path}. Create it first or update the policy path.")
                if not path.is_dir():
                    raise CommandError(f"Monitored path is not a directory for {policy.name}: {path}")
                key = (policy.id, str(path))
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                observer.schedule(handler, str(path), recursive=True)
                watched_count += 1
                self.stdout.write(self.style.SUCCESS(f"Watching {policy.name}: {path}"))

        if watched_count == 0:
            raise CommandError("No valid monitored directories were found in active policies.")

        self.stdout.write(self.style.WARNING(f"Monitoring started for {len(policies)} active policy/policies and {watched_count} folder(s). Press CTRL+C to stop."))
        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
            self.stdout.write(self.style.WARNING("Monitoring stopped."))
        observer.join()

import os
import threading
import time
from datetime import datetime

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

import config
from detector import (
    SEVERITY_RANK,
    ActivityTracker,
    Indicator,
    analyze_file,
    severity_for,
    total_score,
)
from logger import log_event, record_alert
from response import respond


class RansomwareMonitor(FileSystemEventHandler):
    def __init__(self, watch_dir, vault, canaries, auto_kill=False, responder=respond):
        self.watch_dir = os.path.abspath(watch_dir)
        self.vault = vault
        self.canaries = {os.path.normcase(path) for path in canaries}
        self.auto_kill = auto_kill
        self.responder = responder

        self.activity = ActivityTracker()
        self.flagged_files = {}
        self.last_seen = {}
        self.last_alert = {}
        self.last_incident_time = 0.0

        self.alerts = []
        self.incidents = []

    # watchdog callbacks

    def on_created(self, event):
        if not event.is_directory:
            self.handle_change(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self.handle_change(event.src_path, "modified")

    def on_moved(self, event):
        if event.is_directory:
            return
        if self.is_canary(event.src_path):
            self.activity.record()
            self.raise_alert(event.src_path, "renamed", [Indicator(
                "canary_touched", 100, f"Decoy file was renamed to {os.path.basename(event.dest_path)}")])
            return
        self.handle_change(event.dest_path, "renamed", source=event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.handle_delete(event.src_path)

    # detection

    def is_canary(self, path):
        return os.path.normcase(os.path.abspath(path)) in self.canaries

    def rel(self, path):
        return os.path.relpath(os.path.abspath(path), self.watch_dir)

    def handle_change(self, path, event, source=None):
        path = os.path.abspath(path)
        try:
            info = os.stat(path)
        except OSError:
            return

        # Windows often reports one save as several events; skip exact repeats
        signature = (info.st_mtime_ns, info.st_size)
        if event != "renamed" and self.last_seen.get(path) == signature:
            return
        self.last_seen[path] = signature
        self.activity.record()

        if self.is_canary(path):
            self.raise_alert(path, event, [Indicator(
                "canary_touched", 100, "Decoy file was modified")])
            return

        indicators, entropy = analyze_file(path, self.vault.baseline_entropy(path))

        if indicators and self.activity.is_burst():
            indicators.append(Indicator(
                "mass_activity", 30,
                f"{self.activity.count()} file changes in the last {config.ACTIVITY_WINDOW_SECONDS}s"))

        if severity_for(total_score(indicators)) is None:
            # Looks like a normal edit: keep it as the new clean version
            self.vault.save_version(path, entropy)
            action = f"renamed from {self.rel(source)}" if source else event
            log_event(f"File {action}: {self.rel(path)}")
            return

        self.raise_alert(path, event, indicators, source)

    def handle_delete(self, path):
        self.activity.record()
        if self.is_canary(path):
            self.raise_alert(path, "deleted", [Indicator(
                "canary_touched", 100, "Decoy file was deleted")])
        elif self.vault.is_tracked(path):
            log_event(f"File deleted: {self.rel(path)} (clean copy kept in vault)")

    def raise_alert(self, path, event, indicators, source=None):
        score = total_score(indicators)
        severity = severity_for(score)
        now = time.time()

        # Distinct files flagged HIGH or worse inside the activity window
        if SEVERITY_RANK[severity] >= SEVERITY_RANK["HIGH"]:
            self.flagged_files[path] = now
        self.flagged_files = {
            flagged: seen for flagged, seen in self.flagged_files.items()
            if now - seen <= config.ACTIVITY_WINDOW_SECONDS
        }

        # Only repeat an alert for the same file after the cooldown, unless it got worse
        previous_time, previous_severity = self.last_alert.get(path, (0.0, None))
        repeat = (now - previous_time < config.ALERT_COOLDOWN_SECONDS
                  and SEVERITY_RANK[severity] <= SEVERITY_RANK[previous_severity])

        if not repeat:
            self.last_alert[path] = (now, severity)
            alert = {
                "type": "file",
                "time": datetime.now().isoformat(timespec="seconds"),
                "severity": severity,
                "score": score,
                "event": event,
                "path": self.rel(path),
                "source": self.rel(source) if source else None,
                "indicators": [indicator.to_dict() for indicator in indicators],
            }
            self.alerts.append(alert)
            record_alert(alert)
            details = "; ".join(indicator.detail for indicator in indicators)
            log_event(f"{severity} (score {score}) {event}: {self.rel(path)} | {details}", severity)

        canary_hit = any(indicator.name == "canary_touched" for indicator in indicators)
        if canary_hit or len(self.flagged_files) >= config.INCIDENT_MIN_FILES:
            self.declare_incident(canary_hit)

    def declare_incident(self, canary_hit):
        now = time.time()
        if now - self.last_incident_time < config.INCIDENT_COOLDOWN_SECONDS:
            return
        self.last_incident_time = now

        reason = ("a decoy file was touched" if canary_hit else
                  f"{len(self.flagged_files)} files look encrypted in the last "
                  f"{config.ACTIVITY_WINDOW_SECONDS}s")
        incident = {
            "type": "incident",
            "time": datetime.now().isoformat(timespec="seconds"),
            "timestamp": now,
            "severity": "CRITICAL",
            "reason": reason,
        }
        self.incidents.append(incident)
        record_alert(incident)

        log_event("=" * 70, "CRITICAL")
        log_event(f"RANSOMWARE INCIDENT: {reason}", "CRITICAL")
        log_event("Disconnect from the network, stop the attack, then run: python main.py restore", "CRITICAL")
        log_event("=" * 70, "CRITICAL")

        if self.responder is not None:
            # Scanning processes takes a moment, so keep it off the event thread
            threading.Thread(
                target=self.responder, args=(self.watch_dir, self.auto_kill), daemon=True).start()


def create_observer(handler, folder_path):
    observer = Observer()
    observer.schedule(handler, folder_path, recursive=True)
    return observer


def start_monitoring(handler, folder_path):
    observer = create_observer(handler, folder_path)
    observer.start()
    log_event(f"Monitoring {folder_path} (press Ctrl+C to stop)")

    try:
        while observer.is_alive():
            observer.join(1)
    except KeyboardInterrupt:
        log_event("Monitoring stopped by user.")
    finally:
        observer.stop()
        observer.join()

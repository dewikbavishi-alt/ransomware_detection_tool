import argparse
import os
from collections import Counter

import config
from canary import create_canaries
from detector import analyze_file, severity_for, total_score
from logger import log_event, read_alerts
from monitor import RansomwareMonitor, start_monitoring
from vault import Vault


def make_checkers(vault):
    def is_clean(path):
        indicators, entropy = analyze_file(path, vault.baseline_entropy(path))
        return severity_for(total_score(indicators)) is None, entropy

    def is_suspicious(path):
        return not is_clean(path)[0]

    return is_clean, is_suspicious


def cmd_monitor(args):
    folder = os.path.abspath(args.folder)
    os.makedirs(folder, exist_ok=True)

    vault = Vault(config.VAULT_FOLDER, folder)
    canaries = create_canaries(folder)
    is_clean, _ = make_checkers(vault)

    saved, skipped = vault.snapshot(is_clean)
    log_event(f"Vault ready: {vault.file_count()} files protected ({saved} new clean versions saved)")
    log_event(f"{len(canaries)} decoy files in place: {', '.join(config.CANARY_FILES)}")
    for relative in skipped:
        log_event(f"Not backed up, already looks encrypted: {relative}", "MEDIUM")
    if args.kill:
        log_event("Auto-kill is ON: suspect processes will be terminated during an incident", "HIGH")

    handler = RansomwareMonitor(folder, vault, canaries, auto_kill=args.kill)
    start_monitoring(handler, folder)


def cmd_restore(args):
    folder = os.path.abspath(args.folder)
    vault = Vault(config.VAULT_FOLDER, folder)
    if vault.file_count() == 0:
        print("The vault is empty. Run 'python main.py monitor' first to create a baseline.")
        return

    print("Stop the monitor (Ctrl+C) before restoring, or it will report the restored files.")
    _, is_suspicious = make_checkers(vault)
    report = vault.restore(config.QUARANTINE_FOLDER, is_suspicious)

    for relative in report["restored"]:
        log_event(f"Restored clean version: {relative}")
    for relative in report["quarantined"]:
        log_event(f"Quarantined: {relative}")
    log_event(
        f"Restore complete: {len(report['restored'])} restored, {report['unchanged']} unchanged, "
        f"{len(report['quarantined'])} moved to {report['quarantine_dir']}")


def cmd_status(args):
    alerts = read_alerts()
    files = [a for a in alerts if a["type"] == "file"]
    incidents = [a for a in alerts if a["type"] == "incident"]
    counts = Counter(a["severity"] for a in files)

    vault = Vault(config.VAULT_FOLDER, args.folder)
    print(f"Files protected in vault : {vault.file_count()}")
    print(f"File alerts              : {len(files)} "
          f"(CRITICAL {counts['CRITICAL']}, HIGH {counts['HIGH']}, MEDIUM {counts['MEDIUM']})")
    print(f"Incidents                : {len(incidents)}")
    if incidents:
        print(f"Last incident            : {incidents[-1]['time']} - {incidents[-1]['reason']}")
    for alert in files[-5:]:
        print(f"  {alert['time']}  {alert['severity']:<8} {alert['path']}")


def main():
    os.system("")   # turns on colour output in the Windows console

    parser = argparse.ArgumentParser(description="Ransomware detection and recovery tool")
    parser.add_argument("--folder", default=config.WATCH_FOLDER, help="folder to protect")
    commands = parser.add_subparsers(dest="command")

    monitor = commands.add_parser("monitor", help="watch the folder (default)")
    monitor.add_argument("--kill", action="store_true",
                         help="terminate processes that have files open during an incident")
    commands.add_parser("restore", help="restore clean versions from the vault")
    commands.add_parser("status", help="show alert and vault summary")

    args = parser.parse_args()
    if args.command == "restore":
        cmd_restore(args)
    elif args.command == "status":
        cmd_status(args)
    else:
        args.kill = getattr(args, "kill", False)
        cmd_monitor(args)


if __name__ == "__main__":
    main()

"""End-to-end evaluation in temporary sandbox folders.

For each scenario: create sample files, back them up, start the monitor, run
the simulated activity, then restore and check every file is byte-for-byte
identical to the original.
"""

import os
import tempfile
import time

import logger
import simulate_attack
import simulate_benign
from canary import create_canaries
from demo_files import create_demo_files
from main import make_checkers
from monitor import RansomwareMonitor, create_observer
from vault import Vault, iter_files, remove_tree, sha256_of

SETTLE_SECONDS = 1.5


def run_scenario(name, use_canaries=True, attack=True, rename=True):
    workdir = tempfile.mkdtemp(prefix="ransom_eval_")
    watch = os.path.join(workdir, "protected_files")
    logger.configure(os.path.join(workdir, "security.log"),
                     os.path.join(workdir, "alerts.jsonl"), echo=False)
    try:
        create_demo_files(watch)
        canaries = create_canaries(watch) if use_canaries else set()
        vault = Vault(os.path.join(workdir, "vault"), watch)
        is_clean, is_suspicious = make_checkers(vault)
        vault.snapshot(is_clean)
        originals = {path: sha256_of(path) for path in iter_files(watch)}

        handler = RansomwareMonitor(watch, vault, canaries, responder=None)
        observer = create_observer(handler, watch)
        observer.start()
        time.sleep(0.5)

        started = time.time()
        if attack:
            encrypted = simulate_attack.run(watch, rename=rename, delay=0.2, verbose=False)
        else:
            simulate_benign.run(watch, delay=0.2, verbose=False)
            encrypted = []
        time.sleep(SETTLE_SECONDS)
        observer.stop()
        observer.join()

        result = {
            "scenario": name,
            "files_attacked": len(encrypted),
            "alerts": len(handler.alerts),
            "detected": bool(handler.incidents),
        }

        if handler.incidents:
            first = handler.incidents[0]["timestamp"]
            result["seconds_to_detect"] = round(first - started, 2)
            result["files_hit_before_detection"] = sum(1 for t, _ in encrypted if t <= first)

        if attack:
            report = vault.restore(os.path.join(workdir, "quarantine"), is_suspicious)
            recovered = sum(1 for path, digest in originals.items() if sha256_of(path) == digest)
            result["recovered"] = f"{recovered}/{len(originals)}"
            result["quarantined"] = len(report["quarantined"])
        return result
    finally:
        remove_tree(workdir)


def main():
    scenarios = [
        ("Normal user activity", dict(attack=False)),
        ("Encrypt + rename to .locked, canaries on", dict(use_canaries=True, rename=True)),
        ("Encrypt + rename to .locked, canaries off", dict(use_canaries=False, rename=True)),
        ("Encrypt in place, canaries on", dict(use_canaries=True, rename=False)),
        ("Encrypt in place, canaries off", dict(use_canaries=False, rename=False)),
    ]

    results = []
    for name, options in scenarios:
        print(f"Running: {name} ...")
        results.append(run_scenario(name, **options))

    print()
    print("| Scenario | Files attacked | Detected | Time to detect | Files hit before detection | Alerts | Recovered |")
    print("|---|---|---|---|---|---|---|")
    for r in results:
        detect_time = f"{r['seconds_to_detect']} s" if "seconds_to_detect" in r else "-"
        print(f"| {r['scenario']} | {r['files_attacked']} | {'Yes' if r['detected'] else 'No'} | "
              f"{detect_time} | {r.get('files_hit_before_detection', '-')} | {r['alerts']} | "
              f"{r.get('recovered', '-')} |")


if __name__ == "__main__":
    main()

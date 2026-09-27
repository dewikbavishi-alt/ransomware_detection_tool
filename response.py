"""Incident response: find the processes most likely to be encrypting files.

Checking open files for every process takes over 10 seconds on Windows and
blocks Python while it runs, so instead we:
  1. sample every process's disk-write counter twice, one second apart,
  2. check open files only for the heaviest writers,
  3. do all of this in a separate process so detection never pauses.
"""

import multiprocessing
import os
import time

import psutil

from logger import log_event

SYSTEM_PIDS = {0, 4}
TOP_WRITERS = 5


def write_counters():
    counters = {}
    for process in psutil.process_iter(["name"]):
        if process.pid in SYSTEM_PIDS:
            continue
        try:
            counters[process.pid] = (process.info["name"], process.io_counters().write_bytes)
        except (psutil.Error, OSError):
            continue
    return counters


def top_writers(sample_seconds=1.0, limit=TOP_WRITERS, exclude=()):
    before = write_counters()
    time.sleep(sample_seconds)
    after = write_counters()

    writers = []
    for pid, (name, written) in after.items():
        if pid in exclude or pid not in before:
            continue
        delta = written - before[pid][1]
        if delta > 0:
            writers.append({"pid": pid, "name": name, "bytes_written": delta})
    writers.sort(key=lambda writer: writer["bytes_written"], reverse=True)
    return writers[:limit]


def files_open_in(pid, watch_dir):
    watch_dir = os.path.normcase(os.path.abspath(watch_dir)) + os.sep
    try:
        open_files = psutil.Process(pid).open_files()
    except (psutil.Error, OSError):
        return []
    return [f.path for f in open_files if os.path.normcase(f.path).startswith(watch_dir)]


def investigate(watch_dir, auto_kill=False, exclude=()):
    writers = top_writers(exclude=set(exclude) | {os.getpid()})
    if not writers:
        log_event("No process wrote to disk during the check.", "HIGH")
        return writers

    for writer in writers:
        writer["open_files"] = files_open_in(writer["pid"], watch_dir)
        confirmed = bool(writer["open_files"])
        log_event(
            f"{'SUSPECT' if confirmed else 'Active writer'}: {writer['name']} (PID {writer['pid']}) "
            f"wrote {writer['bytes_written'] / 1024:.0f} KB in 1s"
            + (f", has open: {', '.join(writer['open_files'][:3])}" if confirmed else ""),
            "CRITICAL" if confirmed else "HIGH")

        # Only terminate a process we saw holding files in the protected folder
        if auto_kill and confirmed:
            try:
                psutil.Process(writer["pid"]).terminate()
                log_event(f"Terminated {writer['name']} (PID {writer['pid']})", "CRITICAL")
            except psutil.Error as error:
                log_event(f"Could not terminate PID {writer['pid']}: {error}", "HIGH")
    return writers


def respond(watch_dir, auto_kill=False):
    """Start the investigation in a separate process and return immediately."""
    worker = multiprocessing.Process(
        target=investigate, args=(watch_dir, auto_kill, (os.getpid(),)), daemon=True)
    worker.start()
    return worker

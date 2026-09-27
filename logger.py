import json
import os
import sys
import threading
from datetime import datetime

import config

COLORS = {
    "INFO": "",
    "MEDIUM": "\033[33m",           # yellow
    "HIGH": "\033[91m",             # bright red
    "CRITICAL": "\033[1;97;41m",    # bold white on red
}
RESET = "\033[0m"

_lock = threading.Lock()
_settings = {
    "log_file": config.LOG_FILE,
    "alerts_file": config.ALERTS_FILE,
    "echo": True,
}


def configure(log_file=None, alerts_file=None, echo=None):
    """Change where logs go. Used by the tests and the evaluation script."""
    if log_file is not None:
        _settings["log_file"] = log_file
    if alerts_file is not None:
        _settings["alerts_file"] = alerts_file
    if echo is not None:
        _settings["echo"] = echo


def _append(path, line):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as file:
        file.write(line + "\n")


def log_event(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{level}] {message}"

    with _lock:
        if _settings["echo"]:
            color = COLORS.get(level, "") if sys.stdout.isatty() else ""
            print(f"{color}{line}{RESET if color else ''}", flush=True)
        _append(_settings["log_file"], line)


def record_alert(alert):
    """Write one alert as a JSON line so other tools can read it."""
    with _lock:
        _append(_settings["alerts_file"], json.dumps(alert))


def read_alerts():
    path = _settings["alerts_file"]
    if not os.path.exists(path):
        return []

    alerts = []
    with open(path, encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line:
                alerts.append(json.loads(line))
    return alerts

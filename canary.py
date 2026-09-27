"""Decoy (canary) files placed in the watch folder.

Real users never open them, so any change, rename or deletion is a
very strong sign that a program is working through every file.
"""

import os

import config

CANARY_TEXT = (
    "Decoy file created by the ransomware detection tool.\n"
    "Please do not open, edit, move or delete it.\n"
    "Any change to this file raises a CRITICAL alert.\n"
)


def canary_paths(watch_dir):
    return {os.path.abspath(os.path.join(watch_dir, name)) for name in config.CANARY_FILES}


def create_canaries(watch_dir):
    """Create any missing canary files and return the set of their paths."""
    paths = canary_paths(watch_dir)
    for path in paths:
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as file:
                file.write(CANARY_TEXT * 20)
    return paths

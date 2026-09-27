"""Safe ransomware simulator for testing the detector.

It overwrites files with random bytes (like encryption, but with no key) and
drops a ransom note. It only runs inside a folder created by demo_files.py,
which contains a .ransomware_sandbox marker, so it cannot damage real files.
"""

import argparse
import os
import sys
import time

import config
from demo_files import SANDBOX_MARKER

RANSOM_NOTE_NAME = "HOW_TO_DECRYPT_FILES.txt"
RANSOM_NOTE = (
    "*** SIMULATION ONLY - no real ransomware was used ***\n"
    "Your files have been encrypted. This is a test note created by simulate_attack.py.\n"
)


def check_sandbox(folder):
    if not os.path.isfile(os.path.join(folder, SANDBOX_MARKER)):
        raise RuntimeError(
            f"{folder} is not a sandbox folder (no {SANDBOX_MARKER} file). "
            "Run 'python demo_files.py' first. Refusing to run.")


def target_files(folder):
    files = []
    for root, _, names in os.walk(folder):
        for name in names:
            if name != SANDBOX_MARKER:
                files.append(os.path.join(root, name))
    return sorted(files)


def run(folder, rename=True, delay=0.2, drop_note=True, verbose=True):
    """Encrypt every file in the sandbox. Returns (time, path) for each file."""
    check_sandbox(folder)
    encrypted = []

    for path in target_files(folder):
        with open(path, "rb") as file:
            size = len(file.read())
        scrambled = os.urandom(max(size, 16))

        if rename:
            with open(path + ".locked", "wb") as file:
                file.write(scrambled)
            os.remove(path)
        else:
            with open(path, "wb") as file:
                file.write(scrambled)

        encrypted.append((time.time(), path))
        if verbose:
            print(f"[attack] encrypted {os.path.basename(path)}")
        time.sleep(delay)

    if drop_note:
        with open(os.path.join(folder, RANSOM_NOTE_NAME), "w", encoding="utf-8") as note:
            note.write(RANSOM_NOTE)

    return encrypted


def main():
    parser = argparse.ArgumentParser(description="Safe ransomware attack simulator")
    parser.add_argument("--folder", default=config.WATCH_FOLDER)
    parser.add_argument("--in-place", action="store_true",
                        help="overwrite files without renaming them to .locked")
    parser.add_argument("--delay", type=float, default=0.2, help="seconds between files")
    args = parser.parse_args()

    try:
        encrypted = run(args.folder, rename=not args.in_place, delay=args.delay)
    except RuntimeError as error:
        print(error)
        sys.exit(1)
    print(f"[attack] done: {len(encrypted)} files encrypted")


if __name__ == "__main__":
    main()

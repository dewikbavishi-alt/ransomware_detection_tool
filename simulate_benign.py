"""Normal user activity, used to check the detector does not raise false alarms."""

import glob
import os
import random
import shutil
import time
import zipfile

import config
from demo_files import create_demo_files, make_docx, make_png, paragraph


def run(folder, delay=0.1, verbose=True):
    rng = random.Random(42)
    steps = []

    def step(description):
        steps.append(description)
        if verbose:
            print(f"[benign] {description}")
        time.sleep(delay)

    for path in sorted(glob.glob(os.path.join(folder, "meeting_notes_*.txt")))[:2]:
        with open(path, "a", encoding="utf-8") as file:
            file.write("\n\n" + paragraph(rng, 4))
        step(f"edited {os.path.basename(path)}")

    notes = os.path.join(folder, "notes_gujarati.txt")
    with open(notes, "w", encoding="utf-8") as file:
        file.write("આજની મીટિંગ નોંધ: ગ્રાહક સાથે ચર્ચા થઈ. " * 40)
    step("wrote a non-English text file")

    make_docx(os.path.join(folder, "new_proposal.docx"), paragraph(rng, 40))
    step("saved a new Word document")

    with open(os.path.join(folder, "screenshot.png"), "wb") as file:
        file.write(make_png(rng, 64, 64))
    step("saved a new image")

    archive = os.path.join(folder, "backup_archive.zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
        for path in sorted(glob.glob(os.path.join(folder, "*.csv"))):
            zipped.write(path, os.path.basename(path))
    step("created a zip archive (high entropy, but a normal file type)")

    source = sorted(glob.glob(os.path.join(folder, "project_plan_*.md")))[0]
    os.rename(source, source.replace(".md", "_final.md"))
    step("renamed a file")

    copy_dir = os.path.join(folder, "copied_folder")
    os.makedirs(copy_dir, exist_ok=True)
    for path in sorted(glob.glob(os.path.join(folder, "*.pdf"))) + sorted(glob.glob(os.path.join(folder, "*.csv"))):
        shutil.copy2(path, copy_dir)
    step("copied 8 files into a new folder")

    batch_dir = os.path.join(folder, "bulk_export")
    create_demo_files(batch_dir, sets=3, seed=99)
    os.remove(os.path.join(batch_dir, ".ransomware_sandbox"))
    step("bulk-exported 18 files at once (mass activity)")

    return steps


if __name__ == "__main__":
    run(config.WATCH_FOLDER)

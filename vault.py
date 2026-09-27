"""Backup vault that only ever stores clean versions of files.

Files are stored by their SHA-256 hash (so identical content is stored once),
and manifest.json records the version history of every file in the watch folder.
When a change looks malicious, the vault is not updated, so the last clean
version is always there to restore.
"""

import hashlib
import json
import os
import shutil
import stat
import threading
from datetime import datetime

import config
from detector import strip_suspicious_extension


def sha256_of(file_path):
    digest = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def remove_tree(folder):
    """Delete a folder, including the read-only files the vault creates."""
    def make_writable(function, path, _):
        os.chmod(path, stat.S_IWRITE)
        function(path)

    if os.path.exists(folder):
        shutil.rmtree(folder, onexc=make_writable)


def iter_files(folder):
    for root, _, files in os.walk(folder):
        for name in files:
            yield os.path.join(root, name)


class Vault:
    def __init__(self, vault_dir, watch_dir, max_versions=config.MAX_VERSIONS_PER_FILE):
        self.vault_dir = os.path.abspath(vault_dir)
        self.watch_dir = os.path.abspath(watch_dir)
        self.blob_dir = os.path.join(self.vault_dir, "blobs")
        self.manifest_path = os.path.join(self.vault_dir, "manifest.json")
        self.max_versions = max_versions
        self.lock = threading.Lock()

        os.makedirs(self.blob_dir, exist_ok=True)
        self.manifest = self._load()

    def _load(self):
        if not os.path.exists(self.manifest_path):
            return {}
        with open(self.manifest_path, encoding="utf-8") as file:
            return json.load(file)

    def _save(self):
        temp_path = self.manifest_path + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as file:
            json.dump(self.manifest, file, indent=2)
        os.replace(temp_path, self.manifest_path)

    def relpath(self, file_path):
        return os.path.relpath(os.path.abspath(file_path), self.watch_dir)

    def is_tracked(self, file_path):
        return self.relpath(file_path) in self.manifest

    def file_count(self):
        return len(self.manifest)

    def latest(self, file_path):
        versions = self.manifest.get(self.relpath(file_path))
        return versions[-1] if versions else None

    def baseline_entropy(self, file_path):
        """Entropy of the last clean version, also for renamed copies like report.txt.locked."""
        for candidate in (file_path, strip_suspicious_extension(file_path)):
            if candidate is None:
                continue
            version = self.latest(candidate)
            if version and version.get("entropy") is not None:
                return version["entropy"]
        return None

    def save_version(self, file_path, entropy=None):
        """Store the file's current content. Only call this for clean files."""
        digest = sha256_of(file_path)
        if digest is None:
            return False

        relative = self.relpath(file_path)
        with self.lock:
            versions = self.manifest.setdefault(relative, [])
            if versions and versions[-1]["sha256"] == digest:
                return False

            blob_path = os.path.join(self.blob_dir, digest)
            if not os.path.exists(blob_path):
                try:
                    shutil.copyfile(file_path, blob_path)
                except OSError:
                    return False
                os.chmod(blob_path, stat.S_IREAD)   # read-only, harder to tamper with

            versions.append({
                "sha256": digest,
                "size": os.path.getsize(blob_path),
                "entropy": None if entropy is None else round(entropy, 3),
                "saved_at": datetime.now().isoformat(timespec="seconds"),
            })
            del versions[:-self.max_versions]
            self._save()
        return True

    def snapshot(self, is_clean):
        """Back up every file in the watch folder.

        is_clean(path) returns (clean, entropy). Files that already look
        encrypted are skipped and returned so the caller can warn about them.
        """
        saved, skipped = 0, []
        for file_path in iter_files(self.watch_dir):
            clean, entropy = is_clean(file_path)
            if not clean:
                skipped.append(self.relpath(file_path))
            elif self.save_version(file_path, entropy):
                saved += 1
        return saved, skipped

    def restore(self, quarantine_dir, is_suspicious):
        """Put back the last clean version of every file.

        Damaged files and files that look malicious (encrypted copies, ransom
        notes) are moved to a timestamped quarantine folder, never deleted.
        """
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_root = os.path.join(os.path.abspath(quarantine_dir), stamp)
        report = {"restored": [], "unchanged": 0, "quarantined": [], "quarantine_dir": quarantine_root}

        def quarantine(file_path):
            target = os.path.join(quarantine_root, self.relpath(file_path))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.move(file_path, target)
            report["quarantined"].append(self.relpath(file_path))

        for relative, versions in self.manifest.items():
            target = os.path.join(self.watch_dir, relative)
            clean = versions[-1]

            if sha256_of(target) == clean["sha256"]:
                report["unchanged"] += 1
                continue

            if os.path.exists(target):
                quarantine(target)

            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copyfile(os.path.join(self.blob_dir, clean["sha256"]), target)
            report["restored"].append(relative)

        for file_path in list(iter_files(self.watch_dir)):
            if self.relpath(file_path) not in self.manifest and is_suspicious(file_path):
                quarantine(file_path)

        return report

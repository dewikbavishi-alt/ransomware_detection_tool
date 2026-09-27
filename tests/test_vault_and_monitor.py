import os
import tempfile
import unittest

import logger
import simulate_attack
from canary import create_canaries
from demo_files import create_demo_files
from main import make_checkers
from monitor import RansomwareMonitor
from vault import Vault, iter_files, remove_tree, sha256_of


class SandboxTestCase(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="ransom_test_")
        self.watch = os.path.join(self.workdir, "protected_files")
        logger.configure(os.path.join(self.workdir, "security.log"),
                         os.path.join(self.workdir, "alerts.jsonl"), echo=False)
        create_demo_files(self.watch, sets=2)
        self.vault = Vault(os.path.join(self.workdir, "vault"), self.watch)
        self.is_clean, self.is_suspicious = make_checkers(self.vault)

    def tearDown(self):
        remove_tree(self.workdir)

    def path(self, name):
        return os.path.join(self.watch, name)


class VaultTests(SandboxTestCase):
    def test_snapshot_backs_up_every_file_once(self):
        saved, skipped = self.vault.snapshot(self.is_clean)
        self.assertEqual(saved, len(list(iter_files(self.watch))))
        self.assertEqual(skipped, [])
        self.assertEqual(self.vault.snapshot(self.is_clean)[0], 0)

    def test_snapshot_skips_files_that_already_look_encrypted(self):
        with open(self.path("old.txt.locked"), "wb") as file:
            file.write(os.urandom(2048))
        _, skipped = self.vault.snapshot(self.is_clean)
        self.assertEqual(skipped, ["old.txt.locked"])

    def test_restore_after_attack(self):
        self.vault.snapshot(self.is_clean)
        originals = {path: sha256_of(path) for path in iter_files(self.watch)}

        simulate_attack.run(self.watch, rename=True, delay=0, verbose=False)
        report = self.vault.restore(os.path.join(self.workdir, "quarantine"), self.is_suspicious)

        for path, digest in originals.items():
            self.assertEqual(sha256_of(path), digest, path)
        self.assertIn(simulate_attack.RANSOM_NOTE_NAME, report["quarantined"])
        self.assertFalse(any(name.endswith(".locked") for name in os.listdir(self.watch)))

    def test_versions_are_capped(self):
        path = self.path("meeting_notes_1.txt")
        for i in range(8):
            with open(path, "a", encoding="utf-8") as file:
                file.write(f"\nline {i}")
            self.vault.save_version(path, 4.0)
        self.assertEqual(len(self.vault.manifest["meeting_notes_1.txt"]), self.vault.max_versions)

    def test_baseline_entropy_for_renamed_copy(self):
        self.vault.save_version(self.path("meeting_notes_1.txt"), 4.25)
        self.assertEqual(self.vault.baseline_entropy(self.path("meeting_notes_1.txt.locked")), 4.25)


class MonitorTests(SandboxTestCase):
    def setUp(self):
        super().setUp()
        self.canaries = create_canaries(self.watch)
        self.vault.snapshot(self.is_clean)
        self.monitor = RansomwareMonitor(self.watch, self.vault, self.canaries, responder=None)

    def test_normal_edit_updates_the_vault(self):
        path = self.path("meeting_notes_1.txt")
        with open(path, "a", encoding="utf-8") as file:
            file.write("\nAction items: send the report on Monday.")
        self.monitor.handle_change(path, "modified")

        self.assertEqual(self.monitor.alerts, [])
        self.assertEqual(self.vault.latest(path)["sha256"], sha256_of(path))

    def test_encrypted_file_is_not_saved_to_vault(self):
        path = self.path("meeting_notes_1.txt")
        clean_hash = sha256_of(path)
        with open(path, "wb") as file:
            file.write(os.urandom(4096))
        self.monitor.handle_change(path, "modified")

        self.assertEqual(self.monitor.alerts[0]["severity"], "CRITICAL")
        self.assertEqual(self.vault.latest(path)["sha256"], clean_hash)

    def test_three_encrypted_files_declare_an_incident(self):
        for name in ["meeting_notes_1.txt", "meeting_notes_2.txt", "sales_q1.csv"]:
            with open(self.path(name), "wb") as file:
                file.write(os.urandom(4096))
            self.monitor.handle_change(self.path(name), "modified")
        self.assertEqual(len(self.monitor.incidents), 1)

    def test_duplicate_events_raise_one_alert(self):
        path = self.path("meeting_notes_1.txt")
        with open(path, "wb") as file:
            file.write(os.urandom(4096))
        for _ in range(3):
            self.monitor.handle_change(path, "modified")
        self.assertEqual(len(self.monitor.alerts), 1)

    def test_touching_a_canary_is_an_incident(self):
        canary = sorted(self.canaries)[0]
        with open(canary, "a", encoding="utf-8") as file:
            file.write("edited")
        self.monitor.handle_change(canary, "modified")
        self.assertEqual(self.monitor.alerts[0]["indicators"][0]["name"], "canary_touched")
        self.assertEqual(len(self.monitor.incidents), 1)

    def test_deleting_a_canary_is_an_incident(self):
        canary = sorted(self.canaries)[0]
        os.remove(canary)
        self.monitor.handle_delete(canary)
        self.assertEqual(len(self.monitor.incidents), 1)


class SimulatorSafetyTests(unittest.TestCase):
    def test_refuses_folder_without_sandbox_marker(self):
        with tempfile.TemporaryDirectory() as folder:
            with open(os.path.join(folder, "important.txt"), "w", encoding="utf-8") as file:
                file.write("real data")
            with self.assertRaises(RuntimeError):
                simulate_attack.run(folder, delay=0, verbose=False)
            with open(os.path.join(folder, "important.txt"), encoding="utf-8") as file:
                self.assertEqual(file.read(), "real data")


if __name__ == "__main__":
    unittest.main()

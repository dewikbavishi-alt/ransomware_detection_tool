# Ransomware Detection & Recovery Tool

A Python tool that watches a folder in real time, detects ransomware-style behaviour
within seconds, and restores every file from a backup vault that the attack could not poison.

![Python](https://img.shields.io/badge/Python-3.12%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Tests](https://img.shields.io/badge/tests-24%20passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

## Features

| Feature | How it works |
|---|---|
| **Real-time monitoring** | `watchdog` reports every file that is created, modified, renamed or deleted. |
| **Weighted detection** | Each file is checked against several indicators (see below). Their weights add up to a 0–100 score and a severity: **MEDIUM**, **HIGH** or **CRITICAL**. |
| **Canary (decoy) files** | Two decoy files are placed in the folder, named to sort first and last. Nobody should touch them, so any change, rename or deletion is a critical alert. |
| **Incident escalation** | A decoy being touched, or 3+ files flagged HIGH within 60 seconds, becomes one **ransomware incident** with clear next steps. |
| **Poison-proof backup vault** | Every file is backed up at start-up. Normal edits are saved as new versions, but a change that looks malicious is **never** saved, so the last clean copy always survives. Backups are content-addressed by SHA-256 and read-only. |
| **One-command restore** | `python main.py restore` puts back the last clean version of every file and moves encrypted copies and ransom notes to a timestamped quarantine folder (nothing is deleted). |
| **Process investigation** | During an incident it finds the processes writing the most data and checks which of them hold files open in the protected folder. With `--kill`, only a process confirmed in both ways is terminated. |
| **Structured alerts** | Human-readable log in `logs/security.log` plus one JSON alert per line in `logs/alerts.jsonl` for other tools (e.g. a SIEM). |
| **Safe simulators** | An attack simulator and a normal-activity simulator, with a safety lock so the attack can only run in a sandbox folder. |

## Detection indicators

| Indicator | Weight | Why it matters |
|---|---|---|
| `canary_touched` | 100 | A decoy file was modified, renamed or deleted |
| `ransom_note` | 70 | A new file named like `HOW_TO_DECRYPT_FILES.txt` |
| `entropy_jump` | 50 | Entropy rose by 2+ bits/byte compared with the file's last clean version (for example 4.3 → 7.9) |
| `suspicious_extension` | 40 | Known ransomware extensions such as `.locked`, `.encrypted`, `.wncry` |
| `header_mismatch` | 40 | A `.png`, `.pdf`, `.docx` etc. no longer starts with its valid file signature (magic number) |
| `text_corrupted` | 40 | A `.txt`, `.csv`, `.md` etc. now contains binary data |
| `high_entropy` | 30 | Near-random content in a file type that is not normally compressed |
| `mass_activity` | +30 | More than 10 file changes in 60 seconds. Only added when another indicator already fired, because bulk copies and unzips are normal |

```
score = sum of weights (maximum 100)
  30-49 MEDIUM     50-79 HIGH     80-100 CRITICAL
```

**Why not just entropy?** Entropy measures how random data looks, from 0 to 8 bits per byte.
Encrypted data is close to 8, but so are ZIP, PNG, JPEG, PDF and DOCX files. Flagging high entropy
on its own would raise an alarm every time someone saves a photo. This tool compares entropy with
the file's own history, skips formats that are compressed by design, and checks file signatures instead.

## Architecture

```
                     protected_files/  (watched folder + 2 decoy files)
                                 |
                          watchdog events
                                 |
                    +------------v-------------+
                    |    RansomwareMonitor     |
                    |  dedupe -> analyze_file  |
                    |  -> score -> severity    |
                    +---+-----------------+----+
            clean edit  |                 |  suspicious
                        v                 v
              +-----------------+   +--------------------------+
              |  Vault          |   |  Alert (log + JSON)      |
              |  SHA-256 blobs  |   |  3+ files or decoy hit   |
              |  manifest.json  |   |   -> INCIDENT            |
              +--------+--------+   |   -> process investigation|
                       |            |      (separate process)  |
      python main.py restore        +--------------------------+
                       |
                       v
        clean files back + quarantine/<timestamp>/
```

## Evaluation

`python evaluate.py` runs every scenario end to end in a temporary sandbox with 24 sample files
(text, CSV, Markdown, Word, PNG, PDF) plus the decoys. It starts the real monitor, runs the simulator
with 0.2 s between files, then restores and checks every file byte for byte with SHA-256.

| Scenario | Files attacked | Detected | Time to detect | Files hit before detection | Alerts | Recovered |
|---|---|---|---|---|---|---|
| Normal user activity | 0 | No | - | - | 0 | - |
| Encrypt + rename to .locked, canaries on | 26 | Yes | 0.01 s | 1 (the decoy) | 29 | 27/27 |
| Encrypt + rename to .locked, canaries off | 24 | Yes | 0.42 s | 3 | 25 | 25/25 |
| Encrypt in place, canaries on | 26 | Yes | 0.01 s | 1 (the decoy) | 27 | 27/27 |
| Encrypt in place, canaries off | 24 | Yes | 1.22 s | 7 | 25 | 25/25 |

What this shows:
- **No false alarms on normal work.** The normal-activity run edits files, writes non-English (Gujarati) text,
  saves a Word document, an image and a zip archive, renames a file, copies 8 files and bulk-exports 18 files
  at once. It produced 39 file events and zero alerts.
- **Decoys catch the attack before any real file is touched.** The first file hit was the decoy itself.
- **Without decoys, behaviour-based detection still works.** In-place encryption is slower to catch (7 files)
  because a Word document or PNG that is overwritten in place only fails its header check (MEDIUM) until
  mass activity pushes it to HIGH.
- **100% recovery in every attack scenario**, because flagged changes never reach the vault.

The attack is ended automatically here only because the simulator stops. In real life, the incident alert is
the signal to disconnect the machine and stop the process.

## Getting started

Requires Python 3.12+.

```bash
git clone https://github.com/dewikbavishi-alt/ransomware_detection_tool.git
cd ransomware_detection_tool
pip install -r requirements.txt
```

**Try the full demo** (two terminals):

```bash
python demo_files.py                  # 1. create 24 sample files in protected_files/
python main.py monitor                # 2. terminal 1: back up and start watching
python simulate_attack.py             # 3. terminal 2: run the safe attack simulation
```

Watch the alerts and the incident appear in terminal 1, then stop the monitor with **Ctrl+C** and run:

```bash
python main.py restore                # 4. restore every file, quarantine the rest
python main.py status                 # 5. summary of alerts and incidents
```

Other options:

```bash
python simulate_attack.py --in-place       # encrypt without renaming files
python simulate_benign.py                  # normal activity: should cause no alerts
python main.py monitor --kill              # also terminate confirmed suspect processes
python main.py --folder D:\Work monitor    # protect a different folder
python evaluate.py                         # reproduce the evaluation table
python -m unittest discover -s tests -t .  # run the 24 unit tests
```

Settings such as thresholds, weights, extensions and decoy names are in [`config.py`](config.py).

## Project structure

```
├── main.py              # CLI: monitor, restore, status
├── monitor.py           # watchdog handler, scoring, alerts, incident escalation
├── detector.py          # entropy, indicators, severity, activity tracker
├── filetypes.py         # file signatures (magic numbers) and text checks
├── vault.py             # versioned SHA-256 backup vault and restore
├── canary.py            # decoy files
├── response.py          # top-writer process investigation (runs in its own process)
├── logger.py            # console + log file + JSON alerts
├── config.py            # all settings
├── demo_files.py        # creates sample files and the sandbox marker
├── simulate_attack.py   # safe ransomware simulator (sandbox only)
├── simulate_benign.py   # normal user activity for false-positive testing
├── evaluate.py          # end-to-end evaluation of all scenarios
└── tests/               # 24 unit tests (unittest)
```

## Limitations

- **User-mode only.** Ransomware running as administrator can stop this tool or delete the vault. Real
  products protect themselves from the kernel. Keep the vault on a separate drive (`VAULT_FOLDER` in `config.py`)
  and keep offline backups.
- **Some files are lost before detection** when decoys are not reached first (up to 7 in the tests).
  The vault restores them, but only files that existed and were backed up before the attack.
- **Process identification is best effort.** A process is only confirmed if it has a file open at the moment
  of the check. Fast ransomware opens and closes each file quickly, so the tool often lists it only as an
  "active writer" and does not kill it.
- **Partial or intermittent encryption** (encrypting only parts of large files, as some modern families do)
  may keep entropy below the threshold. The header and text checks help but do not fully cover it.
- **Tested with a simulator, not real malware.** Real samples should only be run in an isolated virtual machine.
- **Decoys can cause false alarms** if a person or a sync/backup tool opens them.

## Disclaimer

For education and defensive research. The attack simulator only overwrites files in a folder that contains
a `.ransomware_sandbox` marker created by `demo_files.py`.

## License

MIT, see [LICENSE](LICENSE).

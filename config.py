import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

WATCH_FOLDER = os.path.join(BASE_DIR, "protected_files")
VAULT_FOLDER = os.path.join(BASE_DIR, "backups")
QUARANTINE_FOLDER = os.path.join(BASE_DIR, "quarantine")
LOG_FILE = os.path.join(BASE_DIR, "logs", "security.log")
ALERTS_FILE = os.path.join(BASE_DIR, "logs", "alerts.jsonl")

# Entropy (randomness) of file content, from 0 to 8 bits per byte.
# Plain text is around 4-5, encrypted or compressed data is close to 8.
ENTROPY_THRESHOLD = 7.5
ENTROPY_JUMP = 2.0              # rise over the file's last clean version
ENTROPY_SAMPLE_BYTES = 1024 * 1024
MIN_ENTROPY_BYTES = 512         # entropy is unreliable on very small files

# Mass activity: many file changes in a short time
ACTIVITY_WINDOW_SECONDS = 60
MAX_FILE_CHANGES_PER_MINUTE = 10

# Incident: this many HIGH or CRITICAL files inside the activity window
INCIDENT_MIN_FILES = 3
INCIDENT_COOLDOWN_SECONDS = 60
ALERT_COOLDOWN_SECONDS = 30

# Score needed for each severity (score is capped at 100)
SEVERITY_LEVELS = [
    ("CRITICAL", 80),
    ("HIGH", 50),
    ("MEDIUM", 30),
]

# Clean versions kept in the vault for each file
MAX_VERSIONS_PER_FILE = 5

SUSPICIOUS_EXTENSIONS = {
    ".locked",
    ".encrypted",
    ".crypt",
    ".crypted",
    ".enc",
    ".pay",
    ".ransom",
    ".wncry",
    ".locky",
    ".cerber",
    ".zepto",
    ".crinf",
}

RANSOM_NOTE_KEYWORDS = [
    "decrypt",
    "ransom",
    "recover_files",
    "restore_files",
    "how_to_recover",
    "how_to_restore",
    "your_files",
    "files_encrypted",
]

RANSOM_NOTE_EXTENSIONS = {".txt", ".html", ".htm", ".hta", ".url", ".rtf"}

# Decoy files. Nobody should touch them, so any change means an attack.
# The names sort first and last so a program walking the folder in order
# reaches one of them early.
CANARY_FILES = [
    "!000_decoy_passwords.txt",
    "zzz_decoy_backup_codes.txt",
]
